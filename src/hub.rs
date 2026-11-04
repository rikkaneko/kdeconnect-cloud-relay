use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, ensure};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::protocol::{
  CONNECTION_BUDGET, CONTROL_RESERVE, Control, Event, Identity, PAYLOAD_BUDGET, QUANTUM,
  STREAM_WINDOW, StreamKind, decode_data,
};

pub struct ConnectionIo {
  pub control: mpsc::Sender<Event>,
  pub data: mpsc::Sender<Delivery>,
  pub cancel: CancellationToken,
}

#[derive(Debug)]
pub struct Delivery {
  pub stream_id: Uuid,
  pub sender_id: Uuid,
  pub bytes: Vec<u8>,
  pub total_bytes: u64,
}

struct Bucket {
  tokens: f64,
  updated: Instant,
}

impl Bucket {
  // Monotonic refill applies the same finite burst bound to all admission paths.
  fn take(&mut self, amount: u64, rate: f64, burst: f64) -> bool {
    let now = Instant::now();
    self.tokens = (self.tokens + now.duration_since(self.updated).as_secs_f64() * rate).min(burst);
    self.updated = now;
    if self.tokens < amount as f64 {
      return false;
    }
    self.tokens -= amount as f64;
    true
  }
}

struct Cached {
  request: Control,
  response: Event,
  created: Instant,
}

struct Pending {
  frame_bytes: u64,
  kind: StreamKind,
  dispatched: bool,
}

struct Connection {
  identity: Identity,
  generation: Uuid,
  io: ConnectionIo,
  connected: Instant,
  control_bytes: u64,
  control_messages: usize,
  queued_bytes: u64,
  queued_payload_bytes: u64,
  last_dispatched: Option<Uuid>,
  pending: HashMap<(Uuid, Uuid, u64), Pending>,
  cache: HashMap<Uuid, Cached>,
  cache_order: VecDeque<Uuid>,
  traffic: Bucket,
  controls: Bucket,
  opens: Bucket,
}

#[derive(Default)]
struct Direction {
  limit: u64,
  received: u64,
  written: u64,
  consumed: u64,
  queue: VecDeque<Delivery>,
}

struct Stream {
  endpoints: [Uuid; 2],
  generations: [Uuid; 2],
  account_id: Uuid,
  kind: StreamKind,
  parent_id: Option<Uuid>,
  ready: bool,
  created: Instant,
  progress: Instant,
  directions: [Direction; 2],
}

pub struct Hub {
  connections: HashMap<Uuid, Connection>,
  streams: HashMap<Uuid, Stream>,
  packets: HashMap<(Uuid, Uuid), Uuid>,
  payloads: HashMap<(Uuid, Uuid), Uuid>,
  schedule: VecDeque<(Uuid, usize)>,
  replacements: HashMap<Uuid, Bucket>,
  routed_bytes: u64,
  closed_streams: u64,
  throttles: u64,
  disconnects: u64,
  expired_connections: u64,
}

impl Default for Hub {
  fn default() -> Self {
    Self::new()
  }
}

impl Hub {
  pub fn new() -> Self {
    Self {
      connections: HashMap::new(), streams: HashMap::new(), packets: HashMap::new(),
      payloads: HashMap::new(), schedule: VecDeque::new(), replacements: HashMap::new(),
      routed_bytes: 0, closed_streams: 0, throttles: 0, disconnects: 0, expired_connections: 0,
    }
  }

  pub fn connect(&mut self, identity: Identity, io: ConnectionIo) -> Result<Uuid> {
    ensure!(io.data.max_capacity() == 1 && io.control.max_capacity() <= 128, "invalid writer capacity");
    ensure!(identity.expires_at > time::OffsetDateTime::now_utc().unix_timestamp(), "expired identity");
    let now = Instant::now();
    let bucket = self.replacements.entry(identity.device_id).or_insert(Bucket { tokens: 2.0, updated: now });
    ensure!(bucket.take(1, 0.1, 2.0), "replacement rate exceeded");
    self.fence_device(identity.device_id, "replaced");
    let generation = Uuid::new_v4();
    let device_id = identity.device_id;
    let account_id = identity.account_id;
    self.connections.insert(device_id, Connection {
      identity, generation, io, connected: now, control_bytes: 0, control_messages: 0,
      queued_bytes: 0, queued_payload_bytes: 0, last_dispatched: None, pending: HashMap::new(),
      cache: HashMap::new(), cache_order: VecDeque::new(),
      traffic: Bucket { tokens: 262144.0, updated: now },
      controls: Bucket { tokens: 40.0, updated: now },
      opens: Bucket { tokens: 10.0, updated: now },
    });
    self.emit(device_id, Event::Connected { generation, device_id })?;
    let peers: Vec<_> = self.connections.iter().filter_map(|(id, connection)| {
      (connection.identity.account_id == account_id && *id != device_id).then_some(*id)
    }).collect();
    for peer in peers {
      let _ = self.emit(peer, Event::Presence { device_id, online: true });
    }
    Ok(generation)
  }

  pub fn disconnect(&mut self, device: Uuid, generation: Uuid, reason: &str) {
    if self.connections.get(&device).is_some_and(|connection| connection.generation == generation) {
      self.fence_device(device, reason);
    }
  }

  pub fn fence_device(&mut self, device: Uuid, reason: &str) {
    let Some(connection) = self.connections.remove(&device) else { return };
    self.disconnects = self.disconnects.saturating_add(1);
    if reason == "expired" { self.expired_connections = self.expired_connections.saturating_add(1); }
    connection.io.cancel.cancel();
    let incident: Vec<_> = self.streams.iter().filter_map(|(id, stream)| stream.endpoints.contains(&device).then_some(*id)).collect();
    for id in incident {
      self.close_stream(id, reason);
    }
    let peers: Vec<_> = self.connections.iter().filter_map(|(id, candidate)| {
      (candidate.identity.account_id == connection.identity.account_id).then_some(*id)
    }).collect();
    for peer in peers {
      let _ = self.emit(peer, Event::Presence { device_id: device, online: false });
    }
  }

  pub fn fence_all(&mut self, reason: &str) {
    let devices: Vec<_> = self.connections.keys().copied().collect();
    for device in devices {
      self.fence_device(device, reason);
    }
  }

  pub fn is_online(&self, device: Uuid) -> bool {
    self.connections.get(&device).is_some_and(|connection| !connection.io.cancel.is_cancelled())
  }

  pub fn identities(&self) -> Vec<(Identity, Uuid)> {
    self.connections.values().map(|connection| (connection.identity.clone(), connection.generation)).collect()
  }

  // A canceled or closed stream's frames must be dropped before socket writes.
  pub fn delivery_current(&self, device: Uuid, generation: Uuid, delivery: &Delivery) -> bool {
    let Some(connection) = self.connections.get(&device) else { return false };
    if connection.generation != generation || connection.io.cancel.is_cancelled() {
      return false;
    }
    self.streams.get(&delivery.stream_id).is_some_and(|stream| {
      stream.ready && stream.endpoints.contains(&device)
        && stream.endpoints.contains(&delivery.sender_id)
        && stream.endpoints.iter().zip(stream.generations).all(|(endpoint, expected)| {
          self.connections.get(endpoint).is_some_and(|owner| owner.generation == expected && !owner.io.cancel.is_cancelled())
        })
    })
  }

  pub fn control(&mut self, device: Uuid, generation: Uuid, control: Control) -> Result<()> {
    let connection = self.connections.get_mut(&device).ok_or_else(|| anyhow!("stale connection"))?;
    ensure!(connection.generation == generation && !connection.io.cancel.is_cancelled(), "stale connection");
    if !connection.controls.take(1, 20.0, 40.0) {
      self.throttles += 1;
      return Err(anyhow!("control rate exceeded"));
    }
    if let Control::Window { stream_id, consumed_bytes } = control {
      let stream = self.streams.get_mut(&stream_id).ok_or_else(|| anyhow!("unknown stream"))?;
      ensure!(stream.ready, "stream not ready");
      let recipient = stream.endpoints.iter().position(|id| *id == device).ok_or_else(|| anyhow!("unknown stream"))?;
      ensure!(stream.generations[recipient] == generation, "stale stream");
      let direction = &mut stream.directions[1 - recipient];
      ensure!(consumed_bytes >= direction.consumed && consumed_bytes <= direction.received, "invalid consumption");
      if consumed_bytes > direction.consumed {
        direction.consumed = consumed_bytes;
        stream.progress = Instant::now();
      }
      self.schedule_io();
      return Ok(());
    }
    let request_id = match &control {
      Control::Open { request_id, .. } | Control::Accept { request_id, .. }
      | Control::Reject { request_id, .. } | Control::Close { request_id, .. } => *request_id,
      Control::Window { .. } => unreachable!(),
    };
    // Expiration never allows conflicting reuse inside the live bounded window.
    let now = Instant::now();
    connection.cache.retain(|_, entry| now.duration_since(entry.created) < Duration::from_secs(300));
    connection.cache_order.retain(|id| connection.cache.contains_key(id));
    if let Some(cached) = connection.cache.get(&request_id) {
      ensure!(cached.request == control, "conflicting request identifier");
      let response = cached.response.clone();
      self.emit(device, response)?;
      return Ok(());
    }
    let response = match &control {
      Control::Open { peer_id, kind, parent_id, .. } => {
        if !connection.opens.take(1, 5.0, 10.0) {
          self.throttles += 1;
          Event::Error { request_id: Some(request_id), code: "rate_limited".into(), message: "Stream open rate exceeded".into() }
        } else {
          let account_id = connection.identity.account_id;
          let peer = self.connections.get(peer_id);
          if *peer_id == device || peer.is_none_or(|peer| peer.identity.account_id != account_id || peer.io.cancel.is_cancelled()) {
            Event::Error { request_id: Some(request_id), code: "unavailable".into(), message: "Peer unavailable".into() }
          } else {
            let pair = if device < *peer_id { (device, *peer_id) } else { (*peer_id, device) };
            let existing = match kind { StreamKind::Packet => self.packets.get(&pair), StreamKind::Payload => self.payloads.get(&pair) }.copied();
            let parent_valid = match kind {
              StreamKind::Packet => parent_id.is_none(),
              StreamKind::Payload => parent_id.is_some_and(|parent| self.streams.get(&parent).is_some_and(|stream| {
                stream.ready && stream.kind == StreamKind::Packet && stream.endpoints.contains(&device)
                  && stream.endpoints.contains(peer_id)
              })),
            };
            if !parent_valid {
              Event::Error { request_id: Some(request_id), code: "invalid_parent".into(), message: "Ready packet parent required".into() }
            } else if let Some(id) = existing {
              let stream = &self.streams[&id];
              if stream.parent_id != *parent_id {
                Event::Error { request_id: Some(request_id), code: "conflict".into(), message: "Peer stream already exists".into() }
              } else {
                Event::Result { request_id, stream_id: id, state: if stream.ready { "ready" } else { "offered" }.into(), initiator_id: stream.endpoints[0] }
              }
            } else {
              let mut account_counts = [0, 0, 0];
              let mut endpoint_counts = [[0, 0, 0]; 2];
              for stream in self.streams.values().filter(|stream| stream.account_id == account_id) {
                let index = usize::from(stream.kind == StreamKind::Payload);
                account_counts[index] += 1;
                account_counts[2] += 1;
                for (slot, endpoint) in [device, *peer_id].iter().enumerate() {
                  if stream.endpoints.contains(endpoint) {
                    endpoint_counts[slot][index] += 1;
                    endpoint_counts[slot][2] += 1;
                  }
                }
              }
              let kind_index = usize::from(*kind == StreamKind::Payload);
              let quota = account_counts[kind_index] >= [45, 10][kind_index] || account_counts[2] >= 55
                || endpoint_counts.iter().any(|counts| counts[kind_index] >= [9, 2][kind_index] || counts[2] >= 11);
              if quota {
                Event::Error { request_id: Some(request_id), code: "quota_exceeded".into(), message: "Stream quota exceeded".into() }
              } else {
                let id = Uuid::new_v4();
                let peer_generation = self.connections[peer_id].generation;
                self.streams.insert(id, Stream {
                  endpoints: [device, *peer_id], generations: [generation, peer_generation], account_id,
                  kind: *kind, parent_id: *parent_id, ready: false, created: now, progress: now,
                  directions: [Direction::default(), Direction::default()],
                });
                match kind { StreamKind::Packet => { self.packets.insert(pair, id); }, StreamKind::Payload => { self.payloads.insert(pair, id); } }
                self.emit(*peer_id, Event::Offered { stream_id: id, peer_id: device, kind: *kind, parent_id: *parent_id, initiator_id: device })?;
                Event::Result { request_id, stream_id: id, state: "offered".into(), initiator_id: device }
              }
            }
          }
        }
      }
      Control::Accept { stream_id, .. } | Control::Reject { stream_id, .. } | Control::Close { stream_id, .. } => {
        let stream = self.streams.get_mut(stream_id);
        if stream.as_ref().is_none_or(|stream| !stream.endpoints.contains(&device)) {
          Event::Error { request_id: Some(request_id), code: "not_found".into(), message: "Stream unavailable".into() }
        } else {
          let stream = stream.expect("checked stream");
          let slot = usize::from(stream.endpoints[1] == device);
          ensure!(stream.generations[slot] == generation, "stale stream");
          match &control {
            Control::Accept { .. } => {
              if slot != 1 || stream.ready || stream.created.elapsed() >= Duration::from_secs(30) {
                Event::Error { request_id: Some(request_id), code: "conflict".into(), message: "Stream cannot be accepted".into() }
              } else {
                stream.ready = true;
                let endpoints = stream.endpoints;
                for (index, endpoint) in endpoints.iter().enumerate() {
                  self.emit(*endpoint, Event::Ready { stream_id: *stream_id, peer_id: endpoints[1 - index], initiator_id: endpoints[0] })?;
                }
                self.schedule.push_back((*stream_id, 0));
                self.schedule.push_back((*stream_id, 1));
                Event::Ok { request_id }
              }
            }
            Control::Reject { .. } if slot != 1 || stream.ready => {
              Event::Error { request_id: Some(request_id), code: "conflict".into(), message: "Stream cannot be rejected".into() }
            }
            _ => {
              self.close_stream(*stream_id, if matches!(control, Control::Reject { .. }) { "rejected" } else { "closed" });
              Event::Ok { request_id }
            }
          }
        }
      }
      Control::Window { .. } => unreachable!(),
    };
    let connection = self.connections.get_mut(&device).ok_or_else(|| anyhow!("stale connection"))?;
    if connection.cache.len() >= 256 && let Some(oldest) = connection.cache_order.pop_front() {
      connection.cache.remove(&oldest);
    }
    connection.cache_order.push_back(request_id);
    connection.cache.insert(request_id, Cached { request: control, response: response.clone(), created: now });
    self.emit(device, response)?;
    self.schedule_io();
    Ok(())
  }

  pub fn data(&mut self, device: Uuid, generation: Uuid, bytes: Vec<u8>) -> Result<()> {
    let (stream_id, payload) = decode_data(&bytes)?;
    let payload_bytes = payload.len() as u64;
    let frame_bytes = bytes.len() as u64;
    let connection = self.connections.get_mut(&device).ok_or_else(|| anyhow!("stale connection"))?;
    ensure!(connection.generation == generation && !connection.io.cancel.is_cancelled(), "stale connection");
    if !connection.traffic.take(payload_bytes, 1048576.0, 262144.0) {
      self.throttles += 1;
      return Err(anyhow!("traffic rate exceeded"));
    }
    let stream = self.streams.get_mut(&stream_id).ok_or_else(|| anyhow!("unknown stream"))?;
    ensure!(stream.ready, "stream not ready");
    let slot = stream.endpoints.iter().position(|id| *id == device).ok_or_else(|| anyhow!("unknown stream"))?;
    ensure!(stream.generations[slot] == generation, "stale stream");
    let recipient = stream.endpoints[1 - slot];
    let recipient_generation = stream.generations[1 - slot];
    let direction = &stream.directions[slot];
    let total = direction.received.checked_add(payload_bytes).ok_or_else(|| anyhow!("stream counter overflow"))?;
    ensure!(total <= direction.limit, "stream credit exceeded");
    let kind = stream.kind;
    let (usage, payload_usage) = self.budget_usage(recipient);
    // Payload was already reserved; only envelope overhead increases accounting.
    let fits = usage.checked_add(frame_bytes - payload_bytes).is_some_and(|value| value <= CONNECTION_BUDGET - CONTROL_RESERVE)
      && (kind != StreamKind::Payload || payload_usage.checked_add(frame_bytes - payload_bytes).is_some_and(|value| value <= PAYLOAD_BUDGET));
    let recipient_connection = self.connections.get_mut(&recipient).ok_or_else(|| anyhow!("peer unavailable"))?;
    ensure!(recipient_connection.generation == recipient_generation && !recipient_connection.io.cancel.is_cancelled(), "stale peer");
    if !fits || recipient_connection.pending.len() >= 256 {
      self.close_stream(stream_id, "backpressure");
      return Ok(());
    }
    recipient_connection.pending.insert((stream_id, device, total), Pending { frame_bytes, kind, dispatched: false });
    recipient_connection.queued_bytes += frame_bytes;
    if kind == StreamKind::Payload {
      recipient_connection.queued_payload_bytes += frame_bytes;
    }
    let stream = self.streams.get_mut(&stream_id).expect("checked stream");
    stream.directions[slot].received = total;
    stream.directions[slot].queue.push_back(Delivery { stream_id, sender_id: device, bytes, total_bytes: total });
    stream.progress = Instant::now();
    self.routed_bytes = self.routed_bytes.saturating_add(payload_bytes);
    self.schedule_io();
    Ok(())
  }

  pub fn written(&mut self, device: Uuid, generation: Uuid, delivery: &Delivery) {
    let Some(connection) = self.connections.get_mut(&device) else { return };
    if connection.generation != generation {
      return;
    }
    if let Some(pending) = connection.pending.remove(&(delivery.stream_id, delivery.sender_id, delivery.total_bytes)) {
      connection.queued_bytes -= pending.frame_bytes;
      if pending.kind == StreamKind::Payload {
        connection.queued_payload_bytes -= pending.frame_bytes;
      }
      if let Some(stream) = self.streams.get_mut(&delivery.stream_id)
        && let Some(slot) = stream.endpoints.iter().position(|id| *id == delivery.sender_id) {
        stream.directions[slot].written = stream.directions[slot].written.max(delivery.total_bytes);
      }
    }
    self.schedule_io();
  }

  pub fn control_written(&mut self, device: Uuid, generation: Uuid, event: &Event) {
    let Some(connection) = self.connections.get_mut(&device) else { return };
    if connection.generation == generation {
      let length = serde_json::to_vec(event).map_or(0, |bytes| bytes.len() as u64);
      connection.control_bytes = connection.control_bytes.saturating_sub(length);
      connection.control_messages = connection.control_messages.saturating_sub(1);
    }
  }

  pub fn tick(&mut self) {
    let now = Instant::now();
    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
    let closed: Vec<_> = self.connections.iter().filter_map(|(id, connection)| {
      (connection.io.cancel.is_cancelled() || connection.identity.expires_at <= timestamp
        || now.duration_since(connection.connected) >= Duration::from_secs(86400)).then_some(*id)
    }).collect();
    for device in closed {
      self.fence_device(device, "expired");
    }
    let expired: Vec<_> = self.streams.iter().filter_map(|(id, stream)| {
      ((!stream.ready && now.duration_since(stream.created) >= Duration::from_secs(30))
        || (stream.ready && stream.directions.iter().any(|direction| direction.received > direction.consumed)
          && now.duration_since(stream.progress) >= Duration::from_secs(30))
        || (stream.kind == StreamKind::Payload && (now.duration_since(stream.created) >= Duration::from_secs(120)
          || now.duration_since(stream.progress) >= Duration::from_secs(30))))
        .then_some(*id)
    }).collect();
    for id in expired {
      self.close_stream(id, "timeout");
    }
    self.replacements.retain(|id, bucket| self.connections.contains_key(id) || now.duration_since(bucket.updated) < Duration::from_secs(60));
    for connection in self.connections.values_mut() {
      connection.cache.retain(|_, entry| now.duration_since(entry.created) < Duration::from_secs(300));
      connection.cache_order.retain(|id| connection.cache.contains_key(id));
    }
    self.schedule_io();
  }

  pub fn metrics(&self) -> Value {
    let mut queued = 0;
    let mut reserved = 0;
    let mut controls = 0;
    for (id, connection) in &self.connections {
      queued += connection.queued_bytes;
      controls += connection.control_bytes;
      reserved += self.budget_usage(*id).0;
    }
    json!({
      "connections": self.connections.len(), "streams": self.streams.len(),
      "queuedBytes": queued, "reservedDataBytes": reserved, "controlBytes": controls,
      "routedBytes": self.routed_bytes, "closedStreams": self.closed_streams, "throttles": self.throttles,
      "disconnects": self.disconnects, "expiredConnections": self.expired_connections,
    })
  }

  // Sum future grants, written-but-unconsumed bytes, and every queued frame once.
  fn budget_usage(&self, recipient: Uuid) -> (u64, u64) {
    let Some(connection) = self.connections.get(&recipient) else { return (0, 0) };
    let mut total = connection.queued_bytes;
    let mut payload = connection.queued_payload_bytes;
    for stream in self.streams.values() {
      if let Some(slot) = stream.endpoints.iter().position(|id| *id == recipient) {
        let direction = &stream.directions[1 - slot];
        let reservation = direction.limit - direction.received + direction.written - direction.written.min(direction.consumed);
        total += reservation;
        if stream.kind == StreamKind::Payload {
          payload += reservation;
        }
      }
    }
    (total, payload)
  }

  // Bounded control bytes remain charged until the writer acknowledges them.
  fn emit(&mut self, device: Uuid, event: Event) -> Result<()> {
    let connection = self.connections.get_mut(&device).ok_or_else(|| anyhow!("peer unavailable"))?;
    let bytes = serde_json::to_vec(&event)?.len() as u64;
    if bytes > 16384 || connection.control_bytes + bytes > CONTROL_RESERVE || connection.control_messages >= 128 {
      connection.io.cancel.cancel();
      return Err(anyhow!("control capacity exceeded"));
    }
    if connection.io.control.try_send(event).is_err() {
      connection.io.cancel.cancel();
      return Err(anyhow!("control writer unavailable"));
    }
    connection.control_bytes += bytes;
    connection.control_messages += 1;
    Ok(())
  }

  // One frame ahead of each writer keeps round-robin dispatch meaningful.
  fn schedule_io(&mut self) {
    let count = self.schedule.len();
    for _ in 0..count {
      let Some((id, slot)) = self.schedule.pop_front() else { break };
      let Some(stream) = self.streams.get(&id) else { continue };
      let recipient = stream.endpoints[1 - slot];
      let sender = stream.endpoints[slot];
      let kind = stream.kind;
      let (usage, payload_usage) = self.budget_usage(recipient);
      let direction = &stream.directions[slot];
      let outstanding = direction.limit - direction.consumed.min(direction.written);
      // Leave room for 256 envelope headers in addition to credited payload.
      let capacity = (CONNECTION_BUDGET - CONTROL_RESERVE - 256 * 22).saturating_sub(usage);
      let payload_capacity = if kind == StreamKind::Payload { (PAYLOAD_BUDGET - 256 * 22).saturating_sub(payload_usage) } else { u64::MAX };
      let grant = QUANTUM.saturating_sub(outstanding).min(capacity).min(payload_capacity).min(STREAM_WINDOW.saturating_sub(outstanding));
      if grant > 0 {
        let Some(limit) = direction.limit.checked_add(grant) else {
          self.close_stream(id, "counter_overflow");
          continue;
        };
        if self.emit(sender, Event::Credit { stream_id: id, send_limit_bytes: limit }).is_ok()
          && let Some(stream) = self.streams.get_mut(&id) {
          stream.directions[slot].limit = limit;
        }
      }
      self.schedule.push_back((id, slot));
    }
    // Advance each recipient's cursor only on a dispatch. Incoming floods cannot
    // rotate a blocked writer's cursor to repeatedly favor the flooding stream.
    let recipients: Vec<_> = self.connections.keys().copied().collect();
    for recipient in recipients {
      let connection = &self.connections[&recipient];
      if connection.io.data.capacity() == 0 || connection.io.cancel.is_cancelled() {
        continue;
      }
      let mut candidates: Vec<_> = self.schedule.iter().filter_map(|(id, slot)| {
        let stream = self.streams.get(id)?;
        (stream.endpoints[1 - slot] == recipient && !stream.directions[*slot].queue.is_empty()).then_some((*id, *slot))
      }).collect();
      candidates.sort_unstable_by_key(|(id, _)| *id);
      let candidate = candidates.iter().find(|(id, _)| connection.last_dispatched.is_none_or(|last| *id > last))
        .or_else(|| candidates.first()).copied();
      let Some((id, slot)) = candidate else { continue };
      let stream = self.streams.get_mut(&id).expect("scheduled stream exists");
      let Some(delivery) = stream.directions[slot].queue.pop_front() else { continue };
      let key = (delivery.stream_id, delivery.sender_id, delivery.total_bytes);
      let connection = self.connections.get_mut(&recipient).expect("scheduled recipient exists");
      match connection.io.data.try_send(delivery) {
        Ok(()) => {
          connection.last_dispatched = Some(id);
          if let Some(pending) = connection.pending.get_mut(&key) {
            pending.dispatched = true;
          }
        }
        Err(error) => stream.directions[slot].queue.push_front(error.into_inner()),
      }
    }
  }

  // Retired frames already owned by a writer stay charged until its callback.
  fn close_stream(&mut self, id: Uuid, reason: &str) {
    let children: Vec<_> = self.streams.iter().filter_map(|(child, stream)| (stream.parent_id == Some(id)).then_some(*child)).collect();
    let mut closing = children;
    closing.push(id);
    for stream_id in closing {
      let Some(stream) = self.streams.remove(&stream_id) else { continue };
      let pair = if stream.endpoints[0] < stream.endpoints[1] { (stream.endpoints[0], stream.endpoints[1]) } else { (stream.endpoints[1], stream.endpoints[0]) };
      match stream.kind { StreamKind::Packet => { self.packets.remove(&pair); }, StreamKind::Payload => { self.payloads.remove(&pair); } }
      self.schedule.retain(|(candidate, _)| *candidate != stream_id);
      for endpoint in stream.endpoints {
        if let Some(connection) = self.connections.get_mut(&endpoint) {
          connection.pending.retain(|(pending_id, _, _), pending| {
            if *pending_id == stream_id && !pending.dispatched {
              connection.queued_bytes -= pending.frame_bytes;
              if pending.kind == StreamKind::Payload {
                connection.queued_payload_bytes -= pending.frame_bytes;
              }
              false
            } else { true }
          });
        }
        let _ = self.emit(endpoint, Event::Closed { stream_id, reason: reason.into() });
      }
      self.closed_streams = self.closed_streams.saturating_add(1);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use proptest::prelude::*;

  #[test]
  fn isolated_pair_lifecycle_and_connection_fencing() {
    let mut hub = Hub::new();
    let account = Uuid::new_v4();
    let devices: Vec<_> = (0..4).map(|_| Uuid::new_v4()).collect();
    let mut receivers = Vec::new();
    let mut generations = Vec::new();
    let mut cancellations = Vec::new();
    for (index, device) in devices.iter().enumerate() {
      let (control, controls) = mpsc::channel(128);
      let (data, deliveries) = mpsc::channel(1);
      let cancel = CancellationToken::new();
      let generation = hub.connect(Identity {
        account_id: if index == 3 { Uuid::new_v4() } else { account }, device_id: *device,
        fingerprint: format!("{index:064x}"), expires_at: i64::MAX,
      }, ConnectionIo { control, data, cancel: cancel.clone() }).unwrap();
      receivers.push((controls, deliveries));
      generations.push(generation);
      cancellations.push(cancel);
    }
    let request = Control::Open { request_id: Uuid::new_v4(), peer_id: devices[1], kind: StreamKind::Packet, parent_id: None };
    hub.control(devices[0], generations[0], request.clone()).unwrap();
    let stream_ab = *hub.streams.keys().next().unwrap();
    hub.control(devices[0], generations[0], request).unwrap();
    hub.control(devices[1], generations[1], Control::Open {
      request_id: Uuid::new_v4(), peer_id: devices[0], kind: StreamKind::Packet, parent_id: None,
    }).unwrap();
    assert_eq!(hub.streams.len(), 1);
    assert_eq!(hub.streams[&stream_ab].endpoints[0], devices[0]);
    hub.control(devices[0], generations[0], Control::Accept { request_id: Uuid::new_v4(), stream_id: stream_ab }).unwrap();
    assert!(!hub.streams[&stream_ab].ready);
    hub.control(devices[1], generations[1], Control::Accept { request_id: Uuid::new_v4(), stream_id: stream_ab }).unwrap();
    assert!(hub.streams[&stream_ab].ready);
    hub.control(devices[0], generations[0], Control::Open {
      request_id: Uuid::new_v4(), peer_id: devices[2], kind: StreamKind::Packet, parent_id: None,
    }).unwrap();
    let stream_ac = *hub.streams.keys().find(|id| **id != stream_ab).unwrap();
    hub.control(devices[2], generations[2], Control::Accept { request_id: Uuid::new_v4(), stream_id: stream_ac }).unwrap();
    hub.control(devices[0], generations[0], Control::Open {
      request_id: Uuid::new_v4(), peer_id: devices[3], kind: StreamKind::Packet, parent_id: None,
    }).unwrap();
    assert_eq!(hub.streams.len(), 2);
    hub.control(devices[0], generations[0], Control::Open {
      request_id: Uuid::new_v4(), peer_id: devices[1], kind: StreamKind::Payload, parent_id: Some(stream_ab),
    }).unwrap();
    let child = *hub.streams.keys().find(|id| **id != stream_ab && **id != stream_ac).unwrap();
    hub.control(devices[1], generations[1], Control::Accept { request_id: Uuid::new_v4(), stream_id: child }).unwrap();
    hub.disconnect(devices[1], generations[1], "disconnected");
    assert!(cancellations[1].is_cancelled());
    assert_eq!(hub.streams.len(), 1);
    assert!(hub.streams.contains_key(&stream_ac));
    assert!(hub.is_online(devices[0]));
    let (control, controls) = mpsc::channel(128);
    let (data, deliveries) = mpsc::channel(1);
    let replacement = hub.connect(Identity {
      account_id: account, device_id: devices[0], fingerprint: "new".into(), expires_at: i64::MAX,
    }, ConnectionIo { control, data, cancel: CancellationToken::new() }).unwrap();
    assert!(cancellations[0].is_cancelled());
    assert_ne!(replacement, generations[0]);
    hub.disconnect(devices[0], generations[0], "late_cleanup");
    assert!(hub.is_online(devices[0]));
    assert_eq!(hub.connections[&devices[0]].generation, replacement);
    assert!(hub.control(devices[0], generations[0], Control::Close { request_id: Uuid::new_v4(), stream_id: stream_ac }).is_err());
    assert!(hub.streams.is_empty());
    drop((controls, deliveries));
  }

  #[test]
  fn credits_include_queued_retired_and_writer_owned_bytes() {
    let mut hub = Hub::new();
    let account = Uuid::new_v4();
    let devices = [Uuid::new_v4(), Uuid::new_v4()];
    let mut generations = Vec::new();
    let mut receivers = Vec::new();
    for (index, device) in devices.iter().enumerate() {
      let (control, controls) = mpsc::channel(128);
      let (data, deliveries) = mpsc::channel(1);
      generations.push(hub.connect(Identity {
        account_id: account, device_id: *device, fingerprint: format!("{index:064x}"), expires_at: i64::MAX,
      }, ConnectionIo { control, data, cancel: CancellationToken::new() }).unwrap());
      receivers.push((controls, deliveries));
    }
    hub.control(devices[0], generations[0], Control::Open {
      request_id: Uuid::new_v4(), peer_id: devices[1], kind: StreamKind::Packet, parent_id: None,
    }).unwrap();
    let stream = *hub.streams.keys().next().unwrap();
    hub.control(devices[1], generations[1], Control::Accept { request_id: Uuid::new_v4(), stream_id: stream }).unwrap();
    assert_eq!(hub.streams[&stream].directions[0].limit, QUANTUM);
    let mut frame = vec![1, 1];
    frame.extend_from_slice(stream.as_bytes());
    frame.extend_from_slice(&1024_u32.to_be_bytes());
    frame.extend_from_slice(&[77; 1024]);
    hub.data(devices[0], generations[0], frame.clone()).unwrap();
    hub.data(devices[0], generations[0], frame.clone()).unwrap();
    assert_eq!(hub.connections[&devices[1]].queued_bytes, 2092);
    assert_eq!(hub.budget_usage(devices[1]).0, QUANTUM + 44);
    let first = receivers[1].1.try_recv().unwrap();
    assert!(hub.delivery_current(devices[1], generations[1], &first));
    hub.control(devices[1], generations[1], Control::Window { stream_id: stream, consumed_bytes: 1024 }).unwrap();
    assert_eq!(hub.streams[&stream].directions[0].limit, QUANTUM);
    hub.written(devices[1], generations[1], &first);
    assert_eq!(hub.streams[&stream].directions[0].limit, QUANTUM + 1024);
    let second = receivers[1].1.try_recv().unwrap();
    hub.control(devices[0], generations[0], Control::Close { request_id: Uuid::new_v4(), stream_id: stream }).unwrap();
    assert!(!hub.delivery_current(devices[1], generations[1], &second));
    assert_eq!(hub.connections[&devices[1]].queued_bytes, 1046);
    assert_eq!(hub.budget_usage(devices[1]).0, 1046);
    hub.written(devices[1], generations[1], &second);
    hub.written(devices[1], generations[1], &second);
    assert_eq!(hub.budget_usage(devices[1]).0, 0);
    for (index, receiver) in receivers.iter_mut().enumerate() {
      while let Ok(event) = receiver.0.try_recv() {
        hub.control_written(devices[index], generations[index], &event);
      }
      assert_eq!(hub.connections[&devices[index]].control_bytes, 0);
    }
    assert!(hub.data(devices[0], generations[0], frame).is_err());
  }

  #[test]
  fn offers_deduplication_quotas_and_timeouts_are_bounded() {
    let mut hub = Hub::new();
    let account = Uuid::new_v4();
    let mut identities = Vec::new();
    let mut generations = Vec::new();
    let mut receivers = Vec::new();
    for index in 0..11 {
      let identity = Identity { account_id: account, device_id: Uuid::new_v4(), fingerprint: format!("{index:064x}"), expires_at: i64::MAX };
      let (control, controls) = mpsc::channel(128);
      let (data, deliveries) = mpsc::channel(1);
      generations.push(hub.connect(identity.clone(), ConnectionIo { control, data, cancel: CancellationToken::new() }).unwrap());
      identities.push(identity);
      receivers.push((controls, deliveries));
    }
    let first_request = Uuid::new_v4();
    let quota_request = Uuid::new_v4();
    for peer in 1..=10 {
      hub.control(identities[0].device_id, generations[0], Control::Open {
        request_id: if peer == 1 { first_request } else if peer == 10 { quota_request } else { Uuid::new_v4() },
        peer_id: identities[peer].device_id, kind: StreamKind::Packet, parent_id: None,
      }).unwrap();
    }
    assert_eq!(hub.streams.len(), 9);
    assert!(matches!(&hub.connections[&identities[0].device_id].cache[&quota_request].response,
      Event::Error { code, .. } if code == "quota_exceeded"));
    assert!(hub.control(identities[0].device_id, generations[0], Control::Open {
      request_id: first_request, peer_id: identities[2].device_id, kind: StreamKind::Packet, parent_id: None,
    }).is_err());
    for stream in hub.streams.values_mut() {
      stream.created -= Duration::from_secs(31);
    }
    hub.tick();
    assert!(hub.streams.is_empty());
    assert!(hub.packets.is_empty());
    assert!(hub.schedule.is_empty());
    assert!(hub.connections.values().all(|connection| connection.cache.len() <= 256));
    assert_eq!(hub.connections[&identities[0].device_id].cache.len(), 10);
    hub.connections.get_mut(&identities[0].device_id).unwrap().identity.expires_at = 0;
    hub.tick();
    assert!(!hub.is_online(identities[0].device_id));
    assert_eq!(hub.metrics()["reservedDataBytes"], 0);
  }

  proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn randomized_routing_preserves_generations_and_budgets(actions in prop::collection::vec(0_u8..10, 1..100)) {
      let mut hub = Hub::new();
      let account = Uuid::new_v4();
      let devices = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
      let mut generations = Vec::new();
      let mut receivers = Vec::new();
      for (index, device) in devices.iter().enumerate() {
        let (control, controls) = mpsc::channel(128);
        let (data, deliveries) = mpsc::channel(1);
        generations.push(hub.connect(Identity {
          account_id: account, device_id: *device, fingerprint: format!("{index:064x}"), expires_at: i64::MAX,
        }, ConnectionIo { control, data, cancel: CancellationToken::new() }).unwrap());
        receivers.push((controls, deliveries));
      }
      for action in actions {
        let slot = usize::from(action % 3);
        match action {
          0..=2 => {
            let _ = hub.control(devices[slot], generations[slot], Control::Open {
              request_id: Uuid::new_v4(), peer_id: devices[(slot + 1) % 3], kind: StreamKind::Packet, parent_id: None,
            });
          }
          3 => {
            if let Some((id, stream)) = hub.streams.iter().find(|(_, stream)| !stream.ready) {
              let id = *id;
              let recipient = stream.endpoints[1];
              let generation = stream.generations[1];
              let _ = hub.control(recipient, generation, Control::Accept { request_id: Uuid::new_v4(), stream_id: id });
            }
          }
          4 => {
            if let Some((id, stream)) = hub.streams.iter().find(|(_, stream)| stream.ready) {
              let id = *id;
              let sender = stream.endpoints[0];
              let generation = stream.generations[0];
              let mut frame = vec![1, 1];
              frame.extend_from_slice(id.as_bytes());
              frame.extend_from_slice(&1_u32.to_be_bytes());
              frame.push(42);
              let _ = hub.data(sender, generation, frame);
            }
          }
          5 => {
            if let Some(id) = hub.streams.keys().next().copied() {
              hub.close_stream(id, "test_close");
            }
          }
          6 => hub.tick(),
          7 => {
            if let Some((id, stream)) = hub.streams.iter().find(|(_, stream)| stream.ready) {
              let id = *id;
              let device = stream.endpoints[1];
              let generation = stream.generations[1];
              let consumed_bytes = stream.directions[0].received;
              let _ = hub.control(device, generation, Control::Window { stream_id: id, consumed_bytes });
            }
          }
          8 => hub.disconnect(devices[slot], Uuid::new_v4(), "stale_disconnect"),
          _ => {
            for (index, receiver) in receivers.iter_mut().enumerate() {
              if let Ok(delivery) = receiver.1.try_recv() {
                hub.written(devices[index], generations[index], &delivery);
              }
            }
          }
        }
        for (index, receiver) in receivers.iter_mut().enumerate() {
          while let Ok(event) = receiver.0.try_recv() {
            hub.control_written(devices[index], generations[index], &event);
          }
        }
        for stream in hub.streams.values() {
          for (endpoint, generation) in stream.endpoints.iter().zip(stream.generations) {
            prop_assert_eq!(hub.connections[endpoint].generation, generation);
            prop_assert_eq!(hub.connections[endpoint].identity.account_id, stream.account_id);
          }
          if let Some(parent) = stream.parent_id {
            prop_assert!(hub.streams.contains_key(&parent));
          }
          for direction in &stream.directions {
            prop_assert!(direction.consumed <= direction.received);
            prop_assert!(direction.written <= direction.received);
            prop_assert!(direction.received <= direction.limit);
          }
        }
        for (device, connection) in &hub.connections {
          let (usage, payload) = hub.budget_usage(*device);
          prop_assert!(usage + connection.control_bytes <= CONNECTION_BUDGET);
          prop_assert!(payload <= PAYLOAD_BUDGET);
        }
      }
      hub.fence_all("shutdown");
      prop_assert!(hub.streams.is_empty());
      prop_assert!(hub.connections.is_empty());
      prop_assert!(hub.schedule.is_empty());
    }
  }

  #[test]
  fn recipients_receive_fair_streams_and_invalid_credits_do_not_mutate_state() {
    let mut hub = Hub::new();
    let account = Uuid::new_v4();
    let devices = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
    let mut generations = Vec::new();
    let mut receivers = Vec::new();
    for (index, device) in devices.iter().enumerate() {
      let (control, controls) = mpsc::channel(128);
      let (data, deliveries) = mpsc::channel(1);
      generations.push(hub.connect(Identity {
        account_id: account, device_id: *device, fingerprint: format!("{index:064x}"), expires_at: i64::MAX,
      }, ConnectionIo { control, data, cancel: CancellationToken::new() }).unwrap());
      receivers.push((controls, deliveries));
    }
    let mut streams = Vec::new();
    for sender in 0..2 {
      hub.control(devices[sender], generations[sender], Control::Open {
        request_id: Uuid::new_v4(), peer_id: devices[2], kind: StreamKind::Packet, parent_id: None,
      }).unwrap();
      let stream = *hub.streams.iter().find(|(_, stream)| stream.endpoints[0] == devices[sender]).unwrap().0;
      hub.control(devices[2], generations[2], Control::Accept { request_id: Uuid::new_v4(), stream_id: stream }).unwrap();
      streams.push(stream);
    }
    for (sender, stream) in streams.iter().enumerate() {
      for value in 0..3 {
        let mut frame = vec![1, 1];
        frame.extend_from_slice(stream.as_bytes());
        frame.extend_from_slice(&1_u32.to_be_bytes());
        frame.push(value);
        hub.data(devices[sender], generations[sender], frame).unwrap();
      }
    }
    let before = hub.budget_usage(devices[2]);
    assert!(hub.control(devices[2], generations[2], Control::Window { stream_id: streams[0], consumed_bytes: u64::MAX }).is_err());
    assert_eq!(hub.budget_usage(devices[2]), before);
    assert!(hub.control(devices[3], generations[3], Control::Window { stream_id: streams[0], consumed_bytes: 0 }).is_err());
    let mut forged = vec![1, 1];
    forged.extend_from_slice(streams[0].as_bytes());
    forged.extend_from_slice(&1_u32.to_be_bytes());
    forged.push(9);
    assert!(hub.data(devices[3], generations[3], forged).is_err());
    let mut sources = Vec::new();
    let mut ordered = [Vec::new(), Vec::new()];
    for _ in 0..6 {
      let delivery = receivers[2].1.try_recv().unwrap();
      let slot = usize::from(delivery.sender_id == devices[1]);
      sources.push(delivery.sender_id);
      ordered[slot].push(delivery.bytes[22]);
      hub.written(devices[2], generations[2], &delivery);
    }
    assert_ne!(sources[0], sources[1]);
    assert!(sources.windows(2).all(|pair| pair[0] != pair[1]));
    assert_eq!(ordered, [vec![0, 1, 2], vec![0, 1, 2]]);
    hub.control(devices[2], generations[2], Control::Window { stream_id: streams[0], consumed_bytes: 3 }).unwrap();
    let limit = hub.streams[&streams[0]].directions[0].limit;
    hub.control(devices[2], generations[2], Control::Window { stream_id: streams[0], consumed_bytes: 3 }).unwrap();
    assert_eq!(hub.streams[&streams[0]].directions[0].limit, limit);
    assert!(hub.control(devices[2], generations[2], Control::Window { stream_id: streams[0], consumed_bytes: 2 }).is_err());
    hub.streams.get_mut(&streams[1]).unwrap().progress -= Duration::from_secs(31);
    hub.tick();
    assert!(!hub.streams.contains_key(&streams[1]));
    assert!(hub.streams.contains_key(&streams[0]));
  }
}
