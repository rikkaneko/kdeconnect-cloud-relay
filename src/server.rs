use std::{
  fs::{File, OpenOptions},
  os::unix::fs::{OpenOptionsExt, PermissionsExt},
  sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}},
  time::{Duration, Instant},
};

use anyhow::{Context, Result};
use axum::{
  Json, Router,
  body::Body,
  extract::{DefaultBodyLimit, Extension, Query, State, WebSocketUpgrade, rejection::{JsonRejection, QueryRejection}, ws::{Message, WebSocket}},
  http::{Request, StatusCode},
  response::{IntoResponse, Response},
  routing::{get, patch},
};
use fs2::FileExt;
use futures_util::{SinkExt, StreamExt};
use hyper_util::{rt::{TokioExecutor, TokioIo}, server::conn::auto::Builder, service::TowerToHyperService};
use serde_json::{Value, json};
use tokio::{
  io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
  net::{TcpListener, UnixListener},
  sync::{Mutex, RwLock, Semaphore, mpsc, watch},
  task::JoinSet,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
  config::{Config, canonical_dns_name},
  hub::{ConnectionIo, Hub},
  protocol::{AdminCommand, CONTROL_LIMIT, Control, DirectoryQuery, DisplayUpdate, ENVELOPE_LIMIT, Identity, SUBPROTOCOL},
  store::Store,
  tls,
};

#[derive(Clone)]
pub struct App {
  pub config: Config,
  pub store: Store,
  pub hub: Arc<Mutex<Hub>>,
  pub gate: Arc<RwLock<()>>,
  pub ready: Arc<AtomicBool>,
  pub tls_epoch: Arc<AtomicU64>,
  pub tls_config: watch::Sender<Arc<rustls::ServerConfig>>,
  pub shutdown: CancellationToken,
  pub auth_failures: Arc<AtomicU64>,
}

#[derive(Clone, Default)]
pub struct PeerCertificate {
  pub fingerprint: Option<String>,
  pub expires_at: i64,
  pub tls_epoch: u64,
  pub admission: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
}

impl App {
  pub async fn open(config: Config) -> Result<(Self, File)> {
    std::fs::create_dir_all(&config.state_dir)?;
    std::fs::set_permissions(&config.state_dir, std::fs::Permissions::from_mode(0o700))?;
    let lock = OpenOptions::new().create(true).truncate(false).read(true).write(true)
      .mode(0o600).open(config.state_dir.join("relay.lock"))?;
    lock.try_lock_exclusive().context("state directory already in use")?;
    let server_config = tls::load_server_config(&config)?;
    let store = Store::open(&config.state_dir).await?;
    let (tls_config, _) = watch::channel(Arc::new(server_config));
    Ok((Self {
      config, store, hub: Arc::new(Mutex::new(Hub::new())), gate: Arc::new(RwLock::new(())),
      ready: Arc::new(AtomicBool::new(true)), tls_epoch: Arc::new(AtomicU64::new(0)),
      tls_config, shutdown: CancellationToken::new(), auth_failures: Arc::new(AtomicU64::new(0)),
    }, lock))
  }

  // All protected entry points use TLS identity and freshly checked registration state.
  pub async fn authorize(&self, peer: &PeerCertificate, allow_revoked: bool) -> Result<Identity, Box<Response>> {
    if !self.ready.load(Ordering::SeqCst) {
      return Err(Box::new(api_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", "Authorization unavailable")));
    }
    if peer.tls_epoch != self.tls_epoch.load(Ordering::SeqCst) || peer.expires_at <= time::OffsetDateTime::now_utc().unix_timestamp() {
      return Err(Box::new(api_error(StatusCode::UNAUTHORIZED, "identity_denied", "Client identity denied")));
    }
    let Some(fingerprint) = &peer.fingerprint else {
      self.auth_failures.fetch_add(1, Ordering::Relaxed);
      return Err(Box::new(api_error(StatusCode::UNAUTHORIZED, "identity_required", "Registered client certificate required")));
    };
    match self.store.authorize(fingerprint).await {
      Ok(Some(identity)) if self.ready.load(Ordering::SeqCst) && peer.tls_epoch == self.tls_epoch.load(Ordering::SeqCst)
        && peer.expires_at > time::OffsetDateTime::now_utc().unix_timestamp() => Ok(identity),
      Ok(Some(_)) => Err(Box::new(api_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", "Authorization unavailable"))),
      Ok(None) if allow_revoked => {
        // A repeat DELETE may identify its already-revoked registration, but grants no other access.
        let row = sqlx::query_as::<_, (String, String)>("SELECT d.account_id, d.id FROM certificates c JOIN devices d ON d.id=c.device_id WHERE c.fingerprint=? AND d.revoked=1")
          .bind(fingerprint).fetch_optional(&self.store.pool);
        match tokio::time::timeout(Duration::from_secs(2), row).await {
          Ok(Ok(Some((account, device)))) => Ok(Identity {
            account_id: account.parse().map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", "Authorization unavailable"))?,
            device_id: device.parse().map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", "Authorization unavailable"))?,
            fingerprint: fingerprint.clone(), expires_at: peer.expires_at,
          }),
          Ok(Ok(None)) => Err(Box::new(api_error(StatusCode::FORBIDDEN, "identity_denied", "Client identity denied"))),
          _ => { self.dependency_failed().await; Err(Box::new(api_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", "Authorization unavailable"))) },
        }
      }
      Ok(None) => {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
        Err(Box::new(api_error(StatusCode::FORBIDDEN, "identity_denied", "Client identity denied")))
      }
      Err(_) => {
        self.dependency_failed().await;
        Err(Box::new(api_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", "Authorization unavailable")))
      }
    }
  }

  pub async fn dependency_failed(&self) {
    self.ready.store(false, Ordering::SeqCst);
    self.hub.lock().await.fence_all("authorization_unavailable");
    tracing::warn!(event = "authorization_unavailable");
  }

  // The exclusive gate prevents reads, routing, or writes from crossing a revoke transition.
  pub async fn admin(&self, command: AdminCommand) -> Result<Value> {
    let _gate = self.gate.write().await;
    match command {
      AdminCommand::Metrics => {
        let mut value = self.hub.lock().await.metrics();
        value["authorizationFailures"] = json!(self.auth_failures.load(Ordering::Relaxed));
        value["ready"] = json!(self.ready.load(Ordering::SeqCst));
        Ok(value)
      }
      AdminCommand::TlsReload => {
        // Read and validate replacement material before fencing the current verifier's sessions.
        let replacement = tls::load_server_config(&self.config)?;
        self.tls_epoch.fetch_add(1, Ordering::SeqCst);
        self.hub.lock().await.fence_all("tls_reloaded");
        self.tls_config.send_replace(Arc::new(replacement));
        Ok(json!({"reloaded": true}))
      }
      command => {
        let result = self.store.admin(&command).await;
        if let Err(error) = &result {
          if error.downcast_ref::<sqlx::Error>().is_some() || error.downcast_ref::<tokio::time::error::Elapsed>().is_some() {
            self.dependency_failed().await;
          }
          return result;
        }
        // The committed command identifies its exact authorization scope; fence it
        // without doing unbounded per-connection database work under the gate.
        let mut hub = self.hub.lock().await;
        match &command {
          AdminCommand::DeviceRevoke { device_id } => hub.fence_device(*device_id,"revoked"),
          AdminCommand::CertificateRevoke { fingerprint } => {
            for (identity,generation) in hub.identities() {
              if identity.fingerprint == *fingerprint { hub.disconnect(identity.device_id,generation,"revoked"); }
            }
          }
          AdminCommand::AccountSetEnabled { account_id, enabled:false } => {
            for (identity,generation) in hub.identities() {
              if identity.account_id == *account_id { hub.disconnect(identity.device_id,generation,"account_disabled"); }
            }
          }
          _ => {},
        }
        tracing::info!(event = "operator_command_committed");
        result
      }
    }
  }
}

pub fn router(app: App) -> Router {
  Router::new()
    .route("/v1/info", get(|| async { Json(json!({
      "protocolVersions": [1], "webSocketSubprotocol": SUBPROTOCOL, "experimental": true,
      "limits": {"controlBytes": CONTROL_LIMIT, "envelopeBytes": ENVELOPE_LIMIT,
        "streamWindowBytes": 262144, "connectionQueueBytes": 1048576,
        "devicesPerAccount": 10, "packetStreamsPerDevice": 9, "payloadStreamsPerDevice": 2},
      "capabilities": ["opaque_packet_streams", "opaque_payload_children", "live_only"]
    })) }))
    .route("/health/live", get(|| async { Json(json!({"status":"live"})) }))
    .route("/health/ready", get(|State(app): State<App>| async move {
      if app.ready.load(Ordering::SeqCst) { Json(json!({"status":"ready"})).into_response() }
      else { api_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", "Not ready") }
    }))
    .route("/v1/devices", get(devices))
    .route("/v1/devices/me", patch(update_device).delete(delete_device))
    .route("/v1/tunnel", get(tunnel))
    .fallback(|| async { api_error(StatusCode::NOT_FOUND, "not_found", "Resource not found") })
    .method_not_allowed_fallback(|| async { api_error(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed", "Method not allowed") })
    .layer(DefaultBodyLimit::max(CONTROL_LIMIT))
    .layer(axum::middleware::from_fn(|request: Request<Body>, next: axum::middleware::Next| async move {
      match tokio::time::timeout(Duration::from_secs(10), next.run(request)).await {
        Ok(response) => response,
        Err(_) => api_error(StatusCode::REQUEST_TIMEOUT, "timeout", "Request timed out"),
      }
    }))
    .layer(axum::middleware::from_fn_with_state(app.clone(), |State(app): State<App>, request: Request<Body>, next: axum::middleware::Next| async move {
      // Validate both HTTP authorities before route dispatch, authorization, or
      // upgrade. Forwarded headers never determine the native TLS destination.
      let mut hosts = request.headers().get_all(axum::http::header::HOST).iter();
      let Some(host) = hosts.next() else { return api_error(StatusCode::BAD_REQUEST,"invalid_host","Exactly one valid Host header required"); };
      if hosts.next().is_some() { return api_error(StatusCode::BAD_REQUEST,"invalid_host","Exactly one valid Host header required"); }
      let Ok(host) = host.to_str() else { return api_error(StatusCode::BAD_REQUEST,"invalid_host","Invalid request hostname"); };
      for authority in std::iter::once(host).chain(request.uri().authority().map(|authority| authority.as_str())) {
        let (name, port) = match authority.rsplit_once(':') {
          Some((name,port)) => (name,Some(port)),
          None => (authority,None),
        };
        let Ok(name) = canonical_dns_name(name) else { return api_error(StatusCode::BAD_REQUEST,"invalid_host","Invalid request hostname"); };
        if port.is_some_and(|port| !port.bytes().all(|byte| byte.is_ascii_digit()) || !port.parse::<u16>().is_ok_and(|port| port > 0)) {
          return api_error(StatusCode::BAD_REQUEST,"invalid_host","Invalid request hostname port");
        }
        if !name.eq_ignore_ascii_case(&app.config.server_name) {
          return api_error(StatusCode::MISDIRECTED_REQUEST,"misdirected_request","Request hostname does not match relay domain");
        }
      }
      next.run(request).await
    }))
    .with_state(app)
}

fn api_error(status: StatusCode, code: &str, message: &str) -> Response {
  (status, Json(json!({"code":code,"message":message,"requestId":Uuid::new_v4()}))).into_response()
}

async fn devices(State(app): State<App>, Extension(peer): Extension<PeerCertificate>, query: Result<Query<DirectoryQuery>, QueryRejection>) -> Response {
  let _gate = app.gate.read().await;
  let identity = match app.authorize(&peer, false).await { Ok(value) => value, Err(response) => return *response };
  let query = match query { Ok(Query(value)) => value, Err(_) => return api_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid directory query") };
  let limit = query.limit.unwrap_or(10);
  if !(1..=100).contains(&limit) { return api_error(StatusCode::BAD_REQUEST, "invalid_input", "Limit must be between 1 and 100"); }
  match app.store.directory(&identity, query.after, (limit + 1).min(100)).await {
    Ok(mut records) => {
      let has_more = records.len() > limit as usize;
      records.truncate(limit as usize);
      let hub = app.hub.lock().await;
      let values: Vec<Value> = records.iter().map(|record| json!({
        "id":record.id,"kdeDeviceId":record.kde_device_id,"displayName":record.display_name,
        "online":hub.is_online(record.id)
      })).collect();
      Json(json!({"devices":values,"nextCursor":if has_more { records.last().map(|record|record.id) } else { None }})).into_response()
    }
    Err(_) => { app.dependency_failed().await; api_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", "Directory unavailable") }
  }
}

async fn update_device(State(app): State<App>, Extension(peer): Extension<PeerCertificate>, body: Result<Json<DisplayUpdate>, JsonRejection>) -> Response {
  let _gate = app.gate.read().await;
  let identity = match app.authorize(&peer, false).await { Ok(value) => value, Err(response) => return *response };
  let update = match body { Ok(Json(value)) => value, Err(_) => return api_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid display metadata") };
  if update.display_name.trim().is_empty() || update.display_name.len() > 128 || update.display_name.chars().any(char::is_control) {
    return api_error(StatusCode::BAD_REQUEST, "invalid_input", "Display name must contain 1 to 128 UTF-8 bytes without control characters");
  }
  match app.store.update_display(identity.device_id, &update.display_name).await {
    Ok(()) => Json(json!({"updated":true})).into_response(),
    Err(_) => { app.dependency_failed().await; api_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", "Update unavailable") }
  }
}

async fn delete_device(State(app): State<App>, Extension(peer): Extension<PeerCertificate>) -> Response {
  // Own the commit/fence transition even if the requester disconnects or times out.
  match tokio::spawn(async move {
    let _gate = app.gate.write().await;
    let identity = match app.authorize(&peer, true).await { Ok(value) => value, Err(response) => return *response };
    match app.store.self_revoke(identity.device_id).await {
      Ok(()) => {
        app.hub.lock().await.fence_device(identity.device_id, "revoked");
        StatusCode::NO_CONTENT.into_response()
      }
      Err(_) => { app.dependency_failed().await; api_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", "Revocation unavailable") }
    }
  }).await {
    Ok(response) => response,
    Err(_) => api_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", "Revocation unavailable"),
  }
}

async fn tunnel(State(app): State<App>, Extension(peer): Extension<PeerCertificate>, ws: Result<WebSocketUpgrade, axum::extract::ws::rejection::WebSocketUpgradeRejection>) -> Response {
  let _gate = app.gate.read().await;
  if let Err(response) = app.authorize(&peer, false).await { return *response; }
  let ws = match ws { Ok(ws) => ws, Err(_) => return api_error(StatusCode::BAD_REQUEST, "invalid_upgrade", "WebSocket upgrade required") };
  if !ws.requested_protocols().any(|protocol| protocol == SUBPROTOCOL) {
    return api_error(StatusCode::BAD_REQUEST, "unsupported_protocol", "kdeconnect-relay.v1 subprotocol required");
  }
  drop(_gate);
  ws.protocols([SUBPROTOCOL]).max_message_size(ENVELOPE_LIMIT).max_frame_size(ENVELOPE_LIMIT)
    .read_buffer_size(ENVELOPE_LIMIT).write_buffer_size(0).max_write_buffer_size(ENVELOPE_LIMIT + 1024)
    .on_upgrade(move |socket| socket_session(app, peer, socket)).into_response()
}

async fn socket_session(app: App, peer: PeerCertificate, socket: WebSocket) {
  let cancel = app.shutdown.child_token();
  let (control_tx, mut control_rx) = mpsc::channel(128);
  let (data_tx, mut data_rx) = mpsc::channel(1);
  let (identity, generation) = {
    let _gate = app.gate.read().await;
    let identity = match app.authorize(&peer, false).await { Ok(identity) => identity, Err(_) => return };
    let mut hub = app.hub.lock().await;
    if !app.ready.load(Ordering::SeqCst) || peer.tls_epoch != app.tls_epoch.load(Ordering::SeqCst) { return; }
    let result = hub.connect(identity.clone(), ConnectionIo {control:control_tx, data:data_tx, cancel:cancel.clone()});
    let generation = match result { Ok(value) => value, Err(_) => return };
    (identity, generation)
  };
  let (mut sink, mut source) = socket.split();
  let writer_app = app.clone();
  let writer_cancel = cancel.clone();
  let device = identity.device_id;
  let certificate_expires_at = identity.expires_at;
  let writer = tokio::spawn(async move {
    let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
    heartbeat.tick().await;
    loop {
      tokio::select! {
        biased;
        _ = writer_cancel.cancelled() => break,
        event = control_rx.recv() => {
          let Some(event) = event else { break; };
          let _gate = tokio::select! {
            biased;
            _ = writer_cancel.cancelled() => break,
            gate = writer_app.gate.read() => gate,
          };
          if writer_cancel.is_cancelled() || !writer_app.ready.load(Ordering::SeqCst)
            || time::OffsetDateTime::now_utc().unix_timestamp() >= certificate_expires_at { break; }
          let Ok(text) = serde_json::to_string(&event) else { break; };
          let sent = tokio::select! {
            biased;
            _ = writer_cancel.cancelled() => false,
            result = tokio::time::timeout(Duration::from_secs(10), sink.send(Message::Text(text.into()))) => matches!(result,Ok(Ok(()))),
          };
          writer_app.hub.lock().await.control_written(device,generation,&event);
          if !sent { break; }
        }
        delivery = data_rx.recv() => {
          let Some(mut delivery) = delivery else { break; };
          let _gate = tokio::select! {
            biased;
            _ = writer_cancel.cancelled() => break,
            gate = writer_app.gate.read() => gate,
          };
          let current = !writer_cancel.is_cancelled() && writer_app.ready.load(Ordering::SeqCst)
            && time::OffsetDateTime::now_utc().unix_timestamp() < certificate_expires_at
            && writer_app.hub.lock().await.delivery_current(device,generation,&delivery);
          let sent = if current {
            let bytes = std::mem::take(&mut delivery.bytes);
            tokio::select! {
              biased;
              _ = writer_cancel.cancelled() => false,
              result = tokio::time::timeout(Duration::from_secs(10), sink.send(Message::Binary(bytes.into()))) => matches!(result,Ok(Ok(()))),
            }
          } else { true };
          writer_app.hub.lock().await.written(device,generation,&delivery);
          if !sent { break; }
        }
        _ = heartbeat.tick() => {
          let sent = tokio::select! {
            biased;
            _ = writer_cancel.cancelled() => false,
            result = tokio::time::timeout(Duration::from_secs(10),sink.send(Message::Ping(bytes::Bytes::new()))) => matches!(result,Ok(Ok(()))),
          };
          if !sent { break; }
        }
      }
    }
    writer_cancel.cancel();
  });
  let mut last_activity = Instant::now();
  let mut heartbeat_tokens = 8.0_f64;
  let mut heartbeat_updated = Instant::now();
  let mut expiry = tokio::time::interval(Duration::from_secs(1));
  let started = Instant::now();
  let certificate_remaining = time::OffsetDateTime::from_unix_timestamp(identity.expires_at)
    .ok().and_then(|expiry| Duration::try_from(expiry - time::OffsetDateTime::now_utc()).ok()).unwrap_or(Duration::ZERO);
  // Expiry must cancel writes independently of gate contention or a stalled reader.
  let certificate_cancel = cancel.clone();
  let certificate_expiry = tokio::spawn(async move {
    tokio::time::sleep(certificate_remaining.min(Duration::from_secs(86400))).await;
    certificate_cancel.cancel();
  });
  loop {
    tokio::select! {
      biased;
      _ = cancel.cancelled() => break,
      _ = expiry.tick() => {
        if last_activity.elapsed() >= Duration::from_secs(90) || started.elapsed() >= Duration::from_secs(86400)
          || time::OffsetDateTime::now_utc().unix_timestamp() >= identity.expires_at { break; }
      }
      incoming = source.next() => {
        let Some(Ok(message)) = incoming else { break; };
        last_activity = Instant::now();
        let _gate = tokio::select! {
          biased;
          _ = cancel.cancelled() => break,
          gate = app.gate.read() => gate,
        };
        if cancel.is_cancelled() || !app.ready.load(Ordering::SeqCst) { break; }
        let result = match message {
          Message::Text(text) if text.len() <= CONTROL_LIMIT => match serde_json::from_str::<Control>(&text) {
            Ok(control) => app.hub.lock().await.control(device,generation,control),
            Err(_) => break,
          },
          Message::Binary(data) => app.hub.lock().await.data(device,generation,data.to_vec()),
          Message::Ping(_) | Message::Pong(_) => {
            heartbeat_tokens = (heartbeat_tokens + heartbeat_updated.elapsed().as_secs_f64() * 2.0).min(8.0);
            heartbeat_updated = Instant::now();
            if heartbeat_tokens < 1.0 { break; }
            heartbeat_tokens -= 1.0;
            Ok(())
          }
          _ => break,
        };
        if result.is_err() { break; }
      }
    }
  }
  cancel.cancel();
  certificate_expiry.abort();
  let _ = writer.await;
  let reason = if time::OffsetDateTime::now_utc().unix_timestamp() >= identity.expires_at
    || started.elapsed() >= Duration::from_secs(86400) { "expired" } else { "disconnected" };
  app.hub.lock().await.disconnect(device,generation,reason);
}

pub async fn run(app: App, listener: TcpListener) -> Result<()> {
  let socket_path = app.config.state_dir.join("operator.sock");
  if socket_path.exists() { std::fs::remove_file(&socket_path)?; }
  let operator = UnixListener::bind(&socket_path)?;
  std::fs::set_permissions(&socket_path,std::fs::Permissions::from_mode(0o600))?;
  let admin_slots = Arc::new(Semaphore::new(8));
  let connections = Arc::new(Semaphore::new(app.config.max_connections));
  let handshakes = Arc::new(Semaphore::new(app.config.max_handshakes));
  let mut tasks = JoinSet::new();
  let (authorization_checked, mut authorization_watch) = watch::channel(Instant::now());
  let watchdog_app = app.clone();
  tasks.spawn(async move {
    loop {
      let checked = *authorization_watch.borrow_and_update();
      let remaining = Duration::from_secs(30).saturating_sub(checked.elapsed());
      tokio::select! {
        _ = watchdog_app.shutdown.cancelled() => break,
        result = tokio::time::timeout(remaining,authorization_watch.changed()) => {
          match result {
            Ok(Ok(())) => {},
            Ok(Err(_)) => { watchdog_app.dependency_failed().await; break; },
            Err(_) => {
              // An independent lease closes idle sockets even if a slow write or
              // operator transaction delays the periodic authorization task.
              watchdog_app.dependency_failed().await;
              tokio::select! {
                _ = watchdog_app.shutdown.cancelled() => break,
                _ = authorization_watch.changed() => {},
              }
            }
          }
        }
      }
    }
  });
  let maintenance_app = app.clone();
  tasks.spawn(async move {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut last_auth = Instant::now() - Duration::from_secs(30);
    loop {
      tokio::select! {
        _ = maintenance_app.shutdown.cancelled() => break,
        _ = tick.tick() => {
          maintenance_app.hub.lock().await.tick();
          if last_auth.elapsed() >= Duration::from_secs(20) {
            let _gate = maintenance_app.gate.write().await;
            let check = async {
              sqlx::query("SELECT 1").execute(&maintenance_app.store.pool).await?;
              let identities = maintenance_app.hub.lock().await.identities();
              for (identity,generation) in identities {
                match maintenance_app.store.authorize(&identity.fingerprint).await? {
                  Some(current) if current == identity => {},
                  _ => maintenance_app.hub.lock().await.disconnect(identity.device_id,generation,"revoked"),
                }
              }
              Ok::<(),anyhow::Error>(())
            };
            if matches!(tokio::time::timeout(Duration::from_secs(5),check).await,Ok(Ok(()))) {
              authorization_checked.send_replace(Instant::now());
              maintenance_app.ready.store(true,Ordering::SeqCst);
            } else { maintenance_app.dependency_failed().await; }
            last_auth = Instant::now();
          }
        }
      }
    }
  });
  loop {
    tokio::select! {
      biased;
      _ = app.shutdown.cancelled() => break,
      Some(result) = tasks.join_next() => {
        if result.is_err() {
          tracing::warn!(event="connection_task_failed");
          app.dependency_failed().await;
        }
      },
      accepted = operator.accept() => {
        let (socket,_) = accepted?;
        let Ok(permit) = admin_slots.clone().try_acquire_owned() else { continue; };
        let admin_app = app.clone();
        tasks.spawn(async move {
          let _permit = permit;
          let mut reader = BufReader::new(socket);
          let mut input = String::new();
          let mut limited = (&mut reader).take(1024 * 1024 + 1);
          let read = tokio::time::timeout(Duration::from_secs(5),limited.read_line(&mut input)).await;
          let response = if matches!(read,Ok(Ok(_))) && input.len() <= 1024 * 1024 && input.ends_with('\n') {
            match serde_json::from_str::<AdminCommand>(&input) {
              Ok(command) => match admin_app.admin(command).await {
                Ok(value) => json!({"ok":true,"result":value}),
                Err(error) => {
                  let dependency = error.downcast_ref::<sqlx::Error>().is_some() || error.downcast_ref::<tokio::time::error::Elapsed>().is_some();
                  json!({"ok":false,"code":if dependency {"unavailable"} else {"invalid_command"},"message":if dependency {"Metadata operation unavailable"} else {"Command rejected; check identifiers, quotas, and certificate configuration"}})
                }
              },
              Err(_) => json!({"ok":false,"code":"invalid_input","message":"Invalid operator command"}),
            }
          } else { json!({"ok":false,"code":"invalid_input","message":"Bounded newline-delimited command required"}) };
          let mut output = serde_json::to_vec(&response).unwrap_or_default();
          output.push(b'\n');
          let _ = tokio::time::timeout(Duration::from_secs(5),reader.get_mut().write_all(&output)).await;
        });
      }
      accepted = listener.accept() => {
        let (socket,_) = accepted?;
        let Ok(connection_permit) = connections.clone().try_acquire_owned() else { continue; };
        let Ok(handshake_permit) = handshakes.clone().try_acquire_owned() else { continue; };
        let connection_app = app.clone();
        let mut tls_changes = app.tls_config.subscribe();
        let (tls_config,epoch) = {
          let _gate = app.gate.read().await;
          let config = tls_changes.borrow_and_update().clone();
          (config,app.tls_epoch.load(Ordering::SeqCst))
        };
        tasks.spawn(async move {
          let connection_permit = Arc::new(connection_permit);
          let tls = tokio::select! {
            biased;
            _ = connection_app.shutdown.cancelled() => return,
            result = tokio::time::timeout(Duration::from_secs(10),TlsAcceptor::from(tls_config).accept(socket)) => match result { Ok(Ok(tls)) => tls, _ => return },
          };
          drop(handshake_permit);
          let mut peer = PeerCertificate {tls_epoch:epoch,admission:Some(connection_permit),..PeerCertificate::default()};
          if let Some(certs) = tls.get_ref().1.peer_certificates() {
            let Some(leaf) = certs.first() else { return; };
            let Ok((fingerprint,expires_at)) = tls::certificate_identity(leaf.as_ref()) else { return; };
            peer.fingerprint = Some(fingerprint);
            peer.expires_at = expires_at;
          }
          let service = TowerToHyperService::new(router(connection_app.clone()).layer(Extension(peer)));
          let mut builder = Builder::new(TokioExecutor::new());
          builder.http1().max_buf_size(32 * 1024).header_read_timeout(Duration::from_secs(10)).timer(hyper_util::rt::TokioTimer::new());
          let connection = builder.serve_connection_with_upgrades(TokioIo::new(tls),service);
          tokio::pin!(connection);
          tokio::select! {
            _ = connection_app.shutdown.cancelled() => {},
            _ = tls_changes.changed() => {},
            _ = tokio::time::sleep(Duration::from_secs(86400)) => {},
            _ = &mut connection => {},
          }
        });
      }
    }
  }
  app.ready.store(false,Ordering::SeqCst);
  app.hub.lock().await.fence_all("shutdown");
  tasks.abort_all();
  while tasks.join_next().await.is_some() {}
  app.store.pool.close().await;
  std::fs::remove_file(socket_path)?;
  Ok(())
}
