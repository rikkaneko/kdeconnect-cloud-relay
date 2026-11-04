use std::{collections::{HashMap, VecDeque}, sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}}, time::{Duration, Instant}};

use futures_util::{SinkExt, StreamExt};
use kdeconnect_cloud_relay::{
  config::{CaMode, Config},
  protocol::{AdminCommand, Control, Event, StreamKind, SUBPROTOCOL, decode_data},
  server::{App, run},
  tls,
};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
use rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::{PrivatePkcs8KeyDer, ServerName}, server::WebPkiClientVerifier};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, sync::{Mutex, mpsc, oneshot}};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::{client_async, tungstenite::{Message, client::IntoClientRequest}};
use uuid::Uuid;

enum ClientCommand {
  Control(Control, oneshot::Sender<Instant>),
  Data(Uuid, Vec<u8>, oneshot::Sender<Instant>),
  Attach(Uuid, mpsc::Sender<Vec<u8>>, oneshot::Sender<Instant>),
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ten_tls_clients_two_payloads_and_independent_inner_tls() {
  let directory = tempfile::tempdir().unwrap();
  let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
  root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
  root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
  let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate().unwrap()).unwrap();
  let ca_path = directory.path().join("root.pem");
  std::fs::write(&ca_path, root.pem()).unwrap();
  let mut server_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
  server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
  let server_key = KeyPair::generate().unwrap();
  let server_certificate = server_params.signed_by(&server_key, &root).unwrap();
  let certificate_path = directory.path().join("server.pem");
  let key_path = directory.path().join("server.key");
  std::fs::write(&certificate_path, server_certificate.pem()).unwrap();
  std::fs::write(&key_path, server_key.serialize_pem()).unwrap();
  let config = Config {
    server_name: "localhost".into(),
    bind: "127.0.0.1:0".parse().unwrap(), state_dir: directory.path().join("state"),
    tls_cert_chain_file: certificate_path, tls_private_key_file: key_path,
    client_ca_mode: CaMode::Provided, client_ca_file: Some(ca_path.clone()), client_crl_file: None,
    max_connections: 32, max_handshakes: 16,
  };
  let (app, _lock) = App::open(config).await.unwrap();
  let account = app.admin(AdminCommand::AccountCreate { name: "load-test".into() }).await.unwrap();
  let account_id = account["id"].as_str().unwrap().parse().unwrap();
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let running_app = app.clone();
  let server = tokio::spawn(async move { run(running_app, listener).await });
  let mut devices = Vec::new();
  let mut senders = Vec::new();
  let mut event_receivers = Vec::new();
  let mut data_receivers = Vec::new();
  let mut drivers = Vec::new();
  for index in 0..10 {
    let mut parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let key = KeyPair::generate().unwrap();
    let certificate = parameters.signed_by(&key, &root).unwrap();
    let chain = directory.path().join(format!("client-{index}.pem"));
    let key_file = directory.path().join(format!("client-{index}.key"));
    std::fs::write(&chain, certificate.pem()).unwrap();
    std::fs::write(&key_file, key.serialize_pem()).unwrap();
    let registration = app.admin(AdminCommand::DeviceRegister {
      account_id, kde_device_id: format!("load-{index}"), display_name: format!("device-{index}"),
      certificate_pem: certificate.pem(),
    }).await.unwrap();
    devices.push(registration["id"].as_str().unwrap().parse::<Uuid>().unwrap());
    let client = tls::client_config(CaMode::Provided, Some(&ca_path), Some(&chain), Some(&key_file)).unwrap();
    let transport = TcpStream::connect(address).await.unwrap();
    let connection = TlsConnector::from(Arc::new(client)).connect(ServerName::try_from("localhost").unwrap(), transport).await.unwrap();
    let mut request = format!("wss://localhost:{}/v1/tunnel", address.port()).into_client_request().unwrap();
    request.headers_mut().insert("Sec-WebSocket-Protocol", SUBPROTOCOL.parse().unwrap());
    let (socket, response) = client_async(request, connection).await.unwrap();
    assert_eq!(response.headers()["Sec-WebSocket-Protocol"], SUBPROTOCOL);
    let (commands, mut command_rx) = mpsc::channel::<ClientCommand>(64);
    let (events, event_rx) = mpsc::channel(64);
    let (data, data_rx) = mpsc::channel(256);
    senders.push(commands);
    event_receivers.push(event_rx);
    data_receivers.push(data_rx);
    // Each real client multiplexes writes, incoming data, and cumulative credit.
    drivers.push(tokio::spawn(async move {
      let (mut sink, mut source) = socket.split();
      let mut credits = HashMap::<Uuid, u64>::new();
      let mut sent = HashMap::<Uuid, u64>::new();
      let mut received = HashMap::<Uuid, u64>::new();
      let mut acknowledged = HashMap::<Uuid, u64>::new();
      let mut attachments = HashMap::<Uuid, mpsc::Sender<Vec<u8>>>::new();
      let mut pending = VecDeque::<(Uuid, Vec<u8>, oneshot::Sender<Instant>)>::new();
      loop {
        if pending.front().is_some_and(|(stream, payload, _)| {
          sent.get(stream).copied().unwrap_or(0) + payload.len() as u64 <= credits.get(stream).copied().unwrap_or(0)
        }) {
          let (stream, payload, receipt) = pending.pop_front().unwrap();
          let mut frame = vec![1, 1];
          frame.extend_from_slice(stream.as_bytes());
          frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
          frame.extend_from_slice(&payload);
          *sent.entry(stream).or_default() += payload.len() as u64;
          let started = Instant::now();
          sink.send(Message::Binary(frame.into())).await?;
          let _ = receipt.send(started);
          continue;
        }
        tokio::select! {
          command = command_rx.recv(), if pending.len() < 64 => {
            match command {
              Some(ClientCommand::Control(control, receipt)) => {
                sink.send(Message::Text(serde_json::to_string(&control)?.into())).await?;
                let _ = receipt.send(Instant::now());
              }
              Some(ClientCommand::Data(stream, payload, receipt)) => pending.push_back((stream, payload, receipt)),
              Some(ClientCommand::Attach(stream, incoming, receipt)) => {
                attachments.insert(stream, incoming);
                let _ = receipt.send(Instant::now());
              }
              None => break,
            }
          }
          incoming = source.next() => {
            match incoming {
              Some(Ok(Message::Text(text))) => {
                let event: Event = serde_json::from_str(&text)?;
                match event {
                  Event::Credit { stream_id, send_limit_bytes } => { credits.insert(stream_id, send_limit_bytes); }
                  Event::Presence { .. } | Event::Ok { .. } => {},
                  event => { events.send(event).await?; }
                }
              }
              Some(Ok(Message::Binary(frame))) => {
                let now = Instant::now();
                let (stream, payload) = decode_data(&frame)?;
                let consumed = received.entry(stream).or_default();
                *consumed += payload.len() as u64;
                if let Some(attachment) = attachments.get(&stream) {
                  attachment.send(payload.to_vec()).await?;
                } else {
                  data.send((stream, payload.to_vec(), now)).await?;
                }
                let acknowledged = acknowledged.entry(stream).or_default();
                if *consumed - *acknowledged >= 8192 {
                  sink.send(Message::Text(serde_json::to_string(&Control::Window { stream_id: stream, consumed_bytes: *consumed })?.into())).await?;
                  *acknowledged = *consumed;
                }
              }
              Some(Ok(Message::Ping(bytes))) => sink.send(Message::Pong(bytes)).await?,
              Some(Ok(Message::Pong(_))) => {},
              Some(Ok(Message::Close(_))) | None => break,
              Some(Err(error)) => return Err(anyhow::Error::from(error)),
              _ => {},
            }
          }
        }
      }
      Ok::<(), anyhow::Error>(())
    }));
  }
  // HTTP 101 precedes the asynchronous generation installation; wait for the
  // protocol acknowledgement rather than racing the last upgrade callback.
  for events in &mut event_receivers {
    tokio::time::timeout(Duration::from_secs(5),async {
      loop {
        if matches!(events.recv().await,Some(Event::Connected { .. })) { break; }
      }
    }).await.unwrap();
  }
  assert_eq!(app.hub.lock().await.metrics()["connections"], 10);
  let mut streams = Vec::new();
  for (sender, recipient, parent) in [(0, 1, None), (0, 2, None), (1, 3, None), (0, 2, Some(1)), (1, 3, Some(2))] {
    let kind = if parent.is_some() { StreamKind::Payload } else { StreamKind::Packet };
    let (receipt, received) = oneshot::channel();
    senders[sender].send(ClientCommand::Control(Control::Open {
      request_id: Uuid::new_v4(), peer_id: devices[recipient], kind, parent_id: parent.map(|index| streams[index]),
    }, receipt)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), received).await.unwrap().unwrap();
    let offered = tokio::time::timeout(Duration::from_secs(5), async {
      loop {
        match event_receivers[recipient].recv().await.unwrap() {
          Event::Offered { stream_id, peer_id, .. } if peer_id == devices[sender] => break stream_id,
          Event::Error { code, message, .. } => panic!("offer failed: {code}: {message}"),
          _ => {},
        }
      }
    }).await.unwrap();
    let (receipt, received) = oneshot::channel();
    senders[recipient].send(ClientCommand::Control(Control::Accept { request_id: Uuid::new_v4(), stream_id: offered }, receipt)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), received).await.unwrap().unwrap();
    for endpoint in [sender, recipient] {
      tokio::time::timeout(Duration::from_secs(5), async {
        loop {
          match event_receivers[endpoint].recv().await.unwrap() {
            Event::Ready { stream_id, .. } if stream_id == offered => break,
            Event::Error { code, message, .. } => panic!("accept failed: {code}: {message}"),
            _ => {},
          }
        }
      }).await.unwrap();
    }
    streams.push(offered);
  }
  assert_eq!(app.hub.lock().await.metrics()["streams"], 5);
  let sampling = Arc::new(AtomicBool::new(true));
  let peak_queue = Arc::new(AtomicU64::new(0));
  let peak_reservations = Arc::new(AtomicU64::new(0));
  let monitor_app = app.clone();
  let monitor_sampling = sampling.clone();
  let monitor_queue = peak_queue.clone();
  let monitor_reservations = peak_reservations.clone();
  let monitor = tokio::spawn(async move {
    while monitor_sampling.load(Ordering::SeqCst) {
      let metrics = monitor_app.hub.lock().await.metrics();
      monitor_queue.fetch_max(metrics["queuedBytes"].as_u64().unwrap(), Ordering::SeqCst);
      monitor_reservations.fetch_max(metrics["reservedDataBytes"].as_u64().unwrap(), Ordering::SeqCst);
      tokio::time::sleep(Duration::from_millis(1)).await;
    }
  });
  let mut payloads = Vec::new();
  for (sender, stream) in [(0, streams[3]), (1, streams[4])] {
    let commands = senders[sender].clone();
    payloads.push(tokio::spawn(async move {
      for index in 0..200_u32 {
        let mut bytes = vec![0x5a; 1024];
        bytes[..4].copy_from_slice(&index.to_be_bytes());
        let (receipt, received) = oneshot::channel();
        commands.send(ClientCommand::Data(stream, bytes, receipt)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), received).await.unwrap().unwrap();
        tokio::time::sleep(Duration::from_millis(3)).await;
      }
    }));
  }
  let mut latencies = Vec::new();
  for index in 0..100_u32 {
    let mut bytes = vec![0x33; 1024];
    bytes[..4].copy_from_slice(&index.to_be_bytes());
    let (receipt, received) = oneshot::channel();
    senders[0].send(ClientCommand::Data(streams[0], bytes.clone(), receipt)).await.unwrap();
    let started = tokio::time::timeout(Duration::from_secs(5), received).await.unwrap().unwrap();
    let (stream, actual, arrived) = tokio::time::timeout(Duration::from_secs(5), data_receivers[1].recv()).await.unwrap().unwrap();
    assert_eq!(stream, streams[0]);
    assert_eq!(actual, bytes);
    latencies.push(arrived.duration_since(started).as_micros() as u64);
    tokio::time::sleep(Duration::from_millis(3)).await;
  }
  for task in payloads { task.await.unwrap(); }
  for (recipient, stream) in [(2, streams[3]), (3, streams[4])] {
    for index in 0..200_u32 {
      let (actual_stream, bytes, _) = tokio::time::timeout(Duration::from_secs(5), data_receivers[recipient].recv()).await.unwrap().unwrap();
      assert_eq!(actual_stream, stream);
      assert_eq!(u32::from_be_bytes(bytes[..4].try_into().unwrap()), index);
      assert_eq!(bytes.len(), 1024);
    }
  }
  latencies.sort_unstable();
  let p95 = latencies[94];
  assert!(p95 < 1_000_000, "local relay p95 exceeded prototype target: {p95}us");
  assert!(peak_queue.load(Ordering::SeqCst) <= 10 * 1024 * 1024);
  assert!(peak_reservations.load(Ordering::SeqCst) <= 10 * 1024 * 1024);
  println!("relay_load clients=10 packet_updates=100 payload_streams=2 payload_bytes_each=204800 p95_us={p95} peak_queued_bytes={} peak_reserved_data_bytes={} network=loopback injected_rtt_ms=0",
    peak_queue.load(Ordering::SeqCst), peak_reservations.load(Ordering::SeqCst));

  // Independent peer PKI proves that outer cloud authentication never substitutes
  // for mutually authenticated inner TLS, including a child on the same WSS.
  let mut inner_root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
  inner_root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
  inner_root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
  let inner_root = CertifiedIssuer::self_signed(inner_root_params, KeyPair::generate().unwrap()).unwrap();
  let mut inner_certificates = Vec::new();
  let mut inner_keys = Vec::new();
  for _ in 0..3 {
    let mut parameters = CertificateParams::new(vec!["peer.local".into()]).unwrap();
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth, ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate().unwrap();
    inner_certificates.push(parameters.signed_by(&key, &inner_root).unwrap());
    inner_keys.push(key.serialize_der());
  }
  let mut roots = RootCertStore::empty();
  roots.add(inner_root.der().clone()).unwrap();
  let provider = Arc::new(rustls::crypto::ring::default_provider());
  let client_config = ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions().unwrap()
    .with_root_certificates(roots.clone()).with_client_auth_cert(vec![inner_certificates[0].der().clone()], PrivatePkcs8KeyDer::from(inner_keys[0].clone()).into()).unwrap();
  let mut inner_servers = Vec::new();
  for index in 1..3 {
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots.clone()), provider.clone()).build().unwrap();
    inner_servers.push(ServerConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions().unwrap()
      .with_client_cert_verifier(verifier).with_single_cert(vec![inner_certificates[index].der().clone()], PrivatePkcs8KeyDer::from(inner_keys[index].clone()).into()).unwrap());
  }
  let captured = Arc::new(Mutex::new(Vec::new()));
  let mut inner_sides = Vec::new();
  let mut bridges = Vec::new();
  for (endpoint, stream) in [(0, streams[0]), (1, streams[0]), (0, streams[3]), (2, streams[3])] {
    let (tls_side, bridge) = tokio::io::duplex(64 * 1024);
    let (incoming, mut incoming_rx) = mpsc::channel(32);
    let (receipt, received) = oneshot::channel();
    senders[endpoint].send(ClientCommand::Attach(stream, incoming, receipt)).await.unwrap();
    received.await.unwrap();
    let commands = senders[endpoint].clone();
    let audit = captured.clone();
    inner_sides.push(tls_side);
    bridges.push(tokio::spawn(async move {
      let (mut read, mut write) = tokio::io::split(bridge);
      let mut buffer = [0; 8192];
      loop {
        tokio::select! {
          read = read.read(&mut buffer) => {
            let length = read?;
            if length == 0 { break; }
            audit.lock().await.extend_from_slice(&buffer[..length]);
            let (receipt, received) = oneshot::channel();
            commands.send(ClientCommand::Data(stream, buffer[..length].to_vec(), receipt)).await?;
            tokio::time::timeout(Duration::from_secs(5), received).await??;
          }
          bytes = incoming_rx.recv() => {
            let Some(bytes) = bytes else { break; };
            write.write_all(&bytes).await?;
          }
        }
      }
      Ok::<(), anyhow::Error>(())
    }));
  }
  let child_recipient = inner_sides.pop().unwrap();
  let child_initiator = inner_sides.pop().unwrap();
  let packet_recipient = inner_sides.pop().unwrap();
  let packet_initiator = inner_sides.pop().unwrap();
  let connector = TlsConnector::from(Arc::new(client_config));
  let packet_acceptor = TlsAcceptor::from(Arc::new(inner_servers.remove(0)));
  let payload_acceptor = TlsAcceptor::from(Arc::new(inner_servers.remove(0)));
  let (packet_client, packet_server, payload_client, payload_server) = tokio::time::timeout(Duration::from_secs(10), async {
    tokio::join!(
      connector.connect(ServerName::try_from("peer.local").unwrap(), packet_initiator),
      packet_acceptor.accept(packet_recipient),
      connector.connect(ServerName::try_from("peer.local").unwrap(), child_initiator),
      payload_acceptor.accept(child_recipient),
    )
  }).await.unwrap();
  let mut packet_client = packet_client.unwrap();
  let mut packet_server = packet_server.unwrap();
  let mut payload_client = payload_client.unwrap();
  let mut payload_server = payload_server.unwrap();
  assert_eq!(packet_client.get_ref().1.peer_certificates().unwrap()[0], *inner_certificates[1].der());
  assert_eq!(packet_server.get_ref().1.peer_certificates().unwrap()[0], *inner_certificates[0].der());
  assert_eq!(payload_client.get_ref().1.peer_certificates().unwrap()[0], *inner_certificates[2].der());
  assert_eq!(payload_server.get_ref().1.peer_certificates().unwrap()[0], *inner_certificates[0].der());
  let packet_secret = b"opaque peer packet content that the relay must never decrypt";
  let payload_secret = b"independent child TLS content bound and consented by endpoints";
  packet_client.write_all(packet_secret).await.unwrap();
  packet_client.flush().await.unwrap();
  payload_client.write_all(payload_secret).await.unwrap();
  payload_client.flush().await.unwrap();
  let mut packet_actual = vec![0; packet_secret.len()];
  let mut payload_actual = vec![0; payload_secret.len()];
  tokio::time::timeout(Duration::from_secs(5), async {
    tokio::try_join!(packet_server.read_exact(&mut packet_actual), payload_server.read_exact(&mut payload_actual))
  }).await.unwrap().unwrap();
  assert_eq!(packet_actual, packet_secret);
  assert_eq!(payload_actual, payload_secret);
  let ciphertext = captured.lock().await;
  assert!(!ciphertext.windows(packet_secret.len()).any(|bytes| bytes == packet_secret));
  assert!(!ciphertext.windows(payload_secret.len()).any(|bytes| bytes == payload_secret));
  drop(ciphertext);
  println!("inner_tls sessions=2 same_physical_sender_wss=true verified_peer_certificates=true plaintext_in_relay_frames=false");
  for bridge in bridges { bridge.abort(); }
  sampling.store(false, Ordering::SeqCst);
  monitor.await.unwrap();
  app.shutdown.cancel();
  tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap().unwrap();
  for driver in drivers { driver.abort(); }
}
