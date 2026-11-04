use std::{fs::File, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use futures_util::{SinkExt, StreamExt};
use kdeconnect_cloud_relay::{
  config::{CaMode, Config},
  protocol::{AdminCommand, Control, Event, SUBPROTOCOL, StreamKind, decode_data},
  server::{App, run},
  tls,
};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
  io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
  net::{TcpListener, TcpStream, UnixStream},
  task::JoinHandle,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_tungstenite::{WebSocketStream, tungstenite::{Message, client::IntoClientRequest}};
use uuid::Uuid;

type ClientSocket = WebSocketStream<TlsStream<TcpStream>>;

struct ClientIdentity {
  id: Uuid,
  fingerprint: String,
  certificate: PathBuf,
  key: PathBuf,
  pem: String,
}

struct Fixture {
  _directory: TempDir,
  _lock: File,
  app: App,
  task: JoinHandle<anyhow::Result<()>>,
  address: SocketAddr,
  root: PathBuf,
  clients: Vec<ClientIdentity>,
  account: Uuid,
}

impl Fixture {
  // Independent native TLS identities exercise network authorization, not injected headers.
  async fn start(max_connections: usize, short_lived: bool) -> Self {
    let directory = tempfile::tempdir().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let root = directory.path().join("root.pem");
    std::fs::write(&root, issuer.pem()).unwrap();
    let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate().unwrap();
    let certificate = params.signed_by(&key, &issuer).unwrap();
    let server_chain = directory.path().join("server.pem");
    let server_key = directory.path().join("server.key");
    std::fs::write(&server_chain, certificate.pem()).unwrap();
    std::fs::write(&server_key, key.serialize_pem()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = Config {
      bind: address, server_name:"localhost".into(), state_dir: directory.path().join("state"),
      tls_cert_chain_file: server_chain, tls_private_key_file: server_key,
      client_ca_mode: CaMode::Provided, client_ca_file: Some(root.clone()), client_crl_file: None,
      max_connections, max_handshakes: max_connections.min(16),
    };
    let (app, lock) = App::open(config).await.unwrap();
    let first = app.store.admin(&AdminCommand::AccountCreate { name: "first".into() }).await.unwrap();
    let second = app.store.admin(&AdminCommand::AccountCreate { name: "second".into() }).await.unwrap();
    let account = Uuid::parse_str(first["id"].as_str().unwrap()).unwrap();
    let other = Uuid::parse_str(second["id"].as_str().unwrap()).unwrap();
    let mut clients = Vec::new();
    for index in 0..6 {
      let mut params = CertificateParams::new(vec![format!("client-{index}.test")]).unwrap();
      params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
      if short_lived && index == 0 {
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::seconds(3);
      }
      let key = KeyPair::generate().unwrap();
      let certificate = params.signed_by(&key, &issuer).unwrap();
      let pem = certificate.pem();
      let (fingerprint, _) = tls::certificate_identity(certificate.der().as_ref()).unwrap();
      let certificate_path = directory.path().join(format!("client-{index}.pem"));
      let key_path = directory.path().join(format!("client-{index}.key"));
      std::fs::write(&certificate_path, &pem).unwrap();
      std::fs::write(&key_path, key.serialize_pem()).unwrap();
      let id = if index < 4 {
        let result = app.store.admin(&AdminCommand::DeviceRegister {
          account_id: if index == 3 { other } else { account }, kde_device_id: format!("kde-{index}"),
          display_name: format!("Client {index}"), certificate_pem: pem.clone(),
        }).await.unwrap();
        Uuid::parse_str(result["id"].as_str().unwrap()).unwrap()
      } else { Uuid::nil() };
      clients.push(ClientIdentity { id, fingerprint, certificate: certificate_path, key: key_path, pem });
    }
    let task = tokio::spawn(run(app.clone(), listener));
    for _ in 0..100 {
      if app.config.state_dir.join("operator.sock").exists() { break; }
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(app.config.state_dir.join("operator.sock").exists());
    Self { _directory: directory, _lock: lock, app, task, address, root, clients, account }
  }

  // Raw HTTP keeps server trust, client identity, and response framing visible to tests.
  async fn request(&self, client: Option<usize>, request: &str) -> (u16, Value) {
    let (certificate, key) = client.map(|index| (Some(self.clients[index].certificate.as_path()), Some(self.clients[index].key.as_path())))
      .unwrap_or((None, None));
    let config = tls::client_config(CaMode::Provided, Some(&self.root), certificate, key).unwrap();
    let io = TcpStream::connect(self.address).await.unwrap();
    let mut tls = TlsConnector::from(Arc::new(config))
      .connect("localhost".try_into().unwrap(), io).await.unwrap();
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(3), tls.read_to_end(&mut bytes)).await.unwrap();
    if let Err(error) = read { assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof); }
    let response = String::from_utf8(bytes).unwrap();
    let (headers, body) = response.split_once("\r\n\r\n").expect("HTTP response headers");
    let status = headers.split_whitespace().nth(1).unwrap().parse::<u16>().unwrap();
    let value = if body.is_empty() { Value::Null } else { serde_json::from_str(body).expect("JSON response") };
    (status, value)
  }

  // Use the actual Unix command boundary, including JSON parsing and its acknowledgement.
  async fn operator(&self, command: &AdminCommand) -> Value {
    let mut socket = UnixStream::connect(self.app.config.state_dir.join("operator.sock")).await.unwrap();
    let mut input = serde_json::to_vec(command).unwrap();
    input.push(b'\n');
    socket.write_all(&input).await.unwrap();
    let mut reader = BufReader::new(socket);
    let mut output = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut output)).await.unwrap().unwrap();
    assert!(output.ends_with('\n'));
    let value: Value = serde_json::from_str(&output).unwrap();
    assert!(value.get("ok").is_some());
    value
  }

  // The upgrade runs over independently verified TLS and negotiates the mandatory protocol.
  async fn websocket(&self, client: usize) -> ClientSocket {
    let client = &self.clients[client];
    let config = tls::client_config(CaMode::Provided, Some(&self.root), Some(&client.certificate), Some(&client.key)).unwrap();
    let stream = TcpStream::connect(self.address).await.unwrap();
    let stream = TlsConnector::from(Arc::new(config)).connect("localhost".try_into().unwrap(), stream).await.unwrap();
    let mut request = format!("wss://localhost:{}/v1/tunnel", self.address.port()).into_client_request().unwrap();
    request.headers_mut().insert("sec-websocket-protocol", SUBPROTOCOL.parse().unwrap());
    let (mut socket, response) = tokio_tungstenite::client_async(request, stream).await.unwrap();
    assert_eq!(response.headers()["sec-websocket-protocol"], SUBPROTOCOL);
    event(&mut socket, |event| matches!(event, Event::Connected { .. })).await;
    socket
  }
}

impl Drop for Fixture {
  fn drop(&mut self) {
    self.app.shutdown.cancel();
    self.task.abort();
  }
}

// Consume unrelated live hints while bounding every wait; protocol errors fail immediately.
async fn event(socket: &mut ClientSocket, predicate: impl Fn(&Event) -> bool) -> Event {
  for _ in 0..256 {
    let next = tokio::time::timeout(Duration::from_secs(3), socket.next()).await.unwrap();
    match next.expect("open WebSocket").expect("valid WebSocket frame") {
      Message::Text(text) => {
        let value: Event = serde_json::from_str(&text).unwrap();
        if predicate(&value) { return value; }
        assert!(!matches!(value, Event::Error { .. }), "unexpected event: {value:?}");
      }
      Message::Ping(_) => { socket.flush().await.unwrap(); }
      message => panic!("unexpected WebSocket message: {message:?}"),
    }
  }
  panic!("expected event not observed");
}

// Exercise both offer acceptance and initial send credit for every opened logical stream.
async fn open(sender: &mut ClientSocket, recipient: &mut ClientSocket, peer: Uuid, kind: StreamKind, parent_id: Option<Uuid>) -> Uuid {
  let request = Uuid::new_v4();
  let control = Control::Open { request_id: request, peer_id: peer, kind, parent_id };
  sender.send(Message::Text(serde_json::to_string(&control).unwrap().into())).await.unwrap();
  let result = event(sender, |event| matches!(event, Event::Result { request_id, .. } if *request_id == request)).await;
  let Event::Result { stream_id, .. } = result else { unreachable!() };
  event(recipient, |event| matches!(event, Event::Offered { stream_id: id, .. } if *id == stream_id)).await;
  let accept = Control::Accept { request_id: Uuid::new_v4(), stream_id };
  recipient.send(Message::Text(serde_json::to_string(&accept).unwrap().into())).await.unwrap();
  event(sender, |event| matches!(event, Event::Ready { stream_id: id, .. } if *id == stream_id)).await;
  event(recipient, |event| matches!(event, Event::Ready { stream_id: id, .. } if *id == stream_id)).await;
  event(sender, |event| matches!(event, Event::Credit { stream_id: id, send_limit_bytes } if *id == stream_id && *send_limit_bytes >= 1024)).await;
  event(recipient, |event| matches!(event, Event::Credit { stream_id: id, send_limit_bytes } if *id == stream_id && *send_limit_bytes >= 1024)).await;
  stream_id
}

// Drain already-buffered hints before asserting transport closure after a fence.
async fn closed(socket: &mut ClientSocket) {
  for _ in 0..256 {
    let next = tokio::time::timeout(Duration::from_secs(3), socket.next()).await.unwrap();
    match next {
      None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
      Some(Ok(Message::Text(text))) => { let _: Event = serde_json::from_str(&text).unwrap(); }
      Some(Ok(Message::Ping(_))) => { let _ = socket.flush().await; }
      Some(Ok(_)) => {}
    }
  }
  panic!("fenced WebSocket did not close");
}

#[tokio::test]
async fn native_tls_http_authentication_isolation_and_metadata_validation() {
  let fixture = Fixture::start(64,false).await;
  let (status, info) = fixture.request(None, "GET /v1/info HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await;
  assert_eq!(status, 200);
  assert_eq!(info["webSocketSubprotocol"], SUBPROTOCOL);
  assert_eq!(fixture.request(None, "GET /v1/devices HTTP/1.1\r\nHost: localhost\r\nX-Client-Fingerprint: forged\r\nConnection: close\r\n\r\n").await.0, 401);
  assert_eq!(fixture.request(Some(4), "GET /v1/devices HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.0, 403);
  let (status, first) = fixture.request(Some(0), "GET /v1/devices HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await;
  assert_eq!(status, 200);
  assert_eq!(first["devices"].as_array().unwrap().len(), 3);
  assert!(!first.to_string().contains(&fixture.clients[3].id.to_string()));
  let (_, second) = fixture.request(Some(3), "GET /v1/devices HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await;
  assert_eq!(second["devices"].as_array().unwrap().len(), 1);
  for query in ["limit=0", "limit=1000", "after=invalid", "accountId=forged"] {
    let request = format!("GET /v1/devices?{query} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let (status, error) = fixture.request(Some(0), &request).await;
    assert_eq!(status, 400);
    assert!(error.get("requestId").is_some());
  }
  for body in [json!({"displayName":""}), json!({"displayName":"é".repeat(65)}), json!({"displayName":"name","accountId":"forged"})] {
    let body = body.to_string();
    let request = format!("PATCH /v1/devices/me HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    assert_eq!(fixture.request(Some(0), &request).await.0, 400);
  }
  let body = json!({"displayName":"new name"}).to_string();
  let request = format!("PATCH /v1/devices/me HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len());
  assert_eq!(fixture.request(Some(0), &request).await.0, 200);
  assert!(fixture.app.ready.load(std::sync::atomic::Ordering::SeqCst));
  fixture.app.shutdown.cancel();
}

#[tokio::test]
async fn three_endpoint_multiplexing_children_replacement_and_isolation() {
  let fixture = Fixture::start(64,false).await;
  let mut a = fixture.websocket(0).await;
  let mut b = fixture.websocket(1).await;
  let mut c = fixture.websocket(2).await;
  let request_id = Uuid::new_v4();
  a.send(Message::Text(serde_json::to_string(&Control::Open {
    request_id, peer_id: fixture.clients[3].id, kind: StreamKind::Packet, parent_id: None,
  }).unwrap().into())).await.unwrap();
  let denied = event(&mut a, |event| matches!(event, Event::Error { request_id: Some(id), .. } if *id == request_id)).await;
  assert!(matches!(denied, Event::Error { code, .. } if code == "not_found" || code == "unavailable"));
  let ab = open(&mut a, &mut b, fixture.clients[1].id, StreamKind::Packet, None).await;
  let ac = open(&mut a, &mut c, fixture.clients[2].id, StreamKind::Packet, None).await;
  let payload = open(&mut a, &mut b, fixture.clients[1].id, StreamKind::Payload, Some(ab)).await;
  for (stream, recipient_index, bytes) in [(ab, 1, vec![11; 1024]), (payload, 1, vec![22; 1024]), (ac, 2, vec![33; 1024])] {
    let recipient = if recipient_index == 1 { &mut b } else { &mut c };
    let mut frame = vec![1, 1];
    frame.extend_from_slice(stream.as_bytes());
    frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(&bytes);
    a.send(Message::Binary(frame.into())).await.unwrap();
    loop {
      let message = tokio::time::timeout(Duration::from_secs(3), recipient.next()).await.unwrap().unwrap().unwrap();
      if let Message::Binary(frame) = message {
        let (id, received) = decode_data(&frame).unwrap();
        assert_eq!(id, stream);
        assert_eq!(received, &bytes);
        break;
      }
    }
    recipient.send(Message::Text(serde_json::to_string(&Control::Window { stream_id: stream, consumed_bytes: bytes.len() as u64 }).unwrap().into())).await.unwrap();
  }
  a.send(Message::Text(serde_json::to_string(&Control::Close { request_id: Uuid::new_v4(), stream_id: ab }).unwrap().into())).await.unwrap();
  event(&mut b, |event| matches!(event, Event::Closed { stream_id, .. } if *stream_id == payload)).await;
  assert_eq!(fixture.operator(&AdminCommand::Metrics).await["ok"], true);
  let mut replacement = fixture.websocket(0).await;
  closed(&mut a).await;
  event(&mut c, |event| matches!(event, Event::Closed { stream_id, .. } if *stream_id == ac)).await;
  let fresh = open(&mut replacement, &mut c, fixture.clients[2].id, StreamKind::Packet, None).await;
  assert_ne!(fresh, ac);
  assert_eq!(fixture.operator(&AdminCommand::Metrics).await["ok"], true);
  fixture.app.shutdown.cancel();
}

#[tokio::test]
async fn operator_registration_renewal_revocation_and_idempotent_self_delete() {
  let fixture = Fixture::start(64,false).await;
  let result = fixture.operator(&AdminCommand::DeviceRegister {
    account_id: fixture.account, kde_device_id: "socket-registered".into(), display_name: "Socket device".into(), certificate_pem: fixture.clients[4].pem.clone(),
  }).await;
  assert_eq!(result["ok"], true);
  assert_eq!(fixture.request(Some(4), "GET /v1/devices HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.0, 200);
  let mut active = fixture.websocket(0).await;
  assert_eq!(fixture.operator(&AdminCommand::CertificateApprove {
    device_id: fixture.clients[0].id, certificate_pem: fixture.clients[5].pem.clone(),
  }).await["ok"], true);
  assert_eq!(fixture.operator(&AdminCommand::CertificateRevoke {
    fingerprint: fixture.clients[0].fingerprint.clone(),
  }).await["ok"], true);
  closed(&mut active).await;
  let delete = "DELETE /v1/devices/me HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
  // Revoked old credentials cannot delete the still-active registration after renewal.
  assert_eq!(fixture.request(Some(0), delete).await.0, 403);
  assert_eq!(fixture.request(Some(5), "GET /v1/devices HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.0, 200);
  assert_eq!(fixture.request(Some(1), delete).await.0, 204);
  assert_eq!(fixture.request(Some(1), delete).await.0, 204);
  assert_eq!(fixture.request(Some(1), "GET /v1/devices HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.0, 403);
  let listing = fixture.operator(&AdminCommand::List).await;
  assert_eq!(listing["ok"], true);
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(fixture.app.config.state_dir.join("operator.sock")).unwrap().permissions().mode() & 0o777, 0o600);
  }
  fixture.app.shutdown.cancel();
}

#[tokio::test]
async fn tls_reload_is_atomic_and_database_failure_fences_live_sessions() {
  let fixture = Fixture::start(64,false).await;
  let mut active = fixture.websocket(0).await;
  let original = std::fs::read(&fixture.app.config.tls_cert_chain_file).unwrap();
  std::fs::write(&fixture.app.config.tls_cert_chain_file, "invalid PEM").unwrap();
  assert_eq!(fixture.operator(&AdminCommand::TlsReload).await["ok"], false);
  assert_eq!(fixture.request(Some(0), "GET /v1/devices HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.0, 200);
  assert!(fixture.app.hub.lock().await.is_online(fixture.clients[0].id));
  std::fs::write(&fixture.app.config.tls_cert_chain_file, original).unwrap();
  assert_eq!(fixture.operator(&AdminCommand::TlsReload).await["ok"], true);
  closed(&mut active).await;
  let mut active = fixture.websocket(1).await;
  fixture.app.store.pool.close().await;
  assert_eq!(fixture.request(Some(1), "GET /v1/devices HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.0, 503);
  closed(&mut active).await;
  assert_eq!(fixture.request(None, "GET /health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.0, 503);
  assert_eq!(fixture.request(None, "GET /health/live HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.0, 200);
  fixture.app.shutdown.cancel();
}

#[tokio::test]
async fn websocket_admission_survives_upgrade_and_recovers_on_disconnect() {
  let fixture = Fixture::start(1,false).await;
  let mut active = fixture.websocket(0).await;
  let config = tls::client_config(CaMode::Provided,Some(&fixture.root),None,None).unwrap();
  let socket = TcpStream::connect(fixture.address).await.unwrap();
  let denied = tokio::time::timeout(Duration::from_secs(2),TlsConnector::from(Arc::new(config))
    .connect("localhost".try_into().unwrap(),socket)).await;
  assert!(matches!(denied,Ok(Err(_))),"upgraded WSS must retain its admission permit");
  active.close(None).await.unwrap();
  drop(active);
  tokio::time::timeout(Duration::from_secs(3),async {
    while fixture.app.hub.lock().await.is_online(fixture.clients[0].id) { tokio::task::yield_now().await; }
  }).await.unwrap();
  assert_eq!(fixture.request(None,"GET /v1/info HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.0,200);
}

#[tokio::test]
async fn certificate_expiry_closes_a_reader_waiting_for_authorization_gate() {
  let fixture = Fixture::start(64,true).await;
  let mut active = fixture.websocket(0).await;
  let gate = fixture.app.gate.write().await;
  let message = Control::Open {request_id:Uuid::new_v4(),peer_id:fixture.clients[1].id,kind:StreamKind::Packet,parent_id:None};
  active.send(Message::Text(serde_json::to_string(&message).unwrap().into())).await.unwrap();
  closed(&mut active).await;
  assert!(!fixture.app.hub.lock().await.is_online(fixture.clients[0].id));
  drop(gate);
}

#[tokio::test]
async fn authorization_watchdog_fails_closed_when_rechecks_are_blocked() {
  let fixture = Fixture::start(64,false).await;
  let mut active = fixture.websocket(0).await;
  let gate = fixture.app.gate.write().await;
  tokio::time::pause();
  tokio::time::advance(Duration::from_secs(31)).await;
  tokio::time::timeout(Duration::from_secs(1),async {
    while fixture.app.ready.load(std::sync::atomic::Ordering::SeqCst) { tokio::task::yield_now().await; }
  }).await.unwrap();
  tokio::time::resume();
  closed(&mut active).await;
  assert!(!fixture.app.hub.lock().await.is_online(fixture.clients[0].id));
  drop(gate);
}

#[tokio::test]
async fn ingress_host_policy_covers_every_route_and_websocket_upgrade() {
  let fixture = Fixture::start(64,false).await;
  for host in ["localhost", "LOCALHOST", "localhost:443", "localhost:8443", "localhost:65535", "localhost:00443"] {
    let request = format!("GET /v1/info HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    assert_eq!(fixture.request(None,&request).await.0,200,"matching authority {host}");
  }
  for host in ["", "localhost:", "localhost:0", "localhost:000", "localhost:65536", "localhost:-1", "localhost:+443", "localhost:abc", "localhost:443:8443", "localhost.", "local host", "localhost,evil.example", "user@localhost", "localhost/path", "*.localhost"] {
    let request = format!("GET /v1/info HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let (status,error) = fixture.request(None,&request).await;
    assert_eq!(status,400,"invalid authority {host}");
    assert_eq!(error["code"],"invalid_host");
    assert!(error["requestId"].as_str().is_some());
  }
  for headers in ["", "Host: localhost\r\nHost: localhost\r\n", "Host: localhost\r\nHost: evil.example\r\n"] {
    let request = format!("GET /v1/info HTTP/1.1\r\n{headers}Connection: close\r\n\r\n");
    let (status,error) = fixture.request(None,&request).await;
    assert_eq!(status,400);
    assert_eq!(error["code"],"invalid_host");
  }
  for route in ["/v1/info", "/health/live", "/health/ready", "/v1/devices", "/v1/devices/me", "/v1/tunnel", "/does-not-exist"] {
    let request = format!("GET {route} HTTP/1.1\r\nHost: evil.example\r\nX-Forwarded-Host: localhost\r\nForwarded: host=localhost\r\nConnection: close\r\n\r\n");
    let (status,error) = fixture.request(Some(0),&request).await;
    assert_eq!(status,421,"route {route}");
    assert_eq!(error["code"],"misdirected_request");
  }
  let request = "POST /v1/info HTTP/1.1\r\nHost: evil.example\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
  assert_eq!(fixture.request(None,request).await.0,421);
  let request = "GET /v1/info HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-Host: evil.example\r\nForwarded: host=evil.example\r\nConnection: close\r\n\r\n";
  assert_eq!(fixture.request(None,request).await.0,200);
  let request = "GET https://evil.example/v1/info HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
  assert_eq!(fixture.request(None,request).await.0,421);
  let request = "GET https://localhost:443/v1/info HTTP/1.1\r\nHost: LOCALHOST:8443\r\nConnection: close\r\n\r\n";
  assert_eq!(fixture.request(None,request).await.0,200);
  let client = &fixture.clients[0];
  let config = tls::client_config(CaMode::Provided,Some(&fixture.root),Some(&client.certificate),Some(&client.key)).unwrap();
  let socket = TcpStream::connect(fixture.address).await.unwrap();
  let stream = TlsConnector::from(Arc::new(config)).connect("localhost".try_into().unwrap(),socket).await.unwrap();
  let mut request = format!("wss://localhost:{}/v1/tunnel",fixture.address.port()).into_client_request().unwrap();
  request.headers_mut().insert("host","evil.example".parse().unwrap());
  request.headers_mut().insert("sec-websocket-protocol",SUBPROTOCOL.parse().unwrap());
  let error = tokio_tungstenite::client_async(request,stream).await.unwrap_err();
  let tokio_tungstenite::tungstenite::Error::Http(response) = error else { panic!("expected HTTP rejection"); };
  assert_eq!(response.status().as_u16(),421);
  assert_eq!(fixture.app.hub.lock().await.metrics()["connections"],0);
  assert_eq!(fixture.app.hub.lock().await.metrics()["streams"],0);
}

#[tokio::test]
async fn reload_with_uncovered_server_domain_preserves_live_configuration() {
  let fixture = Fixture::start(64,false).await;
  let mut active = fixture.websocket(0).await;
  let key = KeyPair::generate().unwrap();
  let mut params = CertificateParams::new(vec!["other.example".into()]).unwrap();
  params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
  let certificate = params.self_signed(&key).unwrap();
  let old_chain = std::fs::read(&fixture.app.config.tls_cert_chain_file).unwrap();
  let old_key = std::fs::read(&fixture.app.config.tls_private_key_file).unwrap();
  std::fs::write(&fixture.app.config.tls_cert_chain_file,certificate.pem()).unwrap();
  std::fs::write(&fixture.app.config.tls_private_key_file,key.serialize_pem()).unwrap();
  assert_eq!(fixture.operator(&AdminCommand::TlsReload).await["ok"],false);
  assert!(fixture.app.hub.lock().await.is_online(fixture.clients[0].id));
  assert_eq!(fixture.app.tls_epoch.load(std::sync::atomic::Ordering::SeqCst),0);
  assert_eq!(fixture.request(None,"GET /v1/info HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.0,200);
  std::fs::write(&fixture.app.config.tls_cert_chain_file,old_chain).unwrap();
  std::fs::write(&fixture.app.config.tls_private_key_file,old_key).unwrap();
  assert_eq!(fixture.operator(&AdminCommand::TlsReload).await["ok"],true);
  closed(&mut active).await;
}
