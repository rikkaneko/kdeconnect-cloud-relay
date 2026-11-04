use std::{fs::File, io::{BufReader, Read}, path::Path, sync::Arc};

use anyhow::{Context, Result, ensure};
use rustls::{
  ClientConfig, DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig, SignatureScheme,
  client::danger::HandshakeSignatureValid,
  pki_types::{CertificateDer, UnixTime},
  server::{WebPkiClientVerifier, danger::{ClientCertVerified, ClientCertVerifier}},
};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::config::{CaMode, Config, canonical_dns_name};

pub const PEM_LIMIT: usize = 1024 * 1024;
pub const CHAIN_LIMIT: usize = 16;

// One bounded parser serves server identity, provided roots and client identity.
fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
  let file = File::open(path).context("unable to open certificate file")?;
  ensure!(file.metadata()?.len() <= PEM_LIMIT as u64, "certificate file exceeds size limit");
  let mut data = Vec::new();
  file.take(PEM_LIMIT as u64 + 1).read_to_end(&mut data).context("unable to read certificate file")?;
  ensure!(data.len() <= PEM_LIMIT, "certificate file exceeds size limit");
  let items = rustls_pemfile::read_all(&mut BufReader::new(data.as_slice()))
    .collect::<std::result::Result<Vec<_>, _>>().context("invalid certificate PEM")?;
  ensure!(!items.is_empty() && items.len() <= CHAIN_LIMIT, "certificate bundle must contain 1 to 16 certificates");
  let mut chain = Vec::with_capacity(items.len());
  for item in items {
    let rustls_pemfile::Item::X509Certificate(cert) = item else { anyhow::bail!("certificate PEM contains unsupported material"); };
    let (remaining, _) = X509Certificate::from_der(cert.as_ref()).map_err(|_| anyhow::anyhow!("invalid X.509 certificate"))?;
    ensure!(remaining.is_empty(), "invalid X.509 trailing bytes");
    chain.push(cert);
  }
  Ok(chain)
}

// Client and server verifiers share the same explicit trust-source semantics.
fn roots(mode: CaMode, ca_file: Option<&Path>) -> Result<RootCertStore> {
  let mut roots = RootCertStore::empty();
  match mode {
    CaMode::Provided => {
      let path = ca_file.context("provided mode requires CA file")?;
      for cert in certificates(path)? {
        let (_, parsed) = X509Certificate::from_der(cert.as_ref()).map_err(|_| anyhow::anyhow!("invalid CA certificate"))?;
        ensure!(parsed.basic_constraints()?.is_some_and(|value| value.value.ca), "trust anchor must be a CA certificate");
        if let Some(usage) = parsed.key_usage()? {
          ensure!(usage.value.key_cert_sign(), "trust anchor cannot sign certificates");
        }
        roots.add(cert).context("invalid CA trust anchor")?;
      }
    }
    CaMode::System => {
      ensure!(ca_file.is_none(), "system mode forbids a provided CA file");
      let loaded = rustls_native_certs::load_native_certs();
      if !loaded.errors.is_empty() {
        tracing::warn!(errors = loaded.errors.len(), "system CA store reported loading errors");
      }
      let (_, rejected) = roots.add_parsable_certificates(loaded.certs);
      if rejected > 0 {
        tracing::warn!(rejected, "system CA store contained unsupported certificates");
      }
    }
  }
  ensure!(!roots.is_empty(), "CA trust store contains no usable certificates");
  Ok(roots)
}

pub fn certificate_identity(der: &[u8]) -> Result<(String, i64)> {
  ensure!(der.len() <= PEM_LIMIT, "certificate exceeds size limit");
  let (remaining, certificate) = X509Certificate::from_der(der).map_err(|_| anyhow::anyhow!("invalid client certificate"))?;
  ensure!(remaining.is_empty(), "invalid client certificate trailing bytes");
  ensure!(certificate.validity().is_valid(), "client certificate is outside its validity period");
  ensure!(certificate.extended_key_usage()?.is_some_and(|usage| usage.value.client_auth), "explicit clientAuth usage is required");
  ensure!(!certificate.basic_constraints()?.is_some_and(|value| value.value.ca), "client certificate must be a leaf");
  let fingerprint = format!("{:x}", Sha256::digest(der));
  Ok((fingerprint, certificate.validity().not_after.timestamp()))
}

#[derive(Debug)]
struct ExplicitClientUsage {
  verifier: Arc<dyn ClientCertVerifier>,
}

impl ClientCertVerifier for ExplicitClientUsage {
  fn client_auth_mandatory(&self) -> bool { false }

  fn root_hint_subjects(&self) -> &[DistinguishedName] { self.verifier.root_hint_subjects() }

  fn verify_client_cert(&self, leaf: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], now: UnixTime) -> std::result::Result<ClientCertVerified, rustls::Error> {
    if intermediates.len() >= CHAIN_LIMIT || leaf.len() > PEM_LIMIT || intermediates.iter().map(|cert| cert.len()).sum::<usize>() > PEM_LIMIT {
      return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding));
    }
    self.verifier.verify_client_cert(leaf, intermediates, now)?;
    certificate_identity(leaf.as_ref()).map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::InvalidPurpose))?;
    Ok(ClientCertVerified::assertion())
  }

  fn verify_tls12_signature(&self, message: &[u8], certificate: &CertificateDer<'_>, signature: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
    self.verifier.verify_tls12_signature(message, certificate, signature)
  }

  fn verify_tls13_signature(&self, message: &[u8], certificate: &CertificateDer<'_>, signature: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
    self.verifier.verify_tls13_signature(message, certificate, signature)
  }

  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> { self.verifier.supported_verify_schemes() }
}

pub fn load_server_config(config: &Config) -> Result<ServerConfig> {
  let server_name = canonical_dns_name(&config.server_name).context("invalid configured server name")?;
  let chain = certificates(&config.tls_cert_chain_file)?;
  // Validate presented chain order and signatures before replacing a live config.
  for (index, certificate) in chain.iter().enumerate() {
    let (_, parsed) = X509Certificate::from_der(certificate.as_ref()).map_err(|_| anyhow::anyhow!("invalid server certificate"))?;
    ensure!(parsed.validity().is_valid(), "server certificate chain is outside its validity period");
    if index == 0 {
      ensure!(parsed.extended_key_usage()?.is_some_and(|usage| usage.value.server_auth), "explicit serverAuth usage is required");
      ensure!(!parsed.basic_constraints()?.is_some_and(|value| value.value.ca), "server certificate must be a leaf");
    } else {
      ensure!(parsed.basic_constraints()?.is_some_and(|value| value.value.ca), "server intermediate must be a CA");
      if let Some(usage) = parsed.key_usage()? { ensure!(usage.value.key_cert_sign(), "server intermediate cannot sign certificates"); }
    }
    if let Some(issuer) = chain.get(index + 1) {
      let (_, issuer) = X509Certificate::from_der(issuer.as_ref()).map_err(|_| anyhow::anyhow!("invalid server intermediate"))?;
      ensure!(parsed.issuer() == issuer.subject(), "server certificate chain must be in issuer order");
      parsed.verify_signature(Some(issuer.public_key())).map_err(|_| anyhow::anyhow!("invalid server certificate chain signature"))?;
    }
  }
  let key_file = File::open(&config.tls_private_key_file).context("unable to open server private key")?;
  ensure!(key_file.metadata()?.len() <= PEM_LIMIT as u64, "private key exceeds size limit");
  let mut key_data = Vec::new();
  key_file.take(PEM_LIMIT as u64 + 1).read_to_end(&mut key_data).context("unable to read server private key")?;
  ensure!(key_data.len() <= PEM_LIMIT, "private key exceeds size limit");
  let key = rustls_pemfile::private_key(&mut BufReader::new(key_data.as_slice()))
    .context("invalid private key PEM")?.context("supported unencrypted private key is required")?;
  let provider = Arc::new(rustls::crypto::ring::default_provider());
  // Bind the identity to exactly one configured SNI; extra certificate SANs do
  // not implicitly enable additional relay hostnames or anonymous-IP access.
  let certified_key = rustls::sign::CertifiedKey::from_der(chain, key, provider.as_ref())
    .context("invalid server certificate/key pair")?;
  certified_key.keys_match().context("server certificate/key match could not be verified")?;
  let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
  resolver.add(&server_name, certified_key).context("server certificate SAN does not cover configured server name")?;
  let mut verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots(config.client_ca_mode, config.client_ca_file.as_deref())?), provider.clone());
  if let Some(path) = &config.client_crl_file {
    let crl_file = File::open(path).context("unable to open CRL file")?;
    ensure!(crl_file.metadata()?.len() <= PEM_LIMIT as u64, "CRL exceeds size limit");
    let mut crl_data = Vec::new();
    crl_file.take(PEM_LIMIT as u64 + 1).read_to_end(&mut crl_data)?;
    ensure!(crl_data.len() <= PEM_LIMIT, "CRL exceeds size limit");
    let crls = rustls_pemfile::crls(&mut BufReader::new(crl_data.as_slice())).collect::<std::result::Result<Vec<_>, _>>()
      .context("invalid CRL PEM")?;
    ensure!(!crls.is_empty(), "CRL file is empty");
    for crl in &crls {
      let (remaining, parsed) = CertificateRevocationList::from_der(crl.as_ref()).map_err(|_| anyhow::anyhow!("invalid CRL"))?;
      let now = ASN1Time::now();
      ensure!(remaining.is_empty() && parsed.last_update() <= now && parsed.next_update().is_some_and(|next| next >= now), "CRL is outside its validity period");
    }
    verifier = verifier.with_crls(crls).enforce_revocation_expiration();
  }
  let verifier = Arc::new(ExplicitClientUsage { verifier: verifier.allow_unauthenticated().build()? });
  let mut tls = ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions()?
    .with_client_cert_verifier(verifier).with_cert_resolver(Arc::new(resolver));
  tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
  tls.send_tls13_tickets = 0;
  tls.max_early_data_size = 0;
  tls.alpn_protocols = vec![b"http/1.1".to_vec()];
  Ok(tls)
}

pub fn client_config(mode: CaMode, ca_file: Option<&Path>, cert_chain: Option<&Path>, key: Option<&Path>) -> Result<ClientConfig> {
  let builder = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
    .with_safe_default_protocol_versions()?.with_root_certificates(roots(mode, ca_file)?);
  let mut config = match (cert_chain, key) {
    (None, None) => builder.with_no_client_auth(),
    (Some(chain_path), Some(key_path)) => {
      let chain = certificates(chain_path)?;
      certificate_identity(chain[0].as_ref())?;
      let key_file = File::open(key_path).context("unable to open client private key")?;
      ensure!(key_file.metadata()?.len() <= PEM_LIMIT as u64, "private key exceeds size limit");
      let mut key_data = Vec::new();
      key_file.take(PEM_LIMIT as u64 + 1).read_to_end(&mut key_data).context("unable to read client private key")?;
      ensure!(key_data.len() <= PEM_LIMIT, "private key exceeds size limit");
      let key = rustls_pemfile::private_key(&mut BufReader::new(key_data.as_slice()))
        .context("invalid private key PEM")?.context("supported unencrypted private key is required")?;
      builder.with_client_auth_cert(chain, key).context("invalid client certificate/key pair")?
    }
    _ => anyhow::bail!("client certificate and private key must be configured together"),
  };
  config.resumption = rustls::client::Resumption::disabled();
  config.enable_early_data = false;
  config.alpn_protocols = vec![b"http/1.1".to_vec()];
  Ok(config)
}

#[cfg(test)]
mod tests {
  use super::*;
  use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
  use tempfile::TempDir;
  use ::time::{Duration, OffsetDateTime};
  use tokio_rustls::{TlsAcceptor, TlsConnector};

  struct Pki {
    directory: TempDir,
    config: Config,
    root: CertifiedIssuer<'static, KeyPair>,
    intermediate: CertifiedIssuer<'static, KeyPair>,
  }

  impl Pki {
    // A complete local CA hierarchy lets independent tests exercise real TLS.
    fn new() -> Self {
      let directory = tempfile::tempdir().unwrap();
      let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
      root_params.distinguished_name.push(DnType::CommonName, "relay test root");
      root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
      root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
      let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate().unwrap()).unwrap();
      let mut intermediate_params = CertificateParams::new(Vec::<String>::new()).unwrap();
      intermediate_params.distinguished_name.push(DnType::CommonName, "relay test intermediate");
      intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
      intermediate_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
      let intermediate = CertifiedIssuer::signed_by(intermediate_params, KeyPair::generate().unwrap(), &root).unwrap();
      let mut server_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
      server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
      let server_key = KeyPair::generate().unwrap();
      let server = server_params.signed_by(&server_key, &intermediate).unwrap();
      let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
      client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
      let client_key = KeyPair::generate().unwrap();
      let client = client_params.signed_by(&client_key, &intermediate).unwrap();
      std::fs::write(directory.path().join("root.pem"), root.pem()).unwrap();
      std::fs::write(directory.path().join("intermediate.pem"), intermediate.pem()).unwrap();
      std::fs::write(directory.path().join("server.pem"), format!("{}{}", server.pem(), intermediate.pem())).unwrap();
      std::fs::write(directory.path().join("server.key"), server_key.serialize_pem()).unwrap();
      std::fs::write(directory.path().join("client.pem"), format!("{}{}", client.pem(), intermediate.pem())).unwrap();
      std::fs::write(directory.path().join("client.key"), client_key.serialize_pem()).unwrap();
      let config = Config {
        bind: "127.0.0.1:8443".parse().unwrap(), state_dir: directory.path().to_path_buf(),
        server_name: "localhost".to_owned(),
        tls_cert_chain_file: directory.path().join("server.pem"), tls_private_key_file: directory.path().join("server.key"),
        client_ca_mode: CaMode::Provided, client_ca_file: Some(directory.path().join("root.pem")), client_crl_file: None,
        max_connections: 256, max_handshakes: 32,
      };
      Self { directory, config, root, intermediate }
    }
  }

  // Both endpoints must complete: TLS 1.3 clients may return before a server alert.
  async fn handshake(server: ServerConfig, client: ClientConfig, host: &'static str) -> bool {
    let (server_io, client_io) = tokio::io::duplex(256 * 1024);
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let connector = TlsConnector::from(Arc::new(client));
    let name = rustls::pki_types::ServerName::try_from(host).unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), async {
      tokio::join!(acceptor.accept(server_io), connector.connect(name, client_io))
    }).await;
    matches!(result, Ok((Ok(_), Ok(_))))
  }

  #[tokio::test]
  async fn custom_root_intermediate_and_anonymous_public_tls() {
    let pki = Pki::new();
    let ca = pki.directory.path().join("root.pem");
    let chain = pki.directory.path().join("client.pem");
    let key = pki.directory.path().join("client.key");
    assert!(handshake(load_server_config(&pki.config).unwrap(), client_config(CaMode::Provided, Some(&ca), Some(&chain), Some(&key)).unwrap(), "localhost").await);
    assert!(handshake(load_server_config(&pki.config).unwrap(), client_config(CaMode::Provided, Some(&ca), None, None).unwrap(), "localhost").await);
    let mut intermediate_trust = pki.config.clone();
    intermediate_trust.client_ca_file = Some(pki.directory.path().join("intermediate.pem"));
    assert!(handshake(load_server_config(&intermediate_trust).unwrap(), client_config(CaMode::Provided, Some(&ca), Some(&chain), Some(&key)).unwrap(), "localhost").await);
  }

  #[tokio::test]
  async fn sni_requires_only_configured_name_even_with_additional_sans() {
    let pki = Pki::new();
    let ca = pki.directory.path().join("root.pem");
    let mut params = CertificateParams::new(vec!["localhost".to_owned(), "alternate.example".to_owned()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate().unwrap();
    let leaf = params.signed_by(&key, &pki.intermediate).unwrap();
    std::fs::write(&pki.config.tls_cert_chain_file, format!("{}{}", leaf.pem(), pki.intermediate.pem())).unwrap();
    std::fs::write(&pki.config.tls_private_key_file, key.serialize_pem()).unwrap();
    for host in ["localhost", "LOCALHOST", "LoCaLhOsT"] {
      assert!(handshake(load_server_config(&pki.config).unwrap(), client_config(CaMode::Provided, Some(&ca), None, None).unwrap(), host).await);
    }
    for host in ["alternate.example", "unknown.example", "127.0.0.1"] {
      assert!(!handshake(load_server_config(&pki.config).unwrap(), client_config(CaMode::Provided, Some(&ca), None, None).unwrap(), host).await);
    }
    let mut without_sni = client_config(CaMode::Provided, Some(&ca), None, None).unwrap();
    without_sni.enable_sni = false;
    assert!(!handshake(load_server_config(&pki.config).unwrap(), without_sni, "localhost").await);
  }

  #[test]
  fn server_name_and_san_validation_fail_before_configuration_replacement() {
    let pki = Pki::new();
    for mode in [CaMode::Provided, CaMode::System] {
      let mut config = pki.config.clone();
      config.client_ca_mode = mode;
      if mode == CaMode::System { config.client_ca_file = None; }
      config.tls_cert_chain_file = pki.directory.path().join("missing-server.pem");
      assert!(load_server_config(&config).is_err());
      config.tls_cert_chain_file = pki.config.tls_cert_chain_file.clone();
      config.tls_private_key_file = pki.directory.path().join("missing-server.key");
      assert!(load_server_config(&config).is_err());
    }
    for name in ["", "*.example", "127.0.0.1", "[::1]", "https://localhost", "localhost:443", "localhost."] {
      let mut config = pki.config.clone();
      config.server_name = name.to_owned();
      assert!(load_server_config(&config).is_err());
    }
    // Both startup and reload construct this configuration before publishing it.
    for names in [vec!["wrong.example".to_owned()], vec![]] {
      let mut params = CertificateParams::new(names).unwrap();
      params.distinguished_name.push(DnType::CommonName, "localhost");
      params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
      let key = KeyPair::generate().unwrap();
      let leaf = params.signed_by(&key, &pki.intermediate).unwrap();
      std::fs::write(&pki.config.tls_cert_chain_file, format!("{}{}", leaf.pem(), pki.intermediate.pem())).unwrap();
      std::fs::write(&pki.config.tls_private_key_file, key.serialize_pem()).unwrap();
      assert!(load_server_config(&pki.config).is_err());
    }
  }

  #[tokio::test]
  async fn wildcard_san_covers_configured_concrete_name_without_aliasing_sni() {
    let pki = Pki::new();
    let ca = pki.directory.path().join("root.pem");
    let mut params = CertificateParams::new(vec!["*.example.test".to_owned()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate().unwrap();
    let leaf = params.signed_by(&key, &pki.intermediate).unwrap();
    std::fs::write(&pki.config.tls_cert_chain_file, format!("{}{}", leaf.pem(), pki.intermediate.pem())).unwrap();
    std::fs::write(&pki.config.tls_private_key_file, key.serialize_pem()).unwrap();
    let mut config = pki.config.clone();
    config.server_name = "relay.example.test".to_owned();
    assert!(handshake(load_server_config(&config).unwrap(), client_config(CaMode::Provided, Some(&ca), None, None).unwrap(), "relay.example.test").await);
    assert!(handshake(load_server_config(&config).unwrap(), client_config(CaMode::Provided, Some(&ca), None, None).unwrap(), "ReLaY.ExAmPlE.TeSt").await);
    assert!(!handshake(load_server_config(&config).unwrap(), client_config(CaMode::Provided, Some(&ca), None, None).unwrap(), "other.example.test").await);
  }

  #[tokio::test]
  async fn direct_root_and_multiple_intermediates() {
    let pki = Pki::new();
    let ca = pki.directory.path().join("root.pem");
    let chain_path = pki.directory.path().join("client.pem");
    let key_path = pki.directory.path().join("client.key");
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let key = KeyPair::generate().unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    let direct = params.signed_by(&key, &pki.root).unwrap();
    std::fs::write(&chain_path, direct.pem()).unwrap();
    assert!(handshake(load_server_config(&pki.config).unwrap(), client_config(CaMode::Provided, Some(&ca), Some(&chain_path), Some(&key_path)).unwrap(), "localhost").await);
    let mut second_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    second_params.distinguished_name.push(DnType::CommonName, "second test intermediate");
    second_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    second_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let second = CertifiedIssuer::signed_by(second_params, KeyPair::generate().unwrap(), &pki.intermediate).unwrap();
    let leaf = params.signed_by(&key, &second).unwrap();
    std::fs::write(&chain_path, format!("{}{}{}", leaf.pem(), second.pem(), pki.intermediate.pem())).unwrap();
    assert!(handshake(load_server_config(&pki.config).unwrap(), client_config(CaMode::Provided, Some(&ca), Some(&chain_path), Some(&key_path)).unwrap(), "localhost").await);
  }

  #[tokio::test]
  async fn missing_wrong_intermediate_and_unknown_root_are_rejected() {
    let pki = Pki::new();
    let other = Pki::new();
    let ca = pki.directory.path().join("root.pem");
    let chain_path = pki.directory.path().join("client.pem");
    let key_path = pki.directory.path().join("client.key");
    let leaf = certificates(&chain_path).unwrap().remove(0);
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let key = KeyPair::generate().unwrap();
    let client = params.signed_by(&key, &pki.intermediate).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    for presented in [client.pem(), format!("{}{}", client.pem(), other.intermediate.pem())] {
      std::fs::write(&chain_path, presented).unwrap();
      assert!(!handshake(load_server_config(&pki.config).unwrap(), client_config(CaMode::Provided, Some(&ca), Some(&chain_path), Some(&key_path)).unwrap(), "localhost").await);
    }
    let unknown = other.directory.path().join("client.pem");
    let unknown_key = other.directory.path().join("client.key");
    assert!(!handshake(load_server_config(&pki.config).unwrap(), client_config(CaMode::Provided, Some(&ca), Some(&unknown), Some(&unknown_key)).unwrap(), "localhost").await);
    assert!(certificate_identity(leaf.as_ref()).is_ok());
  }

  #[tokio::test]
  async fn hostname_mismatch_and_key_mismatch_are_rejected() {
    let pki = Pki::new();
    let ca = pki.directory.path().join("root.pem");
    assert!(!handshake(load_server_config(&pki.config).unwrap(), client_config(CaMode::Provided, Some(&ca), None, None).unwrap(), "wrong.example").await);
    let mut config = pki.config.clone();
    config.tls_private_key_file = pki.directory.path().join("client.key");
    assert!(load_server_config(&config).is_err());
    assert!(client_config(CaMode::Provided, Some(&ca), Some(&pki.directory.path().join("client.pem")), Some(&pki.directory.path().join("server.key"))).is_err());
    config = pki.config.clone();
    std::fs::write(&config.tls_cert_chain_file, format!("{}{}", pki.intermediate.pem(), pki.root.pem())).unwrap();
    assert!(load_server_config(&config).is_err());
  }

  #[tokio::test]
  async fn explicit_client_usage_and_non_ca_issuer_fail_at_handshake() {
    let pki = Pki::new();
    let ca = pki.directory.path().join("root.pem");
    for usage in [vec![], vec![ExtendedKeyUsagePurpose::ServerAuth]] {
      let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
      params.extended_key_usages = usage;
      let key = KeyPair::generate().unwrap();
      let leaf = params.signed_by(&key, &pki.root).unwrap();
      let client = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions().unwrap().with_root_certificates(roots(CaMode::Provided, Some(&ca)).unwrap())
        .with_client_auth_cert(vec![leaf.der().clone()], rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into()).unwrap();
      assert!(!handshake(load_server_config(&pki.config).unwrap(), client, "localhost").await);
    }
    let mut issuer_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    issuer_params.distinguished_name.push(DnType::CommonName, "not a CA");
    let invalid_issuer = CertifiedIssuer::signed_by(issuer_params, KeyPair::generate().unwrap(), &pki.root).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let key = KeyPair::generate().unwrap();
    let leaf = params.signed_by(&key, &invalid_issuer).unwrap();
    let client = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
      .with_safe_default_protocol_versions().unwrap().with_root_certificates(roots(CaMode::Provided, Some(&ca)).unwrap())
      .with_client_auth_cert(vec![leaf.der().clone(), invalid_issuer.der().clone()], rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into()).unwrap();
    assert!(!handshake(load_server_config(&pki.config).unwrap(), client, "localhost").await);
  }

  #[tokio::test]
  async fn invalid_validity_and_corrupted_signature_fail_handshake() {
    let pki = Pki::new();
    let ca = pki.directory.path().join("root.pem");
    for (before, after, corrupt) in [
      (Duration::days(-2), Duration::days(-1), false),
      (Duration::days(1), Duration::days(2), false),
      (Duration::days(-1), Duration::days(1), true),
    ] {
      let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
      params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
      params.not_before = OffsetDateTime::now_utc() + before;
      params.not_after = OffsetDateTime::now_utc() + after;
      let key = KeyPair::generate().unwrap();
      let leaf = params.signed_by(&key, &pki.root).unwrap();
      let mut der = leaf.der().to_vec();
      if corrupt { *der.last_mut().unwrap() ^= 1; }
      let client = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions().unwrap().with_root_certificates(roots(CaMode::Provided, Some(&ca)).unwrap())
        .with_client_auth_cert(vec![CertificateDer::from(der)], rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into()).unwrap();
      assert!(!handshake(load_server_config(&pki.config).unwrap(), client, "localhost").await);
    }
  }

  #[tokio::test]
  async fn crl_revocation_and_expiry_are_enforced() {
    let pki = Pki::new();
    let ca = pki.directory.path().join("root.pem");
    let chain_path = pki.directory.path().join("client.pem");
    let key_path = pki.directory.path().join("client.key");
    let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    client_params.serial_number = Some(7_u64.into());
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let key = KeyPair::generate().unwrap();
    let client = client_params.signed_by(&key, &pki.intermediate).unwrap();
    std::fs::write(&chain_path, format!("{}{}", client.pem(), pki.intermediate.pem())).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    let mut crl_params = rcgen::CertificateRevocationListParams {
      this_update: OffsetDateTime::now_utc() - Duration::minutes(1),
      next_update: OffsetDateTime::now_utc() + Duration::days(1),
      crl_number: 1_u64.into(), issuing_distribution_point: None,
      revoked_certs: vec![], key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    let root_crl = crl_params.signed_by(&pki.root).unwrap();
    let mut config = pki.config.clone();
    config.client_crl_file = Some(pki.directory.path().join("revocations.pem"));
    let int_crl = crl_params.signed_by(&pki.intermediate).unwrap();
    std::fs::write(config.client_crl_file.as_ref().unwrap(), format!("{}{}", root_crl.pem().unwrap(), int_crl.pem().unwrap())).unwrap();
    assert!(handshake(load_server_config(&config).unwrap(), client_config(CaMode::Provided, Some(&ca), Some(&chain_path), Some(&key_path)).unwrap(), "localhost").await);
    crl_params.revoked_certs.push(rcgen::RevokedCertParams {
      serial_number: 7_u64.into(), revocation_time: OffsetDateTime::now_utc() - Duration::seconds(30),
      reason_code: None, invalidity_date: None,
    });
    let revoked = crl_params.signed_by(&pki.intermediate).unwrap();
    std::fs::write(config.client_crl_file.as_ref().unwrap(), format!("{}{}", root_crl.pem().unwrap(), revoked.pem().unwrap())).unwrap();
    assert!(!handshake(load_server_config(&config).unwrap(), client_config(CaMode::Provided, Some(&ca), Some(&chain_path), Some(&key_path)).unwrap(), "localhost").await);
    crl_params.this_update = OffsetDateTime::now_utc() - Duration::days(2);
    crl_params.next_update = OffsetDateTime::now_utc() - Duration::days(1);
    let stale = crl_params.signed_by(&pki.intermediate).unwrap();
    std::fs::write(config.client_crl_file.as_ref().unwrap(), stale.pem().unwrap()).unwrap();
    assert!(load_server_config(&config).is_err());
  }

  #[tokio::test]
  async fn intermediate_name_constraints_are_enforced() {
    let pki = Pki::new();
    let ca = pki.directory.path().join("root.pem");
    let mut issuer_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    issuer_params.distinguished_name.push(DnType::CommonName, "constrained intermediate");
    issuer_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    issuer_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    issuer_params.name_constraints = Some(rcgen::NameConstraints {
      permitted_subtrees: vec![rcgen::GeneralSubtree::DnsName("allowed.example".to_owned())],
      excluded_subtrees: vec![],
    });
    let issuer = CertifiedIssuer::signed_by(issuer_params, KeyPair::generate().unwrap(), &pki.root).unwrap();
    for (host, allowed) in [("client.allowed.example", true), ("client.blocked.example", false)] {
      let mut params = CertificateParams::new(vec![host.to_owned()]).unwrap();
      params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
      let key = KeyPair::generate().unwrap();
      let leaf = params.signed_by(&key, &issuer).unwrap();
      let client = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions().unwrap().with_root_certificates(roots(CaMode::Provided, Some(&ca)).unwrap())
        .with_client_auth_cert(vec![leaf.der().clone(), issuer.der().clone()], rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into()).unwrap();
      assert_eq!(handshake(load_server_config(&pki.config).unwrap(), client, "localhost").await, allowed);
    }
  }

  #[test]
  fn certificate_identity_requires_explicit_usage_and_validity() {
    let pki = Pki::new();
    for usage in [vec![], vec![ExtendedKeyUsagePurpose::ServerAuth], vec![ExtendedKeyUsagePurpose::Any]] {
      let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
      params.extended_key_usages = usage;
      let cert = params.signed_by(&KeyPair::generate().unwrap(), &pki.root).unwrap();
      assert!(certificate_identity(cert.der()).is_err());
    }
    for (before, after) in [(Duration::days(-2), Duration::days(-1)), (Duration::days(1), Duration::days(2))] {
      let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
      params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
      params.not_before = OffsetDateTime::now_utc() + before;
      params.not_after = OffsetDateTime::now_utc() + after;
      let cert = params.signed_by(&KeyPair::generate().unwrap(), &pki.root).unwrap();
      assert!(certificate_identity(cert.der()).is_err());
    }
    let chain = certificates(&pki.directory.path().join("client.pem")).unwrap();
    let (fingerprint, expires_at) = certificate_identity(chain[0].as_ref()).unwrap();
    assert_eq!(fingerprint.len(), 64);
    assert!(expires_at > OffsetDateTime::now_utc().unix_timestamp());
  }

  #[test]
  fn provided_ca_and_pem_limits_fail_closed() {
    let pki = Pki::new();
    assert!(roots(CaMode::Provided, None).is_err());
    assert!(roots(CaMode::System, Some(&pki.directory.path().join("root.pem"))).is_err());
    for value in [String::new(), "bad PEM".to_owned(), "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----".to_owned(), "a".repeat(PEM_LIMIT + 1), pki.root.pem().repeat(CHAIN_LIMIT + 1)] {
      let path = pki.directory.path().join("invalid.pem");
      std::fs::write(&path, value).unwrap();
      assert!(roots(CaMode::Provided, Some(&path)).is_err());
    }
    assert!(roots(CaMode::Provided, Some(&pki.directory.path().join("client.pem"))).is_err());
  }

  #[test]
  fn injected_system_store_is_separate_from_provided_only() {
    if let Ok(base) = std::env::var("RELAY_TLS_SYSTEM_TEST_CHILD") {
      let base = Path::new(&base);
      let system = roots(CaMode::System, None).unwrap();
      let provided = roots(CaMode::Provided, Some(&base.join("other.pem"))).unwrap();
      assert_eq!(system.len(), 1);
      assert_eq!(provided.len(), 1);
      assert_ne!(system.roots[0].subject_public_key_info, provided.roots[0].subject_public_key_info);
      let mut config = Config {
        bind: "127.0.0.1:8443".parse().unwrap(), state_dir: base.to_path_buf(),
        server_name: "localhost".to_owned(),
        tls_cert_chain_file: base.join("server.pem"), tls_private_key_file: base.join("server.key"),
        client_ca_mode: CaMode::System, client_ca_file: None, client_crl_file: None,
        max_connections: 256, max_handshakes: 32,
      };
      tokio::runtime::Runtime::new().unwrap().block_on(async {
        let client = client_config(CaMode::System, None, Some(&base.join("client.pem")), Some(&base.join("client.key"))).unwrap();
        assert!(handshake(load_server_config(&config).unwrap(), client, "localhost").await);
        config.client_ca_mode = CaMode::Provided;
        config.client_ca_file = Some(base.join("other.pem"));
        let client = client_config(CaMode::System, None, Some(&base.join("client.pem")), Some(&base.join("client.key"))).unwrap();
        assert!(!handshake(load_server_config(&config).unwrap(), client, "localhost").await);
      });
      return;
    }
    // Process-local environment injection avoids racing Rust 2024 environment mutation.
    let pki = Pki::new();
    let other = Pki::new();
    std::fs::write(pki.directory.path().join("other.pem"), other.root.pem()).unwrap();
    std::fs::create_dir(pki.directory.path().join("empty")).unwrap();
    let result = std::process::Command::new(std::env::current_exe().unwrap())
      .arg("tls::tests::injected_system_store_is_separate_from_provided_only").arg("--exact")
      .env("RELAY_TLS_SYSTEM_TEST_CHILD", pki.directory.path())
      .env("SSL_CERT_FILE", pki.directory.path().join("root.pem"))
      .env("SSL_CERT_DIR", pki.directory.path().join("empty"))
      .output().unwrap();
    assert!(result.status.success(), "system CA subprocess failed: {}", String::from_utf8_lossy(&result.stderr));
  }
}
