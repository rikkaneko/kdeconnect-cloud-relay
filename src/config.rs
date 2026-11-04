use std::{collections::HashMap, env, net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaMode {
  Provided,
  System,
}

// Paths are intentionally not Debug: runtime errors must never echo credentials.
#[derive(Clone)]
pub struct Config {
  pub bind: SocketAddr,
  pub server_name: String,
  pub state_dir: PathBuf,
  pub tls_cert_chain_file: PathBuf,
  pub tls_private_key_file: PathBuf,
  pub client_ca_mode: CaMode,
  pub client_ca_file: Option<PathBuf>,
  pub client_crl_file: Option<PathBuf>,
  pub max_connections: usize,
  pub max_handshakes: usize,
}

impl Config {
  pub fn from_env() -> Result<Self> {
    let mut values = HashMap::new();
    for name in [
      "RELAY_BIND", "RELAY_SERVER_NAME", "RELAY_STATE_DIR", "RELAY_TLS_CERT_CHAIN_FILE",
      "RELAY_TLS_PRIVATE_KEY_FILE", "RELAY_CLIENT_CA_MODE", "RELAY_CLIENT_CA_FILE",
      "RELAY_CLIENT_CRL_FILE", "RELAY_MAX_CONNECTIONS", "RELAY_MAX_HANDSHAKES",
    ] {
      match env::var(name) {
        Ok(value) => {
          ensure!(!value.is_empty() && value.len() <= 4096 && !value.contains('\0'), "invalid {name}");
          values.insert(name, value);
        }
        Err(env::VarError::NotPresent) => {}
        Err(_) => anyhow::bail!("invalid {name}"),
      }
    }
    let bind = values.get("RELAY_BIND").map(String::as_str).unwrap_or("127.0.0.1:8443")
      .parse::<SocketAddr>().context("invalid RELAY_BIND")?;
    let client_ca_mode = match values.get("RELAY_CLIENT_CA_MODE").map(String::as_str).unwrap_or("provided") {
      "provided" => CaMode::Provided,
      "system" => CaMode::System,
      _ => anyhow::bail!("RELAY_CLIENT_CA_MODE must be provided or system"),
    };
    let client_ca_file = values.get("RELAY_CLIENT_CA_FILE").map(PathBuf::from);
    ensure!(client_ca_mode != CaMode::Provided || client_ca_file.is_some(), "RELAY_CLIENT_CA_FILE is required in provided mode");
    ensure!(client_ca_mode != CaMode::System || client_ca_file.is_none(), "RELAY_CLIENT_CA_FILE is forbidden in system mode");
    let max_connections = values.get("RELAY_MAX_CONNECTIONS").map(String::as_str).unwrap_or("256")
      .parse::<usize>().context("invalid RELAY_MAX_CONNECTIONS")?;
    let max_handshakes = values.get("RELAY_MAX_HANDSHAKES").map(String::as_str).unwrap_or("32")
      .parse::<usize>().context("invalid RELAY_MAX_HANDSHAKES")?;
    ensure!((1..=4096).contains(&max_connections), "RELAY_MAX_CONNECTIONS must be between 1 and 4096");
    ensure!((1..=256).contains(&max_handshakes) && max_handshakes <= max_connections, "invalid RELAY_MAX_HANDSHAKES bound");
    Ok(Self {
      bind,
      server_name: canonical_dns_name(values.get("RELAY_SERVER_NAME").context("RELAY_SERVER_NAME is required")?)?,
      state_dir: PathBuf::from(values.get("RELAY_STATE_DIR").map(String::as_str).unwrap_or("./state")),
      tls_cert_chain_file: PathBuf::from(values.get("RELAY_TLS_CERT_CHAIN_FILE").context("RELAY_TLS_CERT_CHAIN_FILE is required")?),
      tls_private_key_file: PathBuf::from(values.get("RELAY_TLS_PRIVATE_KEY_FILE").context("RELAY_TLS_PRIVATE_KEY_FILE is required")?),
      client_ca_mode,
      client_ca_file,
      client_crl_file: values.get("RELAY_CLIENT_CRL_FILE").map(PathBuf::from),
      max_connections,
      max_handshakes,
    })
  }
}

// Configuration, certificate selection, and HTTP ingress share one DNS policy.
// Only concrete ASCII DNS names are allowed; clients supply punycode for IDNs.
pub fn canonical_dns_name(value: &str) -> Result<String> {
  ensure!(!value.is_empty() && value.len() <= 253 && value.is_ascii() && !value.ends_with('.'), "invalid server DNS name");
  ensure!(value.parse::<std::net::IpAddr>().is_err(), "server name must be a DNS name");
  for label in value.split('.') {
    ensure!(!label.is_empty() && label.len() <= 63, "invalid DNS label length");
    ensure!(label.as_bytes()[0].is_ascii_alphanumeric() && label.as_bytes()[label.len()-1].is_ascii_alphanumeric(), "invalid DNS label boundary");
    ensure!(label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'), "invalid DNS label characters");
  }
  rustls::pki_types::DnsName::try_from(value).context("invalid server DNS name")?;
  Ok(value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn environment_validation_and_defaults() {
    if let Ok(scenario) = env::var("RELAY_CONFIG_TEST_CHILD") {
      let result = Config::from_env();
      if scenario == "default" {
        let config = result.unwrap();
        assert_eq!(config.client_ca_mode, CaMode::Provided);
        assert_eq!(config.bind, "127.0.0.1:8443".parse::<SocketAddr>().unwrap());
        assert_eq!(config.max_connections, 256);
        assert_eq!(config.server_name, "localhost");
      } else if scenario == "system" {
        assert_eq!(result.unwrap().client_ca_mode, CaMode::System);
      } else {
        assert!(result.is_err());
      }
      return;
    }
    for (scenario, overrides, removals) in [
      ("default", vec![], vec![]),
      ("system", vec![("RELAY_CLIENT_CA_MODE", "system")], vec!["RELAY_CLIENT_CA_FILE"]),
      ("conflict", vec![("RELAY_CLIENT_CA_MODE", "system")], vec![]),
      ("missing_ca", vec![], vec!["RELAY_CLIENT_CA_FILE"]),
      ("missing_server_name", vec![], vec!["RELAY_SERVER_NAME"]),
      ("missing_server_cert", vec![], vec!["RELAY_TLS_CERT_CHAIN_FILE"]),
      ("missing_server_key", vec![], vec!["RELAY_TLS_PRIVATE_KEY_FILE"]),
      ("system_missing_server_cert", vec![("RELAY_CLIENT_CA_MODE", "system")], vec!["RELAY_CLIENT_CA_FILE", "RELAY_TLS_CERT_CHAIN_FILE"]),
      ("system_missing_server_key", vec![("RELAY_CLIENT_CA_MODE", "system")], vec!["RELAY_CLIENT_CA_FILE", "RELAY_TLS_PRIVATE_KEY_FILE"]),
      ("bad_server_name", vec![("RELAY_SERVER_NAME", "https://relay.example")], vec![]),
      ("bad_mode", vec![("RELAY_CLIENT_CA_MODE", "both")], vec![]),
      ("bad_bind", vec![("RELAY_BIND", "a-hostname:443")], vec![]),
      ("bad_limit", vec![("RELAY_MAX_CONNECTIONS", "0")], vec![]),
      ("bad_handshakes", vec![("RELAY_MAX_HANDSHAKES", "257")], vec![]),
      ("empty_path", vec![("RELAY_TLS_PRIVATE_KEY_FILE", "")], vec![]),
    ] {
      let mut process = std::process::Command::new(env::current_exe().unwrap());
      process.arg("config::tests::environment_validation_and_defaults").arg("--exact");
      for (key, _) in env::vars_os() {
        if key.to_string_lossy().starts_with("RELAY_") { process.env_remove(key); }
      }
      process.env("RELAY_CONFIG_TEST_CHILD", scenario)
        .env("RELAY_SERVER_NAME", "LOCALHOST")
        .env("RELAY_TLS_CERT_CHAIN_FILE", "/tmp/server.pem")
        .env("RELAY_TLS_PRIVATE_KEY_FILE", "/tmp/server.key")
        .env("RELAY_CLIENT_CA_FILE", "/tmp/ca.pem");
      for (key, value) in overrides { process.env(key, value); }
      for key in removals { process.env_remove(key); }
      let result = process.output().unwrap();
      assert!(result.status.success(), "configuration subprocess failed for {scenario}: {}", String::from_utf8_lossy(&result.stderr));
    }
  }

  #[test]
  fn concrete_dns_names_have_one_canonical_form() {
    for (input, expected) in [("localhost", "localhost"), ("Relay.Example.COM", "relay.example.com"), ("xn--bcher-kva.example", "xn--bcher-kva.example")] {
      assert_eq!(canonical_dns_name(input).unwrap(), expected);
    }
    for input in ["", "127.0.0.1", "::1", "[::1]", "*.example.com", "https://relay.example", "relay.example:443", "relay.example/path", "relay.example.", " relay.example", "relay.example ", "bücher.example", "a..example", "-bad.example", "bad-.example", "bad_name.example", "user@relay.example", "relay.example?x"] {
      assert!(canonical_dns_name(input).is_err(), "accepted invalid DNS name: {input}");
    }
    assert!(canonical_dns_name(&format!("{}.example", "a".repeat(64))).is_err());
    assert!(canonical_dns_name(&format!("{}.{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(63))).is_err());
  }
}
