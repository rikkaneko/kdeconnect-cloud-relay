use std::{fs::OpenOptions, os::unix::fs::{OpenOptionsExt, PermissionsExt}, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fs2::FileExt;
use kdeconnect_cloud_relay::{config::Config, protocol::AdminCommand, server::{App, run}, store::Store};
use tokio::{io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader}, net::{TcpListener, UnixStream}};
use uuid::Uuid;

#[derive(Parser)]
#[command(version, about = "Opaque mTLS relay and local operator CLI")]
struct Cli {
  #[command(subcommand)]
  command: Command,
}

#[derive(Subcommand)]
enum Command {
  Serve,
  Init { #[arg(long, default_value = "./state")] state_dir: PathBuf },
  Admin {
    #[arg(long, default_value = "./state")]
    state_dir: PathBuf,
    #[arg(long, help = "Operate directly only when the daemon is stopped")]
    offline: bool,
    #[command(subcommand)]
    command: Operator,
  },
}

#[derive(Subcommand)]
enum Operator {
  AccountCreate { name: String },
  AccountSetEnabled { account_id: Uuid, #[arg(action=clap::ArgAction::Set, value_parser=clap::value_parser!(bool))] enabled: bool },
  DeviceRegister { account_id: Uuid, kde_device_id: String, display_name: String, certificate: PathBuf },
  DeviceRevoke { device_id: Uuid },
  CertificateApprove { device_id: Uuid, certificate: PathBuf },
  CertificateRevoke { fingerprint: String },
  List,
  Metrics,
  TlsReload,
}

#[tokio::main]
async fn main() -> Result<()> {
  tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
  let cli = Cli::parse();
  match cli.command {
    Command::Serve => {
      let config = Config::from_env()?;
      let listener = TcpListener::bind(config.bind).await.context("cannot bind relay listener")?;
      let (app, _lock) = App::open(config).await?;
      let shutdown = app.shutdown.clone();
      tokio::spawn(async move {
        #[cfg(unix)]
        {
          if let Ok(mut terminate) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
          } else { let _ = tokio::signal::ctrl_c().await; }
        }
        shutdown.cancel();
      });
      tracing::info!(event="relay_started",address=%listener.local_addr()?);
      run(app,listener).await?;
    }
    Command::Init { state_dir } => {
      anyhow::ensure!(state_dir.as_os_str().len() <= 4096,"state path too long");
      std::fs::create_dir_all(&state_dir)?;
      std::fs::set_permissions(&state_dir,std::fs::Permissions::from_mode(0o700))?;
      let lock = OpenOptions::new().create(true).truncate(false).read(true).write(true).mode(0o600).open(state_dir.join("relay.lock"))?;
      lock.try_lock_exclusive().context("relay must be stopped for initialization")?;
      let store = Store::open(&state_dir).await?;
      store.pool.close().await;
      println!("{{\"initialized\":true}}");
    }
    Command::Admin { state_dir, offline, command } => {
      anyhow::ensure!(state_dir.as_os_str().len() <= 4096,"state path too long");
      let command = match command {
        Operator::AccountCreate { name } => AdminCommand::AccountCreate { name },
        Operator::AccountSetEnabled { account_id, enabled } => AdminCommand::AccountSetEnabled { account_id, enabled },
        Operator::DeviceRegister { account_id, kde_device_id, display_name, certificate } => {
          let file = tokio::fs::File::open(certificate).await.context("cannot open public certificate file")?;
          let mut certificate_pem = String::new();
          file.take(1024 * 1024 + 1).read_to_string(&mut certificate_pem).await?;
          anyhow::ensure!(certificate_pem.len() <= 1024 * 1024 && !certificate_pem.contains("PRIVATE KEY"),"expected bounded public certificate PEM");
          AdminCommand::DeviceRegister { account_id, kde_device_id, display_name, certificate_pem }
        }
        Operator::DeviceRevoke { device_id } => AdminCommand::DeviceRevoke { device_id },
        Operator::CertificateApprove { device_id, certificate } => {
          let file = tokio::fs::File::open(certificate).await.context("cannot open public certificate file")?;
          let mut certificate_pem = String::new();
          file.take(1024 * 1024 + 1).read_to_string(&mut certificate_pem).await?;
          anyhow::ensure!(certificate_pem.len() <= 1024 * 1024 && !certificate_pem.contains("PRIVATE KEY"),"expected bounded public certificate PEM");
          AdminCommand::CertificateApprove { device_id, certificate_pem }
        }
        Operator::CertificateRevoke { fingerprint } => AdminCommand::CertificateRevoke { fingerprint },
        Operator::List => AdminCommand::List,
        Operator::Metrics => AdminCommand::Metrics,
        Operator::TlsReload => AdminCommand::TlsReload,
      };
      if offline {
        anyhow::ensure!(!matches!(command,AdminCommand::Metrics | AdminCommand::TlsReload),"command requires a running daemon");
        let lock = OpenOptions::new().read(true).write(true).open(state_dir.join("relay.lock"))?;
        lock.try_lock_exclusive().context("relay must be stopped for offline administration")?;
        let store = Store::open(&state_dir).await?;
        let result = store.admin(&command).await?;
        println!("{}",serde_json::to_string_pretty(&result)?);
        store.pool.close().await;
      } else {
        let socket = UnixStream::connect(state_dir.join("operator.sock")).await.context("cannot reach local relay; use --offline only when stopped")?;
        let mut reader = BufReader::new(socket);
        let mut request = serde_json::to_vec(&command)?;
        request.push(b'\n');
        anyhow::ensure!(request.len() <= 1024 * 1024,"operator request too large");
        tokio::time::timeout(Duration::from_secs(5),reader.get_mut().write_all(&request)).await??;
        let mut response = String::new();
        let mut limited = (&mut reader).take(8 * 1024 * 1024);
        tokio::time::timeout(Duration::from_secs(30),limited.read_line(&mut response)).await??;
        let value: serde_json::Value = serde_json::from_str(&response)?;
        println!("{}",serde_json::to_string_pretty(&value)?);
        anyhow::ensure!(value["ok"] == true,"operator command rejected");
      }
    }
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn operator_cli_requires_a_boolean_value_and_valid_identifiers() {
    let account = Uuid::new_v4().to_string();
    let args = ["relay", "admin", "account-set-enabled", &account, "false"];
    let cli = Cli::try_parse_from(args).unwrap();
    assert!(matches!(cli.command,Command::Admin { command:Operator::AccountSetEnabled { enabled:false,.. },.. }));
    assert!(Cli::try_parse_from(["relay","admin","account-set-enabled",&account]).is_err());
    assert!(Cli::try_parse_from(["relay","admin","account-set-enabled",&account,"maybe"]).is_err());
    assert!(Cli::try_parse_from(["relay","admin","device-revoke","not-a-uuid"]).is_err());
  }
}
