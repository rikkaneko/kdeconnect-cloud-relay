use std::{io::Cursor, path::Path, time::Duration};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool, sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous}};
use time::OffsetDateTime;
use tokio::time::timeout;
use uuid::Uuid;

use crate::protocol::{AdminCommand, Identity};

#[derive(Clone)]
pub struct Store {
  pub pool: SqlitePool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRecord {
  pub id: Uuid,
  pub kde_device_id: String,
  pub display_name: String,
}

impl Store {
  pub async fn open(state_dir: &Path) -> Result<Self> {
    // The application holds the lifetime lock; each DB transaction remains bounded.
    std::fs::create_dir_all(state_dir).context("cannot create state directory")?;
    let path = state_dir.join("metadata.db");
    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
      ensure!(metadata.is_file() && !metadata.file_type().is_symlink(), "metadata database must be a regular file");
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
      use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
      std::fs::set_permissions(state_dir, std::fs::Permissions::from_mode(0o700))?;
      options.mode(0o600);
    }
    let file = options.open(&path).context("cannot open metadata database")?;
    #[cfg(unix)]
    {
      use std::os::unix::fs::PermissionsExt;
      file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    drop(file);
    timeout(Duration::from_secs(2), async {
      let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(false)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(Duration::from_millis(250))
        .statement_cache_capacity(64);
      let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .min_connections(1)
        .acquire_timeout(Duration::from_millis(500))
        .connect_with(options).await?;
      let version: String = sqlx::query_scalar("SELECT sqlite_version()").fetch_one(&pool).await?;
      let parts: Vec<u32> = version.split('.').map(str::parse).collect::<std::result::Result<_, _>>()?;
      ensure!(parts.len() == 3 && parts.as_slice() >= [3, 51, 3].as_slice(), "SQLite >=3.51.3 is required");
      sqlx::migrate!("./migrations").run(&pool).await?;
      Ok(Self { pool })
    }).await.context("metadata initialization deadline exceeded")?
  }

  pub async fn authorize(&self, fingerprint: &str) -> Result<Option<Identity>> {
    ensure!(fingerprint.len() == 64 && fingerprint.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "invalid certificate fingerprint");
    timeout(Duration::from_secs(2), async {
      let row = sqlx::query(
        "SELECT a.id AS account_id, d.id AS device_id, c.expires_at FROM certificates c JOIN devices d ON d.id = c.device_id JOIN accounts a ON a.id = d.account_id WHERE c.fingerprint = ? AND c.revoked = 0 AND d.revoked = 0 AND a.enabled = 1 AND c.expires_at > ?"
      ).bind(fingerprint).bind(OffsetDateTime::now_utc().unix_timestamp()).fetch_optional(&self.pool).await?;
      row.map(|row| -> Result<Identity> {
        Ok(Identity {
          account_id: Uuid::parse_str(row.try_get("account_id")?)?,
          device_id: Uuid::parse_str(row.try_get("device_id")?)?,
          fingerprint: fingerprint.to_owned(),
          expires_at: row.try_get("expires_at")?,
        })
      }).transpose()
    }).await.context("authorization deadline exceeded")?
  }

  pub async fn directory(&self, identity: &Identity, after: Option<Uuid>, limit: u32) -> Result<Vec<DeviceRecord>> {
    ensure!((1..=100).contains(&limit), "directory limit must be between 1 and 100");
    timeout(Duration::from_secs(2), async {
      let rows = sqlx::query(
        "SELECT id, kde_device_id, display_name FROM devices WHERE account_id = ? AND revoked = 0 AND id > ? ORDER BY id LIMIT ?"
      ).bind(identity.account_id.to_string()).bind(after.map(|id| id.to_string()).unwrap_or_default()).bind(limit).fetch_all(&self.pool).await?;
      rows.into_iter().map(|row| -> Result<DeviceRecord> {
        Ok(DeviceRecord {
          id: Uuid::parse_str(row.try_get("id")?)?,
          kde_device_id: row.try_get("kde_device_id")?,
          display_name: row.try_get("display_name")?,
        })
      }).collect()
    }).await.context("directory deadline exceeded")?
  }

  pub async fn update_display(&self, device: Uuid, name: &str) -> Result<()> {
    ensure!(!name.trim().is_empty() && name.len() <= 128 && !name.chars().any(char::is_control), "invalid display name");
    timeout(Duration::from_secs(2), async {
      let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
      let result = sqlx::query("UPDATE devices SET display_name = ? WHERE id = ? AND revoked = 0")
        .bind(name).bind(device.to_string()).execute(&mut *tx).await?;
      ensure!(result.rows_affected() == 1, "device not found");
      sqlx::query("INSERT INTO audit(event, subject_id, created_at) VALUES ('display_updated', ?, unixepoch())")
        .bind(device.to_string()).execute(&mut *tx).await?;
      sqlx::query("DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT 10000)").execute(&mut *tx).await?;
      tx.commit().await?;
      Ok(())
    }).await.context("metadata update deadline exceeded")?
  }

  pub async fn self_revoke(&self, device: Uuid) -> Result<()> {
    self.admin(&AdminCommand::DeviceRevoke { device_id: device }).await?;
    Ok(())
  }

  pub async fn admin(&self, command: &AdminCommand) -> Result<Value> {
    // BEGIN IMMEDIATE serializes quota checks, mutations, and their audit entry.
    timeout(Duration::from_secs(2), async {
      let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
      let now = OffsetDateTime::now_utc().unix_timestamp();
      let mut audit: Option<(&str, String)> = None;
      let result = match command {
        AdminCommand::AccountCreate { name } => {
          ensure!(!name.trim().is_empty() && name.len() <= 128 && !name.chars().any(char::is_control), "invalid account name");
          let count: i64 = sqlx::query_scalar("SELECT count(*) FROM accounts").fetch_one(&mut *tx).await?;
          ensure!(count < 1000, "account registry quota exceeded");
          let id = Uuid::new_v4();
          sqlx::query("INSERT INTO accounts(id, name, created_at) VALUES (?, ?, ?)")
            .bind(id.to_string()).bind(name).bind(now).execute(&mut *tx).await?;
          audit = Some(("account_created", id.to_string()));
          json!({ "id": id, "name": name, "enabled": true })
        }
        AdminCommand::AccountSetEnabled { account_id, enabled } => {
          let updated = sqlx::query("UPDATE accounts SET enabled = ? WHERE id = ?")
            .bind(enabled).bind(account_id.to_string()).execute(&mut *tx).await?;
          ensure!(updated.rows_affected() == 1, "account not found");
          audit = Some((if *enabled { "account_enabled" } else { "account_disabled" }, account_id.to_string()));
          json!({ "id": account_id, "enabled": enabled })
        }
        AdminCommand::DeviceRegister { account_id, kde_device_id, display_name, certificate_pem } => {
          ensure!(!kde_device_id.trim().is_empty() && kde_device_id.len() <= 128 && !kde_device_id.chars().any(char::is_control), "invalid KDE device ID");
          ensure!(!display_name.trim().is_empty() && display_name.len() <= 128 && !display_name.chars().any(char::is_control), "invalid display name");
          ensure!(certificate_pem.len() <= 1024 * 1024 && !certificate_pem.contains("PRIVATE KEY"), "invalid certificate input");
          let certs = rustls_pemfile::certs(&mut Cursor::new(certificate_pem.as_bytes())).collect::<std::io::Result<Vec<_>>>()?;
          ensure!(!certs.is_empty() && certs.len() <= 16, "invalid certificate chain");
          let (fingerprint, expiry) = crate::tls::certificate_identity(certs[0].as_ref())?;
          let enabled: Option<bool> = sqlx::query_scalar("SELECT enabled FROM accounts WHERE id = ?")
            .bind(account_id.to_string()).fetch_optional(&mut *tx).await?;
          ensure!(enabled == Some(true), "active account not found");
          let count: i64 = sqlx::query_scalar("SELECT count(*) FROM devices WHERE account_id = ? AND revoked = 0")
            .bind(account_id.to_string()).fetch_one(&mut *tx).await?;
          ensure!(count < 10, "device quota exceeded");
          let duplicate: i64 = sqlx::query_scalar("SELECT count(*) FROM devices WHERE account_id = ? AND kde_device_id = ? AND revoked = 0")
            .bind(account_id.to_string()).bind(kde_device_id).fetch_one(&mut *tx).await?;
          ensure!(duplicate == 0, "active KDE device ID already registered");
          let duplicate: i64 = sqlx::query_scalar("SELECT count(*) FROM certificates WHERE fingerprint = ?")
            .bind(&fingerprint).fetch_one(&mut *tx).await?;
          ensure!(duplicate == 0, "certificate already registered");
          let id = Uuid::new_v4();
          sqlx::query("INSERT INTO devices(id, account_id, kde_device_id, display_name, created_at) VALUES (?, ?, ?, ?, ?)")
            .bind(id.to_string()).bind(account_id.to_string()).bind(kde_device_id).bind(display_name).bind(now).execute(&mut *tx).await?;
          sqlx::query("INSERT INTO certificates(fingerprint, device_id, expires_at, created_at) VALUES (?, ?, ?, ?)")
            .bind(&fingerprint).bind(id.to_string()).bind(expiry).bind(now).execute(&mut *tx).await?;
          audit = Some(("device_registered", id.to_string()));
          json!({ "id": id, "fingerprint": fingerprint })
        }
        AdminCommand::DeviceRevoke { device_id } => {
          let found: i64 = sqlx::query_scalar("SELECT count(*) FROM devices WHERE id = ?")
            .bind(device_id.to_string()).fetch_one(&mut *tx).await?;
          ensure!(found == 1, "device not found");
          sqlx::query("UPDATE devices SET revoked = 1 WHERE id = ?").bind(device_id.to_string()).execute(&mut *tx).await?;
          sqlx::query("UPDATE certificates SET revoked = 1 WHERE device_id = ?").bind(device_id.to_string()).execute(&mut *tx).await?;
          audit = Some(("device_revoked", device_id.to_string()));
          json!({ "id": device_id, "revoked": true })
        }
        AdminCommand::CertificateApprove { device_id, certificate_pem } => {
          ensure!(certificate_pem.len() <= 1024 * 1024 && !certificate_pem.contains("PRIVATE KEY"), "invalid certificate input");
          let certs = rustls_pemfile::certs(&mut Cursor::new(certificate_pem.as_bytes())).collect::<std::io::Result<Vec<_>>>()?;
          ensure!(!certs.is_empty() && certs.len() <= 16, "invalid certificate chain");
          let (fingerprint, expiry) = crate::tls::certificate_identity(certs[0].as_ref())?;
          let found: i64 = sqlx::query_scalar("SELECT count(*) FROM devices d JOIN accounts a ON a.id = d.account_id WHERE d.id = ? AND d.revoked = 0 AND a.enabled = 1")
            .bind(device_id.to_string()).fetch_one(&mut *tx).await?;
          ensure!(found == 1, "active device not found");
          let duplicate: i64 = sqlx::query_scalar("SELECT count(*) FROM certificates WHERE fingerprint = ?")
            .bind(&fingerprint).fetch_one(&mut *tx).await?;
          ensure!(duplicate == 0, "certificate already registered");
          let count: i64 = sqlx::query_scalar("SELECT count(*) FROM certificates WHERE device_id = ? AND revoked = 0 AND expires_at > ?")
            .bind(device_id.to_string()).bind(now).fetch_one(&mut *tx).await?;
          ensure!(count < 2, "certificate overlap quota exceeded");
          sqlx::query("INSERT INTO certificates(fingerprint, device_id, expires_at, created_at) VALUES (?, ?, ?, ?)")
            .bind(&fingerprint).bind(device_id.to_string()).bind(expiry).bind(now).execute(&mut *tx).await?;
          audit = Some(("certificate_approved", device_id.to_string()));
          json!({ "id": device_id, "fingerprint": fingerprint })
        }
        AdminCommand::CertificateRevoke { fingerprint } => {
          ensure!(fingerprint.len() == 64 && fingerprint.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "invalid certificate fingerprint");
          let device: Option<String> = sqlx::query_scalar("SELECT device_id FROM certificates WHERE fingerprint = ?")
            .bind(fingerprint).fetch_optional(&mut *tx).await?;
          let device = device.context("certificate not found")?;
          sqlx::query("UPDATE certificates SET revoked = 1 WHERE fingerprint = ?").bind(fingerprint).execute(&mut *tx).await?;
          audit = Some(("certificate_revoked", device));
          json!({ "fingerprint": fingerprint, "revoked": true })
        }
        AdminCommand::List => {
          let accounts = sqlx::query("SELECT id, name, enabled FROM accounts ORDER BY id LIMIT 1000").fetch_all(&mut *tx).await?;
          let devices = sqlx::query("SELECT id, account_id, kde_device_id, display_name, revoked FROM devices ORDER BY id LIMIT 10000").fetch_all(&mut *tx).await?;
          let certs = sqlx::query("SELECT fingerprint, device_id, expires_at, revoked FROM certificates ORDER BY fingerprint LIMIT 20000").fetch_all(&mut *tx).await?;
          let accounts = accounts.into_iter().map(|row| -> Result<Value> {
            Ok(json!({ "id": row.try_get::<String, _>("id")?, "name": row.try_get::<String, _>("name")?, "enabled": row.try_get::<bool, _>("enabled")? }))
          }).collect::<Result<Vec<_>>>()?;
          let devices = devices.into_iter().map(|row| -> Result<Value> {
            Ok(json!({ "id": row.try_get::<String, _>("id")?, "accountId": row.try_get::<String, _>("account_id")?, "kdeDeviceId": row.try_get::<String, _>("kde_device_id")?, "displayName": row.try_get::<String, _>("display_name")?, "revoked": row.try_get::<bool, _>("revoked")? }))
          }).collect::<Result<Vec<_>>>()?;
          let certs = certs.into_iter().map(|row| -> Result<Value> {
            let expiry = OffsetDateTime::from_unix_timestamp(row.try_get("expires_at")?)?.format(&time::format_description::well_known::Rfc3339)?;
            Ok(json!({ "fingerprint": row.try_get::<String, _>("fingerprint")?, "deviceId": row.try_get::<String, _>("device_id")?, "expiresAt": expiry, "revoked": row.try_get::<bool, _>("revoked")? }))
          }).collect::<Result<Vec<_>>>()?;
          json!({ "accounts": accounts, "devices": devices, "certificates": certs })
        }
        AdminCommand::Metrics | AdminCommand::TlsReload => anyhow::bail!("command requires a running relay"),
      };
      if let Some((event, subject)) = audit {
        sqlx::query("INSERT INTO audit(event, subject_id, created_at) VALUES (?, ?, ?)")
          .bind(event).bind(subject).bind(now).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT 10000)").execute(&mut *tx).await?;
      }
      tx.commit().await?;
      Ok(result)
    }).await.context("operator metadata deadline exceeded")?
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair};

  #[tokio::test]
  async fn registration_authorization_disable_revoke_and_restart() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).await.unwrap();
    let account = store.admin(&AdminCommand::AccountCreate { name: "household".into() }).await.unwrap();
    let account_id = Uuid::parse_str(account["id"].as_str().unwrap()).unwrap();
    let mut params = CertificateParams::new(vec!["device.test".into()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let key = KeyPair::generate().unwrap();
    let pem = params.self_signed(&key).unwrap().pem();
    let registration = store.admin(&AdminCommand::DeviceRegister {
      account_id, kde_device_id: "kde-a".into(), display_name: "Phone".into(), certificate_pem: pem,
    }).await.unwrap();
    let device_id = Uuid::parse_str(registration["id"].as_str().unwrap()).unwrap();
    let fingerprint = registration["fingerprint"].as_str().unwrap();
    let identity = store.authorize(fingerprint).await.unwrap().unwrap();
    assert_eq!(identity.device_id, device_id);
    assert_eq!(identity.account_id, account_id);
    assert!(store.authorize(&"0".repeat(64)).await.unwrap().is_none());
    store.update_display(device_id, "Updated Phone").await.unwrap();
    assert_eq!(store.directory(&identity, None, 10).await.unwrap()[0].display_name, "Updated Phone");
    let other = store.admin(&AdminCommand::AccountCreate { name: "other".into() }).await.unwrap();
    let other_identity = Identity { account_id: Uuid::parse_str(other["id"].as_str().unwrap()).unwrap(), ..identity.clone() };
    assert!(store.directory(&other_identity, None, 10).await.unwrap().is_empty());
    store.admin(&AdminCommand::AccountSetEnabled { account_id, enabled: false }).await.unwrap();
    assert!(store.authorize(fingerprint).await.unwrap().is_none());
    store.admin(&AdminCommand::AccountSetEnabled { account_id, enabled: true }).await.unwrap();
    assert!(store.authorize(fingerprint).await.unwrap().is_some());
    store.pool.close().await;
    let store = Store::open(temp.path()).await.unwrap();
    assert!(store.authorize(fingerprint).await.unwrap().is_some());
    store.self_revoke(device_id).await.unwrap();
    store.self_revoke(device_id).await.unwrap();
    assert!(store.authorize(fingerprint).await.unwrap().is_none());
    assert!(store.directory(&identity, None, 10).await.unwrap().is_empty());
    let snapshot = store.admin(&AdminCommand::List).await.unwrap();
    assert_eq!(snapshot["devices"][0]["revoked"], true);
    assert!(snapshot["certificates"][0]["expiresAt"].as_str().unwrap().ends_with('Z'));
    #[cfg(unix)]
    {
      use std::os::unix::fs::PermissionsExt;
      assert_eq!(std::fs::metadata(temp.path().join("metadata.db")).unwrap().permissions().mode() & 0o777, 0o600);
    }
  }

  #[tokio::test]
  async fn transaction_quotas_uniqueness_and_certificate_overlap() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).await.unwrap();
    let account = store.admin(&AdminCommand::AccountCreate { name: "quota".into() }).await.unwrap();
    let account_id = Uuid::parse_str(account["id"].as_str().unwrap()).unwrap();
    let mut ids = Vec::new();
    let mut pems = Vec::new();
    for index in 0..11 {
      let mut params = CertificateParams::new(vec![format!("device-{index}.test")]).unwrap();
      params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
      let key = KeyPair::generate().unwrap();
      let pem = params.self_signed(&key).unwrap().pem();
      let result = store.admin(&AdminCommand::DeviceRegister {
        account_id, kde_device_id: format!("kde-{index}"), display_name: "Device".into(), certificate_pem: pem.clone(),
      }).await;
      if index == 10 {
        assert!(result.unwrap_err().to_string().contains("quota"));
      } else {
        ids.push(Uuid::parse_str(result.unwrap()["id"].as_str().unwrap()).unwrap());
      }
      pems.push(pem);
    }
    assert!(store.admin(&AdminCommand::CertificateApprove { device_id: ids[0], certificate_pem: pems[1].clone() }).await.is_err());
    let overlap = store.admin(&AdminCommand::CertificateApprove { device_id: ids[0], certificate_pem: pems[10].clone() }).await.unwrap();
    let mut params = CertificateParams::new(vec!["third.test".into()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let pem = params.self_signed(&KeyPair::generate().unwrap()).unwrap().pem();
    assert!(store.admin(&AdminCommand::CertificateApprove { device_id: ids[0], certificate_pem: pem.clone() }).await.unwrap_err().to_string().contains("quota"));
    store.admin(&AdminCommand::CertificateRevoke { fingerprint: overlap["fingerprint"].as_str().unwrap().into() }).await.unwrap();
    assert!(store.authorize(overlap["fingerprint"].as_str().unwrap()).await.unwrap().is_none());
    assert!(store.admin(&AdminCommand::CertificateApprove { device_id: ids[0], certificate_pem: pem.clone() }).await.is_ok());
    store.self_revoke(ids[9]).await.unwrap();
    // A revoked registration frees its slot and KDE ID but never its fingerprint.
    assert!(store.admin(&AdminCommand::DeviceRegister {
      account_id, kde_device_id: "kde-9".into(), display_name: "Replacement".into(), certificate_pem: pems[9].clone(),
    }).await.unwrap_err().to_string().contains("certificate already registered"));
    let mut params = CertificateParams::new(vec!["replacement.test".into()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let pem = params.self_signed(&KeyPair::generate().unwrap()).unwrap().pem();
    assert!(store.admin(&AdminCommand::DeviceRegister {
      account_id, kde_device_id: "kde-0".into(), display_name: "Duplicate".into(), certificate_pem: pem.clone(),
    }).await.unwrap_err().to_string().contains("KDE device ID"));
    assert!(store.admin(&AdminCommand::DeviceRegister {
      account_id, kde_device_id: "kde-9".into(), display_name: "Replacement".into(), certificate_pem: pem,
    }).await.is_ok());
  }

  #[tokio::test]
  async fn invalid_input_schema_guards_and_database_failure() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).await.unwrap();
    assert!(store.admin(&AdminCommand::AccountCreate { name: "".into() }).await.is_err());
    assert!(store.admin(&AdminCommand::AccountCreate { name: "a".repeat(129) }).await.is_err());
    assert!(store.admin(&AdminCommand::AccountCreate { name: "a\nb".into() }).await.is_err());
    assert!(store.authorize("not-a-fingerprint").await.is_err());
    let account = store.admin(&AdminCommand::AccountCreate { name: "validation".into() }).await.unwrap();
    let account_id = Uuid::parse_str(account["id"].as_str().unwrap()).unwrap();
    let mut params = CertificateParams::new(vec!["client.test".into()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let key = KeyPair::generate().unwrap();
    let pem = params.self_signed(&key).unwrap().pem();
    for bad in ["not pem".into(), key.serialize_pem(), "x".repeat(1024 * 1024 + 1)] {
      assert!(store.admin(&AdminCommand::DeviceRegister {
        account_id, kde_device_id: "id".into(), display_name: "name".into(), certificate_pem: bad,
      }).await.is_err());
    }
    let registration = store.admin(&AdminCommand::DeviceRegister {
      account_id, kde_device_id: "id".into(), display_name: "name".into(), certificate_pem: pem,
    }).await.unwrap();
    let device_id = Uuid::parse_str(registration["id"].as_str().unwrap()).unwrap();
    assert!(store.update_display(device_id, &"é".repeat(65)).await.is_err());
    assert!(sqlx::query("INSERT INTO certificates VALUES ('invalid', ?, 9999999999, 0, 0)")
      .bind(device_id.to_string()).execute(&store.pool).await.is_err());
    assert!(sqlx::query("INSERT INTO devices VALUES (?, ?, 'orphan', 'name', 0, 0)")
      .bind(Uuid::new_v4().to_string()).bind(Uuid::new_v4().to_string()).execute(&store.pool).await.is_err());
    let identity = store.authorize(registration["fingerprint"].as_str().unwrap()).await.unwrap().unwrap();
    assert!(store.directory(&identity, None, 0).await.is_err());
    assert!(store.directory(&identity, None, 101).await.is_err());
    let records = store.directory(&identity, Some(device_id), 10).await.unwrap();
    assert!(records.is_empty());
    store.pool.close().await;
    assert!(store.authorize(registration["fingerprint"].as_str().unwrap()).await.is_err());
  }

  #[tokio::test]
  async fn locked_database_fails_within_deadline_and_audit_is_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).await.unwrap();
    let account = store.admin(&AdminCommand::AccountCreate { name: "bounded".into() }).await.unwrap();
    let account_id = Uuid::parse_str(account["id"].as_str().unwrap()).unwrap();
    sqlx::query("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 10001) INSERT INTO audit(event, subject_id, created_at) SELECT 'account_created', 'test', 0 FROM n")
      .execute(&store.pool).await.unwrap();
    store.admin(&AdminCommand::AccountSetEnabled { account_id, enabled: false }).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit").fetch_one(&store.pool).await.unwrap();
    assert_eq!(count, 10000);
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    sqlx::query("UPDATE accounts SET enabled = 1 WHERE id = ?").bind(account_id.to_string()).execute(&mut *tx).await.unwrap();
    let started = std::time::Instant::now();
    assert!(store.admin(&AdminCommand::AccountSetEnabled { account_id, enabled: true }).await.is_err());
    assert!(started.elapsed() < Duration::from_secs(3));
    tx.rollback().await.unwrap();
  }
}
