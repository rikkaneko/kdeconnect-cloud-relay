use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const CONTROL_LIMIT: usize = 16 * 1024;
pub const ENVELOPE_LIMIT: usize = 64 * 1024;
pub const HEADER_LEN: usize = 22;
pub const STREAM_WINDOW: u64 = 256 * 1024;
pub const CONNECTION_BUDGET: u64 = 1024 * 1024;
pub const CONTROL_RESERVE: u64 = 64 * 1024;
pub const PAYLOAD_BUDGET: u64 = 512 * 1024;
pub const QUANTUM: u64 = 16 * 1024;
pub const SUBPROTOCOL: &str = "kdeconnect-relay.v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Identity {
  pub account_id: Uuid,
  pub device_id: Uuid,
  pub fingerprint: String,
  pub expires_at: i64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StreamKind {
  Packet,
  Payload,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum Control {
  #[serde(rename = "stream.open")]
  Open { request_id: Uuid, peer_id: Uuid, kind: StreamKind, parent_id: Option<Uuid> },
  #[serde(rename = "stream.accept")]
  Accept { request_id: Uuid, stream_id: Uuid },
  #[serde(rename = "stream.reject")]
  Reject { request_id: Uuid, stream_id: Uuid },
  #[serde(rename = "stream.close")]
  Close { request_id: Uuid, stream_id: Uuid },
  #[serde(rename = "stream.window")]
  Window { stream_id: Uuid, consumed_bytes: u64 },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all_fields = "camelCase")]
pub enum Event {
  #[serde(rename = "connection.ready")]
  Connected { generation: Uuid, device_id: Uuid },
  #[serde(rename = "stream.offered")]
  Offered { stream_id: Uuid, peer_id: Uuid, kind: StreamKind, parent_id: Option<Uuid>, initiator_id: Uuid },
  #[serde(rename = "stream.result")]
  Result { request_id: Uuid, stream_id: Uuid, state: String, initiator_id: Uuid },
  #[serde(rename = "stream.ready")]
  Ready { stream_id: Uuid, peer_id: Uuid, initiator_id: Uuid },
  #[serde(rename = "stream.closed")]
  Closed { stream_id: Uuid, reason: String },
  #[serde(rename = "stream.credit")]
  Credit { stream_id: Uuid, send_limit_bytes: u64 },
  #[serde(rename = "request.ok")]
  Ok { request_id: Uuid },
  #[serde(rename = "presence.changed")]
  Presence { device_id: Uuid, online: bool },
  #[serde(rename = "error")]
  Error { request_id: Option<Uuid>, code: String, message: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisplayUpdate {
  pub display_name: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryQuery {
  pub after: Option<Uuid>,
  pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum AdminCommand {
  AccountCreate { name: String },
  AccountSetEnabled { account_id: Uuid, enabled: bool },
  DeviceRegister { account_id: Uuid, kde_device_id: String, display_name: String, certificate_pem: String },
  DeviceRevoke { device_id: Uuid },
  CertificateApprove { device_id: Uuid, certificate_pem: String },
  CertificateRevoke { fingerprint: String },
  List,
  Metrics,
  TlsReload,
}

// Validate the envelope before copying opaque bytes or routing to a peer.
pub fn decode_data(data: &[u8]) -> anyhow::Result<(Uuid, &[u8])> {
  anyhow::ensure!((HEADER_LEN..=ENVELOPE_LIMIT).contains(&data.len()), "invalid envelope size");
  anyhow::ensure!(data[0] == 1 && data[1] == 1, "unsupported envelope");
  let stream = Uuid::from_slice(&data[2..18])?;
  let length = u32::from_be_bytes(data[18..22].try_into()?) as usize;
  anyhow::ensure!(length > 0 && length == data.len() - HEADER_LEN, "invalid payload length");
  Ok((stream, &data[HEADER_LEN..]))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn contracts_reject_unknown_fields_and_bad_envelopes() {
    assert!(serde_json::from_str::<DisplayUpdate>(r#"{"displayName":"a","accountId":"x"}"#).is_err());
    assert!(serde_json::from_str::<Control>(r#"{"type":"stream.window","streamId":"00000000-0000-0000-0000-000000000000","consumedBytes":0,"senderId":"x"}"#).is_err());
    for length in 0..HEADER_LEN {
      assert!(decode_data(&vec![0; length]).is_err());
    }
    let id = Uuid::new_v4();
    let mut frame = vec![1, 1];
    frame.extend_from_slice(id.as_bytes());
    frame.extend_from_slice(&1_u32.to_be_bytes());
    frame.push(42);
    assert_eq!(decode_data(&frame).unwrap(), (id, &[42][..]));
    frame.push(0);
    assert!(decode_data(&frame).is_err());
  }
}
