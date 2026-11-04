# KDE Connect Cloud Relay

Experimental cloud relay server for KDEConnect with mTLS authentication.

Connect KDEConnect clients using WSS channels with multiplexed packet and payload streams. The relay stores metadata in SQLite and never stores payloads.

Existing Android/desktop KDE Connect clients need a future cloud transport. This server and its Rust integration clients do not add cloud support to stock clients. Endpoint pairing, feature consent, inner TLS, and image validation remain endpoint responsibilities.

## Features

- Custom root and intermediate CA chains, including explicitly trusted intermediate anchors.
- Certificate-fingerprint registration, account isolation, leased presence, renewal overlap, immediate active-session fencing on local revocation.
- Generation-safe replacement, parent/child stream cancellation, cumulative flow credits, fair scheduling, bounded queues and admission.
- Owner-only local operator CLI/socket, safe aggregate metrics, TLS/CRL reload, and fail-closed database handling.

## Installation

Use Rust 1.99 or newer, a C compiler for bundled SQLite, and local storage on Linux or macOS. The lockfile pins the tested dependency resolution. No external database service or object storage is required.

```sh
cd kdeconnect-cloud-relay;
cargo build --locked --release;
cargo test --locked --all-targets;
cargo clippy --locked --all-targets -- -D warnings;
```

The executable is `target/release/kdeconnect-cloud-relay`. It uses the same service-account identity for its daemon and operator CLI. Install it in your executable search path to use the examples below.

## Environment configuration

| Variable | Description | Required | | Default | 
| --- | --- | --- |
| `RELAY_BIND` | Numeric IP with port | N | `127.0.0.1:8443` |
| `RELAY_SERVER_NAME` | Server domain name | Y | None |
| `RELAY_STATE_DIR` | Local writable metadata directory | N | `./state` |
| `RELAY_TLS_CERT_CHAIN_FILE` | Path to server TLS certificate (PEM) | Y | None |
| `RELAY_TLS_PRIVATE_KEY_FILE` | Path to server TLS private key (PEM, unencrypted) | Y | None |
| `RELAY_CLIENT_CA_MODE` | `provided` or `system` | Y | `provided` |
| `RELAY_CLIENT_CA_FILE` | Path to custom root CA | Required if `RELAY_CLIENT_CA_MODE=provided` | None |
| `RELAY_CLIENT_CRL_FILE` | Path to CRL file | N | None |
| `RELAY_MAX_CONNECTIONS` | Maximum number of concurrent connection | N | `256` |
| `RELAY_MAX_HANDSHAKES` | Maximum number of concurrent handshakes | N | `32` |
| `RUST_LOG` | Log level | N | `info` |

Provided-only deployment:

```sh
export RELAY_TLS_CERT_CHAIN_FILE=/etc/relay/fullchain.pem;
export RELAY_TLS_PRIVATE_KEY_FILE=/etc/relay/privkey.pem;
export RELAY_SERVER_NAME=relay.example.com;
export RELAY_CLIENT_CA_MODE=provided;
export RELAY_CLIENT_CA_FILE=/etc/relay/client-ca.pem;
export RELAY_STATE_DIR=/var/lib/kdeconnect-cloud-relay;
kdeconnect-cloud-relay init --state-dir "$RELAY_STATE_DIR";
kdeconnect-cloud-relay serve;
```

System trust deployment:

```sh
export RELAY_CLIENT_CA_MODE=system;
export RELAY_TLS_CERT_CHAIN_FILE=/etc/relay/fullchain.pem;
export RELAY_TLS_PRIVATE_KEY_FILE=/etc/relay/privkey.pem;
export RELAY_SERVER_NAME=relay.example.com;
kdeconnect-cloud-relay serve;
```

System mode loads native-store CA certificates through `rustls-native-certs`, including its `SSL_CERT_FILE` / `SSL_CERT_DIR` overrides where applicable. Inside a container, this is the container's store. Install your private root there or use provided mode. Reload or restart after store changes. Provided mode does not consult those stores/overrides and never falls back to system trust. System loading errors produce counts in logs; an empty usable store fails startup.

The server certificate chain and private key are required in both CA modes: they identify the HTTPS/WSS server. Client-CA selection controls trust for incoming client identities and does not provide a server identity. Initialization and offline administration do not require TLS environment configuration.

## Required relay domain

Set `RELAY_SERVER_NAME` before starting the daemon. Use one concrete DNS name, such as `relay.example.com`; `localhost` is supported for development. ASCII DNS names, including punycode IDNs, are normalized to lowercase. IP literals, wildcard configuration values, URLs, ports, paths, whitespace, trailing dots and invalid labels are rejected. The leaf certificate must cover this name through its DNS SAN; an applicable wildcard SAN is allowed, but CN-only certificates are rejected. This is validated at startup and TLS reload. A failed reload preserves existing sessions and configuration.

Every incoming TLS connection must send matching SNI. Missing SNI or another name is rejected during the handshake, even if the certificate covers additional names. Every HTTP request must also carry exactly one valid `Host` matching the configured domain, case-insensitively. An optional numeric port from 1 to 65535 is allowed and need not match the internal listener port. An absolute request URI's authority is checked too. `Forwarded` and `X-Forwarded-Host` cannot override these checks.

Missing, duplicate or malformed Host headers return HTTP 400 with `invalid_host`; a valid different DNS hostname returns HTTP 421 with `misdirected_request`. These checks run before every route and WebSocket upgrade, including public info/health and fallback errors. Structurally invalid HTTP may be rejected by the HTTP parser before application error handling.

Existing deployments must add `RELAY_SERVER_NAME`. Health probes need matching SNI and Host. Connect to an IP with curl's `--resolve` while keeping the URL domain correct:

```sh
curl --cacert ./server-root.pem --resolve relay.example.com:8443:127.0.0.1 https://relay.example.com:8443/health/ready;
```

`Host: relay.example.com` alone cannot supply TLS SNI for an IP URL. Changing the allowed domain requires a restart because environment configuration is fixed at startup; certificate reload may change SANs but cannot enable another configured name.

## Root and intermediate chains

The server presents `fullchain.pem` containing its leaf first, then intermediate CAs in issuer order. Clients present an independent clientAuth leaf and their intermediates in the same order. The root normally is omitted from transmitted chains and supplied as a verifier trust anchor. The same custom root may issue both identities, including through different intermediates.

`RELAY_CLIENT_CA_FILE` contains explicitly trusted CA certificates. A configured intermediate may itself be an anchor, trusting only its subtree without its parent root. An intermediate sent by a client is only chain material; it does not become an anchor. Issuers are never downloaded through AIA. Supply the complete intermediate chain.

Client server-trust configuration is independent: clients must trust the server's issuer and verify its hostname. The Rust `tls::client_config` API supports independent `CaMode::Provided` and `CaMode::System`, optional client PEM identity, and normal hostname verification. Future Android/desktop clients need equivalent settings.

CA trust never grants registration or account access automatically. A valid unregistered client certificate receives a protected-route denial. CN/subject fields and forwarded identity headers never determine account ownership.

## Operator usage

Initialize and provision while stopped, then use the running daemon's socket for changes. Replace UUID placeholders with IDs printed by earlier commands; client certificates are public PEM files, not private keys.

```sh
kdeconnect-cloud-relay init --state-dir ./state;
kdeconnect-cloud-relay admin --state-dir ./state --offline account-create personal;
kdeconnect-cloud-relay admin --state-dir ./state --offline device-register ACCOUNT_UUID kde-device-id Laptop ./client-fullchain.pem;
kdeconnect-cloud-relay serve;
```

In another terminal, as the service account:

```sh
kdeconnect-cloud-relay admin --state-dir ./state list;
kdeconnect-cloud-relay admin --state-dir ./state metrics;
kdeconnect-cloud-relay admin --state-dir ./state certificate-approve DEVICE_UUID ./replacement-client.pem;
kdeconnect-cloud-relay admin --state-dir ./state certificate-revoke OLD_SHA256_FINGERPRINT;
kdeconnect-cloud-relay admin --state-dir ./state device-revoke DEVICE_UUID;
kdeconnect-cloud-relay admin --state-dir ./state account-set-enabled ACCOUNT_UUID false;
kdeconnect-cloud-relay admin --state-dir ./state tls-reload;
```

Use `--help` on each command for arguments. Offline commands acquire the daemon's lifetime lock and fail while it runs. The state directory is `0700`; database and operator socket are `0600`. Do not directly modify a live database. A revoke acknowledgement follows database commit and generation/stream fencing. A slow outstanding socket write may delay admission to the exclusive mutation gate up to its 10-second deadline.

To rotate a client certificate, approve the new leaf against the same device, configure the endpoint to reconnect with it, then revoke the old fingerprint. Two active fingerprints permit overlap, not simultaneous authoritative sockets. Device revocation is permanent for that registration; account disable can be reversed.

`tls-reload` rereads the configured paths, validates replacement material, fences all sessions, and installs the verifier. Failure preserves the previous configuration. Environment values are fixed at process startup; changing paths or CA mode requires restart. If CRLs are configured, keep current lists for the verified issuance chains; unknown revocation status and expired CRLs fail closed.

## HTTPS and WebSocket usage

Public example with a private server root:

```sh
curl --cacert ./server-root.pem https://relay.example.com:8443/v1/info;
curl --cacert ./server-root.pem --cert ./client-fullchain.pem --key ./client-privkey.pem https://relay.example.com:8443/v1/devices;
```

`GET /v1/tunnel` requires a registered certificate and `Sec-WebSocket-Protocol: kdeconnect-relay.v1`. See [HTTP OpenAPI](docs/openapi.yaml) and [wire protocol](docs/protocol.md) for framing, controls, flow-credit rules, and errors. A stream is an ordered byte transport; WebSocket boundaries are not TLS-record or KDE-packet boundaries.

## Deployment and recovery

Use `compose.yaml` or `deploy/kdeconnect-cloud-relay.service` as examples. Export `RELAY_SERVER_NAME` for Compose, or set it in the systemd environment file. The example Compose service listens on container port 8443; configure external port mapping or TCP passthrough as appropriate. Mount a readable `tls/` directory owned for UID/GID 10001, with server chain, key, and client CA. Native deployments need a service account, a protected environment file, and local writable state. The systemd service has no privileged-port capability: keep its listener on 8443 and use port forwarding or TCP passthrough for public 443. Expose native TLS directly or use TCP passthrough; HTTP TLS termination/forwarded certificate headers are unsupported.

Run one instance per state directory. SQLite WAL requires local disk. Stop the relay before copying the entire state directory for backup; do not copy only a live main database file. On restore, reconcile all revocations issued since the backup before admitting network access. Startup restores metadata, never presence, queues, or streams. Keep clocks synchronized. For issuer compromise, revoke affected registrations, replace trust/identity/CRLs, then reload; issuer private keys stay outside this service.

Database errors deny protected work and fence connections. Readiness remains false until a bounded periodic reconciliation succeeds. Logs contain event codes and aggregate counts, not stream content, PEM, endpoint keys, or certificate identity headers. Operator metrics contain aggregate connections, streams, queue/reservation bytes, throttles, and authorization failures.

## License

GNU GPLv3.0 or later
