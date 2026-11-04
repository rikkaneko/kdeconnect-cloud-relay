# Cloud Server Specification Plan

## Goal and release boundary

Let enrolled KDE Connect devices discover each other and exchange live clipboard text/images, explicitly shared text/URLs, notification text/icons, and media-player metadata/album art through a self-hosted server across networks. Notification replies/actions and media playback commands are not enabled by admitting their display metadata.

Each device independently establishes one persistent mTLS-authenticated WSS connection to the server, including when no peers are online. Control messages and multiple logical peer streams share that connection. This replaces the previous control-WSS-plus-per-peer-data-WSS proposal.

Each logical peer stream still carries an independent end-to-end TLS session between devices. Server-side mTLS authenticates access to infrastructure; KDE Connect pairing and feature consent authorize access to content.

V1 requires both sharing endpoints to be online and executing. It excludes iOS/iPadOS, durable clipboard history, offline queues, general file transfer, other image/attachment categories, arbitrary plugin tunneling, federation, cross-account sharing, and guaranteed background-mobile delivery. Android clipboard access may require foreground/manual action.


## Ownership and acceptance mapping

| Owner | Responsibility | Acceptance evidence |
| --- | --- | --- |
| Paul | Provisioning, discovery, consent, sharing, offline behavior | Android/desktop stories and live-only boundary |
| Bob | Certificate identity, account isolation, multiplexing, peer trust | Threat model and Qt/Android stream prototype |
| Alice | Server/CA/certificate setup, status, per-peer consent | Missing cert, expired cert, denied clipboard, offline peer, reconnect flows |
| Kay | mTLS termination, CA operations, limits, revocation, recovery | Single-node deployment and certificate lifecycle runbook |
| John | Contract, isolation, stream, device, and failure tests | Requirements mapped to runnable checks |
| Diana | Tradeoffs and human design sign-off | Approved implementation plan before code generation |

## Intended user flow

The endpoint steps describe the intended Android/desktop integration, not functionality already shipped in those clients.

1. Operator deploys the native TLS server with a required DNS name, a covering server certificate/key, local SQLite state, an account/device registry, and selected client-CA mode. `provided` is the default and requires an explicit CA bundle; `system` uses native-store CA certificates. CRLs are optional.
2. Outside KDE Connect, the operator generates a distinct cloud-authentication key pair for each device, obtains its client certificate from the CA, and registers the leaf certificate fingerprint against the account/device. The CA signs the request without needing the private key.
3. User configures the server URL and server trust where needed, then selects the existing `fullchain.pem` and matching `privkey.pem` on Android or desktop. Client validates and imports the pair into protected application storage. The key is never sent to the relay; no enrollment or certificate-issuance request is made by the client.
4. Client uses matching TLS SNI and HTTP Host, validates the server chain/hostname, presents its mTLS identity, and upgrades to WSS. The server checks the client chain, explicit clientAuth usage, certificate validity, configured CRLs where enabled, and active registry identity before granting directory or routing access.
5. Device maintains its own WSS connection without requiring an online peer. Discovery shows only active registrations in the same account; presence is not pairing or clipboard readiness.
6. User requests a peer session. Server authorizes and offers a logical stream to the recipient over its existing WSS. Recipient accepts according to local policy. No extra WSS connection per peer is opened.
7. Endpoints authenticate their KDE Connect certificates over the logical stream, preserve existing pins, and pair with human verification if not already paired.
8. User enables cloud clipboard send/receive per peer, default off. Android provides manual/foreground actions where the OS restricts clipboard access. URLs require an explicit open action.
9. Local registry revocation fences affected connections and incident streams before acknowledgement. CA CRLs are a separate handshake revocation mechanism, applied on startup/reload. Unpairing, fingerprint revocation, device revocation and account disable remain distinct operations.

## Components and trust boundaries

```text
Android A -- one mTLS WSS --> Relay <-- one mTLS WSS -- Desktop B
                               ^
                               |
                         one mTLS WSS
                               |
                           Desktop C

Logical A-B and A-C streams share A's WSS.
Each logical stream carries its own peer-to-peer TLS session.
```

- Server owns client-certificate authorization, directory visibility, presence, stream routing, and resource controls. It stores metadata, not clipboard plaintext or endpoint private keys.
- Outer TLS ends at the native Rust server. TLS termination with forwarded certificate identity is unsupported; optional TCP passthrough preserves native TLS. Inner peer TLS ends only at the devices. The relay observes routing IDs, sizes, timing, and IP addresses.
- Use separate cloud client-auth certificates/keys from existing self-signed KDE Connect peer identities. Issuing or rotating cloud credentials must not reset peer pairing.
- Provider authenticates peer identity before emitting `connectionReceived`. Registry entries and certificate subject display names alone are not peer identity proof.
- Desktop cloud links rank below LAN. Android needs equivalent preference rules. Do not duplicate-send to compensate for ambiguous delivery.
- Enforce incoming/outgoing cloud feature policy at endpoints before packet dispatch. Permit pairing/identity, text/image clipboard, explicit text/URL share, notification display metadata/icons, and media status/album art. Apply field-level restrictions: notification replies/actions/dismiss commands, playback commands, run commands, input control, SFTP, general files, and all other attachments remain outside V1.
- Preserve device-wide LAN capabilities; cloud restrictions need per-link enforcement. Certificate-authenticated access does not imply permission to execute every plugin.

## mTLS authentication and certificate lifecycle

mTLS is the authentication mechanism for WSS and protected HTTPS operations. V1 has no bearer-access-token, refresh-token, or enrollment-token tunnel authentication path.

| Material | Scope / proposed lifetime | Required handling |
| --- | --- | --- |
| Server TLS certificate | Relay hostname; issuer policy | Clients verify chain and hostname; no skip-verification mode |
| Client issuing CA | Operator-controlled trust domain | Use an existing CA workflow; protect issuer keys separately from relay runtime |
| Cloud client certificate | One registration, clientAuth EKU; CA/operator-defined lifetime | Manually issue and register the leaf fingerprint; import `fullchain.pem`; warn before expiry |
| Cloud private key | One device | Generate outside KDE Connect; import matching `privkey.pem` into protected application storage; never upload or log it |
| KDE Connect peer certificate/key | Existing pairing identity | Preserve independently of cloud-auth certificate lifecycle |

### Server identity and ingress domain

`RELAY_SERVER_NAME`, the server certificate chain and matching private key are required in both client-CA modes. CA mode controls trust for incoming client certificates; it does not provide a server identity. Initialization and offline administration do not require TLS environment configuration.

Configure one concrete ASCII DNS name, including punycode or `localhost` for development. Normalize case; reject IP literals, wildcard configuration values, URLs, ports, paths, whitespace, trailing dots and invalid/oversized DNS labels. The server leaf's DNS SAN must cover the configured name; an applicable wildcard SAN is valid, but CN-only identity is insufficient. Validate SAN coverage, chain ordering/signatures, validity, serverAuth usage and key match before startup or certificate replacement.

The TLS certificate resolver serves exactly the configured SNI name. Missing/wrong SNI fails the handshake, even if another certificate SAN covers that name. Every HTTP route, public info/health, fallback response and WSS upgrade requires exactly one matching Host, case-insensitively. A numeric port 1..65535 is allowed and need not match the internal listener port. Absolute-URI authority is checked independently; `Forwarded` and `X-Forwarded-Host` cannot override policy. Missing/malformed/duplicate Host returns 400 `invalid_host`; a valid other DNS name returns 421 `misdirected_request`, using the safe error envelope. Structurally invalid HTTP may fail in the HTTP parser first. Rejected upgrades create no registration generation or stream.

Health probes must supply matching SNI and Host. To connect to an IP, retain the configured name in the URL and use an address override such as curl `--resolve`. Setting Host alone on an IP URL does not supply TLS SNI.

### Runtime configuration

| Variable | Requirement / default |
| --- | --- |
| `RELAY_SERVER_NAME` | Required concrete DNS name covered by the server DNS SAN; no default |
| `RELAY_TLS_CERT_CHAIN_FILE` | Required leaf-first server PEM chain, followed by intermediates |
| `RELAY_TLS_PRIVATE_KEY_FILE` | Required matching unencrypted server PEM key |
| `RELAY_CLIENT_CA_MODE` | `provided` (default) or `system` |
| `RELAY_CLIENT_CA_FILE` | Required only in `provided` mode; forbidden in `system` mode |
| `RELAY_CLIENT_CRL_FILE` | Optional PEM CRL bundle; unset by default |
| `RELAY_BIND` | Numeric bind IP/port; default `127.0.0.1:8443` |
| `RELAY_STATE_DIR` | Local metadata directory; default `./state` |
| `RELAY_MAX_CONNECTIONS` | Default 256; range 1..4096, including upgraded WSS |
| `RELAY_MAX_HANDSHAKES` | Default 32; range 1..256 and no greater than connection limit |
| `RUST_LOG` | Tracing filter; default `info` |

### CA trust and intermediate chains

- `provided` builds a trust store only from the explicitly provided CA bundle. It never falls back to the system store. Accept root anchors and explicitly trusted intermediate CA anchors; trusting an intermediate authorizes its issuance subtree without requiring its parent root.
- `system` loads native-store CA certificates through `rustls-native-certs`, including supported `SSL_CERT_FILE`/`SSL_CERT_DIR` overrides. In a container this is the container's store. Reject simultaneous `RELAY_CLIENT_CA_FILE` configuration. Empty usable trust stores fail startup; malformed provided bundles fail startup/reload.
- Server and client leaves may be issued directly by a custom root or through intermediate CAs, including separate intermediates under the same root. Present the leaf first and necessary intermediates in issuer order; normally omit the root. An intermediate presented by a client is chain material, never an automatically trusted anchor. No AIA/issuer network fetch occurs.
- Endpoint trust for the server is independent of the relay's client-CA selection. A CA-trusted client still needs an active registered leaf fingerprint. Subjects/CNs and HTTP identity headers do not determine account membership.

### Optional CRLs and local revocation

`RELAY_CLIENT_CRL_FILE` contains one or more CA-signed PEM Certificate Revocation Lists. They identify certificates revoked before expiry and are checked during incoming client-certificate chain verification. With intermediates, supply current CRLs from the relevant issuers in the verified chain. These lists do not control how endpoints check the relay's server certificate.

When configured, malformed, empty, future-dated or expired CRL bundles fail startup/reload. Revoked certificates, expired revocation information, or unknown required chain revocation status fail verification. CRLs are optional: leaving the setting unset disables CA-CRL checking but preserves chain/usage/validity checks and registry authorization/revocation.

The relay reads CA/CRL/certificate files at startup and explicit local `tls-reload`; it does not automatically download or watch CRLs. Replacing a file alone does not apply it. Successful reload validates all replacement material, fences current sessions, and installs the new verifier; failure preserves the previous configuration and sessions. Changing an environment value, including domain, CA mode or configured path, requires restart. Native trust-store changes also require reload/restart.

Local fingerprint/device/account revocation is separate: it updates SQLite and fences the exact affected live generations before reporting success, without requiring a CA CRL update. Conversely, adding a fingerprint to the registry does not override a CA revocation. Active registry/expiry rechecks are not automatic CRL-file rereads.

### Manual provisioning and PEM import

Certificate issuance is an external operator/CA responsibility. KDE Connect does not generate cloud-authentication keys, submit CSRs, contact a CA, or renew certificates automatically. There is no client enrollment API or bootstrap token flow in V1.

- `fullchain.pem` contains the client leaf certificate first, followed by intermediate certificates in issuer order. The root is a separate trust anchor and normally is not included in the presented chain. The certificate must permit TLS client authentication.
- `privkey.pem` contains the matching private key. The initial V1 import contract supports unencrypted PEM keys in algorithms supported by the selected Android/desktop TLS backends. Reject encrypted keys with a clear unsupported-format message; passphrase prompts and encrypted-PEM support are deferred.
- Configure relay server trust independently: the client certificate chain is not the server's CA trust bundle. Verify the relay hostname and server chain without disabling verification.
- Before saving, bound input sizes, parse PEM, check certificate/key match, chain ordering/signatures, validity dates, and client-authentication usage. Present actionable errors without echoing file contents. A locally valid pair may still be rejected by the server's trust/registration policy.
- Import through the platform file picker into application-private storage; do not depend on Android document-provider paths or the original files remaining present. Protect imported material with OS access controls and credential facilities supported by the TLS backend. Do not assume an imported PEM key becomes hardware-backed or non-exportable. Exclude private-key copies from ordinary backups, telemetry, and logs.
- Replace the stored pair atomically only after local validation succeeds; invalid imports must preserve the previous usable configuration. Keep the currently active identity until the user applies the replacement. The app never deletes or modifies the original selected files.

Prototype PEM import, protected storage, and TLS key loading on Android and each desktop backend before freezing supported key formats. External CA tooling and its signing-key storage remain outside the client and relay implementation.

Verify every presented client certificate against the selected trust anchors, validity, intended usage, proof of possession and configured CRLs. Certificate-free TLS is allowed for public routes only, with matching SNI/Host still required. Protected HTTP/WSS authorization resolves the verified leaf SHA-256 fingerprint to an active registration/account. A CA-signed but unregistered certificate is denied. Do not trust caller-supplied account IDs, sender IDs, or an unchecked certificate CN as authorization.

A registration permits at most two active approved certificate fingerprints during renewal, but at most one active WSS. Issuing a new certificate does not automatically disable a lost/stolen one: explicitly revoke the old fingerprint. Reject globally duplicate fingerprints and duplicate active KDE device IDs within an account; replacing peer identity requires separate trust handling.

Local certificate/registration/account revocation commits and fences affected connections/streams before acknowledgement. Obtaining the exclusive transition gate can wait for an existing socket write, bounded by its 10-second deadline. Active authorization is rechecked periodically with an independent 30-second fail-closed watchdog, including idle connections; dependency failure denies protected work, fences sessions and makes readiness false until reconciliation succeeds. Certificate expiry and the 24-hour maximum connection lifetime have independent cancellation. TLS resumption and early data are disabled in this implementation.

Display certificate expiry in settings and warn before it (initial warning target: 14 days). Renewal is manual: operator obtains a replacement pair, approves/registers its fingerprint against the existing device, and the user imports/applies it before expiry. Stop retrying an expired/revoked identity until credentials or registration are corrected; show a recoverable action-required state. V1 certificate rotation establishes a new mTLS connection, fences the old one, closes its logical streams, and recreates peer TLS sessions. Brief interruption is expected; no transparent stream migration or dual-connection drain is promised.

Use overlapping trust anchors for rollover, synchronized clocks, current CRLs where enabled, and the documented emergency issuer-compromise recovery procedure. Relay environment configuration names protected server-key files; endpoint and issuing-CA private keys never belong on the relay. Imported endpoint keys remain in protected client storage.

## Implemented experimental HTTPS and WSS interface

Use `/v1` and the linked OpenAPI/wire contracts: UUID identifiers, bounded input, strict unknown-field rejection and safe errors are implemented. Protected HTTPS requests may use short-lived mTLS connections in addition to the single persistent WSS. Contracts remain experimental pending actual Android/desktop integration.

| Operation | Authentication | Required behavior |
| --- | --- | --- |
| `GET /v1/info` | Public | Public protocol versions and limits, no tenant information |
| `GET /v1/devices` | Registered client certificate | Paginated account-only candidates and leased presence |
| `PATCH /v1/devices/me` | Registered client certificate | Display name only, 1..128 UTF-8 bytes without control characters; cannot change ownership or trusted identity |
| `GET /v1/tunnel` | Registered client certificate | WSS upgrade using versioned `kdeconnect-relay.v1` subprotocol; one active connection per registration |
| `DELETE /v1/devices/me` | Registered client certificate | Idempotent self-revocation; repeat allowed for an already-revoked registration, but a revoked old credential cannot delete an active renewed device |
| `GET /health/live`, `GET /health/ready` | Public, matching SNI/Host | Minimal status; readiness fails when authorization metadata is unavailable |

Account creation, certificate fingerprint registration, and revoking other devices are local operator operations in V1. Key generation, CSR/signing, and renewal happen through external CA tooling; neither the client nor relay exposes an issuance/renewal API. Client certificates do not grant operator privileges.

TLS rejection happens before a usable HTTP/WSS session. Application errors use `code`, `message`, and `requestId`; malformed Host uses 400 and domain mismatch 421 before authorization or upgrade. Offline, inaccessible, unknown and cross-account stream destinations return the same `unavailable` error; wrong-owner/inaccessible control stream references use uniform `not_found` errors. Never include submitted key material or content in errors.

## One connection per device and multiplexed streams

This is application-level multiplexing over WebSocket; WebSocket itself does not supply independent peer byte streams. Specify the binary envelope and state machine separately from OpenAPI.

1. After mTLS and upgrade, server assigns a connection generation. Bind it to the authenticated registration; clients cannot choose their sender/account identity.
2. A device can stay connected with zero active peer streams. Directory/presence operations and heartbeats continue independently.
3. A `stream.open` control request names the destination registration and a request ID. Server checks same-account active participants, limits, and local recipient acceptance via `stream.offered`.
4. Server allocates an unguessable UUID stream ID, chooses roles atomically, and binds it to exact registration/connection-generation pairs. One packet stream per unordered device pair; simultaneous opens converge while preserving original initiator/recipient roles and explicit acceptance. Payload children require a ready packet parent with the same endpoints/generations. Endpoints, not the opaque relay, must establish parent authentication/consent. Cache at most 256 request outcomes per generation for five minutes; identical retries return the original outcome snapshot, possibly historical after closure, and conflicting reuse closes the connection.
5. Recipient sends `stream.accept` or `stream.reject`; both endpoints receive `stream.ready` only after acceptance. Offers expire in 30 seconds. Routing acceptance does not attest peer TLS authentication or feature consent.
6. Binary data messages have a 22-byte header: version u8 (`1`), kind u8 (`1`), stream UUID (16 bytes), and big-endian payload length u32, followed by exactly that many positive-length opaque bytes. The full message is at most 64 KiB. Server derives the destination from its authorized stream table and rejects unknown, closed, not-ready, stale-generation, wrong-owner or cross-account data.
7. Extract data into the stream's ordered byte adapter; feed that adapter into an independent peer TLS engine. A WebSocket message is a chunk, not necessarily one TLS record or one KDE packet.
8. Authenticate encrypted peer identity and certificate pins before exposing `CloudDeviceLink`. Bind the inner authenticated exchange to stream ID, endpoint identities, roles, and protocol version. Outer mTLS cannot replace pairing.
9. `stream.close` closes only that logical stream; other streams and the device WSS remain usable. Protocol-wide violations or device revocation close the connection and all incident streams.

Use separate control message schemas and a strict binary envelope schema with bounded parsing before allocation. No compression. WSS client implementations follow standard masking/framing rules; do not depend on nonstandard fragmentation behavior.

Each direction uses cumulative consumed-byte updates and server-issued cumulative send limits. Current grants target 16 KiB outstanding credit per direction beneath a 256 KiB hard window. Duplicate consumption is harmless; decreasing/impossible counters, overflow or excess data close the offending connection. Account for unspent grants, queued/writer-owned frames and written/unconsumed payload; release only as both consumption and write completion permit. Use fair per-stream dispatch, a 1 MiB aggregate connection budget, 64 KiB control reservation and at most 512 KiB payload reservations. Fixed TLS/WebSocket buffers and task overhead are additional bounded process memory, not queue counters. A stalled stream or socket closes under the documented deadlines rather than allowing unbounded queues.

One TCP connection still has transport-level head-of-line blocking: packet loss or a large write can delay multiple streams. Small chunks and fair scheduling reduce application queue contention, not TCP loss coupling. This is the selected V1 tradeoff for text and bounded image payloads; small chunks, control reservation, and fair scheduling are mandatory. Re-evaluate transport isolation before large-file support.

No server-side broadcast of shared TLS ciphertext: TLS keys/session state differ per peer. Sending clipboard content to two peers creates two peer-encrypted streams, multiplexed through one physical WSS.

## Reconnect, replacement, and delivery semantics

At most one authenticated WSS generation owns a registration. An authorized replacement atomically fences the old generation, closes its streams, and prevents its delayed callbacks/frames from affecting the replacement. Rate-limit replacement attempts. Certificate overlap permits renewal, not concurrent authoritative sockets.

A WSS disconnect invalidates every incident logical stream at both endpoints. Other devices' unrelated streams remain intact. The disconnected device reconnects with bounded backoff/jitter, refreshes directory state, opens new streams, and performs fresh peer TLS handshakes. No stream/session byte replay, migration, or clipboard action retry is automatic.

Control events are hints scoped to the live generation. Refresh directory after reconnect; old stream IDs are never resumed. This removes the previous optional REST session-inspection requirement.

Transport write success is not confirmation that the peer applied clipboard content. No exactly-once or offline-delivery guarantee exists. If B is offline, A's WSS stays connected and a request to B returns explicit unavailable status; the server does not retain content for B.

## Clipboard and capability behavior

- Preserve existing text packet formats. Proposed limits are 256 KiB decoded UTF-8 text and 512 KiB complete decrypted JSON packet. Both apply; escaping can exceed the packet limit. Reject rather than truncate.
- Per-peer cloud send/receive consent defaults off. Respect password-manager hints, while explaining they cannot identify every secret.
- Suppress automatic application of reconnect snapshots on the cloud path without changing LAN behavior; explicit send is the recovery action.
- Suppress rebroadcast of remotely applied changes; test three-device fan-out, LAN/cloud handover, and OS clipboard-sharing interactions.
- No global latest clipboard is promised. Live arrivals follow a documented local policy; no durable clock-based conflict resolution is introduced.
- Android focus loss, denied clipboard access, Doze, process death, and service restrictions must have explicit recoverable UI states. An active server lease does not prove clipboard execution readiness.
- Text/URL sharing needs explicit receiver action. Only the three image purposes below may use payload streams. General files, clipboard file-URL entries, MMS/SMS attachments, contact photos, and arbitrary inline base64 blobs remain excluded; validate fields rather than only checking for a payload.

## Small image payloads

Only clipboard images, notification icons, and media album art are admitted in V1. Payload support does not enable general file sharing or every action in the related plugins.

| Purpose | Existing packet context | Proposed per-item cap | Receive behavior |
| --- | --- | --- | --- |
| Clipboard image | `kdeconnect.clipboard.file`, restricted to validated image content | 4 MiB | Apply decoded image MIME content only after complete validation and consent; preserve current clipboard on failure |
| Notification icon | `kdeconnect.notification` with its associated icon descriptor | 256 KiB | Render notification text immediately; missing/rejected icon uses a placeholder |
| Media album art | `kdeconnect.mpris` artwork response bound to requested player/art identifier | 1 MiB | Render player metadata immediately; missing/rejected art uses a placeholder |

PNG and JPEG static images are the initial formats. Sender may convert supported local source images into these formats before transfer; measure the final encoded bytes. Unknown-length/infinite payloads, SVG, animated images, unsupported formats, and arbitrary files are rejected. Enforce the lower of cloud limits and local device/plugin limits. Do not raise limits automatically or silently truncate; a sender may explicitly resize/re-encode and validate again.

### Live transfer protocol and client integration

1. Exchange the normal feature metadata over the authenticated peer packet stream. The cloud transport adds an encrypted descriptor containing a unique transfer ID, parent-session binding, allowed purpose, declared MIME, exact encoded length, SHA-256 digest, and feature correlation (clipboard revision, notification ID, or player/art request).
2. Receiver admits a transfer only after parent peer authentication, feature-specific consent, packet/field allowlisting, size checks, and current feature correlation. Reject unsolicited album art and detached/reused transfers. Notification/media queries allow only list/status/art fields; they do not enable reply/action/dismiss or playback commands.
3. Create a payload child stream over the same device WSS connections. Count its slot at both endpoints and enforce one active payload per peer pair and two per device. No additional physical WSS, HTTP download endpoint, or object-storage service is needed.
4. Each payload stream establishes independent end-to-end peer TLS, verifies the same pinned peer identities, and authenticates a transfer header binding it to the specific parent TLS session and encrypted descriptor. Specify a reviewed session-binding mechanism during the prototype; device IDs or an outer stream ID alone are insufficient. The server authorizes child ownership/generation and parent membership, but cannot inspect encrypted MIME, purpose, digest, or content.
5. Stream bounded chunks into an application-private client temporary file, with backpressure and a running byte count/hash. Reject zero/unknown/over-cap advertised length before transfer and abort if actual bytes exceed declared length or the hard cap. Require exact completion and digest match; a sender digest checks transfer consistency, not whether image content is safe.
6. Validate actual format, dimensions, static-image constraints, and decoded-size bounds before applying content. Proposed limits: 16 megapixels, 8192 pixels per axis, and 64 MiB pixel output. Decoder working memory and processing time need separate limits; honor image orientation and use checked size arithmetic. Reject malformed or misleading data without invoking arbitrary format handlers.
7. Reconstruct the bounded payload input expected by existing plugin transfer jobs only through a completion path that enforces validation before rendering/application. Clipboard images become image MIME data, not a generic file URL. Ignore untrusted filenames for paths and use generated private names.
8. Closing/revoking/replacing a parent session cancels every child. Cancel superseded clipboard revisions, closed-notification icon requests, and stale player/art requests; late completion must not overwrite newer state. Partial files are deleted on rejection, mismatch, timeout, disconnect, and cancellation. No automatic resume/replay.
9. Do not fetch received album-art URLs or arbitrary image URLs on the receiver as a fallback. Treat artwork identifiers as correlation values, not trusted locations. Sender resolves only its own current media artwork; notification/clipboard sources are local application content.

Notification display/icons and media status/art require separate per-peer feature consent, default off. Failure to transfer an optional icon/art must not block text metadata or disconnect the peer. Repeated abuse may close a stream/connection under the documented rate policy.

### Resource and storage policy

Encoded item caps do not increase the existing 64 KiB WSS envelope, 256 KiB stream buffer, or 1 MiB aggregate queued-byte limits. Chunk larger items; never buffer an entire image in relay memory. Fair scheduling reserves capacity for control and clipboard text; one stalled image transfer cannot monopolize the queue.

The relay enforces 30 seconds without payload-stream progress and 120 seconds total stream lifetime. Future endpoints must also bound image processing and temporary ownership. Client temporary payload bytes and image caches share a proposed 32 MiB aggregate disk budget; reserve declared space before admission, clean partials before new admissions, and evict completed artwork/icon caches by bounded LRU. No clipboard image history is kept; release temporary clipboard staging after the platform assumes ownership. Any platform-required backing files need explicit bounded ownership/lifetime cleanup.

No server payload persistence, offline delivery, thumbnails in logs, or arbitrary inline-base64 transport is added. A malicious endpoint's claimed purpose cannot be semantically checked by the opaque relay; receiving-client validation is mandatory.

## Server resource limits and deployment

The server implementation uses one Rust relay instance and local SQLite metadata, replacing the original FastAPI/Pydantic and PostgreSQL candidates. Native TLS replaces the gateway identity-header boundary. No Redis or multi-node coordination in V1.

Server limits below are implemented defaults; rows marked endpoint remain proposed client requirements.

| Limit | Default / scope | Behavior |
| --- | --- | --- |
| Devices per account | 10 | Reject over-quota registration |
| Active WSS per registration | 1 | Fence old generation on authenticated replacement |
| Control message | 16 KiB | Reject before unbounded allocation |
| Binary data envelope | 64 KiB including header | Bound reassembled WebSocket message size; split stream bytes |
| Decrypted JSON plugin packet | 512 KiB, endpoint | Proposed endpoint limit before JSON parsing; relay cannot inspect it |
| Stream window | 256 KiB hard maximum per direction | Current outstanding credit target/grant increment <=16 KiB |
| Aggregate queued bytes per connection | 1 MiB | Limit aggregate streams independently of individual limits |
| Peer packet streams per device/account | 9 / 45 | Bound full-mesh fan-out for ten-device default |
| Payload streams per device/account | 2 / 10 | One per peer pair; count each active transfer at both endpoints |
| All streams per device/account | 11 / 55 | Enforce aggregate and per-kind limits together |
| Clipboard image / notification icon / album art | 4 MiB / 256 KiB / 1 MiB, endpoint | Proposed encoded item caps; not semantically enforceable by the opaque relay |
| Decoded image | 16 megapixels, 8192 per axis, 64 MiB pixel output, endpoint | Proposed decoder working-memory/time and output bounds |
| Relay rate per device | 1 MiB/s sustained, 256 KiB burst | Reject excess traffic under the wire policy |
| Heartbeat / presence expiry | 30 / 90 seconds | Expire stale presence |
| Authorization lease | At most 30 seconds | Independent watchdog includes idle sockets; local revocation fences before acknowledgement |
| Connection / TLS handshake admission | 256 / 32 concurrent | Validated environment limits; upgraded WSS retains its admission slot |
| Control / open / replacement buckets | 20/s burst 40 / 5/s burst 10 / 1 per 10s burst 2 | Bound control work, stream creation and generation churn |
| Stream / socket deadlines | Offer 30s; stalled backlog/payload 30s; payload lifetime 120s; socket write 10s | Cancel stalled work; consumed idle packet sessions remain usable |
| Maximum connection lifetime | 24 hours or certificate expiry, whichever is earlier | Independent cancellation even during gate contention |

Bounded control/data channels and admission protect global memory/work. Measure defaults under deployment conditions; queue counters are not peak RSS or a WAN delivery guarantee.

Expose WSS on 443 using native TLS on an unprivileged listener with port mapping or TCP passthrough. The implemented server derives identity directly from verified TLS state and never accepts certificate identity headers. Public info/health routes allow missing client certificates; protected routes require registered identity. Provided-only client-CA trust is the default; explicit system trust and configured intermediate anchors are supported. A future TLS-terminating gateway mode would need its own protected identity boundary and is not implemented.

Configure WebSocket upgrade and idle timeout beyond heartbeat. No public inbound KDE Connect LAN ports are needed. Run unprivileged, close streams on shutdown, and fail closed when authorization dependencies are unavailable.

Production target is Linux; development verification uses macOS. Operator CLI commands use an owner-only Unix socket while running. Offline initialization/administration must acquire the same lifetime lock. State directory mode is 0700, database/socket 0600. SQLite uses local disk, WAL, FULL synchronization and foreign keys. Stop before copying the entire metadata directory; restore offline and reconcile later revocations before exposing service. Deployment examples provide Docker/Compose and systemd configuration, but container execution remains unverified.

Persist account/device metadata, approved certificate fingerprints/expiry, revocation, and safe audit records. Keep presence, generations, stream maps, and buffers ephemeral. No endpoint or issuing-CA private keys belong in the relay database. Backups need restricted access and a revocation reconciliation policy before restored service becomes available.

Logs/traces/metrics must exclude private keys, content, URL bodies, decrypted packets, and raw certificate identity headers. Monitor connections, streams, queued bytes, authorization failures, expiry/renewal, throttling, and disconnects. Routing metadata remains visible to the operator.

V1 relays image bytes live and stores no payload objects on the server. Client-only bounded temporary files/caches follow the Resource and storage policy above. Future persistent server-side binary transfers require client-encrypted S3-compatible storage with official clients, quotas, expiry, integrity, cancellation, and cleanup.

## Primary protocol references

- [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html): WebSocket transport and client authentication; peer-stream multiplexing is our application protocol.
- [Rustls server certificate resolver](https://docs.rs/rustls/latest/rustls/server/struct.ResolvesServerCertUsingSni.html): native SNI selection and certificate-name validation.
- [Rustls client certificate verifier](https://docs.rs/rustls/latest/rustls/server/struct.WebPkiClientVerifier.html): incoming client-chain trust and optional CRLs.
