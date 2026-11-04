# Relay WebSocket Protocol V1

Status: experimental server contract. The HTTP contract is [openapi.yaml](openapi.yaml). Clients must implement inner peer TLS, certificate pinning, pairing and consent independently.

## Session

Upgrade `GET /v1/tunnel` over verified native TLS with a registered client certificate and `kdeconnect-relay.v1`. No compression is negotiated. Server sends `connection.ready` with `generation` and `deviceId`. UUIDs are canonical JSON strings; binary UUIDs are their 16 bytes. All JSON names below are case-sensitive; unknown input fields fail.

The daemon requires `RELAY_SERVER_NAME`, covered by the server certificate's DNS SAN, independently of client-CA mode. TLS requires matching SNI; missing or unknown names fail the handshake, including certificate-covered aliases not explicitly configured. HTTP requires exactly one matching Host, optionally with a numeric port 1..65535; an absolute URI authority must also match. Case is ignored, trailing dots are rejected, and forwarded headers confer no authority. Host validation runs on all routes and before WSS upgrade: malformed/missing/duplicate Host returns 400 `invalid_host`; a valid other name returns 421 `misdirected_request`. No connection generation or stream is created for a rejected upgrade.

One registration owns one connection generation. Replacement closes old incident streams and cancels the old socket. No old stream or data can resume. Account ownership and sender identity always come from TLS/registry state.

## Controls

Text messages contain one JSON object, <=16384 UTF-8 bytes. Request IDs are client-generated UUIDs, scoped to the current generation.

| Client `type` | Required fields | Behavior |
| --- | --- | --- |
| `stream.open` | `requestId`, `peerId`, `kind` (`packet` or `payload`) | Packet requires absent/null `parentId`; payload requires ready packet `parentId` with identical endpoints/generations |
| `stream.accept` | `requestId`, `streamId` | Only original recipient; offer must still be pending |
| `stream.reject` | `requestId`, `streamId` | Only original recipient, before readiness |
| `stream.close` | `requestId`, `streamId` | Either participant; cancels children |
| `stream.window` | `streamId`, `consumedBytes` unsigned integer | Cumulative received payload bytes consumed by the endpoint |

Server events:

| Server `type` | Fields |
| --- | --- |
| `connection.ready` | `generation`, `deviceId` |
| `stream.offered` | `streamId`, `peerId`, `kind`, `parentId`, `initiatorId` |
| `stream.result` | `requestId`, `streamId`, `state` (`offered` or `ready`), `initiatorId` |
| `stream.ready` | `streamId`, `peerId`, `initiatorId` |
| `stream.closed` | `streamId`, `reason` |
| `stream.credit` | `streamId`, `sendLimitBytes` unsigned integer |
| `request.ok` | `requestId` |
| `presence.changed` | `deviceId`, `online` |
| `error` | nullable `requestId`, `code`, `message` |

The original opener is inner-TLS initiator; the original recipient is responder. Simultaneous packet opens converge on the first offer and preserve these roles. The reverse open is not implicit acceptance. Offers expire in 30 seconds. Payload children also require recipient acceptance, and routing acceptance does not attest inner-TLS authentication or feature consent.

Retain at most 256 request outcomes per generation for five minutes. Identical retries return the original outcome snapshot, without recreating streams; a subsequent stream closure can make that snapshot historical. Conflicting request-ID reuse closes the connection. Overflow evicts the oldest entry. Request IDs are not durable delivery identifiers.

Example packet open and accept:

```json
{"type":"stream.open","requestId":"6bda2cf9-a801-45c6-9c81-0679cc2233e1","peerId":"6dca6f91-c403-4d44-9acd-a7cf2eac143d","kind":"packet"}
```

```json
{"type":"stream.accept","requestId":"9602e980-6279-47a1-9f3c-fbdab4c1baf1","streamId":"3d6f15cf-5c52-4520-9c2d-c9742b007a39"}
```

## Binary envelope

| Offset | Width | Value |
| --- | --- | --- |
| 0 | 1 | Version `1` |
| 1 | 1 | Data kind `1` |
| 2 | 16 | Stream UUID bytes |
| 18 | 4 | Big-endian unsigned payload length |
| 22 | declared length | Opaque stream bytes |

Length must be positive and exact; full reassembled message <=65536 bytes. No padding or trailing bytes. A WebSocket chunk can contain partial or multiple TLS records; endpoints adapt ordered bytes to their inner TLS implementation.

## Credits and scheduling

Each stream direction has separate cumulative received/written/consumed counters and a server-issued cumulative send limit. Start at zero and wait for `stream.ready` plus positive `stream.credit`. Send only bytes within the latest limit; received window updates never reset counters. A duplicate consumption value is harmless; decreasing, impossible, or overflowing values are protocol violations.

The implementation targets 16 KiB outstanding credit per direction, beneath the 256 KiB hard window, and grants in increments <=16 KiB. Send smaller chunks as needed; the 64 KiB envelope limit is not an unconditional send grant. Report consumption only after the endpoint has consumed bytes into its bounded stream adapter. The relay releases capacity only when both consumption and socket-write completion permit it. An early consumption message never frees writer-owned memory.

Aggregate reservation accounting includes unspent grants, buffered bytes, writer-owned frames, and written/unconsumed payload. Each connection has 1 MiB budget, including 64 KiB reserved for bounded controls. Payload reservations use at most 512 KiB. Headers and retired writer-owned frames remain accounted. Per-stream round-robin dispatch preserves order and avoids one stream monopolizing application queues. TCP loss can still delay the shared connection.

## Limits and closure

Packet streams: 9/device,45/account. Payload:2/device,10/account,one/pair. Combined:11/device,55/account. Pending offers count. Payloads require an existing parent; parent closure/expiry/revocation cancels children. No opaque content is persisted, decoded, broadcast, resumed, or automatically retried.

Device traffic bucket:1 MiB/s sustained,256 KiB burst. Controls:20/s,burst40; opens:5/s,burst10; replacements:1 per10 seconds,burst2. Heartbeat Ping/Pong flood protection:2/s,burst8. Exceeding protocol/rate limits closes the connection; normal unavailable/quota/conflict requests return bounded errors. Offline, inaccessible, unknown, and cross-account destinations all return the same `unavailable` error without revealing account membership. Wrong-owner control references use uniform `not_found` errors.

WebSocket ping interval30 seconds; no activity90 seconds closes. Offers30 seconds; unconsumed packet backlog30 seconds; payload no progress30 seconds and total lifetime120 seconds; socket writes10 seconds. A stalled physical socket can close its entire connection. Idle packet sessions without backlog remain available.

Unknown/not-ready/wrong-owner stream data, invalid credits, malformed JSON/envelopes, or stale-generation operations terminate the offending connection. Normal stream close affects only that stream and children. Reconnect refreshes directory and establishes fresh peer TLS; transport write success never confirms content application.

## Trust and privacy

The relay cannot verify encrypted MIME, purpose, image limits, feature consent, peer certificate pins, or parent TLS-session binding. Endpoints must implement those checks before using content. The relay sees IP addresses, routing IDs, sizes and timing. Logs and metrics exclude content and raw certificate identity material.
