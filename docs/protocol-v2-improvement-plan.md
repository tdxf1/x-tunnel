# x-tunnel Protocol v2 Improvement Plan

Status: design proposal.

This document proposes a protocol v2 for x-tunnel. The goal is to improve
security, compatibility, observability, and long-term protocol hygiene while
keeping the current WS/WSS + smux architecture recognizable and migratable.

This is not a plan for impersonating a third-party protocol or bypassing a
specific network enforcement system. The design focuses on reducing accidental
metadata leakage, removing long-lived secrets from handshake-visible fields,
making negotiation explicit, and giving the implementation a clean path for
future extensions.

## 1. Executive Summary

The current protocol has a solid base:

- WebSocket/WSS transport.
- smux multiplexing.
- A compact stream open header.
- A Hello control stream with capability negotiation.
- Negotiated TCP/UDP open status and structured open error codes.

The biggest remaining protocol issues are not the 4-byte smux open header. They
are the fields exposed before the encrypted tunnel is established:

- `client_id` and `channel_id` are placed in the WebSocket URL query.
- The bearer token is placed in `Sec-WebSocket-Protocol`.
- The internal Hello frame contains a fixed `XTUN` magic and only a narrow
  capability payload.
- Authentication is not bound to a channel nonce, the server endpoint, or a
  freshness window.

Protocol v2 should:

- Keep `wss://` as the production transport and treat `ws://` as local testing
  unless explicitly allowed.
- Move channel metadata from WebSocket URL query into an encrypted in-band
  `ChannelInit` frame.
- Replace bearer-token subprotocol authentication with a nonce-based proof sent
  after WebSocket upgrade.
- Keep the existing smux TCP/UDP/Ping stream header for compatibility, but add a
  negotiated v2 stream open frame for peers that support it.
- Convert protocol extension fields to length-delimited TLV records.
- Make migration incremental: v1 peers keep working; v2 clients can downgrade
  only when policy allows.

## 2. Design Goals

### 2.1 Primary Goals

- Minimize handshake-visible metadata.
- Keep credentials out of URL, access logs, and WebSocket subprotocol fields.
- Preserve backward compatibility during rollout.
- Keep per-stream overhead small.
- Make feature negotiation explicit and testable.
- Keep protocol errors structured enough for SOCKS5 and HTTP proxy mappings.
- Avoid coupling the project to the wire shape of mainstream proxy protocols.

### 2.2 Non-Goals

- Do not imitate browser, QUIC, Shadowsocks, Trojan, VMess, VLESS, or Hysteria
  wire formats.
- Do not add protocol morphing rules targeted at a specific censor or firewall.
- Do not rely on security through undocumented magic bytes.
- Do not redesign the whole data path away from WebSocket + smux in this phase.
- Do not break v1 peers without an explicit compatibility window.

## 3. Current Protocol Snapshot

### 3.1 Transport

The client connects with:

```text
ws://server/path?client_id=<uuid>&channel_id=<n>
wss://server/path?client_id=<uuid>&channel_id=<n>
```

When token auth is enabled, the token is sent as a WebSocket subprotocol:

```text
Sec-WebSocket-Protocol: <token>
```

### 3.2 Session Model

- Each client process has a `client_id`.
- Each WebSocket channel has a `channel_id`.
- The server groups channels by `client_id`.
- Each WebSocket channel carries one smux session.

### 3.3 Stream Open Header

Every smux stream starts with:

```text
kind (u8) | ip_strategy (u8) | target_len (BE16) | target bytes
```

Current stream kinds:

| Value | Name | Meaning |
| --- | --- | --- |
| `1` | TCP | Open TCP stream. |
| `2` | UDP | Open UDP relay stream. |
| `3` | Ping | RTT probe. |
| `4` | Hello | Protocol negotiation. |

### 3.4 Hello Frame

The v1 Hello payload is:

```text
magic "XTUN" | version (u8) | status (u8) | msg_len (BE16) | capabilities (BE32) | message
```

### 3.5 Status Frames

When negotiated, TCP/UDP streams begin with:

```text
status (u8) | msg_len (BE16) | message
```

or, with structured error codes:

```text
status (u8) | code (u8) | msg_len (BE16) | message
```

## 4. Risk Analysis

### 4.1 Metadata Exposure

The current URL query carries stable channel metadata. This is useful for
server-side grouping before smux starts, but it creates avoidable exposure in:

- reverse proxy access logs,
- server HTTP logs,
- load balancer logs,
- debugging traces,
- copied URLs.

### 4.2 Credential Placement

`Sec-WebSocket-Protocol` is designed for protocol-name negotiation, not long
lived bearer credentials. Using it for a token is simple, but it increases the
chance that credentials are captured by generic HTTP/WebSocket logging.

### 4.3 Negotiation Shape

The v1 Hello frame is functional but rigid:

- capabilities are only 32 bits,
- message is the only variable-length field,
- no nonce,
- no proof,
- no explicit session/channel metadata,
- no room for structured extension records without changing the frame again.

### 4.4 Downgrade Ambiguity

The current client treats EOF, unexpected EOF, or timeout during Hello as legacy
server behavior. That is good for compatibility, but v2 needs a policy switch so
operators can forbid downgrade when they require in-band auth and metadata
privacy.

## 5. Protocol v2 Overview

Protocol v2 introduces three concepts:

1. **Clean WebSocket handshake**

   The WebSocket URL does not include `client_id`, `channel_id`, or credentials.
   The client may still use the configured path, but the path is no longer a
   protocol metadata carrier.

2. **In-band ChannelInit frame**

   Immediately after smux session creation, the client opens a control stream
   and sends a v2 `ChannelInit` frame containing session metadata, capabilities,
   freshness data, and an authentication proof.

   "In-band" means "inside the WebSocket data stream." It is confidential only
   when the transport is `wss://`. With `ws://`, it still avoids URL/header logs
   but does not provide network-layer confidentiality.

3. **Length-delimited extension records**

   v2 frames use a small fixed header plus TLV extension records. This lets the
   protocol add fields without consuming global bytes for every future feature.

## 6. Transport Rules

### 6.1 Production Transport

Production deployments should use `wss://`.

`ws://` remains supported for local tests and trusted private networks, but v2
should add an explicit flag such as:

```text
-allow-plain-ws
```

Without that flag, client startup should reject `ws://` when v2 strict mode is
enabled.

### 6.2 WebSocket Request Shape

The v2 default request should be:

```text
GET /configured-path HTTP/1.1
Host: example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: ...
Sec-WebSocket-Version: 13
```

No protocol-required query parameters:

```text
client_id: removed from URL
channel_id: removed from URL
token: removed from Sec-WebSocket-Protocol
```

### 6.3 Subprotocol Usage

Avoid placing secrets in `Sec-WebSocket-Protocol`.

Two acceptable modes:

- omit subprotocol entirely;
- send a non-secret protocol label, for example `x-tunnel-v2`.

The non-secret label is optional. It can help server routing, but it should not
be required for authentication.

## 7. v2 Control Stream

### 7.1 Stream Kind

Keep v1 `streamKindHello = 4` for compatibility. The payload determines whether
the peer is speaking v1 or v2.

The client opens a smux stream and writes the existing v1 open header:

```text
kind=4 | ip_strategy=0 | target_len=0
```

Then it writes a v2 frame.

New servers can distinguish v1 and v2 control payloads by peeking at the first
bytes after the smux open header:

- v1 begins with ASCII `XTUN`;
- v2 begins with a known `frame_type` and `version=2`.

Old v1 servers will not understand a v2 control payload. Clients that run in a
fallback-capable mode should treat that as a failed v2 probe and retry with a
fresh v1 channel. Do not attempt to reuse a partially negotiated control stream
after a failed v2 probe.

### 7.2 v2 Frame Header

Use this common frame header for control frames:

```text
frame_type (u8)
version (u8)
flags (u16 BE)
body_len (u32 BE)
body bytes
```

Frame types:

| Value | Name | Direction |
| --- | --- | --- |
| `1` | ChannelInit | client -> server |
| `2` | ChannelAccept | server -> client |
| `3` | ChannelReject | server -> client |
| `4` | KeepaliveHint | either |
| `5` | SessionUpdate | either |

The body is a sequence of TLV records.

### 7.3 TLV Record Format

```text
type (u16 BE) | length (u16 BE) | value bytes
```

Rules:

- Unknown critical records reject the frame.
- Unknown non-critical records are ignored.
- Criticality is encoded in the high bit of `type`.
- `length` is the number of value bytes.
- Duplicate singleton records reject the frame.
- Total frame size is capped by config, default `16 KiB`.

Record type layout:

```text
0x0001..0x3fff: non-critical standard records
0x4000..0x7fff: non-critical private records
0x8001..0xbfff: critical standard records
0xc000..0xffff: critical private records
```

## 8. ChannelInit Body

The client sends `ChannelInit` immediately after smux session creation.

Required records:

| Type | Name | Value |
| --- | --- | --- |
| `0x8001` | SessionID | 16 random bytes or UUID bytes |
| `0x8002` | ChannelID | uint32 BE, 1-based |
| `0x8003` | ClientNonce | 32 random bytes |
| `0x8004` | Timestamp | int64 BE Unix seconds |
| `0x8005` | Capabilities | uint64 BE |
| `0x8006` | AuthProof | proof bytes |

Optional records:

| Type | Name | Value |
| --- | --- | --- |
| `0x0007` | ClientName | short UTF-8 label for logs |
| `0x0008` | BuildInfo | short UTF-8 version/build string |
| `0x0009` | DesiredChannelCount | uint16 BE |
| `0x000a` | TransportHints | bitset |
| `0x000b` | Padding | random bytes, ignored |

### 8.1 SessionID

`SessionID` replaces URL-level `client_id`.

It should be generated once per client process. It must be random enough that it
does not reveal host identity. It should not encode machine names, user names,
MAC addresses, timestamps, or stable hardware IDs.

### 8.2 ChannelID

`ChannelID` replaces URL-level `channel_id`.

The server groups channels after successful authentication. If a duplicate
`SessionID + ChannelID` arrives, the server may replace the old channel as v1
does today.

### 8.3 Timestamp

The timestamp gives the server a freshness window for authentication. Default
allowed skew:

```text
300 seconds
```

Strict deployments can lower it. Local tests can disable it.

### 8.4 AuthProof

For pre-shared-token deployments, use HMAC-SHA256:

```text
auth_key = HKDF-SHA256(token, salt="x-tunnel-v2-auth", info=server_name)
proof = HMAC-SHA256(auth_key, transcript)
```

`transcript` includes:

```text
frame_type
version
flags
SessionID
ChannelID
ClientNonce
Timestamp
Capabilities
configured server name
configured websocket path
```

Properties:

- the token itself is never sent;
- proof is bound to freshness data;
- proof is bound to expected server name and path;
- replay is limited by timestamp and nonce cache.

Server nonce-cache behavior:

- cache `(SessionID, ChannelID, ClientNonce)` for at least the timestamp window;
- reject exact repeats;
- bound cache memory with LRU eviction;
- count nonce replays in metrics.

### 8.5 mTLS Mode

When mTLS is enabled, `AuthProof` can be optional if the server policy allows
certificate-only auth.

Recommended policy:

- `auth=token`: require HMAC proof;
- `auth=mtls`: require verified client certificate;
- `auth=token+mtls`: require both.

### 8.6 Pre-Auth Resource Controls

Moving authentication from the WebSocket handshake into the smux control stream
creates a short unauthenticated resource window. The server must bound it.

Recommended controls:

- set a short pre-auth deadline, default `5s`;
- cap unauthenticated WebSocket connections separately from authenticated
  sessions;
- cap unauthenticated smux streams to the single control stream;
- close the channel if the first stream is not a valid v1 Hello or v2
  ChannelInit;
- do not create or replace a `SessionID + ChannelID` entry until authentication
  succeeds;
- count pre-auth timeouts and malformed pre-auth streams in metrics.

## 9. ChannelAccept Body

The server replies with `ChannelAccept` after authentication and negotiation.

Required records:

| Type | Name | Value |
| --- | --- | --- |
| `0x8005` | Capabilities | uint64 BE negotiated capabilities |
| `0x8010` | ServerNonce | 32 random bytes |
| `0x8011` | ServerTime | int64 BE Unix seconds |

Optional records:

| Type | Name | Value |
| --- | --- | --- |
| `0x0012` | MaxFrameSize | uint32 BE |
| `0x0013` | MaxStreams | uint32 BE |
| `0x0014` | IdleTimeoutMs | uint32 BE |
| `0x0015` | Message | UTF-8 diagnostic |
| `0x0016` | Padding | random bytes, ignored |

The client must use the negotiated capability intersection. Required
capabilities missing from the response fail the channel.

## 10. ChannelReject Body

The server replies with `ChannelReject` when it understood v2 but cannot accept
the channel.

Required records:

| Type | Name | Value |
| --- | --- | --- |
| `0x8020` | RejectCode | uint16 BE |

Optional records:

| Type | Name | Value |
| --- | --- | --- |
| `0x0021` | Message | UTF-8 diagnostic |
| `0x0022` | RetryAfterMs | uint32 BE |

Reject codes:

| Value | Name |
| --- | --- |
| `1` | UnsupportedVersion |
| `2` | MissingRequiredCapability |
| `3` | AuthenticationFailed |
| `4` | TimestampSkew |
| `5` | ReplayDetected |
| `6` | ResourceLimit |
| `7` | PolicyDenied |
| `8` | MalformedFrame |

## 11. Capability Map v2

Move from 32-bit to 64-bit capabilities.

Initial v2 capabilities:

| Bit | Name | Meaning |
| --- | --- | --- |
| `1 << 0` | TCP | TCP streams are supported. |
| `1 << 1` | UDP | UDP streams are supported. |
| `1 << 2` | Ping | Ping streams are supported. |
| `1 << 3` | IPStrategy | IP strategy is understood. |
| `1 << 4` | TCPStatus | TCP open status is supported. |
| `1 << 5` | UDPStatus | UDP open status is supported. |
| `1 << 6` | OpenStatusCode | Structured open error code is supported. |
| `1 << 7` | StreamOpenV2 | v2 stream open frame is supported. |
| `1 << 8` | StatusV2 | v2 status frame is supported. |
| `1 << 9` | ChannelMetrics | per-channel metrics are supported. |
| `1 << 10` | DrainSignal | graceful drain signal is supported. |
| `1 << 11` | DatagramV2 | future UDP datagram framing is supported. |

Required v2 baseline:

```text
TCP | Ping | TCPStatus | OpenStatusCode
```

UDP remains optional.

## 12. Stream Open v2

The current stream open header is compact and should remain for v1 and legacy
compatibility. For peers that negotiate `StreamOpenV2`, add a new stream kind:

```text
kind=5 StreamOpenV2
```

The old smux open header remains the first bytes:

```text
kind=5 | ip_strategy=0 | target_len=0
```

Then the stream writes a v2 open frame:

```text
frame_type=16
version=2
flags
body_len
TLV body
```

Required records:

| Type | Name | Value |
| --- | --- | --- |
| `0x8030` | Network | uint8: 1 TCP, 2 UDP, 3 Ping |
| `0x8031` | Target | UTF-8 `host:port`, omitted for Ping |
| `0x8032` | IPStrategy | uint8 |
| `0x8033` | StreamID | uint64 BE, client-generated |

Optional records:

| Type | Name | Value |
| --- | --- | --- |
| `0x0034` | DeadlineMs | uint32 BE |
| `0x0035` | EarlyData | bytes |
| `0x0036` | Padding | random bytes, ignored |

Why keep this optional:

- The v1 open header is already efficient.
- v2 open adds extensibility for future per-stream options.
- Implementing it behind a capability avoids breaking current tests.

## 13. Status v2

For peers that negotiate `StatusV2`, use a TLV status frame instead of the v1
status tuple.

```text
frame_type=17
version=2
flags
body_len
TLV body
```

Required records:

| Type | Name | Value |
| --- | --- | --- |
| `0x8040` | Status | uint8: 0 OK, 1 Error |
| `0x8041` | Code | uint16 BE |

Optional records:

| Type | Name | Value |
| --- | --- | --- |
| `0x0042` | Message | UTF-8 diagnostic |
| `0x0043` | RetryAfterMs | uint32 BE |
| `0x0044` | RemoteAddr | UTF-8 address selected by server |

Status code values should include current open errors:

| Value | Name |
| --- | --- |
| `0` | None |
| `1` | BadTarget |
| `2` | PolicyDenied |
| `3` | DialFailed |
| `4` | ResourceLimit |
| `5` | AuthenticationRequired |
| `6` | UnsupportedNetwork |
| `7` | Timeout |

Local mappings stay as they are today:

- SOCKS5 policy denial maps to `0x02`.
- other SOCKS5 remote open failures map to `0x05`.
- HTTP policy denial maps to `403`.
- other HTTP remote open failures map to `502`.

## 14. UDP v2 Direction

Keep current UDP stream chunks in phase 1:

```text
chunk_len (BE16) | payload
```

Server-to-client replies keep:

```text
addr_len (BE16) | payload_len (BE16) | addr | payload
```

Only introduce `DatagramV2` after control-channel v2 is stable. A future
DatagramV2 can define:

```text
session_id (u64)
packet_id (u32)
flags (u16)
target_len (u16)
payload_len (u16)
target
payload
```

That should be a separate design and test batch.

## 15. Downgrade Policy

Add a client option:

```text
-protocol-mode auto|v1|v2|v2-strict
```

Behavior:

| Mode | Behavior |
| --- | --- |
| `auto` | Try v2, fall back to v1, then legacy if allowed. |
| `v1` | Use current v1 Hello only. |
| `v2` | Require v2 when server understands it; allow v1 fallback on legacy errors. |
| `v2-strict` | Require v2 ChannelInit success; no v1 or legacy fallback. |

Recommended defaults:

- development: `auto`;
- production new deployments: `v2`;
- security-sensitive deployments: `v2-strict`.

Server option:

```text
-accept-protocols v1,v2
```

This lets operators disable v1 after a migration window.

## 16. Logging and Metrics

### 16.1 Logging

Never log:

- token values,
- auth proofs,
- nonces,
- full SessionID by default,
- full target address in privacy mode.

Safe log fields:

- protocol version,
- negotiated capability hex,
- short session ID prefix,
- channel ID,
- rejection code,
- reason category,
- local listener kind.

### 16.2 Metrics

Add counters:

```text
x_tunnel_client_protocol_v2_attempts_total
x_tunnel_client_protocol_v2_success_total
x_tunnel_client_protocol_v2_failures_total
x_tunnel_client_protocol_v2_downgrades_total
x_tunnel_server_protocol_v2_accepts_total
x_tunnel_server_protocol_v2_rejections_total
x_tunnel_server_protocol_v2_replay_rejections_total
x_tunnel_server_protocol_v2_auth_failures_total
```

Add gauges:

```text
x_tunnel_client_channel_protocol_version{channel="N"}
x_tunnel_client_channel_capabilities{channel="N"}
```

## 17. Configuration Changes

New flags:

```text
-protocol-mode auto|v1|v2|v2-strict
-accept-protocols v1,v2
-allow-plain-ws
-auth-mode token|mtls|token+mtls
-auth-skew 5m
-nonce-cache-size 65536
-protocol-max-frame 16384
-privacy-logs
```

JSON config fields should mirror these names:

```json
{
  "protocol_mode": "v2",
  "accept_protocols": "v1,v2",
  "allow_plain_ws": false,
  "auth_mode": "token",
  "auth_skew": "5m",
  "nonce_cache_size": 65536,
  "protocol_max_frame": 16384,
  "privacy_logs": true
}
```

## 18. Implementation Plan

### Phase 1: Protocol Helpers

Add to `internal/wire/protocol.go` or a neighboring `internal/wire` file:

- common v2 frame encoder/decoder,
- TLV encoder/decoder,
- typed helpers for uint8/uint16/uint32/uint64/int64/string/bytes,
- duplicate-record validation,
- critical unknown-record handling,
- max frame length enforcement.

Tests:

- exact wire bytes for v2 frames,
- malformed length rejection,
- duplicate singleton rejection,
- unknown critical rejection,
- unknown non-critical ignore,
- max frame size rejection,
- short read/write behavior.

### Phase 2: In-Band ChannelInit

Add client path:

- open Hello control stream as today,
- send v2 `ChannelInit`,
- read `ChannelAccept` or `ChannelReject`,
- store negotiated v2 capabilities on the channel.

Add server path:

- detect v2 control frame,
- validate required records,
- validate timestamp,
- validate auth proof or mTLS policy,
- group channel by SessionID after auth,
- replace duplicate ChannelID only after auth succeeds.

Tests:

- v2 successful negotiation,
- bad proof rejection,
- timestamp skew rejection,
- replay rejection,
- missing required record rejection,
- v1 fallback in `auto`,
- no fallback in `v2-strict`.

### Phase 3: Remove Handshake Metadata by Default

Change v2 client dial:

- do not append `client_id` or `channel_id` query params in v2 modes;
- do not send token as WebSocket subprotocol in v2 modes;
- optionally send non-secret `x-tunnel-v2` subprotocol only when configured.

Keep v1 behavior in `v1` and fallback paths.

Tests:

- v2 dial URL contains no protocol-required query params;
- v2 dialer does not expose token as subprotocol;
- v1 mode keeps current behavior;
- mixed v2 client with v1 server works only when downgrade policy allows.

### Phase 4: Status and StreamOpen v2

Implement `StatusV2` first because it is low-risk and preserves local proxy
behavior.

Then implement `StreamOpenV2` behind capability negotiation.

Tests:

- v2 TCP OK status,
- v2 TCP policy denial mapping,
- v2 HTTP policy denial mapping,
- v2 UDP OK status,
- v2 malformed target status,
- fallback to v1 TCPStatus/UDPStatus when peer lacks v2 status.

### Phase 5: Operator Defaults and Docs

Update:

- `docs/protocol.md`,
- `README.md`,
- `docs/deployment.md`,
- `docs/troubleshooting.md`,
- example JSON configs.

Recommended staged defaults:

1. Release A: `protocol-mode=auto`, server accepts `v1,v2`.
2. Release B: new examples use `protocol-mode=v2`.
3. Release C: production examples use `v2-strict`.
4. Release D: consider disabling v1 in hardened examples only.

## 19. Compatibility Matrix

| Client | Server | Expected behavior |
| --- | --- | --- |
| v1 | v1 | Current behavior. |
| v2 auto | v1 | Fall back to v1/legacy. |
| v2 | v1 | Fall back only if policy allows. |
| v2-strict | v1 | Fail channel. |
| v1 | v2 accept `v1,v2` | Current v1 behavior. |
| v1 | v2 accept `v2` only | Reject. |
| v2 | v2 | ChannelInit + ChannelAccept. |
| v2-strict | v2 | ChannelInit + ChannelAccept only. |

## 20. Rollback Plan

Every phase should be shippable independently.

Rollback rules:

- If v2 helper tests fail, do not enable v2 negotiation.
- If ChannelInit auth causes production issues, set client `protocol-mode=v1`
  and server `accept-protocols=v1,v2`.
- If v2 status mapping causes local proxy regressions, disable `StatusV2`
  capability while leaving ChannelInit active.
- If StreamOpenV2 causes stream regressions, disable `StreamOpenV2` capability
  and keep the v1 stream open header.

## 21. Security Review Checklist

- Token is never sent in URL, query, logs, or subprotocol in v2 mode.
- Auth proof is bound to nonce, timestamp, server name, and path.
- Server rejects replayed nonces.
- Server enforces timestamp skew.
- Server groups channels only after auth success.
- Duplicate channel replacement happens only after auth success.
- v2 strict mode cannot silently downgrade.
- Unknown critical TLVs reject the frame.
- Unknown non-critical TLVs are ignored.
- Frame length limits are enforced before allocation.
- Logs redact sensitive values.
- Metrics count auth failures and replay rejections without exposing secrets.

## 22. Test Matrix

Unit tests:

- v2 frame encode/decode golden bytes.
- TLV parser edge cases.
- HMAC proof stable test vector.
- timestamp skew checks.
- nonce cache behavior.
- capability intersection.
- downgrade policy decisions.

Integration tests:

- local WSS v2 channel negotiation.
- local WSS v2-strict rejects v1 server.
- local WSS auto falls back to v1 server.
- bad token does not create a session.
- replayed ChannelInit does not replace a valid channel.
- no query metadata in v2 dial URL.
- no token subprotocol in v2 dialer.
- TCP and UDP proxy flows still work after v2 negotiation.

Fuzz tests:

- v2 frame parser.
- TLV parser.
- ChannelInit validator.
- StatusV2 parser.

## 23. Suggested File-Level Changes

Likely implementation areas:

- `internal/wire`: v2 frame and TLV helpers.
- `internal/app`: WebSocket dial path, server upgrade path, channel metadata
  grouping, protocol negotiation, auth policy.
- `internal/wire/*_test.go` and `internal/app/*_test.go`: protocol helper
  unit tests and negotiation tests.
- `internal/app/integration_test.go`: end-to-end compatibility and
  no-metadata assertions.
- `README.md` and `docs/*.md`: operator guidance.
- `examples/*.json`: v2 config examples.

## 24. Recommended First PR

The first PR should be intentionally small:

1. Add v2 frame/TLV helpers.
2. Add golden-byte tests.
3. Add HMAC proof helper and test vectors.
4. Add config parsing for `protocol-mode` without changing runtime behavior.

This gives the codebase a verified protocol foundation before touching the live
WebSocket/session path.

## 25. Final Recommendation

The best near-term direction is not to make x-tunnel look like a mainstream
proxy protocol. The better design is a small, explicit, versioned control
protocol over the existing encrypted WebSocket + smux transport:

```text
WSS
  -> smux
  -> v2 ChannelInit with in-band auth and metadata
  -> negotiated stream/status capabilities
  -> compact TCP/UDP data streams
```

This keeps x-tunnel understandable, testable, and operationally safer. It also
avoids locking the project into a recognizable clone of any one public protocol.

## 26. DingTalk Stream API Reference Notes

Context7 documentation for DingTalk Open Platform Stream mode shows a useful
model for a production IM/event platform:

- Applications use SDK-managed Stream mode over WebSocket-style long
  connections.
- Each connection is authenticated with application credentials such as
  `clientId` and `clientSecret`.
- Stream mode is documented as TLS-protected and authenticated per connection.
- Events are delivered with stable envelope metadata such as `eventId`,
  `eventType`, `eventBornTime`, and `data`.
- Handlers return explicit acknowledgement states. Success returns
  `EventStatusSuccess` or `EventAckStatus.SUCCESS`; failure returns
  `EventStatusLater` or `EventAckStatus.LATER`, allowing later retry.
- HTTP callback mode uses signature, timestamp, nonce, and encrypted payloads,
  which reinforces the same design pattern: authenticate freshness, bind the
  request to a nonce, and avoid trusting unauthenticated payloads.

The important lesson is not to copy DingTalk's business payloads. The lesson is
to copy the shape of a mature event protocol:

```text
connect
  -> authenticate connection
  -> deliver framed messages with stable IDs and timestamps
  -> require explicit ACK/NACK
  -> retry only when receiver asks for later delivery or the connection fails
  -> keep transport security and application-level freshness checks separate
```

### 26.1 What x-tunnel Should Borrow

Borrow these ideas for protocol v2:

- **Connection-scoped authentication**: `ChannelInit` should authenticate the
  channel before it can join a session or replace an old channel.
- **Nonce and timestamp freshness**: the proposed `ClientNonce` and `Timestamp`
  records match the mature-platform pattern used in signed callback APIs.
- **Stable message identifiers**: add `StreamID` to `StreamOpenV2` and keep it
  in status/error logs. This gives retries and diagnostics a stable reference.
- **Explicit ACK states**: keep TCP/UDP open status, and extend v2 control
  frames with accept/reject codes rather than relying on connection close.
- **Retry semantics by category**: distinguish retryable failures from permanent
  failures. For example, `ResourceLimit` can include `RetryAfterMs`, while
  `BadTarget` should not be retried.
- **SDK-like defaults**: hide low-level handshake details behind sane defaults
  such as `protocol-mode=v2`, TLS required, privacy logs enabled, and strict
  frame limits.

### 26.2 What x-tunnel Should Not Borrow

Do not borrow these parts directly:

- DingTalk event JSON payloads are business-domain envelopes, not a transport
  tunnel frame format.
- DingTalk's `SUCCESS`/`LATER` event ACK model is for at-least-once event
  delivery. x-tunnel's TCP streams are interactive byte streams, so only stream
  open and control messages should have explicit ACK semantics.
- DingTalk's SDK hides reconnect behavior from application code. x-tunnel still
  needs visible operator metrics because it is a network tunnel.

### 26.3 Concrete Changes Inspired by DingTalk

Add these refinements to the v2 design:

1. Add an optional `AckPolicy` TLV for control messages.

   ```text
   0 = no explicit ack required
   1 = ack required
   2 = ack or retry hint required
   ```

2. Add `RetryAfterMs` consistently to `ChannelReject` and `StatusV2` for
   retryable categories.

3. Add a `MessageID` or reuse `StreamID` in every v2 control response so logs can
   correlate request and response without logging target details.

4. Add a `BornTime` or `CreatedAt` TLV for control messages where replay,
   timeout, or queueing decisions matter. For `ChannelInit`, the existing
   `Timestamp` record covers this.

5. Classify status codes:

   ```text
   permanent: BadTarget, PolicyDenied, UnsupportedNetwork
   retryable: ResourceLimit, Timeout, transient DialFailed
   security: AuthenticationRequired, AuthenticationFailed, ReplayDetected
   ```

6. Add integration tests that assert retryable and permanent failures are mapped
   differently in metrics and logs.

### 26.4 Source Pointers

- DingTalk Stream mode overview:
  `https://open.dingtalk.com/document/development/event-subscription-overview`
- DingTalk Stream SDK examples:
  `https://open.dingtalk.com/document/development/stream`
- DingTalk robot message callback shape:
  `https://open.dingtalk.com/document/dingstart/receive-message`
- DingTalk signed HTTP callback pattern:
  `https://open.dingtalk.com/document/isvapp/configure-synchttp-push`
