# x-tunnel Protocol v2 Improvement Plan

Status: implemented as a v2-only design. v1/Hello compatibility and downgrade
paths are intentionally not part of the current plan.

## 1. Decision

The current project architecture can support a v2 protocol without keeping v1
compatibility, and this is the cleaner direction for the current codebase.

The key architectural reason is that x-tunnel already has a natural split:

- WebSocket carries one smux session per channel.
- The first smux stream can authenticate and negotiate the whole channel before
  any user traffic is accepted.
- TCP/UDP/Ping streams are already isolated behind a small open header and can
  keep their hot payload path unchanged.

That lets v2 replace the old URL/subprotocol/Hello control plane while leaving
the data plane compact.

## 2. Goals

- Remove credentials from WebSocket URL query strings and subprotocol headers.
- Authenticate each channel before creating or joining a server-side client
  session.
- Reject unsupported peers explicitly; no v1 fallback and no silent downgrade.
- Keep TCP/UDP payload bytes raw after successful open-status.
- Keep protocol extension points structured with v2 frame and TLV records.
- Bound pre-auth resource use with a timeout and small frame limit.

## 3. Non-Goals

- No `protocol-mode=auto|v1|v2`.
- No `accept-protocols=v1,v2`.
- No v1 `XTUN` Hello stream.
- No bearer token in `Sec-WebSocket-Protocol`.
- No `client_id` or `channel_id` in WebSocket query parameters.
- No immediate rewrite of TCP/UDP payload transport into framed messages.

## 4. Current v2 Flow

1. Client dials `ws://` or `wss://` without protocol metadata in URL query or
   WebSocket subprotocols.
2. Server upgrades WebSocket and creates a smux server with a pre-auth deadline.
3. Client opens the first smux stream and writes `ChannelInit`.
4. Server parses `ChannelInit`, validates timestamp, verifies HMAC proof, checks
   nonce replay, negotiates capabilities, and enforces `-max-clients`.
5. Server writes `ChannelAccept` or `ChannelReject`.
6. Only after `ChannelAccept` does the server accept TCP/UDP/Ping streams.

## 5. v2 Frame Format

All v2 control frames use:

```text
frame_type (u8) | version (u8) | flags (BE16) | body_len (BE32) | body ...
```

Current frame types:

| Type | Name |
| --- | --- |
| `1` | ChannelInit |
| `2` | ChannelAccept |
| `3` | ChannelReject |

`version` is `2`. `body_len` is capped at `16 KiB`.

## 6. TLV Rules

Frame bodies are TLV records:

```text
record_type (BE16) | record_len (BE16) | value ...
```

Rules:

- High-bit record types are critical.
- Unknown critical records reject the frame.
- Unknown non-critical records are ignored.
- Duplicate records reject the frame.
- Required record lengths are exact.

## 7. ChannelInit

Required records:

| Type | Name | Value |
| --- | --- | --- |
| `0x8001` | SessionID | 16-byte client session ID. |
| `0x8002` | ChannelID | BE32 positive channel number. |
| `0x8003` | ClientNonce | 32 random bytes. |
| `0x8004` | Timestamp | BE64 Unix seconds. |
| `0x8005` | Capabilities | BE64 bitset. |
| `0x8006` | AuthProof | HMAC-SHA256 proof. |

Auth proof:

```text
auth_key = HKDF-SHA256(token, salt="x-tunnel-v2-auth", info=server_name)
proof = HMAC-SHA256(auth_key, transcript)
```

The transcript includes frame type/version, session ID, channel ID, client
nonce, timestamp, capabilities, server name, and request path. The token itself
is never transmitted.

## 8. ChannelAccept

Records:

| Type | Name | Value |
| --- | --- | --- |
| `0x8005` | Capabilities | BE64 negotiated capabilities. |
| `0x8010` | ServerNonce | 32 random bytes. |
| `0x8011` | ServerTime | BE64 Unix seconds. |
| `0x0012` | MaxFrameSize | Optional BE32. |
| `0x0013` | MaxStreams | Optional BE32. |
| `0x0015` | Message | Optional diagnostic text. |

## 9. ChannelReject

Records:

| Type | Name | Value |
| --- | --- | --- |
| `0x8020` | RejectCode | BE16 reject code. |
| `0x0021` | RejectReason | Optional diagnostic text. |

Reject codes:

| Code | Name |
| --- | --- |
| `1` | UnsupportedVersion |
| `2` | MissingRequiredCapability |
| `3` | AuthenticationFailed |
| `4` | TimestampSkew |
| `5` | ReplayDetected |
| `6` | ResourceLimit |
| `7` | PolicyDenied |
| `8` | MalformedFrame |

## 10. Capabilities

Current advertised baseline:

| Bit | Name |
| --- | --- |
| `1 << 0` | TCP |
| `1 << 1` | UDP |
| `1 << 2` | Ping |
| `1 << 3` | IPStrategy |
| `1 << 4` | TCPStatus |
| `1 << 5` | UDPStatus |
| `1 << 6` | OpenStatusCode |
| `1 << 9` | ChannelStats |

Required baseline:

- `TCP`
- `Ping`
- `TCPStatus`
- `OpenStatusCode`

Missing required capabilities reject the channel. There is no compatibility
mode that continues without them.

## 11. Data Plane

After v2 `ChannelAccept`, TCP/UDP/Ping streams use the compact existing open
header:

```text
kind (u8) | ip_strategy (u8) | target_len (BE16) | target bytes ...
```

This keeps connection setup and payload forwarding close to the old hot-path
cost while still requiring v2 authentication first.

TCP and UDP opens always receive a structured status-code frame before payload:

```text
status (u8) | code (u8) | msg_len (BE16) | message bytes ...
```

Codes:

| Code | Name |
| --- | --- |
| `0` | None |
| `1` | BadTarget |
| `2` | PolicyDenied |
| `3` | DialFailed |
| `4` | ResourceLimit |

## 12. Implementation Mapping

- `internal/wire/protocol_v2.go`: v2 frame, TLV, ChannelInit/Accept/Reject,
  HMAC proof, timestamp, and capability helpers.
- `internal/wire/protocol.go`: TCP/UDP/Ping stream open and status helpers.
- `internal/app/client.go`: WebSocket dial without query/subprotocol metadata,
  v2 ChannelInit, and v2 capability storage.
- `internal/app/server.go`: pre-auth smux lifecycle, v2 validation, replay
  cache, ChannelAccept/Reject, and authenticated stream loop.
- `internal/app/config.go`: `auth-skew` and `preauth-timeout`.
- `docs/protocol.md`: current v2-only protocol specification.

## 13. Security Properties

- Token is not sent on the wire; it derives the HMAC key.
- Captured `ChannelInit` cannot be replayed because nonce tuples are cached.
- Stale and far-future timestamps are rejected when `auth-skew > 0`.
- Bad auth does not create a server-side client session.
- Unsupported or malformed control frames fail closed.

## 14. Validation Plan

Required before shipping:

- `go test ./...`
- v2 wire unit tests for frame bytes, TLV duplicate rejection, unknown critical
  rejection, HMAC proof, timestamp skew, and capability negotiation.
- local integration test through SOCKS5, HTTP proxy, TCP forward, and UDP.
- manual real tunnel smoke test with local origin, server, client, and `curl`.
- bad-token test proving the server rejects before session creation.
- simulated censor/GFW proxy integration test proving the current WebSocket
  request and early client WebSocket payload do not expose the old query,
  subprotocol, token, or `XTUN` markers while real tunnel traffic still works.
- benchmark comparison against the saved pre-v2 baseline.

## 15. Performance Expectation

v2 intentionally adds HMAC/TLV work only once per channel. The per-stream data
path stays compact:

- TCP/UDP open header remains 4 bytes plus target.
- TCP/UDP payload bytes remain raw after open-status.
- Ping remains an 8-byte echo payload.

For normal tunnel traffic, connection and payload performance should be at least
as good on the hot path as the previous design. The ChannelInit handshake may be
heavier than the old Hello frame, but it replaces URL/subprotocol bearer-token
auth with a real proof and happens once per channel, not per stream.

If measured results show a regression in data-path benchmarks or real traffic,
optimize the v2 control encoder/decoder or capability bookkeeping before adding
more protocol features.

## 16. Performance Investigation Result

The observed performance concern was not the TCP/UDP hot path. The hot path
remains the compact stream open/status format and currently benchmarks faster
than the pre-v2 baseline after stack header and string-write optimizations.

Root cause of the remaining v2 overhead:

- `ChannelInit` is a real control-plane authentication step, so it necessarily
  does TLV encode/decode plus HMAC proof work.
- The initial implementation allocated avoidable short-lived buffers while
  building TLV bodies and the HMAC transcript.

Protocol-preserving optimizations applied:

- pre-size TLV encode buffers before writing records;
- build the HMAC transcript with an exact-capacity byte slice instead of
  `bytes.Buffer` plus reflective `binary.Write`;
- use stack arrays for small v2 frame/TLV integer fields;
- keep all on-wire bytes unchanged and covered by golden/unit tests.

Latest same-window local benchmark sample on Apple M3, comparing `HEAD` before
this v2 change set against the current working tree with:

```bash
go test -run '^$' -bench 'Benchmark(SmuxOpenHeaderRoundTrip|TCPOpenStatusRoundTrip|ChunkRoundTrip|UDPReplyRoundTrip)$' -benchmem -benchtime=300ms -count=5 ./internal/app
go test -run '^$' -bench 'Benchmark(ChannelInitRoundTrip|ComputeV2AuthProof)$' -benchmem -benchtime=300ms -count=5 ./internal/wire
```

| Benchmark | Before optimization | After optimization |
| --- | ---: | ---: |
| `SmuxOpenHeaderRoundTrip` | about `168 ns/op`, `168 B/op`, `7 allocs/op` | about `144 ns/op`, `152 B/op`, `6 allocs/op` |
| `TCPOpenStatusRoundTrip` | about `166 ns/op`, `166 B/op`, `7 allocs/op` | about `143 ns/op`, `150 B/op`, `6 allocs/op` |
| `UDPReplyRoundTrip` | about `703 ns/op`, `2728 B/op`, `9 allocs/op` | about `680 ns/op`, `2712 B/op`, `8 allocs/op` |
| `ChunkRoundTrip` | about `471 ns/op`, `2932 B/op`, `6 allocs/op` | about `476 ns/op`, `2932 B/op`, `6 allocs/op` |
| `ChannelInitRoundTrip` | no v1 equivalent | about `1.35 us/op`, `1224 B/op`, `25 allocs/op` |
| `ComputeV2AuthProof` | no v1 equivalent | about `1.51 us/op`, `1857 B/op`, `25 allocs/op` |

Conclusion: the v2 control plane has a deliberate once-per-channel cost, but
the protocol hot path is not slower. Optimization should continue to target
control-plane allocation and transcript construction, not TCP/UDP payload
framing.

## 17. Simulated Blocking Test

`TestIntegrationSimulatedCensorProxyAllowsV2Tunnel` inserts a local TCP proxy
between a real x-tunnel client and server:

```text
client -> simulated censor proxy -> x-tunnel server -> local origin
```

The proxy actively blocks connections if the WebSocket upgrade request or early
client WebSocket payload contains any of these legacy or high-signal markers:

- `client_id`
- `channel_id`
- `Sec-WebSocket-Protocol`
- the Go default `Go-http-client` User-Agent
- the configured token string
- `XTUN`
- any query string on the WebSocket request line

The current v2 tunnel passes through that proxy and successfully transfers the
same payload through both SOCKS5 and TCP-forward paths. This test is intentionally
request-shape focused: it validates that authentication metadata moved into the
post-upgrade v2 `ChannelInit` proof, that the WebSocket upgrade no longer exposes
the Go default client User-Agent, and that the hot TCP/UDP payload protocol is
unchanged.

Focused command:

```bash
go test -run TestIntegrationSimulatedCensorProxyAllowsV2Tunnel -count=1 ./internal/app
```
