# x-tunnel Protocol Specification

Status: v2-only current implementation snapshot.

This document describes the wire behavior implemented in `internal/wire` and
used by `cmd/x-tunnel`. Current builds do not negotiate, accept, or downgrade to
the previous `XTUN` Hello protocol. A peer that cannot complete v2
`ChannelInit` is rejected before any client session is created.

Standards references used for local proxy behavior:

- SOCKS Protocol Version 5: RFC 1928, <https://www.rfc-editor.org/rfc/rfc1928>
- Username/Password Authentication for SOCKS V5: RFC 1929, <https://www.rfc-editor.org/rfc/rfc1929>
- HTTP Semantics, including CONNECT and hop-by-hop header handling: RFC 9110, <https://www.rfc-editor.org/rfc/rfc9110>

## 1. Topology

x-tunnel has two runtime roles:

- Client mode: starts local SOCKS5, HTTP proxy, and TCP forward listeners, then
  dials a remote WebSocket server.
- Server mode: accepts WebSocket connections, authenticates v2 channels, opens
  smux streams, and dials target TCP/UDP endpoints directly or through an
  upstream SOCKS5 proxy.

The transport stack is:

```text
local app
  -> local SOCKS5 / HTTP / TCP listener
  -> smux stream
  -> WebSocket binary messages
  -> TCP or TLS 1.3 WebSocket connection
  -> remote server
  -> target TCP/UDP endpoint
```

## 2. WebSocket Transport

Supported schemes:

- `ws://`
- `wss://`

For `wss://`, the client uses TLS 1.3. ECH can be enabled by default and
disabled with fallback mode. `-insecure` disables certificate verification for
standard TLS fallback behavior and should not be used in production.

The WebSocket request does not carry protocol metadata:

- no `client_id` query parameter;
- no `channel_id` query parameter;
- no token in `Sec-WebSocket-Protocol`.

Authentication happens after the WebSocket upgrade, on the first smux stream,
using v2 `ChannelInit`.

The client also sets a generic WebSocket request `User-Agent` instead of
leaving Go's default `Go-http-client` value on the upgrade request. This is
request-shape hygiene only; it does not carry protocol state and does not change
the TCP/UDP data path.

## 3. v2 Channel Authentication

Each WebSocket channel carries one smux session. Immediately after smux setup,
the client opens the first stream and sends a v2 frame:

```text
frame_type (u8) | version (u8) | flags (BE16) | body_len (BE32) | body ...
```

Current frame values:

| Type | Name |
| --- | --- |
| `1` | ChannelInit |
| `2` | ChannelAccept |
| `3` | ChannelReject |

The current v2 frame version is `2`. `body_len` is capped by
`MaxV2FrameSize` (`16 KiB`).

Frame bodies are TLV records:

```text
record_type (BE16) | record_len (BE16) | value ...
```

Rules:

- Record types with the high bit set are critical. Unknown critical records
  reject the frame.
- Unknown non-critical records are ignored.
- Duplicate record types are rejected.
- Required record lengths are validated exactly.

`ChannelInit` records:

| Type | Name | Required | Value |
| --- | --- | --- | --- |
| `0x8001` | SessionID | yes | 16 bytes. Derived from the client UUID. |
| `0x8002` | ChannelID | yes | BE32, positive. |
| `0x8003` | ClientNonce | yes | 32 random bytes. |
| `0x8004` | Timestamp | yes | BE64 Unix seconds. |
| `0x8005` | Capabilities | yes | BE64 capability bitset. |
| `0x8006` | AuthProof | yes | HMAC-SHA256 proof. |

The proof is:

```text
auth_key = HKDF-SHA256(token, salt="x-tunnel-v2-auth", info=server_name)
proof = HMAC-SHA256(auth_key, ChannelInit transcript)
```

The transcript includes frame type/version, session ID, channel ID, client
nonce, timestamp, capabilities, server name, and request path. The token itself
is never sent over WebSocket headers, URL query parameters, or TLV records.

Server validation order:

1. Parse `ChannelInit`.
2. Check timestamp skew (`-auth-skew`, default `5m`).
3. Verify HMAC proof.
4. Reject replayed `(SessionID, ChannelID, ClientNonce)` values.
5. Negotiate required capabilities.
6. Enforce `-max-clients`.
7. Reply with `ChannelAccept` and only then start accepting data streams.

The pre-auth stage is bounded by `-preauth-timeout` (default `5s`).

## 4. v2 Capabilities

Current baseline capability bits:

| Bit | Name | Meaning |
| --- | --- | --- |
| `1 << 0` | TCP | TCP streams are supported. |
| `1 << 1` | UDP | UDP streams are supported. |
| `1 << 2` | Ping | Ping streams are supported. |
| `1 << 3` | IPStrategy | IP strategy byte is understood. |
| `1 << 4` | TCPStatus | TCP streams begin with an open-status frame. |
| `1 << 5` | UDPStatus | UDP streams begin with an open-status frame. |
| `1 << 6` | OpenStatusCode | Status frames include a structured error code byte. |
| `1 << 9` | ChannelStats | Channel metrics expose negotiated capabilities. |

The v2 runtime requires `TCP`, `Ping`, `TCPStatus`, and `OpenStatusCode`.
Current builds advertise the full baseline above. There is no v1 fallback when
required v2 capabilities are missing.

## 5. smux Stream Open Header

After v2 channel authentication, every data stream starts with the compact
open header:

```text
kind (u8) | ip_strategy (u8) | target_len (BE16) | target bytes ...
```

Stream kinds:

| Value | Name | Meaning |
| --- | --- | --- |
| `1` | TCP | Open a TCP proxy stream to `target`. |
| `2` | UDP | Open a UDP relay stream to `target`. |
| `3` | Ping | Echo an 8-byte ping payload. |

Unknown stream kinds are logged, counted in
`x_tunnel_server_unsupported_streams_total`, and closed.

IP strategies:

| Value | CLI | Meaning |
| --- | --- | --- |
| `0` | default | Use default resolver/dialer behavior. |
| `1` | `4` | IPv4 only. |
| `2` | `6` | IPv6 only. |
| `3` | `4,6` | Prefer IPv4, fall back to IPv6. |
| `4` | `6,4` | Prefer IPv6, fall back to IPv4. |

Limits:

- `target_len <= 65535`.
- TCP and UDP streams reject `ip_strategy` values outside `0..4`.
- TCP/UDP targets must be valid `host:port` authorities.

## 6. TCP Streams

After a TCP open header, the server validates target syntax, target policy, and
then dials the target. Before proxied bytes begin, it writes:

```text
status (u8) | code (u8) | msg_len (BE16) | message bytes ...
```

Status values:

| Value | Name | Meaning |
| --- | --- | --- |
| `0` | OK | Target policy and remote TCP dial succeeded. |
| `1` | Error | Target validation, policy, dial, or resource-limit failure. |

Structured codes:

| Value | Name | Meaning |
| --- | --- | --- |
| `0` | None | No structured error. Used for OK. |
| `1` | BadTarget | Invalid IP strategy or malformed target. |
| `2` | PolicyDenied | Target policy rejected the target. |
| `3` | DialFailed | Remote TCP dial or upstream setup failed. |
| `4` | ResourceLimit | Server stream limit was reached. |

Local mapping:

- SOCKS5 CONNECT maps `PolicyDenied` to reply `0x02`; other remote open errors
  map to `0x05`.
- HTTP proxy and CONNECT map `PolicyDenied` to `403 Forbidden`; other remote
  open errors map to `502 Bad Gateway`.
- TCP forward listeners close the local connection on remote open error.

After OK, TCP bytes are copied bidirectionally until either side exits, then
both connections are closed.

## 7. UDP Streams

A UDP stream is bound to one target. The local SOCKS5 UDP association binds to
the first requested `DST.ADDR:DST.PORT`; later packets for different targets are
dropped instead of being sent over the same stream.

The server writes the same status-code frame shape as TCP before UDP chunks
begin. After OK, client-to-server datagrams are sent as chunks:

```text
chunk_len (BE16) | payload bytes ...
```

Server-to-client UDP replies include the source address string and payload:

```text
addr_len (BE16) | payload_len (BE16) | addr bytes ... | payload bytes ...
```

Limits:

- `chunk_len <= 65535`.
- `addr_len <= 65535`.
- `payload_len <= 65535`.
- UDP reply addresses must be valid non-empty `host:port` values with ports in
  `1..65535`.

## 8. Ping Streams

A ping stream uses:

```text
stream open header(kind=3, ip_strategy=0, target="")
8-byte payload
```

The server echoes the exact 8-byte payload. The client measures RTT around
write/read completion.

## 9. Local SOCKS5 and HTTP Proxy Behavior

The local SOCKS5 command and UDP packet parsing follows RFC 1928 for supported
commands and address encodings, with x-tunnel target validation before remote
streams are opened. SOCKS5 UDP request packets must use `RSV=0x0000`,
`FRAG=0`, and IPv4/domain/IPv6 address forms.

The local HTTP proxy accepts:

- `CONNECT host:port HTTP/1.1`, defaulting missing ports to `443`;
- absolute-form `http://host[:port]/path` requests, defaulting missing ports to
  `80`;
- origin-form requests with a valid `Host` header, defaulting missing ports to
  `80`.

Non-CONNECT absolute-form requests are accepted only with the `http` scheme.
Malformed authorities, URL userinfo, invalid DNS hostnames, and mismatched
`Host`/URL authorities are rejected with `400 Bad Request`. Hop-by-hop headers
are stripped before forwarding, and forwarded non-CONNECT requests append
`Via: 1.1 x-tunnel`.

Successful CONNECT returns `HTTP/1.1 200 Connection Established` without
`Content-Length` or `Transfer-Encoding`, then switches to opaque tunnel bytes.

## 10. Risk Map

### Compatibility

- The protocol is v2-only at channel authentication. Old clients and servers
  fail closed instead of silently downgrading.
- The TCP/UDP/Ping data open header remains compact for performance, but it is
  reachable only after v2 `ChannelAccept`.
- Future incompatible control-plane changes must use new v2 frame/TLV records
  and must reject unknown critical records.

### Reliability

- TCP/UDP open failures have structured status codes. Mid-stream TCP failures
  are still byte-stream closures rather than structured protocol errors.
- Reconnect timing and major network timeouts are configurable through
  `GlobalConfig`.

### Security

- Tokens are pre-shared secrets used only to derive HMAC proofs.
- `ws://` is allowed for local tests and trusted private networks; exposed
  deployments should use `wss://`, source CIDR filtering, and optionally mTLS.
- Server-side egress policy is pre-dial: CIDR rules apply to literal IP targets,
  and host rules apply to literal domain targets before DNS resolution.

## 11. Evolution Rules

- Keep authentication and capability negotiation on v2 control frames.
- Keep the hot TCP/UDP payload path raw unless a measured requirement justifies
  additional framing.
- Add tests for exact wire bytes before changing encoders/decoders.
- Prefer explicit rejection over fallback when peers do not support required v2
  behavior.
