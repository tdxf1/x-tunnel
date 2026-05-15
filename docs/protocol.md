# x-tunnel Protocol Specification

Status: current implementation snapshot.

This document describes the wire behavior implemented in `x-tunnel.go` before any protocol evolution. It is intentionally conservative: any future change to these bytes must either remain backward-compatible or introduce explicit version/capability negotiation.

## 1. Topology

x-tunnel has two runtime roles:

- Client mode: starts local listeners and dials a remote WebSocket server.
- Server mode: accepts WebSocket connections, opens smux streams, and dials target TCP/UDP endpoints directly or through an upstream SOCKS5 proxy.

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

For `wss://`, the client uses TLS 1.3. ECH can be enabled by default and disabled with fallback mode. `-insecure` disables certificate verification for standard TLS fallback behavior.

Authentication, when configured, uses the `Sec-WebSocket-Protocol` header:

```text
Sec-WebSocket-Protocol: <token>
```

Current limitations:

- The token is a bearer secret and is not a full authentication protocol.
- The token is compared as an exact subprotocol value.
- There is no separate session-auth frame after WebSocket upgrade.

## 3. Client Session and Channels

Each client process generates one `client_id` UUID. Each WebSocket channel is dialed with query parameters:

```text
client_id=<uuid>
channel_id=<1-based integer>
```

The server groups channels by `client_id`. If a channel connects with an existing `channel_id`, the old WebSocket connection for that channel is closed and replaced.

Each WebSocket channel carries one smux session.

## 4. smux Stream Open Header

Every new smux stream starts with a fixed 4-byte header followed by an optional target string:

```text
0                   1                   2                   3
+-------------------+-------------------+-------------------+
| kind              | ip_strategy       | target_len (BE16) |
+-------------------+-------------------+-------------------+
| target bytes ...                                      |
+-------------------------------------------------------+
```

Fields:

- `kind`: stream type.
- `ip_strategy`: requested target IP selection strategy.
- `target_len`: big-endian uint16 length of the following target string.
- `target`: UTF-8 string, usually `host:port`.

Stream kinds:

| Value | Name | Meaning |
| --- | --- | --- |
| `1` | TCP | Open a TCP proxy stream to `target`. |
| `2` | UDP | Open a UDP relay stream to `target`. |
| `3` | Ping | Echo an 8-byte ping payload. |

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
- There is no protocol version byte in the current header.
- Unknown stream kinds are ignored by falling through the server switch.

## 5. TCP Stream

After a TCP stream open header, both sides proxy raw bytes until either direction exits. The implementation then closes both the target connection and the smux stream.

Current behavior:

- No structured remote dial error is returned to the local client.
- The local SOCKS5 CONNECT response is sent before the remote TCP stream is opened.
- The HTTP CONNECT response is sent before the remote TCP stream is opened.

## 6. Ping Stream

A ping stream has:

```text
stream open header(kind=3, ip_strategy=0, target="")
8-byte payload
```

The server echoes the exact 8-byte payload. The client measures RTT around write/read completion.

## 7. UDP Stream

A UDP stream is opened for one current target. Client-to-server datagrams are sent as chunks:

```text
0                   1
+-------------------+
| chunk_len (BE16)  |
+-------------------+
| payload bytes ... |
+-------------------+
```

Limits:

- `chunk_len <= 65535`.
- Zero-length chunks are ignored.

Server-to-client UDP replies include the source address string and payload:

```text
0                   1                   2                   3
+-------------------+-------------------+-------------------+
| addr_len (BE16)   | payload_len (BE16)|
+-------------------+-------------------+-------------------+
| addr bytes ...                                        |
+-------------------------------------------------------+
| payload bytes ...                                     |
+-------------------------------------------------------+
```

Limits:

- `addr_len <= 65535`.
- `payload_len <= 65535`.

## 8. SOCKS5 UDP Packet Format

The local SOCKS5 UDP association accepts standard SOCKS5 UDP request packets:

```text
RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT(2) | DATA
```

Current behavior:

- `FRAG` must be `0`.
- `ATYP` supports IPv4, domain, and IPv6.
- IPv6 targets are formatted as `[host]:port` after parsing.
- UDP destination ports listed in `-block` are silently dropped.

## 9. Current Risk Map

### Compatibility Risks

- No protocol version negotiation exists, so changing the stream open header would break existing clients and servers.
- No capability flags exist, so optional features such as compression, metrics, stronger auth, or status replies cannot be safely negotiated.
- Unknown stream kinds are not explicitly rejected, which makes interoperability failures hard to diagnose.

### Reliability Risks

- Remote TCP dial failures are not propagated as structured local SOCKS5/HTTP errors.
- Fixed reconnect timing can cause retry storms when many clients reconnect together.
- Some timeout values are hard-coded instead of using `GlobalConfig`.
- Graceful shutdown and listener lifecycle are not centralized.

### Security Risks

- WebSocket token auth is a bearer-token subprotocol check only.
- `-insecure` and ECH fallback behavior must stay explicit in logs because misuse weakens TLS validation.
- There is no target allow/deny policy for server-side egress.

### Testability Risks

- The project currently has no automated tests.
- Protocol encoders/decoders are embedded in the main file but can be unit-tested before refactoring.
- Local smoke tests exist only as documented manual commands, not as automated integration tests.

## 10. Evolution Rules

- Do not change existing wire bytes until unit tests cover current encoders/decoders.
- Add negotiation before introducing incompatible stream framing.
- Keep current WS/WSS + smux behavior working while adding tests and docs.
- Prefer explicit errors over silent fallthrough for future protocol versions.
