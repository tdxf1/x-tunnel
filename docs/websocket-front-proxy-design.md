# WebSocket Front Proxy Design

Date: 2026-05-17

## Goal

Add an optional client-side front proxy for the WebSocket tunnel connection. The
immediate target is the Baidu CONNECT style shown in
`/Users/xxxx/Downloads/baidu/test_proxy.go`: connect to a Baidu node, send a
custom HTTP `CONNECT` request, then use the established TCP tunnel as the
underlying connection for `ws://` or `wss://`.

This must be controlled by the JSON config file and must not change the x-tunnel
v2 protocol, smux framing, local SOCKS5/HTTP proxy behavior, or server-side
egress proxy behavior.

## Current x-tunnel Fit

The right integration point is `internal/app/client.go:dialWebSocketWithECH`.
That function already centralizes the WebSocket client dial path, builds a
`gorilla/websocket.Dialer`, supports `-ip` dial overrides through `NetDial`, and
then lets gorilla perform the `ws` upgrade or `wss` TLS+upgrade flow. JSON config
loading is centralized in `internal/app/config.go`, and startup validation
already separates client mode from server mode.

The Baidu sample is a TCP-level CONNECT prelude: it dials
`cloudnproxy.baidu.com:443`, sends `CONNECT <target> HTTP/1.1` with fake `Host`,
`X-T5-Auth`, and mobile `User-Agent` headers, reads an HTTP response, and returns
the same `net.Conn` after status 200.

## Open Source Research

### MetaCubeX/mihomo

Note: the current default `main` branch of `MetaCubeX/mihomo` is a Python Honkai:
Star Rail package, not the Go proxy core. The Go proxy core is still visible on
the `Meta` branch; the evidence below uses commit
`5e22035118d13fa609164670111cc674906bb2a4`.

- mihomo models proxy pre-dialing as `dialer-proxy`: `BasicOption.NewDialer`
  chooses `proxydialer.NewByName(...)` when configured, otherwise direct dialer.
  Source:
  <https://github.com/MetaCubeX/mihomo/blob/5e22035118d13fa609164670111cc674906bb2a4/adapter/outbound/base.go#L193-L219>
- `proxydialer.NewByName` resolves a named proxy from the runtime proxy map and
  delegates `DialContext` to that proxy. This gives arbitrary outbound protocols
  a common "dial this node through another node" hook.
  Source:
  <https://github.com/MetaCubeX/mihomo/blob/5e22035118d13fa609164670111cc674906bb2a4/component/proxydialer/byname.go#L17-L36>
  and
  <https://github.com/MetaCubeX/mihomo/blob/5e22035118d13fa609164670111cc674906bb2a4/component/proxydialer/proxydialer.go#L23-L49>
- VMess WebSocket first obtains an underlay `net.Conn` through its configured
  dialer, then layers WebSocket/TLS over that existing connection. That
  separation is exactly the shape x-tunnel needs.
  Source:
  <https://github.com/MetaCubeX/mihomo/blob/5e22035118d13fa609164670111cc674906bb2a4/adapter/outbound/vmess.go#L277-L332>
  and
  <https://github.com/MetaCubeX/mihomo/blob/5e22035118d13fa609164670111cc674906bb2a4/transport/vmess/websocket.go#L337-L444>

### go-gost/x

Evidence uses commit `07ca57055aca4a38edc96e277edd60b3c3528e2e`.

- gost separates `Dial`, `Handshake`, and `Connect`. The WebSocket dialer first
  gets a raw connection through `options.Dialer.Dial`, then its handshake creates
  a `websocket.Dialer` whose `NetDial` returns the already-established
  connection.
  Source:
  <https://github.com/go-gost/x/blob/07ca57055aca4a38edc96e277edd60b3c3528e2e/dialer/ws/dialer.go#L56-L113>
- Its HTTP connector writes a real HTTP CONNECT request over an existing
  connection and reads the HTTP response. This is the closest reusable pattern
  for the Baidu CONNECT stage.
  Source:
  <https://github.com/go-gost/x/blob/07ca57055aca4a38edc96e277edd60b3c3528e2e/connector/http/connector.go#L46-L118>
- Its chain transport wires network dialer options before handshakes/connectors,
  which reinforces the boundary: proxying belongs below transport handshakes, not
  inside the payload protocol.
  Source:
  <https://github.com/go-gost/x/blob/07ca57055aca4a38edc96e277edd60b3c3528e2e/chain/transport.go#L33-L64>

### chisel

Evidence uses commit `b9d12191f6346c0a2ecd359b21a2f5f2c51dbfdd`.

- chisel exposes WebSocket proxying directly through gorilla's `websocket.Dialer`:
  it sets `NetDialContext` for custom dialing and, when an outbound proxy is
  configured, uses either `Dialer.Proxy` for HTTP CONNECT proxies or `NetDial`
  for SOCKS5.
  Source:
  <https://github.com/jpillora/chisel/blob/b9d12191f6346c0a2ecd359b21a2f5f2c51dbfdd/client/client_connect.go#L79-L93>
  and
  <https://github.com/jpillora/chisel/blob/b9d12191f6346c0a2ecd359b21a2f5f2c51dbfdd/client/client.go#L265-L293>

### Xray-core

Evidence uses commit `1bdb488c9ec09ea51e6899697d5b7437f3cf6eb2`.

- Xray's WebSocket transport uses `websocket.Dialer.NetDial` to route the raw
  underlying TCP connection through its own system dialer. For certain TLS
  fingerprint modes, it uses `NetDialTLSContext` because it performs the TLS
  handshake itself. x-tunnel does not need this in the first implementation if
  gorilla continues to own TLS.
  Source:
  <https://github.com/XTLS/Xray-core/blob/1bdb488c9ec09ea51e6899697d5b7437f3cf6eb2/transport/internet/websocket/dialer.go#L49-L112>

## Decision

Use a small x-tunnel-specific front-proxy dialer, not a full mihomo-style
multi-proxy chain.

Rationale:

- x-tunnel has one client-to-server WebSocket transport. A full proxy graph would
  add configuration and lifecycle complexity without immediate value.
- The open-source implementations agree on the important boundary: create or wrap
  the raw underlay `net.Conn`, then run TLS/WebSocket/protocol negotiation above
  it.
- The Baidu behavior is not a standard `http.ProxyURL` proxy because it needs a
  fake `Host` and `X-T5-Auth`; using gorilla `Dialer.Proxy` alone cannot express
  that safely.

## Config Shape

Add a nullable client-side config object:

```json
{
  "listen": "socks5://127.0.0.1:11080",
  "forward": "wss://x-tunnel.example.com/tunnel",
  "token": "replace-with-server-token",
  "fallback": true,
  "websocket_front_proxy": {
    "enabled": true,
    "type": "http_connect",
    "server": "cloudnproxy.baidu.com:443",
    "connect_host": "sptest.baidu.com",
    "headers": {
      "X-T5-Auth": "482857715",
      "User-Agent": "okhttp/3.11.0 Dalvik/2.1.0 (Linux; Build/RKQ1.200826.002) baiduboxapp/11.0.5.12 (Baidu; P1 11)",
      "Proxy-Connection": "keep-alive",
      "Connection": "keep-alive"
    }
  }
}
```

Field meaning:

- `enabled`: explicit switch. When false or object is absent, behavior remains
  current direct dialing.
- `type`: first implementation supports only `http_connect`.
- `server`: front proxy TCP endpoint.
- `connect_host`: optional HTTP Host header override for the CONNECT request.
  If empty, use the target authority.
- `headers`: additional CONNECT headers. `Host` is not accepted here; use
  `connect_host`.

Do not add CLI flags for the auth token in the first pass. Keeping this config
file only reduces accidental shell history exposure and matches the requested
switch-by-config behavior.

## Runtime Flow

When `websocket_front_proxy.enabled` is true:

1. `dialWebSocketWithECH` parses the WebSocket target as it does today.
2. The existing `-ip` override logic still decides the actual TCP target
   authority. If `-ip` is set, CONNECT targets the override IP/port; otherwise it
   targets the `forward` URL host/port.
3. `websocket.Dialer.NetDialContext` calls `dialFrontProxy(ctx, targetAuthority)`.
4. `dialFrontProxy` TCP dials `websocket_front_proxy.server`.
5. It writes an HTTP CONNECT request using `net/http`, not raw string
   concatenation.
6. It validates HTTP status 200.
7. It returns a `net.Conn` that preserves any bytes already buffered by
   `http.ReadResponse`.
8. gorilla continues the existing `ws` or `wss` flow over that connection.
9. v2 `ChannelInit`, smux, TCP/UDP stream open headers, and local proxy behavior
   are unchanged.

Important `wss` detail: use `NetDialContext`, not `NetDialTLSContext`, for the
first pass. That lets gorilla keep using x-tunnel's existing `TLSClientConfig`,
including mTLS, `fallback`, and `insecure` behavior.

## Implementation Plan

1. Add config structs and globals in `internal/app/config.go`.
2. Parse `websocket_front_proxy` in `loadConfigFile`.
3. Validate the config only in client mode:
   - `type` must be `http_connect`;
   - `server` must be valid `host:port`;
   - header names and values must reject CR/LF and empty names;
   - `Host` in `headers` must be rejected in favor of `connect_host`;
   - warn but do not fail if `wss` uses ECH without `fallback`.
4. Add `internal/app/front_proxy.go`:
   - `type WebSocketFrontProxyConfig`;
   - `func frontProxyEnabled() bool`;
   - `func dialWebSocketFrontProxy(ctx context.Context, target string) (net.Conn, error)`;
   - a small buffered-connection wrapper for bytes already consumed by
     `bufio.Reader`.
5. Change `dialWebSocketWithECH` so its `newDialer` always constructs one
   `NetDialContext` when front proxy or `-ip` is active. The address rewrite and
   front proxy should compose in one helper rather than competing `NetDial`
   assignments.
6. Add client startup logs in `internal/app/run.go` showing front proxy type and
   server, without printing headers or auth token values.
7. Update README config section and add an example JSON, probably
   `examples/baidu-front-proxy-client.json`.

## Edge Cases And Blind Spots

- ECH DNS lookup is still direct today. The front proxy wraps only the WebSocket
  TCP connection. For Baidu front proxy testing, use `"fallback": true` first.
- If the front proxy sends extra bytes after the CONNECT response header, the
  implementation must preserve them. Otherwise TLS/WebSocket can lose bytes.
- `-ip` override and `wss` SNI/Host must stay separated: CONNECT may target an IP
  override, but TLS ServerName and WebSocket Host should remain derived from
  `forward`.
- Do not log `X-T5-Auth` or arbitrary CONNECT headers.
- Do not support UDP through this feature. It is only the client-to-server
  WebSocket underlay; x-tunnel UDP streams remain inside smux after the tunnel is
  established.
- Standard `http.ProxyURL` is insufficient for Baidu because the sample requires
  non-standard Host/auth/request shape.
- The Baidu endpoint behavior is external and may drift. Real verification must
  be repeated before declaring production readiness.

## Tests

Minimum unit and integration tests:

- config loads `websocket_front_proxy`;
- config rejects unknown type, missing server when enabled, invalid host:port,
  `Host` in headers, CR/LF injection in names or values;
- fake CONNECT proxy receives the expected method, target authority,
  `connect_host`, `X-T5-Auth`, and `User-Agent`;
- fake CONNECT proxy non-200 returns a clear error and closes the socket;
- buffered bytes after CONNECT are preserved;
- `dialWebSocketWithECH` succeeds for `ws://` through a fake CONNECT front proxy;
- `dialWebSocketWithECH` succeeds for `wss://` with `fallback=true` and
  `insecure=true` through a fake CONNECT front proxy;
- `-ip` override still reaches the chosen IP/port while WebSocket request Host
  remains the `forward` host.

Verification commands:

```bash
go test ./internal/app
go test ./...
```

Manual smoke after implementation:

```bash
go run /Users/xxxx/Downloads/baidu/test_proxy.go myip.ipip.net:80
./x-tunnel -config ./examples/baidu-front-proxy-client.json
curl --socks5-hostname 127.0.0.1:11080 https://ifconfig.me
```

## Final Recommendation

Implement this as a narrow, config-gated `http_connect` WebSocket front proxy in
the client dial path. Keep the provider interface generic enough for future
front proxies, but ship only the Baidu-compatible CONNECT behavior now. This
matches the best parts of mihomo/gost/Xray/chisel without importing their full
proxy-chain model into x-tunnel.
