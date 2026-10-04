# grounds-http-server

An HTTP/1.1 server for [Bend 2](https://github.com/bendlang/bend): `serve(handler, config)`, on `grounds-wire` sockets and `grounds-http-wire` framing.

```python
import ../http/server/server.bend as Server
import ../http/core/request.bend as Req
import ../http/core/response.bend as Res
import ../http/core/text.bend as T

def hello(r: Req.Request) -> Res.Response:
  Res.ok("hello, " ++ T.or(Req.param(r, "name"), "world") ++ "\n")

def main() -> IO(Unit):
  Server.serve_pure(~hello, Server.default(8080))
```

`serve_pure` takes a handler that does no IO; `serve` takes one returning `IO(Response)`. `examples/hello.bend` answers `curl 'localhost:8080/?name=x'` with `hello, x`.

## Behaviour

- **Config:** `Config{port, max_head_bytes, max_body_bytes, max_requests, idle_ms, request_ms, drain_ms, tls, trust_proxy}`. `default(port)` gives 16 KiB heads, 1 MiB bodies, 100 requests per connection, 5 s idle, 10 s per request and 10 s to drain. It serves plain HTTP unless `with_tls(cfg, cert, key)` supplies PEM file paths.
- **Environment:** `from_env(cfg)` overrides fields from `PORT`, `HTTP_MAX_HEAD_BYTES`, `HTTP_MAX_BODY_BYTES`, `HTTP_MAX_REQUESTS`, `HTTP_IDLE_MS`, `HTTP_REQUEST_MS` and `HTTP_DRAIN_MS`. A value that is not a number stops the program with its name. `HTTP_TLS_CERT` and `HTTP_TLS_KEY` set TLS together; one missing, an unreadable file or a mismatched pair stops the server before it listens.
- **Timeouts:** an idle connection closes after `idle_ms` without a byte. Once a request's first bytes arrive, its head and body must all arrive within `request_ms`, else it gets 408 and the connection closes. A client that trickles one byte at a time cannot hold a connection. Each response write must also go out within `request_ms`.
- **Graceful stop:** on SIGTERM or SIGINT the server stops accepting and closes idle connections. Requests under way finish, and their responses say `connection: close`. `serve` returns once no connection is left. After `drain_ms` it exits anyway and says how many connections it cut.
- **Bodies:** a request body can be framed by Content-Length or by chunked coding. A request with both is refused with 400, which prevents smuggling. Any other Transfer-Encoding gets 501.
- **Multipart:** `core/multipart.bend` parses a completed `multipart/form-data` body into byte-exact parts. Pass `Mp.Limits{max_parts, max_header_bytes, max_headers}`; the server's `max_body_bytes` limits the total body before parsing. `examples/multipart.bend` shows the handler.
- **Concurrency:** each connection runs on its own (`IO.spawn`), so a slow client does not hold up the others.
- **Keep-alive:** a connection reads requests one after another, including pipelined ones. It closes on `Connection: close`, on HTTP/1.0 without `keep-alive`, after `max_requests`, when the client closes, or during a stop. The last response says `connection: close`.
- **Refusals:** a malformed request gets its status (400, 413, 431, 501 or 505) with the reason as text, and the connection closes. The handler never sees it.
- **Fuel:** Bend's termination check needs every loop bounded. The accept loop counts down 2^32 − 1 turns, and a connection counts down `max_requests`.

## TLS and proxies

`examples/tls.bend` serves HTTPS when `HTTP_TLS_CERT` and `HTTP_TLS_KEY` are set. The handshake must finish within `request_ms`. The OpenSSL 3 server requires TLS 1.2 or newer, disables 0-RTT and accepts only an `http/1.1` ALPN offer. It loads and checks the certificate and key before opening the port.

`Server.secure(req)` reads the server's `x-forwarded-proto` marker. On a direct connection the server replaces every incoming copy with `https` or `http`, so a client cannot claim to be secure by sending that header. `with_trust_proxy(cfg, True{})` accepts the incoming value on a plain connection. Use that switch only behind a proxy that removes client-supplied copies and sets its own value.

`Mw.hsts(~next)` adds `Strict-Transport-Security: max-age=31536000` to responses. Use it on an HTTPS listener; browsers ignore the header over plain HTTP. `Server.redirect_https(host, req)` returns a 308 redirect to a caller-supplied canonical host, keeping the request target. Serve it on a separate HTTP listener, as in `examples/redirect.bend`.

## Streaming

`serve_out` takes a handler that returns `Out`: `Whole{response}`, `Stream{status, headers, body}`, or `Upgrade{accept, session}`. A streamed `body` gets a `Sink` and writes chunks with `send(sink, bytes)` and `send_text(sink, text)`. `examples/stream.bend` streams server-sent events and a 10 MiB download.

`serve_out_context(~C, ~handler, context, cfg)` supplies immutable runtime
configuration to `handler(context: C, request: Request) -> IO(Out)`, where `C`
is Data. The handler remains a closed template; the context can come from host
effects such as configuration, entropy or a monotonic clock. Connections and
keep-alive requests receive the same context. This does not provide a mutable
session store or key rotation. Existing `serve_out`, `serve` and `serve_pure`
use the same server path with an empty context. `examples/context.bend` checks
an effect-created value across whole responses, streaming and concurrent clients.

`sse(body)` is a 200 `text/event-stream`. Its body writes events with these calls:

| Call | Does |
|---|---|
| `emit(k, Ev.Message{name, data, id})` | writes one event; data with LFs becomes several `data:` lines |
| `event(k, data)`, `named(k, name, data)` | `emit` with no id |
| `retry(k, ms)` | tells clients to wait `ms` before they reconnect |
| `ping(k)` | writes a `:` comment line, a heartbeat |
| `last_id(req)` | the request's `Last-Event-ID`, to resume after |
| `live(k)` | `Live{ok, sink}`: `ok` is False once a write has failed, as the client is gone |
| `sse.every(~tick, ms, k)` | calls `tick(k)` every `ms`, with a heartbeat when it writes nothing, until a write fails |

`Ev` is `../core/event.bend`. The client reads the same `Ev.Message`, so a service can relay events as they are. `http/core` proves `sse_reads_back`: what `emit` writes, the client's parser reads back as the same event, for any name and id with no CR or LF and any data with no CR.

```python
def ticks(k: Server.Sink) -> IO(Server.Sink):
  Server.emit(k, Ev.Message{"price", "42", Some{"7"}})

def app(r: Req.Request) -> IO(Server.Out):
  IO.pure(Server.Out, Server.sse(k => Server.sse.every(~ticks, 1000, k)))
```

If a write fails, the rest are dropped and the connection closes after the body function returns. HTTP/1.0 clients also get chunked coding.

## WebSocket

`websocket.bend` validates the RFC 6455 HTTP handshake and computes `Sec-WebSocket-Accept` with Bend SHA-1. An HTTP handler can return `Server.Upgrade{accept, session}`. The server sends a bare 101 response, then gives the socket and any bytes received after the HTTP headers to `session`. A session owns and must close the socket. `websocket_conn.bend` supplies a bounded session that handles masked client frames, fragmented messages, ping/pong, close, UTF-8 text, and one optional text or binary reply per message. It caps each frame and completed message at 1 MiB and uses a receive timeout supplied by the caller. `examples/websocket.bend` is an echo server on port 8088.

`websocket_frame.bend` is the pure incremental frame codec. The connection rejects unmasked and malformed frames. This initial API does not negotiate extensions or subprotocols. The application must check `Origin` and authenticate before upgrading when browser credentials or private data are involved. The example is an unauthenticated echo endpoint.

## Health

`health(~next)` answers `/healthz` with 200 while the process runs. It answers `/readyz` with 200, or with 503 once a stop has begun, so a load balancer stops sending new requests. It wraps an `Out` handler: `Server.serve_out(~Server.health(~app), cfg)`. For a Response handler use `~Server.health(~Server.whole(~app))`.

## Middleware

`middleware.bend` has wrappers that take the next handler as a template, so a stack is one expression the compiler inlines (`examples/stack.bend`):

```python
def small() -> U32:
  16

Server.serve(~Mw.logger(~Mw.request_id(~Mw.body_limit(~small, ~Mw.recover(~app)))), cfg)
```

- `recover`: the handler returns `IO(Result<String, Response>)`; `Fail{why}` logs `why` to stderr and answers 500.
- `body_limit(~max, ~next)`: a body over `max` bytes gets 413; `max` is a def with no arguments.
- `request_id`: adds `x-request-id`, 16 random hex digits.
- `logger`: prints `GET /todos/2 200 0ms` per request.
- `hsts`: adds a one-year Strict-Transport-Security header.
- `auth(~verify, ~next)`: parses Bearer or Basic Authorization, calls `verify(credential) -> IO(Maybe<Principal>)`, then calls `next(principal, request)` only for `Some{principal}`. The request passed to `next` has Authorization removed. `Principal{subject, claims}` and `Claim{name, value}` come from `core/auth.bend`.

`auth` sends 401 and `WWW-Authenticate` for missing, unsupported or rejected credentials. Missing credentials offer both Bearer and Basic challenges. A rejected Bearer token includes `error="invalid_token"`; malformed Bearer syntax or repeated Authorization fields get 400 with `error="invalid_request"`. The realm is `grounds`; Basic challenges advertise UTF-8. Use Basic only with TLS. The verifier decides token validity, password checking, claims and authorization policy; the middleware does not retain secrets.

`cors(~policy, ~next)` reads a fresh `Cors.Policy` per request. Ordinary responses receive `Vary: Origin` and CORS fields only for listed origins. The wrapper removes downstream CORS fields first so a handler cannot override the policy. A request with `OPTIONS`, one Origin and `Access-Control-Request-Method` is a preflight: allowed method and requested headers get 204, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers` when requested, `Access-Control-Max-Age`, and `Vary` on Origin, requested method and requested headers. Denied preflights get 403 without an allow origin. With credentials enabled, the response echoes an exact allowed origin and `Access-Control-Allow-Credentials: true`; a wildcard policy entry never combines with credentials. The policy holds serialized origins, such as `https://app.example`, without a trailing slash.

## Checks

`moon run http_server:check`:

The runtime-context fixture first checks native and Bun whole/stream responses,
keep-alive reuse, 32 concurrent requests and graceful shutdown. Existing checks:

1. Builds `examples/hello` and serves it on 8080.
2. Asserts the curl answer, and keep-alive: curl reports "Re-using existing connection" for two URLs.
3. Runs `examples/probe.py`: refusals, pipelining, chunked bodies, TE with CL, and a request served while another client waits half-sent.
4. Runs `examples/timeouts.py`: an idle, a half-sent and a trickling connection each close in time (about 11 s), measured with a monotonic clock.
5. Runs `ab -c 100 -n 2000`, with and without keep-alive; no request may fail.
6. Serves `examples/stack.bend` on 8082 and checks each wrapper.
7. Serves `examples/stream.bend`: 3 server-sent events, heartbeats until the client goes (`examples/hb.py`), a 10 MiB streamed body, `/healthz`, `/readyz`, and a bad `HTTP_*` value.
8. Runs `examples/stop.py`: SIGTERM with an idle and a slow connection open. The slow request must finish, the idle one must close, and a short `HTTP_DRAIN_MS` must cut.
9. Serves the TLS and redirect examples: trusted curl, certificate and host rejection, ALPN, TLS 1.1 rejection, handshake deadline, protocol-header stripping, trusted proxy opt-in, HSTS and 308 redirect.
10. Serves `examples/auth.bend` and checks Bearer and Basic success, challenges, malformed credentials, duplicate fields and removal of Authorization before the handler.
11. Serves `examples/cors.bend` and checks exact and denied origins, credentials, 204 preflight, `Vary`, method and header allowlists.
12. Proves the WebSocket handshake and frame examples, then serves `examples/websocket.bend` to check upgrade, frame echo, fragmentation, ping/pong, close, and protocol refusals with raw sockets.
13. Builds both multipart fixtures through `tools/bend_native.sh` to release the frontend before C compilation, serves `examples/multipart.bend`, compares 200 generated requests with Python's email parser, checks part and header limits, and sends a binary part from the client builder.
14. Runs the cold check on the existing examples and auth. CORS policy lookups and multipart parsing currently make some String and List constructors reference counted.

`check_phases.json` declares thirteen ordered resource phases covering these
checks. Each fixture is stopped and waited for before its phase ends. The
shared temporary directory retains generated outputs for later checks. Use
`tools/build_guard.py --phases http/server/check_phases.json` around the Moon
command to apply the same 1 GiB process-tree cap and a 120-second deadline to
each declared phase; startup, transitions and final cleanup are bounded to ten
seconds. Every mandatory phase must finish successfully. The optional Bun
context phase records an explicit skip when Bun is absent. The manifest and
announcement helper participate in Moon cache inputs.
