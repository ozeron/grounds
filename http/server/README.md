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
- **Concurrency:** each connection runs on its own (`IO.spawn`), so a slow client does not hold up the others.
- **Keep-alive:** a connection reads requests one after another, including pipelined ones. It closes on `Connection: close`, on HTTP/1.0 without `keep-alive`, after `max_requests`, when the client closes, or during a stop. The last response says `connection: close`.
- **Refusals:** a malformed request gets its status (400, 413, 431, 501 or 505) with the reason as text, and the connection closes. The handler never sees it.
- **Fuel:** Bend's termination check needs every loop bounded. The accept loop counts down 2^32 − 1 turns, and a connection counts down `max_requests`.

## TLS and proxies

`examples/tls.bend` serves HTTPS when `HTTP_TLS_CERT` and `HTTP_TLS_KEY` are set. The handshake must finish within `request_ms`. The OpenSSL 3 server requires TLS 1.2 or newer, disables 0-RTT and accepts only an `http/1.1` ALPN offer. It loads and checks the certificate and key before opening the port.

`Server.secure(req)` reads the server's `x-forwarded-proto` marker. On a direct connection the server replaces every incoming copy with `https` or `http`, so a client cannot claim to be secure by sending that header. `with_trust_proxy(cfg, True{})` accepts the incoming value on a plain connection. Use that switch only behind a proxy that removes client-supplied copies and sets its own value.

`Mw.hsts(~next)` adds `Strict-Transport-Security: max-age=31536000` to responses. Use it on an HTTPS listener; browsers ignore the header over plain HTTP. `Server.redirect_https(host, req)` returns a 308 redirect to a caller-supplied canonical host, keeping the request target. Serve it on a separate HTTP listener, as in `examples/redirect.bend`.

## Streaming

`serve_out` takes a handler that returns `Out`: either `Whole{response}` or `Stream{status, headers, body}`. `body` gets a `Sink` and writes the body in chunks with `send(sink, bytes)` and `send_text(sink, text)`. `examples/stream.bend` streams server-sent events and a 10 MiB download.

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

## Checks

`moon run http_server:check`:
1. Builds `examples/hello` and serves it on 8080.
2. Asserts the curl answer, and keep-alive: curl reports "Re-using existing connection" for two URLs.
3. Runs `examples/probe.py`: refusals, pipelining, chunked bodies, TE with CL, and a request served while another client waits half-sent.
4. Runs `examples/timeouts.py`: an idle, a half-sent and a trickling connection each close in time (about 11 s).
5. Runs `ab -c 100 -n 2000`, with and without keep-alive; no request may fail.
6. Serves `examples/stack.bend` on 8082 and checks each wrapper.
7. Serves `examples/stream.bend`: 3 server-sent events, heartbeats until the client goes (`examples/hb.py`), a 10 MiB streamed body, `/healthz`, `/readyz`, and a bad `HTTP_*` value.
8. Runs `examples/stop.py`: SIGTERM with an idle and a slow connection open. The slow request must finish, the idle one must close, and a short `HTTP_DRAIN_MS` must cut.
9. Serves the TLS and redirect examples: trusted curl, certificate and host rejection, ALPN, TLS 1.1 rejection, handshake deadline, protocol-header stripping, trusted proxy opt-in, HSTS and 308 redirect.
10. Runs the cold check on all examples.
