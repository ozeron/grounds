# grounds-http-server

An HTTP/1.1 server for [Bend 2](https://github.com/bendlang/bend): `serve(handler, config)`, on `grounds-wire` sockets and `grounds-http1` framing.

```python
import ../http_server/server.bend as Server
import ../http/request.bend as Req
import ../http/response.bend as Res
import ../http/text.bend as T

def hello(r: Req.Request) -> Res.Response:
  Res.ok("hello, " ++ T.or(Req.param(r, "name"), "world") ++ "\n")

def main() -> IO(Unit):
  Server.serve_pure(~hello, Server.default(8080))
```

`serve_pure` takes a handler that does no IO; `serve` takes one returning `IO(Response)`. `examples/hello.bend` answers `curl 'localhost:8080/?name=x'` with `hello, x`.

## Behaviour

- **Config:** `Config{port, max_head_bytes, max_body_bytes, max_requests, idle_ms, request_ms}`. `default(port)` gives 16 KiB heads, 1 MiB bodies, 100 requests per connection, 5 s idle and 10 s per request.
- **Timeouts:** a connection with no request under way closes after `idle_ms` without a byte. Once a request's first bytes come, its head and body must all arrive within `request_ms`, else it gets 408 and the connection closes. A client trickling a byte at a time cannot hold a connection.
- **Concurrency:** each connection runs on its own (`IO.spawn`), so a slow client does not hold up the others.
- **Keep-alive:** a connection reads requests one after another, pipelined ones included. It closes on `Connection: close`, on HTTP/1.0 without `keep-alive`, after `max_requests`, or when the client closes. The last response says `connection: close`.
- **Refusals:** a malformed request gets its status (400, 413, 431, 501 or 505) with the reason as text, and the connection closes. The handler never sees it.
- **Fuel:** Bend's termination check needs every loop bounded, so the accept loop counts down 2^32 − 1 connections and a connection counts down `max_requests`.

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

## Checks

`moon run http_server:check`:
1. Builds `examples/hello` and serves it on 8080.
2. Asserts the curl answer, and keep-alive: curl reports "Re-using existing connection" for two URLs.
3. Runs `examples/probe.py`: refusals, pipelining, and a request served while another client waits half-sent.
4. Runs `examples/timeouts.py`: an idle, a half-sent and a trickling connection each close in time (about 11 s).
5. Runs `ab -c 100 -n 2000`, with and without keep-alive; no request may fail.
6. Serves `examples/stack.bend` on 8082 and checks each wrapper.
7. Runs the cold check on both examples.

## Next

Chunked request bodies and graceful shutdown (`../http/docs/TODO.md`).
