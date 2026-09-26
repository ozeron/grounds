# grounds-http-server

An HTTP/1.1 server for [Bend 2](https://github.com/bendlang/bend): `serve(handler, config)`, on `grounds-wire` sockets and `grounds-http1` framing.

```python
import ../http_server/server.bend as Server
import ../http/request.bend as Req
import ../http/response.bend as Res
import ../http/status.bend as S

def hello(r: Req.Request) -> IO(Res.Response):
  IO.pure(Res.Response, Res.text(S.ok(), "hello\n"))

def main() -> IO(Unit):
  Server.serve(~hello, Server.default(8080))
```

`examples/hello.bend` answers `curl 'localhost:8080/?name=x'` with `hello, x`.

## Behaviour

- **Config:** `Config{port, max_head_bytes, max_body_bytes, max_requests}`. `default(port)` gives 16 KiB heads, 1 MiB bodies and 100 requests per connection.
- **Concurrency:** each connection runs on its own (`IO.spawn`), so a slow client does not hold up the others.
- **Keep-alive:** a connection reads requests one after another, pipelined ones included. It closes on `Connection: close`, on HTTP/1.0 without `keep-alive`, after `max_requests`, or when the client closes. The last response says `connection: close`.
- **Refusals:** a malformed request gets its status (400, 413, 431, 501 or 505) with the reason as text, and the connection closes. The handler never sees it.
- **Fuel:** Bend's termination check needs every loop bounded, so the accept loop counts down 2^32 − 1 connections and a connection counts down `max_requests`.

## Checks

`moon run http_server:check`:
1. Builds `examples/hello` and serves it on 8080.
2. Asserts the curl answer, and keep-alive: curl reports "Re-using existing connection" for two URLs.
3. Runs `examples/probe.py`: refusals, pipelining, and a request served while another client waits half-sent.
4. Runs the cold check.

## Next

Chunked request bodies, request timeouts (an idle connection is held until the client closes), graceful shutdown, and the router and JSON layers (`../http/docs/TODO.md`).
