# grounds-http-client

HTTP/1.1 requests from [Bend 2](https://github.com/bendlang/bend) to other services, on `grounds-wire` sockets and `grounds-http-wire` framing.

```python
import ../http/client/client.bend as Client
import ../http/core/text.bend as T

def said(r: Client.R()) -> String:
  match r:
    case Done{res}:
      T.or(Client.text(res), "(not UTF-8)")
    case Fail{e}:
      Client.show(e)

def main() -> IO(Unit):
  IO.bind(Client.R(), Unit, Client.get("http://orders:8080/orders/7"), r => IO.print(said(r)))
```

## API

| Call | Does |
|---|---|
| `get(url)` | GET with `default()` |
| `post(url, content_type, body)` | POST a body of bytes |
| `request(cfg, method, url, headers, body)` | any method, your config and headers |
| `text(res)` | the body as text, when it is UTF-8 |
| `show(err)` | why a request failed, as text |

A result is `Done{Res.Response}` or `Fail{Err}`. `Err` is one of `BadUrl`, `Https`, `NoHost`, `Refused{errno}`, `Timeout`, `Closed`, `TooLarge` and `BadResponse`.

## Behaviour

- **Config:** `Config{timeout_ms, max_head_bytes, max_body_bytes}`. `default()` gives 10 s, 16 KiB and 8 MiB. Change fields with `with_timeout` and `with_max_body`.
- **Timeout:** one deadline covers the whole request: resolving the host, connecting, sending and reading the last byte.
- **URLs:** only `http://host[:port][/path][?query]`. The host can be a name, which is resolved to IPv4, or an address. `https://` fails with `Https`, because the client has no TLS.
- **Framing:** a response is read by Content-Length, chunked coding, or to the close when it has neither. A 1xx response is skipped. There is no body after HEAD, or on a 204 or 304.
- **Safety:** you cannot set Host, Content-Length, Transfer-Encoding or Connection; the client writes these itself. A header whose name or value has CR, LF or NUL is dropped. A target with a space or a control char is `BadUrl`.
- **Connections:** each request opens one connection and closes it after the response (`connection: close`). There is no pool yet.

## Checks

`moon run http_client:check` runs the URL unit tests and `tests/live.bend`. The live test runs against two servers:
- `tests/fake.py`, which sends chunked replies, read-to-close replies, stalls, cut bodies, oversized bodies, 100 Continue and garbage;
- the server's `examples/stream`, which sends a streamed 4 MiB body and server-sent events.

Every case must print its line from `tests/live.out`. Then the cold check runs.
