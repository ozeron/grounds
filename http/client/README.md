# grounds-http-client

HTTP/1.1 requests from [Bend 2](https://github.com/bendlang/bend) to other services, over TCP or TLS. It is built on `grounds-wire` sockets and `grounds-http-wire` framing.

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
| `get(url)`, `post(url, content_type, body)` | one request with `default()` |
| `request(cfg, method, url, headers, body)` | any method, your config and headers |
| `get_json(A, url, decoder)` | GET, then decode the JSON body into `A` |
| `post_json(A, url, encode, value)` | POST `value` as JSON, read the JSON reply |
| `pool(cfg, base, n)` | a pool of up to `n` kept connections to `base` (`http[s]://host[:port]`) |
| `send(pool, method, path, headers, body)`, `pool.get(pool, path)` | a request through the pool |
| `pool.close(pool)` | close the pool once each connection in use comes back |
| `download(~f, cfg, url, headers)` | GET, handing the body to `f(status, bytes)` as it is read |
| `text(res)`, `show(err)`, `jshow(jerr)` | a body as text; an error as text |

A result is `Done{Res.Response}` or `Fail{Err}`. `Err` is one of `BadUrl`, `BadMethod`, `NoHost`, `Refused{errno}`, `Tls{why}`, `Timeout`, `Closed`, `TooLarge`, `BadResponse` and `Redirects`. The JSON calls fail with `JErr`: `JHttp{err}`, `JStatus{code, body}` for a status other than 2xx, `JBad` for a body that is not JSON, or `JValue` for JSON the decoder refuses.

## Behaviour

- **Config:** `Config{timeout_ms, max_head_bytes, max_body_bytes, retries, backoff_ms, redirects, idle_ms}`. `default()` gives 10 s, 16 KiB of head, 8 MiB of body, no retries, 5 redirects and a 4 s idle limit. Change it with `with_timeout`, `with_max_body`, `with_retries(n, backoff_ms)`, `with_redirects(n)` and `with_idle(ms)`.
- **Timeout:** one deadline covers the whole call: resolving the host, connecting, the TLS handshake, sending, reading, and every redirect and retry.
- **Pool:** idle connections to one origin, at most `n`. A request takes an idle connection, opens a new one when there is room, or waits for one to come back. An idle connection older than `idle_ms` is closed, not used. A response with `connection: close`, from HTTP/1.0, or read to the close gives its connection up. If the server has closed a kept connection, the request is tried once more on a new one, but only for a method safe to repeat: GET, HEAD, PUT, DELETE, OPTIONS or TRACE.
- **Retries:** off by default. `with_retries(n, ms)` tries a request that is safe to repeat up to `n` more times. It retries on a failed connection (`Refused`, `Timeout`, `Closed`) and on 502, 503 or 504. The first wait is `ms`, and each wait doubles, up to 5 s.
- **Redirects:** 301, 302, 303, 307 and 308 are followed, up to `redirects` times; one more fails with `Redirects`. A 303, or a 301 or 302 answering a POST, is followed with a GET and no body; otherwise the method and body stay. A redirect from http to https is never followed; the 3xx comes back as it is. A redirect to another url drops `Authorization` and `Cookie`. With `redirects` 0, every 3xx comes back as it is.
- **Downloads:** `download` hands the body to `f` a piece at a time, however large: there is no body limit. `f` answers `True` to go on or `False` to stop. `timeout_ms` applies to each read. Redirects are not followed.
- **TLS:** `https://` urls use OpenSSL 3, loaded at run time. The certificate chain and the host name are always checked, and TLS 1.2 is the floor. `GROUNDS_TLS_CA` names a PEM file to trust as well as the system's roots.
- **Framing:** a response is read by Content-Length, chunked coding, or to the close when it has neither. Up to 8 1xx responses are skipped. There is no body after HEAD, or on a 204 or 304.
- **Safety:** you cannot set Host, Content-Length, Transfer-Encoding or Connection; the client writes these itself. A header with CR, LF or NUL in its name or value is dropped. A url whose target or host has one is `BadUrl`, and a method name that is not a token is `BadMethod`.
- **Counting:** `get`, `post`, `request`, the JSON calls and `download` are cold: no value is reference counted. A pool passes its connections through a channel, and a channel counts what it carries, so a program that uses a pool is partly counted.

## Laws

`LAWS.bend`, proven in `PROOF.bend`:
- `url_target`, `url_authority`: a url the client takes has no CR, LF or NUL in its target or its Host.
- `check_target`, `check_authority`: the same holds for every url that passes `url.check`, including pool paths and redirects.
- `method_clean`: a method the client sends has none either.
- `request_safe`: combined with http/wire's `request_head`, the head the client writes for any method, url and headers has one empty line, at its end, and CR or LF only where a line ends. No header value, url or method can add a header or start a second request.

## Checks

`moon run http_client:check`:
1. The URL unit tests and the proofs.
2. `tests/live.bend` against `tests/fake.py` and the server's `examples/stream`: framing and faults.
3. `tests/more.bend`: the pool, keep-alive and stale connections, retries, each redirect code, JSON, downloads and TLS. Every case must print its line from `tests/more.out`.
4. `tests/fuzz.py`: 2000 random responses, valid and mutated, sent in random pieces. Each must read as a reference parser written from http1.bend's rules says.
5. The cold check on the one-shot examples.

`tests/soak.py` is a longer run, by hand: rounds of every kind of request, while it watches the memory and sockets of the client and of the server.
