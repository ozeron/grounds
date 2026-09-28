# grounds-http-client

HTTP/1.1 requests from [Bend 2](https://github.com/bendlang/bend) to other services, over TCP or TLS, with JSON, forms, streamed bodies and server-sent events. It is built on `grounds-wire` sockets and `grounds-http-wire` framing. `docs/API.md` is the design this API follows.

```python
import ../http/client/client.bend as C
import ../http/core/text.bend as T

def said(r: C.R(C.Reply)) -> String:
  match r:
    case Done{rep}:
      T.or(C.utf8(rep), "(not UTF-8)")
    case Fail{e}:
      C.show(e)

def main() -> IO(Unit):
  IO.bind(C.R(C.Reply), Unit, C.fetch("http://orders:8080/orders/7"), r => IO.print(said(r)))
```

## Modules

| Module | Has |
|---|---|
| `client.bend` (`C`) | one-shot requests, and the types every call shares |
| `pool.bend` (`Pool`) | the same verbs through a pool of kept connections |
| `../core/event.bend` (`Ev`) | `Ev.Message{name, data, id}`, the event type the server writes too |

## Building a request

A request is a value. Build it, then send it.

| Call | Gives |
|---|---|
| `get(url)`, `head(url)`, `delete(url)` | a request with no body |
| `post(url, body)`, `put(url, body)`, `patch(url, body)` | a request with that body |
| `method(name, url, body)` | any method; a name that is not a token fails with `BadMethod` |
| `with(req, kv)` | these headers added, in order |
| `bearer(req, token)` | `authorization: Bearer token` added |
| `query(req, kv)` | the pairs added to the url's query, percent-encoded |
| `idempotent(req, key)` | `idempotency-key: key` added, and the request marked safe to retry |

| Body | Sends |
|---|---|
| `empty()` | nothing; `content-length: 0` for POST, PUT and PATCH |
| `text(s)` | `s` in UTF-8, as `text/plain; charset=utf-8` |
| `json(j)` | `J.encode(j)`, as `application/json`, with `accept: application/json` |
| `form(kv)` | the pairs percent-encoded, as `application/x-www-form-urlencoded` |
| `bytes(kind, bs)` | the bytes as they are, with Content-Type `kind` |
| `multipart(boundary, parts)` | binary `multipart/form-data`, with a validated `Mp.Boundary` |

`kv` is a list of `(name, value)` pairs. A body's Content-Type, and `json`'s Accept, are added only when the headers have none.

For multipart, import `../core/multipart.bend as Mp`, construct parts as `Mp.Part{name, filename, kind, body}`, and pass a boundary returned by `Mp.make_boundary(value)` to `C.multipart`. Each part body is a byte list; `filename` and `kind` are optional. Choose a fresh boundary whose delimiter line does not occur in a body. `examples/multipart.bend` sends a binary file part to the server example.

## Sending

The same calls exist in `C`, taking a `Config`, and in `Pool`, taking a pool.

| Call | Gives |
|---|---|
| `send(c, req)` | `R(Reply)`, whatever the status |
| `send_ok(c, req)` | `R(Reply)`; a status other than 2xx is `Status{code, body}` |
| `send_json(A, c, req, dec)` | `R(A)`: a 2xx body decoded by `dec`; an empty body reads as `null` |
| `stream(~f, c, req)` | `R(Head)`; `f(bytes)` gets the body as it is read, and answers `True` to go on |
| `events(~on, c, req)` | `R(Ended)`; `on(message)` gets each event, and answers `True` to go on |
| `events_retry(~on, c, req, n)` | as `events`, reconnecting up to `n` times with `Last-Event-ID` |
| `fetch(url)`, `fetch_json(A, url, dec)` | `send_ok` and `send_json` of a GET, with `default()` |

`R(A)` is `Done{A}` or `Fail{Err}`. `Reply{status, headers, body}` has the body as bytes: read it with `utf8(reply)`, and a header with `header(headers, name)`. `Ended{last_id, reconnects}` says where a stream stopped. `show(err)` says why a call failed.

`Err` is one of `BadUrl`, `BadMethod`, `NoHost`, `Refused{errno}`, `Tls{why}`, `Timeout`, `Closed`, `TooLarge`, `BadResponse`, `Redirects`, `Status{code, body}`, `BadJson`, `BadValue` and `NotEvents{kind}`.

```python
# JSON in, JSON out, typed
r <- C.send_json(Order, cfg, C.post(u, C.json(enc(order))), dec_order)

# a form, with a token
r <- C.send_ok(cfg, C.bearer(C.post(u, C.form([("q", "cups"), ("n", "2")])), token))

# events, resumed after a drop
r <- C.events_retry(~on, cfg, C.get("https://feed/prices"), 10)

# through a pool, closed on every path
x <- Pool.with(C.R(Item), cfg, 8, p => Pool.send_json(Item, p, C.get("http://items/7"), dec_item))
```

## Behaviour

- **Config:** `Config{timeout_ms, max_head_bytes, max_body_bytes, retries, backoff_ms, redirects, idle_ms}`. `default()` gives 10 s, 16 KiB of head, 8 MiB of body, no retries, 5 redirects and a 4 s idle limit. Change it with `with_timeout`, `with_max_body`, `with_retries(n, backoff_ms)`, `with_redirects(n)` and `with_idle(ms)`.
- **Timeout:** one deadline covers the whole call: resolving the host, connecting, the TLS handshake, sending, reading, and every redirect and retry. `stream` and `events` apply it to each read instead.
- **Retries:** off by default. `with_retries(n, ms)` tries a request up to `n` more times on `Refused`, `Timeout` or `Closed`, and on 502, 503 or 504. Only GET, HEAD, PUT, DELETE, OPTIONS, TRACE and `idempotent` requests are retried. The first wait is `ms`, and each wait doubles, up to 5 s.
- **Redirects:** 301, 302, 303, 307 and 308 are followed, up to `redirects` times; one more fails with `Redirects`. A 303, or a 301 or 302 answering a POST, is followed with a GET and no body; otherwise the method and body stay. A redirect from http to https is followed. One from https to http never is, as it would send the next request in clear text, and the 3xx comes back as it is. A redirect to another url drops `Authorization` and `Cookie`. `stream` and `events` do not follow redirects.
- **Pool:** `Pool.open(cfg, n)` keeps up to `n` connections, to any origin; `Pool.close(p)` closes them once each one in use comes back, and `Pool.with` does both. A request takes an idle connection to its own origin, opens one while there is room, closes another origin's oldest idle one when the pool is full, or waits. An idle connection older than `idle_ms` is closed, not used. If the server has closed a kept connection, the request is tried once more on a new one, when it is safe to retry.
- **Events:** `events` adds `accept: text/event-stream` and `cache-control: no-cache`. A status other than 2xx is `Status`, and a Content-Type other than `text/event-stream` is `NotEvents`; `on` is not called in either case. Parsing follows WHATWG's event stream format: CR, LF or CRLF lines, a leading BOM dropped, `data:` lines joined with LF, `message` when there is no `event:`, ids carried to later events, `:` comments skipped. `events_retry` waits the server's `retry:` value, or `backoff_ms` doubling up to 5 s. It sends the last id a blank line confirmed, and does not reconnect after `on` answers `False`, `Status` or `NotEvents`.
- **TLS:** `https://` urls use OpenSSL 3, loaded at run time. The certificate chain and the host name are always checked, and TLS 1.2 is the floor. `GROUNDS_TLS_CA` names a PEM file to trust as well as the system's roots.
- **Framing:** a response is read by Content-Length, chunked coding, or to the close when it has neither. Up to 8 1xx responses are skipped. There is no body after HEAD, or on a 204 or 304.
- **Safety:** you cannot set Host, Content-Length, Transfer-Encoding or Connection; the client writes them. A header with CR, LF or NUL in its name or value is dropped. A url whose target or host has one is `BadUrl`.
- **Counting:** the basic one-shot request examples are cold: no value is reference counted. The multipart builder makes some String constructors reference counted. A pool passes its connections through a channel, and a channel counts what it carries, so a program that uses `Pool` is partly counted. Measured on 5000 local GETs: one-shot requests run 1–14% slower in a program that also uses a pool, and the pool is about 1.8× faster than one-shot, from keep-alive.

## Laws

`LAWS.bend`, proven in `PROOF.bend`:
- `url_target`, `url_authority`, `check_target`, `check_authority`: a url the client takes, or follows in a redirect, has no CR, LF or NUL in its target or its Host.
- `method_clean`: a method the client sends has none either.
- `request_safe`: combined with http/wire's `request_head`, the head the client writes for any method, url and headers has one empty line, at its end, and CR or LF only where a line ends. `with`, `bearer`, `query` and `idempotent` reach the same writer.
- `form_reads_back`: `form(kv)` decodes, with core's query parser, to the same pairs, for names and values of unreserved chars. Escaped chars are covered by the unit tests.

`http/core` proves `sse_reads_back`: the events the server writes parse back, with the parser `events` uses, to the same names, data and ids. `http/wire` proves `body_length` and `chunked_reads_back`.

## Checks

`moon run http_client:check`:
1. The URL unit tests and the proofs.
2. `tests/live.bend` against `tests/fake.py` and the server's `examples/stream`: framing, faults and every builder.
3. `tests/more.bend`: the pool, keep-alive and stale connections, retries, each redirect code, JSON, streams and TLS. Every case must print its line from `tests/more.out`.
4. `tests/events.bend`: event streams, stops, errors and reconnects, as `tests/events.out`.
5. `tests/fuzz.py`: 2000 random responses, valid and mutated, sent in random pieces. Each must read as a reference parser written from http1.bend's rules says.
6. `tests/fuzz_events.py`: 1000 random event streams, chunked or to the close, in pieces that split UTF-8 chars. Each must read as a reference parser written from WHATWG's rules says.
7. The cold check on `tests/live.bend` and the four examples: `get`, `json`, `stream` and `events`.

`tests/soak.py` is a longer run, by hand: rounds of every kind of request through a pool, while it watches the memory and sockets of the client and of the server.
