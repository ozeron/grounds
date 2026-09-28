# grounds-http-client: API v2

The target API for the client, with POST and server-sent events. It replaces the v1 calls in `client.bend`. Nothing here is built yet. Build order is at the end.

## Goals

- A request is a value you build. One `send` runs it.
- The same verbs work through one-shot connections and through a pool. Only the module prefix changes.
- There is one error type, whatever the call.
- Imports are few. You never need `M.MGet{}`, `H.Header{…}` or `S.Status{…}` to make a call or read a reply.
- A program that never uses a pool stays cold: no value is reference counted.

## Bend constraints the design follows

- There are no named fields and no defaults. Records stay small, and setters add the rest.
- There are no pipes and no methods. Calls nest, so a common call needs at most two levels.
- A function value can be used only once. A callback is a template (`~f`), and a template cannot take a type parameter. So a callback's argument types are fixed: `Event`, `Head`, bytes.
- A pool passes connections through a channel, and a channel counts what it carries. So the pool has its own module. That keeps pool code out of programs that do not use it.

## Modules

```python
import ../http/client/client.bend as C     # one-shot requests, the shared types
import ../http/client/pool.bend as Pool    # the same verbs through a pool
```

## Types

```python
# name and value; a list of them is how headers, query and form fields are written
def Kv() -> Type:
  List<&1, String & String>

type Body is Type:
  Empty{}
  Bytes{kind: String, bytes: List<&2, U32>}   # kind is the Content-Type
  Text{text: String}                          # text/plain; charset=utf-8
  Json{value: J.Json}                         # application/json
  Form{fields: Kv()}                          # application/x-www-form-urlencoded

type Req is Type:
  Req{method: M.Method, url: String, headers: Kv(), body: Body, key: Maybe<&2, String>}

type Reply is Type:
  Reply{status: U32, headers: Kv(), body: List<&2, U32>}

# a streamed reply's start, before its body
type Head is Type:
  Head{status: U32, headers: Kv()}

type Event is Type:
  Event{name: String, data: String, id: Maybe<&2, String>}

type Err is Data:
  BadUrl{}             # not http[s]://host[:port][/path][?query]
  BadMethod{}          # a method name that is not a token
  NoHost{}             # the host name did not resolve
  Refused{code: U32}   # the connection failed, with errno
  Tls{why: String}     # the TLS handshake failed
  Timeout{}            # past timeout_ms
  Closed{}             # the server closed before the reply was whole
  TooLarge{}           # past max_head_bytes or max_body_bytes
  BadResponse{}        # not HTTP/1.1 as RFC 9112 frames it
  Redirects{}          # more redirects than the config follows
  Status{code: U32, body: String}   # send_ok, send_json, events: not 2xx
  BadJson{err: J.Error}             # send_json: the body is not JSON
  BadValue{err: J.Access}           # send_json: the JSON is not the value asked for
  NotEvents{kind: String}           # events: the Content-Type is not text/event-stream

def R(-A: Type) -> Type:
  Result<&1, &1, Err, A>
```

`Config` stays as it is: `default()`, `with_timeout`, `with_max_body`, `with_retries`, `with_redirects` and `with_idle`.

## Building requests

| Call | Gives |
|---|---|
| `C.get(url)`, `C.head(url)`, `C.delete(url)` | a request with an empty body |
| `C.post(url, body)`, `C.put(url, body)`, `C.patch(url, body)` | a request with that body |
| `C.method(name, url, body)` | any method; a name that is not a token makes `send` fail with `BadMethod` |
| `C.with(req, kv)` | the request with these headers added, in order |
| `C.bearer(req, token)` | `authorization: Bearer token` added |
| `C.query(req, kv)` | the pairs added to the url's query, percent-encoded |
| `C.idempotent(req, key)` | `idempotency-key: key` added, and the request marked safe to retry |

| Body | Sends |
|---|---|
| `C.empty()` | nothing; `content-length: 0` for POST, PUT and PATCH |
| `C.text(s)` | `s` in UTF-8, `text/plain; charset=utf-8` |
| `C.json(j)` | `J.encode(j)`, `application/json` |
| `C.form(kv)` | the pairs percent-encoded, `application/x-www-form-urlencoded` |
| `C.bytes(kind, bs)` | the bytes as they are, with Content-Type `kind` |

Rules:
- A body sets Content-Type unless the request's headers already have one.
- You cannot set Host, Content-Length, Transfer-Encoding or Connection. The client writes them.
- `json` also sets `accept: application/json` unless an Accept header is there.

## Sending

The same four calls exist in `C`, taking a `Config`, and in `Pool`, taking a `Pool`:

| Call | Gives |
|---|---|
| `send(c, req)` | `R(Reply)`, with any status |
| `send_ok(c, req)` | `R(Reply)`; a status other than 2xx is `Status{code, body}` |
| `send_json(A, c, req, dec)` | `R(A)`: 2xx, then the body decoded by `dec`; an empty body reads as `null` |
| `stream(~f, c, req)` | `R(Head)`; `f(bytes)` gets the body as it is read |

`stream` checks the status first. A reply that is not 2xx is `Status{code, body}`, and `f` is not called. `f` answers `True` to go on and `False` to stop.

Short forms, for the common calls through `C` with `default()`:

| Call | Is |
|---|---|
| `C.fetch(url)` | `send_ok(default(), get(url))` |
| `C.fetch_json(A, url, dec)` | `send_json(A, default(), get(url), dec)` |

## POST

```python
# JSON in, JSON out, typed
r <- C.send_json(Order, cfg, C.post(u, C.json(enc(order))), dec_order)

# a form, with a token
r <- C.send_ok(cfg, C.bearer(C.post(u, C.form([("q", "cups"), ("n", "2")])), token))

# safe to retry: the server deduplicates on the key
r <- C.send_ok(C.with_retries(cfg, 3, 100), C.idempotent(C.post(u, C.json(j)), key))
```

Retry rules stay the same: GET, HEAD, PUT, DELETE, OPTIONS and TRACE, plus any request marked `idempotent`. A pooled request on a kept connection that the server closed is tried once more on a new one, under the same rule.

## Server-sent events, client side

```python
def on(ev: C.Event) -> IO(Bool):
  IO.bind(Unit, Bool, IO.print(C.event.data(ev)), u => IO.pure(Bool, True{}))

r <- C.events(~on, cfg, C.get(u))          # R(C.Ended)
```

| Call | Does |
|---|---|
| `events(~on, c, req)` | reads the stream until it ends or `on` answers `False` |
| `events_retry(~on, c, req, n)` | as `events`, reconnecting up to `n` times, with `Last-Event-ID` |

```python
type Ended is Type:
  Ended{last_id: Maybe<&2, String>, reconnects: U32}
```

Behaviour:
- `accept: text/event-stream` and `cache-control: no-cache` are added.
- A status other than 2xx is `Status{code, body}`. A Content-Type other than `text/event-stream` is `NotEvents{kind}`. `on` is not called in either case.
- Parsing follows the WHATWG event stream format:
  - Lines end in CR, LF or CR LF. A BOM at the start is dropped.
  - `data:` lines join with LF. A blank line dispatches the event.
  - An event with no `data:` line is dropped.
  - `event:` sets the name, which is `message` when absent.
  - `id:` sets the id, and the id carries over to later events. An id with a NUL is ignored.
  - `retry:` with digits sets the reconnect delay.
  - A line that starts with `:` is a comment, as heartbeats are, and is skipped.
  - One space after the colon is dropped.
- `timeout_ms` applies to each read, not to the whole stream.
- `events_retry` waits the server's `retry:` value, or `backoff_ms` doubling up to 5 s. It sends the last id as `Last-Event-ID`. It does not reconnect after `on` answers `False`, after `Status`, or after `NotEvents`.
- Accessors: `C.event.name(ev)`, `C.event.data(ev)` and `C.event.id(ev)` read one field each. Match `Event{name, data, id}` to read several.

## Server-sent events, server side

Additions to `http/server`, with the current `event` and `named` kept as wrappers:

| Call | Does |
|---|---|
| `Server.emit(k, Event{name, data, id})` | writes one event; data with LFs becomes several `data:` lines |
| `Server.retry(k, ms)` | writes `retry: ms` |
| `Server.ping(k)` | writes a `:` comment line, a heartbeat |
| `Server.last_id(req)` | the request's `Last-Event-ID`, if any |
| `Server.live(k)` | False once a write has failed: the client is gone |
| `Server.sse.every(~tick, ms, k)` | calls `tick(k)` every `ms`, sending a heartbeat when it writes nothing, until `live(k)` is False |

The server and the client share one `Event` type, from `http/core`, so a service can relay events without converting them.

## Pools

| Call | Does |
|---|---|
| `Pool.open(cfg, n)` | a pool of up to `n` kept connections, for any origin |
| `Pool.with(A, cfg, n, f)` | opens a pool, runs `f(pool)`, gives its `A`, and closes the pool on every path |
| `Pool.close(p)` | closes it once each connection in use comes back |
| `Pool.send`, `send_ok`, `send_json`, `stream`, `events`, `events_retry` | as in `C`, through the pool |

Behaviour:
- A request takes an idle connection to its own origin. If it finds none, it opens a new one while there is room. If the pool is full, it closes the idle connection to another origin that has waited longest, and opens a new one in its place. If every connection is in use, it waits.
- An idle connection older than `idle_ms` is closed, not used.
- `stream`, `events` and `events_retry` hold their connection until the body ends.
- Programs that use `Pool` are partly reference counted. See the measured numbers in `../README.md`.

## Reading replies

| Call | Gives |
|---|---|
| `C.utf8(reply)` | the body as a `Maybe` String, when it is UTF-8 |
| `C.header(kvs, name)` | the first value of `name`, ignoring case |
| `C.show(err)` | why a call failed, as text |

A `Reply` is read once. To use several parts, match `Reply{status, headers, body}`.

## Examples

```python
# GET with a header, 5 s
r <- C.send_ok(C.with_timeout(C.default(), 5000), C.with(C.get(u), [("x-trace", id)]))

# typed JSON through a pool
x <- Pool.with(C.R(Item), cfg, 8, p => Pool.send_json(Item, p, C.get("http://items/7"), dec_item))

# a large download
r <- C.stream(~write_piece, cfg, C.get("https://files/big.bin"))

# events, with resume
r <- C.events_retry(~on, cfg, C.bearer(C.get("https://feed/prices"), token), 10)
```

## Laws

The v1 laws are kept:
- `request_safe` still holds for requests built with `with`, `query`, `bearer` and `idempotent`. They reach the same writer.
- `chunked_reads_back` still covers streamed bodies.

New laws:
- `sse_reads_back`: the events `Server.emit` writes parse back, with `C.events`' parser, to the same names, data and ids. This holds for data with LFs, and for data that holds text such as `data:` or `id:`.
- `form_reads_back`: `C.form(kv)` decodes, with core's query parser, to the same pairs.
- `body_length`: the Content-Length that `send` writes is the length of the body bytes it sends.

## Build order

1. `Req`, `Body`, `Reply`, the merged `Err`, and `send`, `send_ok` and `send_json` in `C`. Port `tests/live.bend` and `tests/more.bend`.
2. `pool.bend` with the any-origin pool and `Pool.with`. Port the pool tests.
3. The rest of the builders: bodies, `with`, `bearer`, `query` and `idempotent`, then `stream`.
4. The SSE parser and `events` and `events_retry`, with a Python fake stream in the tests.
5. The server additions and the shared `Event`.
6. `sse_reads_back`, `form_reads_back` and `body_length`, proven. Then extend the fuzzer to event streams.

Remove v1's `get`, `post`, `request`, `get_json`, `post_json`, `download`, `pool.get` and `send` in step 1. Only tests and examples use them.
