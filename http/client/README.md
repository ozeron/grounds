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
| `url.bend` | verbs, `url(s)` (`Url{..}`, or `UBad{}`, which a request reports as `BadUrl`) and `form.enc`: plain values, apart so their laws need no sockets |
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

Both differential servers bind an OS-assigned loopback port and pass a unique
run URL to their Bend clients. Unrelated HTTP probes do not consume corpus
entries. Acceptance requires every server case and client result, exact
reference comparisons, and a successful client exit. `tests/fuzz_harness_test.py`
checks probe isolation and rejects output without served cases as part of the
package gate.

`tests/soak.py` is a longer run, by hand: rounds of every kind of request through a pool, while it watches the memory and sockets of the client and of the server.

## Opt-in Bend TLS (native, synthetic keys)

Import `bend_client.bend` as `C` and `bend_pool.bend` as `Pool`. These are separate
entry modules with their own Config/request/reply types. The legacy `client.bend`
and `pool.bend` APIs and cold graphs stay unchanged; OpenSSL remains their default.
No environment variable switches a legacy program to Bend TLS.

Construct admission inputs with `bend_transport.from_pem(normalization_bytes,
profile_bytes, anchor_pems, Clock{civil_seconds, monotonic_ms})`. `anchor_pems`
contains 1..16 explicit PEM certificates, one certificate per byte list. The
Unicode bytes are the pinned `crypto/unicode32_nfkc.bin` and
`crypto/unicode32_prepare.bin`; Bend authenticates them before chain verification.
Read files with OS byte IO, never a host TLS/crypto helper. `Clock` pairs a trusted
wall-clock sample (UTC seconds since 0001-01-01) with the corresponding `IO.now()`
millisecond sample. Each handshake advances that sample by elapsed monotonic
seconds. Resample when wall-clock corrections matter for a long-lived process.

For larger trust stores, `from_bundle(normalization, profile, pem_bytes, clock)`
and `from_bundle_file(normalization, profile, path, clock)` admit 1..256 roots
from one PEM bundle of at most 2 MiB; a malformed or duplicate entry fails the
whole load.

To trust the host's CA bundle, call it explicitly:
`from_system_bundle(normalization, profile, clock)` returns
`IO(R(System{path, policy}))`. It reads `SSL_CERT_FILE` if set and non-empty
(no fallback if that file is missing), else the first of
`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`,
`/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`, `/etc/ssl/ca-bundle.pem`
and `/etc/ssl/cert.pem` that opens, and reports that `path`.
`from_system_bundle_paths(normalization, profile, candidates, clock)` takes
the list from the caller. System files keep the bundle limits and whole-load
rejection, but byte-identical duplicates are dropped and OpenSSL
`TRUSTED CERTIFICATE` blocks are skipped, never trusted (NixOS ships them).
On macOS this is `/etc/ssl/cert.pem`: Keychain trust settings and user-added
roots are not seen. Nothing else, including `default`, reads host trust.
Details and measurements: [TLS_PROFILE.md](../../TLS_PROFILE.md), version 3.

`from_pem` returns the existing legacy `R(Policy)` / `Err`. Pass a successful
policy to `C.default(policy)`, then use the usual builders, Config setters,
send/send_ok/send_json, stream, events/events_retry and pool calls. The convenience
calls are `C.fetch(cfg,url)` and `C.fetch_json(A,cfg,url,decoder)` because trust
inputs are required. `tests/bend_tls.bend` is a complete runnable example.

TLS 1.3 uses the frozen [profile](../../TLS_PROFILE.md), always offers ALPN
`http/1.1`, derives SNI and SAN verification identity from each destination URL,
and maps verification/protocol errors to the **same** legacy `Err` type
(`Tls{why}`, preserving `certificate:` + `x509_chain.show(reason)`). IPv4 literals
use IP SANs without SNI. The existing URL parser supports DNS and IPv4, not IPv6
URL literals. No ambient roots (host roots only through `from_system_bundle`), verification bypass or TLS fallback is provided.
An HTTPS-to-HTTPS redirect opens/reuses only that destination's origin and
re-verifies every new connection; private headers are stripped as before.

### Real-world behaviour of the Bend TLS client (M6)

`CLIENT_AUDIT.md` compares this path with RFC 9110/9112. The pure rules
live in `policy.bend`, which `test.bend` checks without sockets.

- **Deadlines:** `timeout_ms` still bounds the whole call. Two new
  options are off (0) by default. `C.with_connect_timeout(cfg, ms)` bounds
  each TCP connect and TLS handshake, per new connection.
  `C.with_read_timeout(cfg, ms)` bounds each read of a head or body, in
  `send`, `stream` and `events`, pooled or not, so a stalled server fails
  fast while a slow download that keeps arriving is not cut short. It
  never bounds a write: a slow upload that keeps going is bounded by
  `timeout_ms` only. Waiting for a connection of a full pool ends at the
  total deadline (`Timeout`), and a retry whose backoff would reach it
  is not made: the last outcome is returned at once.
  `C.with_max_head(cfg, n)` sets the head limit. DNS resolution is not
  bounded; it is a blocking `wire_resolve`.
- **Requests:** a header whose name is not a token (for example
  `Transfer-Encoding ` with a trailing space, or `X:Y`), or whose value
  holds a control character other than tab, is dropped, like one with
  CR, LF or NUL. A URL's `#fragment` is never sent. No `Accept-Encoding`
  is added. `user-agent: grounds-bend` is added unless the caller sets a
  User-Agent; `C.with_user_agent(cfg, s)` changes it and
  `C.without_user_agent(cfg)` sends none.
- **Responses:** the final status must be 200–599. A 101, a 9th 1xx, or
  a code outside that range is `BadResponse`, and its connection is
  closed. A response with both Content-Length and Transfer-Encoding is
  framed by chunked coding and its connection is never reused (RFC 9112
  §6.3). A Content-Length list of one value (`5, 5`) is that length.
  Conflicting or non-digit Content-Length values,
  Transfer-Encodings other than one `chunked`, obs-fold, bare LF, bad
  chunk sizes and oversized heads are refused. Each case is a live test.
- **Redirects:** a Location may be absolute, network-path (`//host/p`),
  absolute-path, relative (`b?x=1`, `../d`) or query-only. It is resolved
  per RFC 3986 with dot segments removed (for absolute and network-path
  Locations too) and the fragment dropped. A
  scheme other than http(s), or an empty Location, is not followed.
  Authorization, Cookie and Proxy-Authorization are dropped when the
  origin (scheme, host ignoring ASCII case, port) changes, and kept on the
  same origin, even when the Location is absolute. When a 303, or a 301
  or 302 for POST, turns the request into a GET, the body and its
  Content-Type, -Encoding, -Language and -Location headers are dropped.
  307 and 308 keep the method and body for every method.
- **Keep-alive:** the pool reuses a connection per origin. Idle
  connections past `idle_ms`, `Connection: close` responses, HTTP/1.0,
  close-delimited bodies, extra bytes after a body, and CL+TE responses
  are not reused. Only idempotent requests are retried on a stale
  connection. The live tests count the server's connections.
- **Deferred:** chunked or streamed uploads, gzip/deflate, CONNECT
  proxies, and a DNS timeout (see `CLIENT_AUDIT.md`).

The affine TLS owner travels through HTTP framing and the pool. Ordinary calls
retain one absolute deadline through DNS, connect, handshake, writes, reads,
redirects and retries, pool waits and retry backoff included. Streaming/SSE
apply `timeout_ms`, and `read_ms` when set, per read.
Authenticated close_notify can terminate a close-delimited body; bare EOF and
partial records fail as truncation. Pooled safe requests can reconnect once after
a stale connection. Rebuilding affine Unicode tables on new connections adds
startup cost; this path has no session resumption. There is no WebSocket client
in this package. Server WSS is checked with independent Python and Go peers.

`moon run http_client:check --force` also runs the M6 live groups
(`tests/bend_m6_check.py`: framing, redirects, pool, deadlines and stream, 74
scenarios against two independent Python TLS peers). It also runs the native M4b live corpus,
legacy graph audit and emitted C/native symbol/library/loader audit with host TLS
and cookie effects replaced by proven abort controls. Set
`GROUNDS_M4B_CLIENT_ARTIFACTS` to a **new** directory to retain exact outputs and
JSON reports. New Bun client/WSS work is unsupported and ungated; existing Bun
regressions continue. Live credentials remain blocked by `crypto/ERASURE.md`.
