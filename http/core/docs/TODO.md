# grounds-http-core: plan

Specs in this folder: [RFC 9110](rfc9110.txt) (HTTP semantics), [RFC 9112](rfc9112.txt) (HTTP/1.1), [RFC 3986](rfc3986.txt) (URIs), [RFC 6265](rfc6265.txt) (cookies).

## Packages, in build order

1. [x] **wire**: byte-exact TCP (`../wire`), after `bend-kit-wire`. Base's `TCP.send` and `TCP.recv` take and give `String`, decoded as UTF-8, which is not binary-safe. `bend-kit-wire` on BendHub (`0x096635686408886b7d907f16c4550317`) has byte-exact TCP, UDP and TLS; reuse or learn from it.
2. [x] **http**: methods, status, headers, query, request and response (this package, scaffolded).
3. [x] **http1** (`../http1`): request heads and Content-Length bodies parsed, responses written, malformed input refused (RFC 9112). [x] Chunked coding (§7); trailers read and dropped.
4. [x] **http_server** (`../http_server`): accept loop, a spawned computation per connection, keep-alive and pipelining, `serve(handler, config)` with head, body and request limits. [x] Idle and request timeouts, graceful shutdown, streamed responses, health, env config and server TLS.
5. [ ] **http_json**: `decode(req, decoder)` (checks Content-Type, the body limit, parse and decode errors, as `DecodeError{UnsupportedContentType, BodyTooLarge, InvalidJson, InvalidValue}`) and `response(status, encode, value)`.
6. [x] **http_router** (`../http_router`): routes as data, `route_req(routes, req)` gives `Found{route, params}`, `NotFound` or `MethodNotAllowed{allowed}`.
7. [ ] **http_middleware**: `BodyLimit`, `RequestId`, `Logger`, `Timeout`, `Recover`; later compression, rate limits and forwarded headers. Auth and CORS are complete.
8. [x] **http_client** (`../client`): one deadline, size limits, a pool with keep-alive, retries, redirects, JSON, streamed downloads, TLS; laws against injection; a response fuzzer and a soak test.
9. [x] Cookies (RFC 6265, SameSite per 6265bis).
10. [ ] Later: forms, multipart, streamed request bodies, WebSockets, a cold pool and IPv6.

## http, against RFC 9110

- [x] Methods, case-sensitive (§9.1); unknown ones kept as `MOther`
- [x] Status codes and reason phrases for the common ones (§15)
- [x] Header fields in order, repeats kept, names case-insensitive (§5.1, §5.3)
- [x] `get`, `all`, `add`, `set`, `remove` on headers
- [x] Query pairs with repeats, `%XX` and `+` decoded, UTF-8 checked (RFC 3986 §2.1, application/x-www-form-urlencoded)
- [x] Request: method, target, headers, body bytes; `path`, `query`, `header`
- [x] Response: status, headers, body bytes; `text`, `html`, `bytes`, `empty`, `redirect` (303), `not_found`, `bad_request`, `header`
- [x] Cookies: first matching `Cookie` pair; safe `Set-Cookie` and clear defaults; HMAC-SHA256 signatures
- [x] Bearer and UTF-8 Basic credential parsing, duplicate Authorization rejection and authenticated principal handoff
- [x] CORS allowlist decisions and safe credential handling, with 204 preflight and `Vary: Origin`
- [ ] Header value rules: trim optional white space, reject CR, LF and NUL (§5.5)
- [ ] Field list values: split `a, b` into items for `all` where the header is a list (§5.6.1)
- [ ] Target forms beyond origin-form: absolute-form, authority-form, asterisk-form (RFC 9112 §3.2)
- [ ] Path percent-decoding and normalisation, dot segments (RFC 3986 §5.2.4)
- [ ] `Content-Type` parsing: media type and parameters (§8.3)
- [ ] Laws: `get` finds the first of repeated names; `set` leaves exactly one; `parse(show(m)) == m`

## Measured (M1 tests 1 and 2)

- Middleware as nested templates works: `run(~rec.wrap(~log.wrap(~app)), x)` typechecks and runs, so a wrapper is a def taking `~next`.
- Route tables: rebuilt per request (`routes()`) stays cold; one table reused makes Lists and all they hold reference counted.

## Open design questions

- Accessors take a request whole (single-use values). Is matching on `Request{…}` enough, or should reads hand the request back, like `Array.get` does?
- Middleware composition syntax: test whether Bend templates (`~handler`) allow `Middleware.apply(req, ~routes, ~Recover.wrap, …)` before fixing the API.
- `Body`: bytes for v1; a stream type later without breaking `Request` and `Response`.
