# grounds-http-core

HTTP messages for [Bend 2](https://github.com/bendlang/bend), per [RFC 9110](docs/rfc9110.txt): methods, status codes, headers, query strings, requests and responses. The message types are used by `grounds-http-wire` (the wire format), `grounds-http-server` (`serve`), `grounds-http-router` and `grounds-http-json`.

```python
import ../http/core/request.bend as Req
import ../http/core/response.bend as Res
import ../http/core/status.bend as S
import ../http/core/headers.bend as H

def handle(r: Req.Request) -> Res.Response:
  match r:
    case Req.Request{_, _, hs, _}:
      Res.header(Res.text(S.ok(), greet(H.get(hs, "x-name"))), "cache-control", "no-store")
```

## Modules

| File | Holds |
|---|---|
| `method.bend` | `Method`: `MGet`, `MPost`, …, `MOther{name}`; `parse`, `show` (case-sensitive, §9) |
| `status.bend` | `Status{code}`, `ok()`, `permanent_redirect()` (308), `not_found()`, `request_timeout()`, …, `reason` (§15) |
| `headers.bend` | `Header{name, value}` in order; `get` (first), `all`, `add`, `set`, `remove`; names compare ignoring case (§5) |
| `query.bend` | `Param{key, value}` pairs, repeats kept; `parse` decodes `%XX` and `+`; `get` (first) |
| `request.bend` | `Request{method, target, headers, body}`; `path`, `query`, `param` (a query value), `header`, `body` |
| `response.bend` | `Response{status, headers, body}`; `new`, `empty`, `ok`, `bytes`, `text`, `html`, `redirect`, `not_found`, `bad_request`, `header` |
| `text.bend` | compares and cuts Strings by reading only; `or(maybe, default)`, `u32(digits)` |
| `event.bend` | server-sent events: `Message{name, data, id}`, which the server writes and the client reads; `write`, `retry`, `ping`, and the WHATWG parser `feed` |
| `cookie.bend` | `get(req, name)`, `set(res, name, value)`, `clear(res, name)`, and HMAC-SHA256 `sign(key, value)` / `verify(key, signed)` |
| `auth.bend` | strict Bearer and UTF-8 Basic credentials, duplicate detection, `Principal{subject, claims}` |
| `cors.bend` | CORS allowlist policy, origin decisions, request field inspection and preflight header validation |

Bodies are bytes (`List<U32>`, 0..255). Text goes through `grounds-utf8`.

## Cookies

`Ck.set(res, name, value)` adds a separate `Set-Cookie` header with `Path=/; HttpOnly; Secure; SameSite=Lax`. `Ck.clear(res, name)` uses the same scope and `Max-Age=0`. An empty name leaves the response alone. Names and values are percent-encoded from UTF-8 where needed to fit the cookie grammar; `Ck.get(req, name)` reads the first matching pair across `Cookie` headers, decodes that format and returns `None{}` for malformed encoding. The name match is case-sensitive. [RFC 6265](docs/rfc6265.txt) defines the original cookie grammar; [6265bis](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis) defines `SameSite`.

`Ck.sign(key, value)` returns `IO(Result)` with `value.<64 lowercase hex digits>`; `Ck.verify(key, signed)` returns `IO(Result)` containing `Some{value}` only for a valid HMAC-SHA256 signature. A malformed or incorrect signature gives `Done{None{}}`; an unavailable crypto library gives `Fail`. The native target loads OpenSSL 3 `libcrypto` at run time (`BEND_LIBCRYPTO` overrides its path); the JS target returns ENOSYS. Use a random secret key of at least 32 bytes and separate keys or signed purpose tags when several cookie types share an application.

## Authentication credentials

`Auth.parse_header(value)` parses an RFC 6750 Bearer token or RFC 7617 Basic user/password pair into `Got{Credential}`. Bearer tokens must follow the RFC token grammar; Basic uses strict, canonical Base64 and UTF-8, rejects control characters and requires the first colon to divide user from password. Malformed values have `BadBearer{}` or `BadBasic{}`; unknown schemes have `Unsupported{}`. `Auth.take(req)` also rejects repeated Authorization fields and returns the request with Authorization removed. `Principal{subject, claims}` is supplied only by an application verifier, through [server middleware](../server/README.md#middleware). Serve Basic credentials over TLS. The verifier can apply any required Unicode normalization or account policy.

## CORS policy

`Cors.Policy{origins, credentials, methods, headers, max_age}` holds serialized allowed origins (or `"*"`), case-sensitive methods, case-insensitive allowed header names, and a preflight cache age in seconds. `Cors.decide` returns `Exact{origin}`, `Any{}` or `Deny{}`; it rejects unsafe Origin field values. `Cors.header_value` validates a requested header list and returns a normalized list from the configured names. The `cors_safe` law proves that exact results come from the allowlist and that wildcard results require an explicit `"*"` with credentials disabled.

## Design

- **HTTP knows nothing about JSON.** It deals in bytes, headers, content types and lengths. `http_json` bridges the two, so the server serves protobuf, images or HTML just as well.
- **Layers, not one package.** Routing is not HTTP: a router maps a method and target to a route, and the server maps requests to responses. Each layer is its own package.
- **The router returns data.** It matches a request to a route value from your own type plus params, and your code dispatches with an exhaustive `match`. It stores no handler functions, which Bend's single-use values make awkward, and routing stays pure and testable.
- **Middleware composes at compile time.** A middleware is a handler that takes the next handler; there is no runtime list of functions.
- **Two error levels.** Protocol errors (a bad request line, a bad `Content-Length`, a bad chunk) stay inside HTTP/1.1 and become responses or a closed connection. Applications see only data errors: a JSON decode failure, no route, a bad query.
- **Limits are explicit.** The server reads a body only up to its configured limit; nothing allocates without bound.
- **A request is used once.** Bend values are single-use, so an accessor like `Req.path(r)` takes the request whole. To read several parts, match on `Request{method, target, headers, body}`.
- **Cold baseline.** The basic HTTP helpers keep Strings free of reference counting in `examples/hello.bend`, as `check.sh` verifies. CORS policy lookups currently share Strings and Lists when one policy is checked against several names.

`moon run http:check` runs the tests, examples, HMAC vectors checked against Python, and cold checks.

**Laws.** `LAWS.bend`, proven in `PROOF.bend`: `same_ci` is equality of the lowercased Strings; a header is found under any spelling of its name, and its first value is the one read; a query key's first value is the one read. `set_cookie_clean`: every value `set` writes has no CR or LF. `cors_safe`: the CORS decision never selects an unlisted origin or a wildcard with credentials. `sse_reads_back`: events `write` makes, `feed` reads back as the same names, data and ids, for any name and id with no CR or LF and any data with no CR, `data:` or `id:` text inside it included. `write_joins`: events written one at a time make the same stream as written together.
