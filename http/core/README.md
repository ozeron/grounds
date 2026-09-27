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
| `status.bend` | `Status{code}`, `ok()`, `not_found()`, `request_timeout()`, …, `reason` (§15) |
| `headers.bend` | `Header{name, value}` in order; `get` (first), `all`, `add`, `set`, `remove`; names compare ignoring case (§5) |
| `query.bend` | `Param{key, value}` pairs, repeats kept; `parse` decodes `%XX` and `+`; `get` (first) |
| `request.bend` | `Request{method, target, headers, body}`; `path`, `query`, `param` (a query value), `header`, `body` |
| `response.bend` | `Response{status, headers, body}`; `new`, `empty`, `ok`, `bytes`, `text`, `html`, `redirect`, `not_found`, `bad_request`, `header` |
| `text.bend` | compares and cuts Strings by reading only; `or(maybe, default)`, `u32(digits)` |

Bodies are bytes (`List<U32>`, 0..255). Text goes through `grounds-utf8`.

## Design

- **HTTP knows nothing about JSON.** It deals in bytes, headers, content types and lengths. `http_json` bridges the two, so the server serves protobuf, images or HTML just as well.
- **Layers, not one package.** Routing is not HTTP: a router maps a method and target to a route, and the server maps requests to responses. Each layer is its own package.
- **The router returns data.** It matches a request to a route value from your own type plus params, and your code dispatches with an exhaustive `match`. It stores no handler functions, which Bend's single-use values make awkward, and routing stays pure and testable.
- **Middleware composes at compile time.** A middleware is a handler that takes the next handler; there is no runtime list of functions.
- **Two error levels.** Protocol errors (a bad request line, a bad `Content-Length`, a bad chunk) stay inside HTTP/1.1 and become responses or a closed connection. Applications see only data errors: a JSON decode failure, no route, a bad query.
- **Limits are explicit.** The server reads a body only up to its configured limit; nothing allocates without bound.
- **A request is used once.** Bend values are single-use, so an accessor like `Req.path(r)` takes the request whole. To read several parts, match on `Request{method, target, headers, body}`.
- **Shares no String.** Every helper reads Strings without keeping them, so a program using http keeps Strings free of reference counting; `check.sh` verifies it on `examples/hello.bend`.

`moon run http:check` runs the tests, the example and the cold check.
