# grounds-http-wire

HTTP/1.1 on the wire for [Bend 2](https://github.com/bendlang/bend), per [RFC 9112](../core/docs/rfc9112.txt): a request parsed from bytes, a response written to bytes. Messages are `grounds-http-core`'s `Request` and `Response`.

```python
import ../http/wire/http1.bend as H1

H1.parse(bytes, max_head_bytes, max_body_bytes)
# Parsed{request, close, rest}: rest is what follows (a pipelined request)
# More{}: not all here yet; read more and parse again
# Bad{err}: refused; answer with H1.status(err), then close
H1.write(response, close)   # the bytes to send
```

## What it accepts

- Lines end in CRLF; a bare CR or LF is refused. One empty line before the request line is skipped (§2.2).
- The request line is exactly `method SP target SP version`. The method is a token, the target has no control chars, and the version is `HTTP/1.1` or `HTTP/1.0`; any other `HTTP/x.y` is `BadVersion` (505).
- A header is `name ":" OWS value OWS`. The name is a token, with nothing between it and the colon; the value holds no control char but tab. A line that starts with white space continues the one before (obs-fold) and is refused (§5.2).
- `Content-Length` is all digits; two that differ are refused (§6.3). `Transfer-Encoding` is `Unsupported` (501) until chunked bodies are read.
- HTTP/1.1 needs exactly one `Host`; HTTP/1.0 at most one (§3.2).
- A head past `max_head_bytes` is `HeadTooLarge` (431); a body past `max_body_bytes` is `BodyTooLarge` (413), refused before it is read.
- `close` is true for `Connection: close`, and for HTTP/1.0 unless `Connection: keep-alive`.

`write` sends the status line, the headers, `content-length`, and `connection: close` or `keep-alive` (an HTTP/1.0 client keeps a connection only when told). A handler's own framing headers (`Content-Length`, `Transfer-Encoding`, `Connection`) are dropped, since the writer decides them, and so is any header with a CR, LF or NUL, which would split the response. `parse_response` reads a response back, for clients and tests.

## Bytes

The parser works on its own `Bytes` list (`B.BNil`, `B.BCon{head, tail}`); `B.of_list` and `B.to_list` convert from and to the `List<U32>` a socket gives. A generic `List<U32>` that is read and then used again makes every List in the program reference counted, where a list type of its own is read without that. Two more rules keep it cold: a classifier copies a byte, `(b + 0 : U32)`, before using it twice, and the writer has its own `head_bytes`, since one def shared by a reader and the writer would share Strings.

## Tests

`test.bend` holds 32 cases: a valid request, each rejection above, incomplete input, a body with a pipelined request after it, and write then `parse_response` giving the response back. That round trip is a test, not a law: a proof would need `U32.show` and digit parsing to invert on any length, which is not cheap in Bend yet. `moon run http1:check` runs the tests, `examples/echo.bend`, and the cold check.
