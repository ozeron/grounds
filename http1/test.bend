import Base
import ./http1.bend as H1
import ./bytes.bend as B
import ../http/method.bend as M
import ../http/status.bend as S
import ../http/headers.bend as H
import ../http/request.bend as Req
import ../http/response.bend as Res

# each def is a test: it checks only if both sides compute to the same value

def b(s: String) -> B.Bytes:
  H1.to_bytes(s)

def p(s: String) -> H1.Parsed:
  H1.parse(b(s), 200, 16)

def P() -> Type:
  H1.Parsed

def get_ok() -> {p("GET /?name=x HTTP/1.1\r\nHost: localhost\r\nUser-Agent: curl\r\n\r\n") == H1.Parsed{Req.Request{M.MGet{}, "/?name=x", [H.Header{"Host", "localhost"}, H.Header{"User-Agent", "curl"}], []}, False{}, b("")} : P()}:
  {==}

def value_trimmed() -> {p("GET / HTTP/1.1\r\nHost: \t x \r\n\r\n") == H1.Parsed{Req.Request{M.MGet{}, "/", [H.Header{"Host", "x"}], []}, False{}, b("")} : P()}:
  {==}

def leading_crlf() -> {p("\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n") == H1.Parsed{Req.Request{M.MGet{}, "/", [H.Header{"Host", "x"}], []}, False{}, b("")} : P()}:
  {==}

def body_and_rest() -> {p("POST /u HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabcGET") == H1.Parsed{Req.Request{M.MPost{}, "/u", [H.Header{"Host", "x"}, H.Header{"Content-Length", "3"}], [97, 98, 99]}, False{}, b("GET")} : P()}:
  {==}

def conn_close() -> {p("GET / HTTP/1.1\r\nHost: x\r\nConnection: Keep-Alive, close\r\n\r\n") == H1.Parsed{Req.Request{M.MGet{}, "/", [H.Header{"Host", "x"}, H.Header{"Connection", "Keep-Alive, close"}], []}, True{}, b("")} : P()}:
  {==}

def http10_closes() -> {p("GET / HTTP/1.0\r\n\r\n") == H1.Parsed{Req.Request{M.MGet{}, "/", [], []}, True{}, b("")} : P()}:
  {==}

def http10_keep() -> {p("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n") == H1.Parsed{Req.Request{M.MGet{}, "/", [H.Header{"Connection", "keep-alive"}], []}, False{}, b("")} : P()}:
  {==}

def more_head() -> {p("GET / HTTP/1.1\r\nHost:") == H1.More{} : P()}:
  {==}

def more_cr() -> {p("GET / HTTP/1.1\r") == H1.More{} : P()}:
  {==}

def more_body() -> {p("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nab") == H1.More{} : P()}:
  {==}

def bare_lf() -> {p("GET / HTTP/1.1\nHost: x\n\n") == H1.Bad{H1.BadLine{}} : P()}:
  {==}

def bare_cr() -> {p("GET / HTTP/1.1\rHost: x\r\n\r\n") == H1.Bad{H1.BadLine{}} : P()}:
  {==}

def two_spaces() -> {p("GET  / HTTP/1.1\r\nHost: x\r\n\r\n") == H1.Bad{H1.BadLine{}} : P()}:
  {==}

def not_version() -> {p("GET / FOO\r\nHost: x\r\n\r\n") == H1.Bad{H1.BadLine{}} : P()}:
  {==}

def bad_version() -> {p("GET / HTTP/2.0\r\nHost: x\r\n\r\n") == H1.Bad{H1.BadVersion{}} : P()}:
  {==}

def bad_method() -> {p("G(T / HTTP/1.1\r\nHost: x\r\n\r\n") == H1.Bad{H1.BadLine{}} : P()}:
  {==}

def space_before_colon() -> {p("GET / HTTP/1.1\r\nHost : x\r\n\r\n") == H1.Bad{H1.BadHeader{}} : P()}:
  {==}

def no_colon() -> {p("GET / HTTP/1.1\r\nHost x\r\n\r\n") == H1.Bad{H1.BadHeader{}} : P()}:
  {==}

def ctl_in_value() -> {p("GET / HTTP/1.1\r\nHost: a\u{1}b\r\n\r\n") == H1.Bad{H1.BadHeader{}} : P()}:
  {==}

def obs_fold() -> {p("GET / HTTP/1.1\r\nHost: x\r\nX-A: a\r\n b\r\n\r\n") == H1.Bad{H1.ObsFold{}} : P()}:
  {==}

def two_lengths() -> {p("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab") == H1.Bad{H1.BadLength{}} : P()}:
  {==}

def same_lengths() -> {p("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na") == H1.Parsed{Req.Request{M.MPost{}, "/", [H.Header{"Host", "x"}, H.Header{"Content-Length", "1"}, H.Header{"Content-Length", "1"}], [97]}, False{}, b("")} : P()}:
  {==}

def length_not_digits() -> {p("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1a\r\n\r\n") == H1.Bad{H1.BadLength{}} : P()}:
  {==}

def length_empty() -> {p("POST / HTTP/1.1\r\nHost: x\r\nContent-Length:\r\n\r\n") == H1.Bad{H1.BadLength{}} : P()}:
  {==}

def no_host() -> {p("GET / HTTP/1.1\r\n\r\n") == H1.Bad{H1.BadHost{}} : P()}:
  {==}

def two_hosts() -> {p("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n") == H1.Bad{H1.BadHost{}} : P()}:
  {==}

def chunked() -> {p("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n") == H1.Bad{H1.Unsupported{}} : P()}:
  {==}

def head_too_large() -> {H1.parse(b("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), 10, 16) == H1.Bad{H1.HeadTooLarge{}} : P()}:
  {==}

def body_too_large() -> {p("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 17\r\n\r\n") == H1.Bad{H1.BodyTooLarge{}} : P()}:
  {==}

def err_status() -> {H1.status(H1.BodyTooLarge{}) == S.Status{413} : S.Status}:
  {==}

def written() -> {H1.write(Res.text(S.ok(), "hi"), False{}) == b("HTTP/1.1 200 OK\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 2\r\n\r\nhi") : B.Bytes}:
  {==}

def written_close() -> {H1.write(Res.header(Res.empty(S.no_content()), "Content-Length", "99"), True{}) == b("HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: close\r\n\r\n") : B.Bytes}:
  {==}

# write then parse gives the response back, with the framing it added
def round_trip() -> {H1.parse_response(H1.write(Res.header(Res.text(S.not_found(), "nope"), "x-a", "1"), False{}), 200) == H1.RParsed{404, [H.Header{"content-type", "text/plain; charset=utf-8"}, H.Header{"x-a", "1"}, H.Header{"content-length", "4"}], b("nope"), b("")} : H1.RParsed}:
  {==}
