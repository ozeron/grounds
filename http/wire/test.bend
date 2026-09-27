import Base
import ./http1.bend as H1
import ./bytes.bend as B
import ../core/method.bend as M
import ../core/status.bend as S
import ../core/headers.bend as H
import ../core/request.bend as Req
import ../core/response.bend as Res

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

def chunked() -> {p("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n") == H1.More{} : P()}:
  {==}

def head_too_large() -> {H1.parse(b("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), 10, 16) == H1.Bad{H1.HeadTooLarge{}} : P()}:
  {==}

def body_too_large() -> {p("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 17\r\n\r\n") == H1.Bad{H1.BodyTooLarge{}} : P()}:
  {==}

def err_status() -> {H1.status(H1.BodyTooLarge{}) == S.Status{413} : S.Status}:
  {==}

def written() -> {H1.write(Res.text(S.ok(), "hi"), False{}) == b("HTTP/1.1 200 OK\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 2\r\nconnection: keep-alive\r\n\r\nhi") : B.Bytes}:
  {==}

def written_close() -> {H1.write(Res.header(Res.empty(S.no_content()), "Content-Length", "99"), True{}) == b("HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: close\r\n\r\n") : B.Bytes}:
  {==}

# write then parse gives the response back, with the framing it added
# a header value with CR LF would start a header of its own
def written_crlf() -> {H1.write(Res.header(Res.empty(S.no_content()), "x-a", "1\r\nset-cookie: x"), False{}) == b("HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: keep-alive\r\n\r\n") : B.Bytes}:
  {==}

def written_nul() -> {H1.write(Res.header(Res.header(Res.empty(S.no_content()), "x\u{0}a", "1"), "x-b", "2"), False{}) == b("HTTP/1.1 204 No Content\r\nx-b: 2\r\ncontent-length: 0\r\nconnection: keep-alive\r\n\r\n") : B.Bytes}:
  {==}

def round_trip() -> {H1.parse_response(H1.write(Res.header(Res.text(S.not_found(), "nope"), "x-a", "1"), False{}), 200) == H1.RParsed{404, [H.Header{"content-type", "text/plain; charset=utf-8"}, H.Header{"x-a", "1"}, H.Header{"content-length", "4"}, H.Header{"connection", "keep-alive"}], b("nope"), b("")} : H1.RParsed}:
  {==}

# spellings and orders the laws cover in general

def chunked_mixed_case() -> {p("POST / HTTP/1.1\r\nHost: x\r\ntRANSFER-eNCODING: Chunked\r\n\r\n0\r\n\r\n") == H1.Parsed{Req.Request{M.MPost{}, "/", [H.Header{"Host", "x"}, H.Header{"tRANSFER-eNCODING", "Chunked"}], []}, False{}, b("")} : P()}:
  {==}

def bad_length_first() -> {p("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: x\r\nContent-Length: 1\r\n\r\na") == H1.Bad{H1.BadLength{}} : P()}:
  {==}

def written_lowercase_length() -> {H1.write(Res.header(Res.empty(S.no_content()), "content-length", "9"), False{}) == b("HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: keep-alive\r\n\r\n") : B.Bytes}:
  {==}

# chunked bodies

def chunked_body() -> {p("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n1;x=y\r\nd\r\n0\r\n\r\nGET") == H1.Parsed{Req.Request{M.MPost{}, "/", [H.Header{"Host", "x"}, H.Header{"Transfer-Encoding", "chunked"}], [97, 98, 99, 100]}, False{}, b("GET")} : P()}:
  {==}

def chunked_crlf_in_data() -> {p("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n0\r\n\r\n\r\n0\r\n\r\n") == H1.Parsed{Req.Request{M.MPost{}, "/", [H.Header{"Host", "x"}, H.Header{"Transfer-Encoding", "chunked"}], [48, 13, 10, 13, 10]}, False{}, b("")} : P()}:
  {==}

def chunked_trailers() -> {p("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nA\r\n0123456789\r\n0\r\nX-T: 1\r\n\r\n") == H1.Parsed{Req.Request{M.MPost{}, "/", [H.Header{"Host", "x"}, H.Header{"Transfer-Encoding", "chunked"}], [48, 49, 50, 51, 52, 53, 54, 55, 56, 57]}, False{}, b("")} : P()}:
  {==}

def chunked_more() -> {p("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab") == H1.More{} : P()}:
  {==}

def chunked_more_end() -> {p("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r") == H1.More{} : P()}:
  {==}

def chunked_too_large() -> {p("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n11\r\n") == H1.Bad{H1.BodyTooLarge{}} : P()}:
  {==}

def chunked_sum_too_large() -> {p("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n9\r\n123456789\r\n8\r\n") == H1.Bad{H1.BodyTooLarge{}} : P()}:
  {==}

def chunked_bad_size() -> {p("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n 3\r\nabc\r\n0\r\n\r\n") == H1.Bad{H1.BadLength{}} : P()}:
  {==}

def chunked_no_crlf_after_data() -> {p("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcd\r\n0\r\n\r\n") == H1.Bad{H1.BadLength{}} : P()}:
  {==}

def chunked_bare_lf() -> {p("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\nabc\r\n0\r\n\r\n") == H1.Bad{H1.BadLength{}} : P()}:
  {==}

def te_and_length() -> {p("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n") == H1.Bad{H1.BadLength{}} : P()}:
  {==}

def te_gzip() -> {p("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n") == H1.Bad{H1.Unsupported{}} : P()}:
  {==}

def te_twice() -> {p("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n") == H1.Bad{H1.Unsupported{}} : P()}:
  {==}

# streamed responses

def chunk_hex() -> {H1.chunk(b("0123456789abcdefg")) == b("11\r\n0123456789abcdefg\r\n") : B.Bytes}:
  {==}

def chunk_empty() -> {H1.chunk(b("")) == b("") : B.Bytes}:
  {==}

def stream_head() -> {H1.write_head(200, [H.Header{"content-type", "text/event-stream"}, H.Header{"Content-Length", "3"}], False{}) == b("HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\nconnection: keep-alive\r\n\r\n") : B.Bytes}:
  {==}

# what write_head and chunk write, the parser reads back
def stream_reads_back() -> {p("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" ++ H1.latin1(B.app(H1.chunk(b("ab")), B.app(H1.chunk(b("c")), H1.last_chunk())))) == H1.Parsed{Req.Request{M.MPost{}, "/", [H.Header{"Host", "x"}, H.Header{"Transfer-Encoding", "chunked"}], [97, 98, 99]}, False{}, b("")} : P()}:
  {==}

# responses, as a client reads them

def rr(s: String, eof: Bool) -> H1.RParsed:
  H1.read_response(b(s), 200, 16, eof, False{})

def rr_length() -> {rr("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhiX", False{}) == H1.RParsed{200, [H.Header{"Content-Length", "2"}], b("hi"), b("X")} : H1.RParsed}:
  {==}

def rr_chunked() -> {rr("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n1\r\n!\r\n0\r\n\r\n", False{}) == H1.RParsed{200, [H.Header{"Transfer-Encoding", "chunked"}], b("hi!"), b("")} : H1.RParsed}:
  {==}

def rr_to_close_more() -> {rr("HTTP/1.1 200 OK\r\n\r\nabc", False{}) == H1.RMore{} : H1.RParsed}:
  {==}

def rr_to_close() -> {rr("HTTP/1.1 200 OK\r\n\r\nabc", True{}) == H1.RParsed{200, [], b("abc"), b("")} : H1.RParsed}:
  {==}

def rr_no_content() -> {rr("HTTP/1.1 204 No Content\r\n\r\n", False{}) == H1.RParsed{204, [], b(""), b("")} : H1.RParsed}:
  {==}

def rr_head() -> {H1.read_response(b("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"), 200, 16, False{}, True{}) == H1.RParsed{200, [H.Header{"Content-Length", "5"}], b(""), b("")} : H1.RParsed}:
  {==}

def rr_continue() -> {rr("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n", False{}) == H1.RParsed{100, [], b(""), b("HTTP/1.1 200 OK\r\n")} : H1.RParsed}:
  {==}

def rr_too_large() -> {rr("HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n", False{}) == H1.RBad{H1.BodyTooLarge{}} : H1.RParsed}:
  {==}

def rr_two_lengths() -> {rr("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab", False{}) == H1.RBad{H1.BadLength{}} : H1.RParsed}:
  {==}

def wr_get() -> {H1.write_request("GET", "/a?b", "x:81", [H.Header{"accept", "*/*"}, H.Header{"Content-Length", "9"}], b(""), False{}) == b("GET /a?b HTTP/1.1\r\nhost: x:81\r\naccept: */*\r\nconnection: close\r\n\r\n") : B.Bytes}:
  {==}

def wr_post() -> {H1.write_request("POST", "/", "x", [], b("hi"), True{}) == b("POST / HTTP/1.1\r\nhost: x\r\ncontent-length: 2\r\nconnection: close\r\n\r\nhi") : B.Bytes}:
  {==}

def wr_post_empty() -> {H1.write_request("POST", "/", "x", [], b(""), True{}) == b("POST / HTTP/1.1\r\nhost: x\r\ncontent-length: 0\r\nconnection: close\r\n\r\n") : B.Bytes}:
  {==}
