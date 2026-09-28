import Base
import ./event.bend as Ev
import ./method.bend as M
import ./status.bend as S
import ./headers.bend as H
import ./query.bend as Q
import ./request.bend as Req
import ./response.bend as Res
import ./text.bend as T
import ./cookie.bend as Ck
import ./auth.bend as Auth
import ./cors.bend as Cors

# each def is a test: it checks only if both sides compute to the same value

def method_get() -> {M.parse("GET") == M.MGet{} : M.Method}:
  {==}

def method_case() -> {M.parse("get") == M.MOther{"get"} : M.Method}:
  {==}

def method_show() -> {M.show(M.MPatch{}) == "PATCH" : String}:
  {==}

def status_reason() -> {S.reason(S.not_found()) == "Not Found" : String}:
  {==}

def hs() -> List<&2, H.Header>:
  [H.Header{"Accept", "text/html"}, H.Header{"X-Tag", "a"}, H.Header{"x-tag", "b"}]

def header_ci() -> {H.get(hs(), "accept") == Some{"text/html"} : Maybe<&2, String>}:
  {==}

def header_first() -> {H.get(hs(), "X-TAG") == Some{"a"} : Maybe<&2, String>}:
  {==}

def header_missing() -> {H.get(hs(), "cookie") == None{} : Maybe<&2, String>}:
  {==}

def header_all() -> {H.all(hs(), "x-tag") == ["a", "b"] : List<&2, String>}:
  {==}

def header_set() -> {H.set(hs(), "x-tag", "c") == [H.Header{"Accept", "text/html"}, H.Header{"x-tag", "c"}] : List<&2, H.Header>}:
  {==}

def query_repeats() -> {Q.parse("tag=rust&tag=bend&page=2") == [Q.Param{"tag", "rust"}, Q.Param{"tag", "bend"}, Q.Param{"page", "2"}] : List<&2, Q.Param>}:
  {==}

def query_decode() -> {Q.parse("q=a%20b+c&e=%C3%A9") == [Q.Param{"q", "a b c"}, Q.Param{"e", "\u{E9}"}] : List<&2, Q.Param>}:
  {==}

def query_no_value() -> {Q.parse("flag&&x=") == [Q.Param{"flag", ""}, Q.Param{"x", ""}] : List<&2, Q.Param>}:
  {==}

def req() -> Req.Request:
  Req.Request{M.MGet{}, "/users/7?tag=a", [H.Header{"Host", "x"}], []}

def req_path() -> {Req.path(req()) == "/users/7" : String}:
  {==}

def req_query() -> {Req.query(req()) == [Q.Param{"tag", "a"}] : List<&2, Q.Param>}:
  {==}

def req_header() -> {Req.header(req(), "host") == Some{"x"} : Maybe<&2, String>}:
  {==}

def res_text() -> {Res.text(S.ok(), "hi") == Res.Response{S.Status{200}, [H.Header{"content-type", "text/plain; charset=utf-8"}], [104, 105]} : Res.Response}:
  {==}

def res_header() -> {Res.header(Res.empty(S.no_content()), "cache-control", "no-store") == Res.Response{S.Status{204}, [H.Header{"cache-control", "no-store"}], []} : Res.Response}:
  {==}

def cookie_defaults() -> {Ck.set(Res.empty(S.ok()), "sid", "abc") == Res.Response{S.Status{200}, [H.Header{"set-cookie", "sid=abc; Path=/; HttpOnly; Secure; SameSite=Lax"}], []} : Res.Response}:
  {==}

def cookie_injection_escaped() -> {Ck.set(Res.empty(S.ok()), "s\nid", "x\r\nSet-Cookie: injected=1;") == Res.Response{S.Status{200}, [H.Header{"set-cookie", "s%0Aid=x%0D%0ASet-Cookie:%20injected=1%3B; Path=/; HttpOnly; Secure; SameSite=Lax"}], []} : Res.Response}:
  {==}

def cookie_first_pair() -> {Ck.get(Req.Request{M.MGet{}, "/", [H.Header{"Cookie", "theme=dark; sid=abc"}, H.Header{"cookie", "sid=other"}], []}, "sid") == Some{"abc"} : Maybe<&2, String>}:
  {==}

def cookie_decodes_value() -> {Ck.get(Req.Request{M.MGet{}, "/", [H.Header{"cookie", "message=x%20y%3B%E2%82%AC"}], []}, "message") == Some{"x y;€"} : Maybe<&2, String>}:
  {==}

def cookie_rejects_bad_encoding() -> {Ck.get(Req.Request{M.MGet{}, "/", [H.Header{"cookie", "sid=%FF"}], []}, "sid") == None{} : Maybe<&2, String>}:
  {==}

def cookie_first_bad_does_not_skip() -> {Ck.get(Req.Request{M.MGet{}, "/", [H.Header{"cookie", "sid=%FF; sid=valid"}], []}, "sid") == None{} : Maybe<&2, String>}:
  {==}

def cookie_quoted_value() -> {Ck.get(Req.Request{M.MGet{}, "/", [H.Header{"cookie", "sid=\"abc\""}], []}, "sid") == Some{"abc"} : Maybe<&2, String>}:
  {==}

def cookie_clear() -> {Ck.clear(Res.empty(S.ok()), "sid") == Res.Response{S.Status{200}, [H.Header{"set-cookie", "sid=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax"}], []} : Res.Response}:
  {==}

def cookie_empty_name_ignored() -> {Ck.set(Res.empty(S.ok()), "", "x") == Res.empty(S.ok()) : Res.Response}:
  {==}

def bearer_case_and_token() -> {Auth.parse_header("bEaReR mF_9.B5f-4.1JqM") == Auth.Got{Auth.Bearer{"mF_9.B5f-4.1JqM"}} : Auth.Attempt}:
  {==}

def bearer_rejects_bad_token() -> {Auth.parse_header("Bearer abc?") == Auth.BadBearer{} : Auth.Attempt}:
  {==}

def bearer_rejects_payload_after_padding() -> {Auth.parse_header("Bearer a=b") == Auth.BadBearer{} : Auth.Attempt}:
  {==}

def bearer_requires_token() -> {Auth.parse_header("Bearer ") == Auth.BadBearer{} : Auth.Attempt}:
  {==}

def basic_example() -> {Auth.parse_header("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==") == Auth.Got{Auth.Basic{"Aladdin", "open sesame"}} : Auth.Attempt}:
  {==}

def basic_utf8() -> {Auth.parse_header("Basic dGVzdDoxMjPCow==") == Auth.Got{Auth.Basic{"test", "123£"}} : Auth.Attempt}:
  {==}

def basic_rejects_bad_padding() -> {Auth.parse_header("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=A") == Auth.BadBasic{} : Auth.Attempt}:
  {==}

def basic_requires_colon() -> {Auth.parse_header("Basic dGVzdA==") == Auth.BadBasic{} : Auth.Attempt}:
  {==}

def basic_rejects_controls() -> {Auth.parse_header("Basic dGUAc3Q6cA==") == Auth.BadBasic{} : Auth.Attempt}:
  {==}

def basic_rejects_bad_utf8() -> {Auth.parse_header("Basic dGVzdDr/") == Auth.BadBasic{} : Auth.Attempt}:
  {==}

def auth_strips_authorization() -> {Auth.take(Req.Request{M.MGet{}, "/", [H.Header{"Host", "x"}, H.Header{"Authorization", "Bearer t"}], []}) == Auth.Taken{Auth.Got{Auth.Bearer{"t"}}, Req.Request{M.MGet{}, "/", [H.Header{"Host", "x"}], []}} : Auth.Taken}:
  {==}

def auth_rejects_duplicate() -> {Auth.take(Req.Request{M.MGet{}, "/", [H.Header{"Authorization", "Bearer a"}, H.Header{"authorization", "Bearer b"}], []}) == Auth.Taken{Auth.Duplicate{}, Req.Request{M.MGet{}, "/", [], []}} : Auth.Taken}:
  {==}

def cors_exact_origin() -> {Cors.decide(["https://a.example"], True{}, "https://a.example") == Cors.Exact{"https://a.example"} : Cors.Decision}:
  {==}

def cors_denies_unlisted() -> {Cors.decide(["https://a.example"], False{}, "https://b.example") == Cors.Deny{} : Cors.Decision}:
  {==}

def cors_wildcard_without_credentials() -> {Cors.decide(["*"], False{}, "https://b.example") == Cors.Any{} : Cors.Decision}:
  {==}

def cors_wildcard_with_credentials_denied() -> {Cors.decide(["*"], True{}, "https://b.example") == Cors.Deny{} : Cors.Decision}:
  {==}

def cors_exact_after_wildcard_with_credentials() -> {Cors.decide(["*", "https://app.example"], True{}, "https://app.example") == Cors.Exact{"https://app.example"} : Cors.Decision}:
  {==}

def cors_rejects_unsafe_origin() -> {Cors.decide(["https://app.example\r\nx: y"], False{}, "https://app.example\r\nx: y") == Cors.Deny{} : Cors.Decision}:
  {==}

def cors_headers_normalized() -> {Cors.header_value("X-Token, Content-Type", ["content-type", "x-token"]) == Some{"x-token, content-type"} : Maybe<&2, String>}:
  {==}

def cors_headers_reject_unlisted() -> {Cors.header_value("X-Token, X-Secret", ["x-token"]) == None{} : Maybe<&2, String>}:
  {==}

def cors_headers_reject_empty_member() -> {Cors.header_value("X-Token,", ["x-token"]) == None{} : Maybe<&2, String>}:
  {==}

def cors_observe_keeps_request() -> {Cors.observe(Req.Request{M.MGet{}, "/", [H.Header{"Origin", "https://a.example"}], []}) == Cors.Observed{Cors.One{"https://a.example"}, Cors.Absent{}, Cors.Absent{}, Req.Request{M.MGet{}, "/", [H.Header{"Origin", "https://a.example"}], []}} : Cors.Observed}:
  {==}

# DevX helpers

def q_get() -> {Q.get(Q.parse("a=1&b=2&a=3"), "a") == Some{"1"} : Maybe<&2, String>}:
  {==}

def q_get_none() -> {Q.get(Q.parse("a=1"), "b") == None{} : Maybe<&2, String>}:
  {==}

def req_param() -> {Req.param(Req.Request{M.MGet{}, "/?name=x%20y", [], []}, "name") == Some{"x y"} : Maybe<&2, String>}:
  {==}

def or_default() -> {T.or(None{}, "world") == "world" : String}:
  {==}

def u32_ok() -> {T.u32("42") == Some{42} : Maybe<&2, U32>}:
  {==}

def u32_bad() -> {T.u32("4x") == None{} : Maybe<&2, U32>}:
  {==}

def u32_empty() -> {T.u32("") == None{} : Maybe<&2, U32>}:
  {==}

# every standard method reads back from its name (was a law: nine cases)

def round_trip_get() -> {M.parse(M.show(M.MGet{})) == M.MGet{} : M.Method}:
  {==}

def round_trip_head() -> {M.parse(M.show(M.MHead{})) == M.MHead{} : M.Method}:
  {==}

def round_trip_post() -> {M.parse(M.show(M.MPost{})) == M.MPost{} : M.Method}:
  {==}

def round_trip_put() -> {M.parse(M.show(M.MPut{})) == M.MPut{} : M.Method}:
  {==}

def round_trip_delete() -> {M.parse(M.show(M.MDelete{})) == M.MDelete{} : M.Method}:
  {==}

def round_trip_connect() -> {M.parse(M.show(M.MConnect{})) == M.MConnect{} : M.Method}:
  {==}

def round_trip_options() -> {M.parse(M.show(M.MOptions{})) == M.MOptions{} : M.Method}:
  {==}

def round_trip_trace() -> {M.parse(M.show(M.MTrace{})) == M.MTrace{} : M.Method}:
  {==}

def round_trip_patch() -> {M.parse(M.show(M.MPatch{})) == M.MPatch{} : M.Method}:
  {==}

def other_name() -> {M.show(M.MOther{"BREW"}) == "BREW" : String}:
  {==}

# server-sent events

def fed.es(f: Ev.Fed) -> List<&2, Ev.Message>:
  match f:
    case Ev.Fed{_, es}:
      es

def evs(s: String) -> List<&2, Ev.Message>:
  fed.es(Ev.feed(s, Ev.start()))

def ev_round_trip() -> {evs(Ev.write(Ev.Message{"tick", "a\nb", Some{"7"}})) == [Ev.Message{"tick", "a\nb", Some{"7"}}] : List<&2, Ev.Message>}:
  {==}

def ev_data_like_fields() -> {evs(Ev.write(Ev.Message{"x", "data: y\nid: 9", None{}})) == [Ev.Message{"x", "data: y\nid: 9", None{}}] : List<&2, Ev.Message>}:
  {==}

def ev_defaults() -> {evs("data: hi\n\n") == [Ev.Message{"message", "hi", None{}}] : List<&2, Ev.Message>}:
  {==}

def ev_crlf_cr() -> {evs("data: a\r\ndata: b\rid: 1\r\n\r\n") == [Ev.Message{"message", "a\nb", Some{"1"}}] : List<&2, Ev.Message>}:
  {==}

def ev_bom_comment() -> {evs("\u{feff}: ping\n\ndata:x\n\n") == [Ev.Message{"message", "x", None{}}] : List<&2, Ev.Message>}:
  {==}

def ev_id_carries() -> {evs("id: 5\ndata: a\n\ndata: b\n\n") == [Ev.Message{"message", "a", Some{"5"}}, Ev.Message{"message", "b", Some{"5"}}] : List<&2, Ev.Message>}:
  {==}

def ev_no_data() -> {evs("event: x\n\ndata\n\n") == [Ev.Message{"message", "", None{}}] : List<&2, Ev.Message>}:
  {==}

def rest.evs(f: Ev.Fed) -> List<&2, Ev.Message>:
  match f:
    case Ev.Fed{p, _}:
      fed.es(Ev.feed("b\n\n", p))

def ev_split() -> {rest.evs(Ev.feed("data: a", Ev.start())) == [Ev.Message{"message", "ab", None{}}] : List<&2, Ev.Message>}:
  {==}

def fed.p(f: Ev.Fed) -> Ev.P:
  match f:
    case Ev.Fed{p, _}:
      p

def ev_retry() -> {Ev.retry.of(fed.p(Ev.feed("retry: 250\n\n", Ev.start()))) == Some{250n} : Maybe<&2, Nat>}:
  {==}

def last.of(f: Ev.Fed) -> Maybe<&2, String>:
  match f:
    case Ev.Fed{p, _}:
      Ev.tail.last(Ev.tail(p))

# a reconnect sends only an id a blank line confirmed
def ev_id_unconfirmed() -> {last.of(Ev.feed("id: 1\n\ndata: a\nid: 2\n", Ev.start())) == Some{"1"} : Maybe<&2, String>}:
  {==}

def ev_id_no_data() -> {last.of(Ev.feed("id: 3\n\n", Ev.start())) == Some{"3"} : Maybe<&2, String>}:
  {==}
