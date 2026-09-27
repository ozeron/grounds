import Base
import ./method.bend as M
import ./status.bend as S
import ./headers.bend as H
import ./query.bend as Q
import ./request.bend as Req
import ./response.bend as Res
import ./text.bend as T

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
