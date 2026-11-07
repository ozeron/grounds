import Base
import ./url.bend as C
import ./policy.bend as P
import ../core/headers.bend as H

# each def is a test: it checks only if both sides compute to the same value

def plain() -> {C.url("http://localhost/a?b=1") == C.Url{False{}, "localhost", 80, "/a?b=1", "localhost"} : C.Url}:
  {==}

def port() -> {C.url("http://10.0.0.7:8080") == C.Url{False{}, "10.0.0.7", 8080, "/", "10.0.0.7:8080"} : C.Url}:
  {==}

def query_only() -> {C.url("http://h:81?x") == C.Url{False{}, "h", 81, "/?x", "h:81"} : C.Url}:
  {==}

def https() -> {C.url("https://h/x") == C.Url{True{}, "h", 443, "/x", "h"} : C.Url}:
  {==}

def no_scheme() -> {C.url("h/") == C.UBad{} : C.Url}:
  {==}

def no_host() -> {C.url("http:///x") == C.UBad{} : C.Url}:
  {==}

def user_info() -> {C.url("http://u@h/") == C.UBad{} : C.Url}:
  {==}

def port_zero() -> {C.url("http://h:0/") == C.UBad{} : C.Url}:
  {==}

def port_big() -> {C.url("http://h:65536/") == C.UBad{} : C.Url}:
  {==}

def port_empty() -> {C.url("http://h:/") == C.UBad{} : C.Url}:
  {==}

def space_in_target() -> {C.url("http://h/a b") == C.UBad{} : C.Url}:
  {==}

def crlf_in_target() -> {C.url("http://h/a\r\nX: y") == C.UBad{} : C.Url}:
  {==}

def https_port() -> {C.url("https://h:8443") == C.Url{True{}, "h", 8443, "/", "h:8443"} : C.Url}:
  {==}

def ftp() -> {C.url("ftp://h/") == C.UBad{} : C.Url}:
  {==}

# forms

def form_plain() -> {C.form.enc([("a", "1"), ("b", "x-y_z.~")]) == "a=1&b=x-y_z.~" : String}:
  {==}

def form_escaped() -> {C.form.enc([("q", "a b&c=d"), ("x", "\u{e9}")]) == "q=a+b%26c%3Dd&x=%C3%A9" : String}:
  {==}

def form_empty() -> {C.form.enc([]) == "" : String}:
  {==}

# client policies (policy.bend)

def hdr_ok() -> {P.header.ok("X-Trace", "a\tb c") == True{} : Bool}:
  {==}

def hdr_obs_text() -> {P.header.ok("X-Name", "caf\u{e9}") == True{} : Bool}:
  {==}

def hdr_name_space() -> {P.header.ok("Transfer-Encoding ", "chunked") == False{} : Bool}:
  {==}

def hdr_name_colon() -> {P.header.ok("X:Y", "v") == False{} : Bool}:
  {==}

def hdr_name_empty() -> {P.header.ok("", "v") == False{} : Bool}:
  {==}

def hdr_name_crlf() -> {P.header.ok("X\r\nHost", "v") == False{} : Bool}:
  {==}

def hdr_value_ctl() -> {P.header.ok("X-A", "a\u{1}b") == False{} : Bool}:
  {==}

def hdr_value_del() -> {P.header.ok("X-A", "a\u{7f}") == False{} : Bool}:
  {==}

def hdr_value_nul() -> {P.header.ok("X-A", "a\u{0}") == False{} : Bool}:
  {==}

def hdr_value_lf() -> {P.header.ok("X-A", "a\nContent-Length: 0") == False{} : Bool}:
  {==}

def final_200() -> {P.final(200) == True{} : Bool}:
  {==}

def final_599() -> {P.final(599) == True{} : Bool}:
  {==}

def final_101() -> {P.final(101) == False{} : Bool}:
  {==}

def final_199() -> {P.final(199) == False{} : Bool}:
  {==}

def final_99() -> {P.final(99) == False{} : Bool}:
  {==}

def final_600() -> {P.final(600) == False{} : Bool}:
  {==}

def private_proxy() -> {P.private("Proxy-Authorization") == True{} : Bool}:
  {==}

def private_cookie() -> {P.private("COOKIE") == True{} : Bool}:
  {==}

def private_other() -> {P.private("X-Api") == False{} : Bool}:
  {==}

def content_type() -> {P.content("Content-Type") == True{} : Bool}:
  {==}

def content_length() -> {P.content("content-length") == False{} : Bool}:
  {==}

def get_303_put() -> {P.to_get(303, "PUT", False{}) == True{} : Bool}:
  {==}

def get_303_head() -> {P.to_get(303, "HEAD", True{}) == False{} : Bool}:
  {==}

def get_302_post() -> {P.to_get(302, "POST", False{}) == True{} : Bool}:
  {==}

def get_301_post() -> {P.to_get(301, "POST", False{}) == True{} : Bool}:
  {==}

def get_302_put() -> {P.to_get(302, "PUT", False{}) == False{} : Bool}:
  {==}

def get_307_post() -> {P.to_get(307, "POST", False{}) == False{} : Bool}:
  {==}

def get_308_post() -> {P.to_get(308, "POST", False{}) == False{} : Bool}:
  {==}

def loc_abs_path() -> {P.resolve("/a/./b/../c?x#f", True{}, "/old") == P.RSame{"/a/c?x"} : P.Ref}:
  {==}

def loc_net_https() -> {P.resolve("//other:8443/p#f", True{}, "/") == P.RAbs{"https://other:8443/p"} : P.Ref}:
  {==}

def loc_net_http() -> {P.resolve("//h/p", False{}, "/") == P.RAbs{"http://h/p"} : P.Ref}:
  {==}

def loc_rel() -> {P.resolve("b?x=1", True{}, "/chain/a?q") == P.RSame{"/chain/b?x=1"} : P.Ref}:
  {==}

def loc_rel_up() -> {P.resolve("../d", True{}, "/chain/c/e") == P.RSame{"/chain/d"} : P.Ref}:
  {==}

def loc_rel_above_root() -> {P.resolve("../../../x", True{}, "/a/b") == P.RSame{"/x"} : P.Ref}:
  {==}

def loc_rel_dot() -> {P.resolve("./", True{}, "/a/b") == P.RSame{"/a/"} : P.Ref}:
  {==}

def loc_rel_dotdot_last() -> {P.resolve("..", True{}, "/a/b/c") == P.RSame{"/a/"} : P.Ref}:
  {==}

def loc_query() -> {P.resolve("?n=2", True{}, "/p/q?n=1") == P.RSame{"/p/q?n=2"} : P.Ref}:
  {==}

def loc_upper_scheme() -> {P.resolve("HTTPS://H/x", False{}, "/") == P.RAbs{"https://H/x"} : P.Ref}:
  {==}

def loc_abs_http() -> {P.resolve("http://h:8080/x#y", True{}, "/") == P.RAbs{"http://h:8080/x"} : P.Ref}:
  {==}

def loc_mailto() -> {P.resolve("mailto:a@b", True{}, "/") == P.RNone{} : P.Ref}:
  {==}

def loc_empty() -> {P.resolve("", True{}, "/") == P.RNone{} : P.Ref}:
  {==}

def loc_fragment_only() -> {P.resolve("#top", True{}, "/x") == P.RNone{} : P.Ref}:
  {==}

def frag_cut() -> {P.frag.cut("/a?b#c#d") == "/a?b" : String}:
  {==}

def origin_case() -> {P.origin.same(True{}, "Example.COM", 443, True{}, "example.com", 443) == True{} : Bool}:
  {==}

def origin_port() -> {P.origin.same(True{}, "h", 443, True{}, "h", 8443) == False{} : Bool}:
  {==}

def origin_scheme() -> {P.origin.same(True{}, "h", 443, False{}, "h", 443) == False{} : Bool}:
  {==}

# network-path and absolute Locations lose their dot segments too; the
# query is kept as it is
def loc_net_dots() -> {P.resolve("//other/a/../b", True{}, "/") == P.RAbs{"https://other/b"} : P.Ref}:
  {==}

def loc_net_dots_query() -> {P.resolve("//other:8443/a/./b/../c?x=/../y#f", True{}, "/") == P.RAbs{"https://other:8443/a/c?x=/../y"} : P.Ref}:
  {==}

def loc_net_dots_http() -> {P.resolve("//h/../../x/", False{}, "/") == P.RAbs{"http://h/x/"} : P.Ref}:
  {==}

def loc_net_bare() -> {P.resolve("//h", True{}, "/") == P.RAbs{"https://h"} : P.Ref}:
  {==}

def loc_net_query_only() -> {P.resolve("//h?a/../b", True{}, "/") == P.RAbs{"https://h?a/../b"} : P.Ref}:
  {==}

def loc_abs_dots() -> {P.resolve("https://h/a/../../b?q=1", False{}, "/") == P.RAbs{"https://h/b?q=1"} : P.Ref}:
  {==}

def loc_abs_dot_last() -> {P.resolve("http://h:8080/x/./y/.", True{}, "/") == P.RAbs{"http://h:8080/x/y/"} : P.Ref}:
  {==}

def loc_abs_upper_dots() -> {P.resolve("HTTPS://H/a/%2e%2e/./b", False{}, "/") == P.RAbs{"https://H/a/%2e%2e/b"} : P.Ref}:
  {==}

# a User-Agent unless the caller set one
def agent_default() -> {P.agent(Some{"grounds-bend"}, [H.Header{"accept", "*/*"}]) == [H.Header{"accept", "*/*"}, H.Header{"user-agent", "grounds-bend"}] : List<&2, H.Header>}:
  {==}

def agent_caller() -> {P.agent(Some{"grounds-bend"}, [H.Header{"User-Agent", "mine/1"}]) == [H.Header{"User-Agent", "mine/1"}] : List<&2, H.Header>}:
  {==}

def agent_caller_case() -> {P.agent(Some{"grounds-bend"}, [H.Header{"USER-AGENT", "x"}, H.Header{"a", "b"}]) == [H.Header{"USER-AGENT", "x"}, H.Header{"a", "b"}] : List<&2, H.Header>}:
  {==}

def agent_caller_invalid() -> {P.agent(Some{"grounds-bend"}, [H.Header{"User-Agent", "a\nb"}]) == [H.Header{"User-Agent", "a\nb"}, H.Header{"user-agent", "grounds-bend"}] : List<&2, H.Header>}:
  {==}

def agent_off() -> {P.agent(None{}, [H.Header{"a", "b"}]) == [H.Header{"a", "b"}] : List<&2, H.Header>}:
  {==}

def agent_off_caller() -> {P.agent(None{}, [H.Header{"User-Agent", "mine"}]) == [H.Header{"User-Agent", "mine"}] : List<&2, H.Header>}:
  {==}
