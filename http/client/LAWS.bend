import Base
import ./client.bend as C
import ../wire/http1.bend as H1
import ../wire/LAWS.bend as WL
import ../core/headers.bend as H
import ../core/method.bend as M
import ../core/query.bend as Q

# Laws grounds-http-client must keep. `bend PROOF.bend` fails while any is
# open or false.

# Injection (RFC 9112 §3)
# ---------

# a url the client takes has a target and an authority (its Host) without
# CR, LF or NUL: none can end the request line or the Host line early
law url_target:
  for +s: String
  for +tls: Bool
  for +h: String
  for +p: U32
  for +t: String
  for +a: String
  for e: {C.url(s) == C.Url{tls, h, p, t, a} : C.Url}
  {H1.unsafe(t, False{}) == False{} : Bool}

law url_authority:
  for +s: String
  for +tls: Bool
  for +h: String
  for +p: U32
  for +t: String
  for +a: String
  for e: {C.url(s) == C.Url{tls, h, p, t, a} : C.Url}
  {H1.unsafe(a, False{}) == False{} : Bool}

# the same for any url that url.check passed: a pool's, and a redirect's
law check_target:
  for +u: C.Url
  for +tls: Bool
  for +h: String
  for +p: U32
  for +t: String
  for +a: String
  for e: {C.url.check(u) == C.Url{tls, h, p, t, a} : C.Url}
  {H1.unsafe(t, False{}) == False{} : Bool}

law check_authority:
  for +u: C.Url
  for +tls: Bool
  for +h: String
  for +p: U32
  for +t: String
  for +a: String
  for e: {C.url.check(u) == C.Url{tls, h, p, t, a} : C.Url}
  {H1.unsafe(a, False{}) == False{} : Bool}

# a method the client sends has a name without CR, LF or NUL
law method_clean:
  for +v: C.Verb
  for +n: String
  for +hd: Bool
  for +z: Bool
  for +g: Bool
  for e: {C.verb.check(v) == Some{C.Verb{n, hd, z, g}} : Maybe<&2, C.Verb>}
  {H1.unsafe(n, False{}) == False{} : Bool}

# end to end: for any method and url the client takes, and any headers, the
# head it writes has one empty line, at its end, and CR or LF only where a
# line ends (http/wire's request_head): no header value, url or method can
# add a header or start a second request
law request_safe:
  for +m: M.Method
  for +s: String
  for +hs: List<&2, H.Header>
  for +len: H1.Dec
  for +sized: Bool
  for +close: Bool
  for +n: String
  for +hd: Bool
  for +z: Bool
  for +g: Bool
  for +tls: Bool
  for +host: String
  for +p: U32
  for +t: String
  for +a: String
  for ev: {C.verb.check(C.verb(m)) == Some{C.Verb{n, hd, z, g}} : Maybe<&2, C.Verb>}
  for +eu: {C.url(s) == C.Url{tls, host, p, t, a} : C.Url}
  {WL.hdr(H1.request.head(n, t, a, hs, len, sized, close)) == True{} : Bool}

# Forms (application/x-www-form-urlencoded)
# -----

# a char a form writes as it is and a query reads back as it is: an
# unreserved one (RFC 3986 §2.3); none of those is past ASCII, or %, +, &
# or =, and the checker is told so rather than left to count
def form.ch(+x: U32) -> Bool:
  Bool.and(C.unreserved(x), Bool.and(U32.is_lt(x, 128), Bool.and(Bool.not(U32.is_eq(x, 37)), Bool.and(Bool.not(U32.is_eq(x, 43)), Bool.and(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61)))))))

def form.s(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{Chr{+x}, t}:
      Bool.and(form.ch(x), form.s(t))

def form.plain(ps: List<&2, Q.Param>) -> Bool:
  match ps:
    case Nil{}:
      True{}
    case Con{Q.Param{k, v}, t}:
      Bool.and(form.s(k), Bool.and(form.s(v), form.plain(t)))

# pairs as a form takes them
def kv.of(ps: List<&2, Q.Param>) -> C.Kv():
  match ps:
    case Nil{}:
      []
    case Con{Q.Param{k, v}, t}:
      Con{(k, v), kv.of(t)}

# a form the client sends reads back, with core's query parser, as the
# same pairs, in order, for names and values of unreserved chars. Escaped
# chars (%XX, +) are left to the unit tests and the fuzzer
law form_reads_back:
  for +ps: List<&2, Q.Param>
  for +e: {form.plain(ps) == True{} : Bool}
  {Q.parse(C.form.enc(kv.of(ps))) == ps : List<&2, Q.Param>}
