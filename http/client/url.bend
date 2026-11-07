import Base
import ../wire/http1.bend as H1
import ../core/method.bend as M
import ../../utf8/utf8.bend as U
import ../../wire/ip.bend as I

# What a request is aimed at, as plain values: its verb, its URL, and form
# fields. Apart from client.bend, whose sockets would void these laws

# names and values: headers, query pairs and form fields
def Kv() -> Type:
  List<&1, String & String>
# a method's name, whether it is HEAD, whether it expects a body, and
# whether it is safe to repeat (RFC 9110 §9.2.2)
type Verb is Data:
  Verb{name: String, head: Bool, sized: Bool, again: Bool}

def verb(m: M.Method) -> Verb:
  match m:
    case M.MGet{}:
      Verb{"GET", False{}, False{}, True{}}
    case M.MHead{}:
      Verb{"HEAD", True{}, False{}, True{}}
    case M.MPost{}:
      Verb{"POST", False{}, True{}, False{}}
    case M.MPut{}:
      Verb{"PUT", False{}, True{}, True{}}
    case M.MPatch{}:
      Verb{"PATCH", False{}, True{}, False{}}
    case M.MDelete{}:
      Verb{"DELETE", False{}, False{}, True{}}
    case M.MOptions{}:
      Verb{"OPTIONS", False{}, False{}, True{}}
    case M.MTrace{}:
      Verb{"TRACE", False{}, False{}, True{}}
    case other:
      Verb{M.show(other), False{}, False{}, False{}}

def verb.final(ok: Bool, n: String, +h: Bool, +z: Bool, +g: Bool) -> Maybe<&2, Verb>:
  match ok:
    case True{}:
      Some{Verb{n, h, z, g}}
    case False{}:
      None{}

# a method's name must be a token (RFC 9110 §9.1), which has no CR, LF,
# NUL or space: a name of the caller's own is checked here
def verb.check(v: Verb) -> Maybe<&2, Verb>:
  match v:
    case Verb{+n, +h, +z, +g}:
      verb.final(Bool.and(Bool.not(H1.unsafe(n, False{})), H1.is_token.s(n)), n, h, z, g)

# whether to use TLS, the host, port, the target to send (origin-form:
# /path?query), and the Host header's value
type Url is Data:
  Url{tls: Bool, host: String, port: U32, target: String, authority: String}
  UBad{}

def host.char(+x: U32) -> Bool:
  Bool.or(Bool.or(Bool.and(U32.is_ge(x, 97), U32.is_le(x, 122)), Bool.and(U32.is_ge(x, 65), U32.is_le(x, 90))),
    Bool.or(Bool.and(U32.is_ge(x, 48), U32.is_le(x, 57)), Bool.or(U32.is_eq(x, 45), U32.is_eq(x, 46))))

# a target, copied, and whether its chars are all visible ASCII with no
# space; a byte past 127 is kept for the server to refuse or take
type Tgt is Data:
  Tgt{t: String, ok: Bool}

def target.go(s: String, acc: String, ok: Bool) -> Tgt:
  match s:
    case SNil{}:
      Tgt{String.reverse(acc), ok}
    case SCon{Chr{+x}, t}:
      target.go(t, SCon{Chr{x}, acc}, Bool.and(ok, Bool.and(U32.is_gt(x, 32), Bool.not(U32.is_eq(x, 127)))))

def s.copy(s: String, acc: String) -> String:
  match s:
    case SNil{}:
      String.reverse(acc)
    case SCon{Chr{x}, t}:
      s.copy(t, SCon{Chr{(x + 0 : U32)}, acc})

# an IPv6 host goes in brackets in the authority (RFC 3986 section 3.2.2)
def url.br(br: Bool, h: String) -> String:
  match br:
    case True{}:
      "[" ++ h ++ "]"
    case False{}:
      h

def url.auth(given: Bool, br: Bool, port: U32, h: String) -> String:
  match given:
    case True{}:
      url.br(br, h) ++ ":" ++ U32.show(port)
    case False{}:
      url.br(br, h)

def url.make(tls: Bool, auth: String, host: String, port: U32, target: String) -> Url:
  Url{tls, host, port, target, auth}

def url.done(ok: Bool, tls: Bool, br: Bool, +host: String, +port: U32, given: Bool, target: String) -> Url:
  match ok:
    case True{}:
      url.make(tls, url.auth(given, br, port, s.copy(host, "")), host, port, target)
    case False{}:
      UBad{}

def url.tgt(g: Tgt, tls: Bool, br: Bool, host: String, port: U32, given: Bool) -> Url:
  match g:
    case Tgt{t, ok}:
      url.done(ok, tls, br, host, port, given, t)

def url.target(+tls: Bool, +br: Bool, host: String, +port: U32, +given: Bool, t: String) -> Url:
  match t:
    case SNil{}:
      url.done(True{}, tls, br, host, port, given, "/")
    case SCon{Chr{63}, r}:
      url.tgt(target.go(r, "?/", True{}), tls, br, host, port, given)
    case SCon{Chr{47}, r}:
      url.tgt(target.go(r, "/", True{}), tls, br, host, port, given)
    case _:
      UBad{}

def port.num(s: String, +n: Nat, ok: Bool, any: Bool) -> Maybe<&2, U32>:
  match s:
    case SNil{}:
      Bool.pick(Maybe<&2, U32>, Bool.and(Bool.and(ok, any), Bool.and(Nat.is_le(n, 65535n), Nat.is_le(1n, n))), Some{U32.from_nat(n)}, None{})
    case SCon{Chr{+x}, t}:
      port.num(t, Nat.add(Nat.mul(10n, n), Nat.sub(U32.to_nat(x), 48n)), Bool.and(ok, Bool.and(U32.is_ge(x, 48), Bool.and(U32.is_le(x, 57), Nat.is_le(n, 65535n)))), True{})

def url.port.end(m: Maybe<&2, U32>, tls: Bool, br: Bool, host: String, t: String) -> Url:
  match m:
    case Some{p}:
      url.target(tls, br, host, p, True{}, t)
    case None{}:
      UBad{}

# the port's digits, up to / or ? or the end: 1 to 65535
def url.port(s: String, +tls: Bool, +br: Bool, host: String, acc: String) -> Url:
  match s:
    case SNil{}:
      url.port.end(port.num(String.reverse(acc), 0n, True{}, False{}), tls, br, host, "")
    case SCon{Chr{47}, t}:
      url.port.end(port.num(String.reverse(acc), 0n, True{}, False{}), tls, br, host, SCon{Chr{47}, t})
    case SCon{Chr{63}, t}:
      url.port.end(port.num(String.reverse(acc), 0n, True{}, False{}), tls, br, host, SCon{Chr{63}, t})
    case SCon{c, t}:
      url.port(t, tls, br, host, SCon{c, acc})

def url.host.end(ok: Bool, +tls: Bool, +br: Bool, host: String, s: String) -> Url:
  match ok s:
    case False{} _:
      UBad{}
    case True{} SCon{Chr{58}, t}:
      url.port(t, tls, br, host, "")
    case True{} rest:
      url.target(tls, br, host, Bool.pick(U32, tls, 443, 80), False{}, rest)

# the host, reversed in acc, up to : or / or ? or the end
def url.host(s: String, +tls: Bool, acc: String, ok: Bool, any: Bool) -> Url:
  match s:
    case SNil{}:
      url.host.end(Bool.and(ok, any), tls, False{}, String.reverse(acc), "")
    case SCon{Chr{58}, t}:
      url.host.end(Bool.and(ok, any), tls, False{}, String.reverse(acc), SCon{Chr{58}, t})
    case SCon{Chr{47}, t}:
      url.host.end(Bool.and(ok, any), tls, False{}, String.reverse(acc), SCon{Chr{47}, t})
    case SCon{Chr{63}, t}:
      url.host.end(Bool.and(ok, any), tls, False{}, String.reverse(acc), SCon{Chr{63}, t})
    case SCon{Chr{+x}, t}:
      url.host(t, tls, SCon{Chr{x}, acc}, Bool.and(ok, host.char(x)), True{})

# an IPv6 literal in brackets: its canonical text (RFC 5952) is the host,
# and in brackets the authority's, so equal addresses written differently
# are one origin. Then ":port", a target, or the end
def url.v6.lit(m: Maybe<&2, String>, +tls: Bool, rest: String) -> Url:
  match m:
    case Some{h}:
      url.host.end(True{}, tls, True{}, h, rest)
    case None{}:
      UBad{}

# a char onto a reversed side, when it belongs there
def url.v6.put(here: Bool, +c: U32, acc: String) -> String:
  match here:
    case True{}:
      SCon{Chr{c}, acc}
    case False{}:
      acc

# the text between "[" and the first "]" (inner) and after it (rest), both
# reversed; after: whether the "]" came
type Br is Data:
  Br{inner: String, rest: String, after: Bool}

def url.v6.scan(s: String, +after: Bool, inner: String, rest: String) -> Br:
  match s:
    case SNil{}:
      Br{inner, rest, after}
    case SCon{Chr{+c}, t}:
      url.v6.scan(t, Bool.or(after, U32.is_eq(c, 93)), url.v6.put(Bool.and(Bool.not(after), U32.is_ne(c, 93)), c, inner), url.v6.put(after, c, rest))

def url.v6.br(b: Br, +tls: Bool) -> Url:
  match b:
    case Br{inner, rest, True{}}:
      url.v6.lit(I.v6.canon(String.reverse(inner)), tls, String.reverse(rest))
    case Br{_, _, False{}}:
      UBad{}

# after "[": an IPv6 literal up to "]"; a "%" zone, an IPvFuture "v1.x" or
# a dotted IPv4 tail is not IPv6 text and fails
def url.v6(s: String, +tls: Bool) -> Url:
  url.v6.br(url.v6.scan(s, False{}, "", ""), tls)

def url.start.c(br: Bool, +c: U32, t: String, +tls: Bool) -> Url:
  match br:
    case True{}:
      url.v6(t, tls)
    case False{}:
      url.host(SCon{Chr{c}, t}, tls, "", True{}, False{})

# the authority: "[" starts an IPv6 literal, anything else a name or IPv4
def url.start(s: String, +tls: Bool) -> Url:
  match s:
    case SNil{}:
      UBad{}
    case SCon{Chr{+c}, t}:
      url.start.c(U32.is_eq(c, 91), c, t, tls)

def url.raw(s: String) -> Url:
  match s:
    case SCon{'h', SCon{'t', SCon{'t', SCon{'p', SCon{':', SCon{'/', SCon{'/', rest}}}}}}}:
      url.start(rest, False{})
    case SCon{'h', SCon{'t', SCon{'t', SCon{'p', SCon{'s', SCon{':', SCon{'/', SCon{'/', rest}}}}}}}}:
      url.start(rest, True{})
    case _:
      UBad{}

def url.final(bad: Bool, +tls: Bool, h: String, +port: U32, t: String, au: String) -> Url:
  match bad:
    case True{}:
      UBad{}
    case False{}:
      Url{tls, h, port, t, au}

# a url is used only when its target and authority have no CR, LF or NUL:
# the parser already refuses them, and this check is what the laws read
def url.check(u: Url) -> Url:
  match u:
    case Url{+tls, h, +port, +t, +au}:
      url.final(Bool.or(H1.unsafe(t, False{}), H1.unsafe(au, False{})), tls, h, port, t, au)
    case UBad{}:
      UBad{}

# http[s]://host[:port][/path][?query], the scheme in lowercase; host is a
# name, an IPv4 address, or an IPv6 address in brackets ("[2001:db8::1]",
# kept as its canonical text without the brackets; no zone ID). No user
# info, no fragment
def url(s: String) -> Url:
  url.check(url.raw(s))
# a char a form writes as it is (RFC 3986 §2.3)
def unreserved(+x: U32) -> Bool:
  Bool.or(Bool.or(Bool.and(U32.is_ge(x, 97), U32.is_le(x, 122)), Bool.and(U32.is_ge(x, 65), U32.is_le(x, 90))),
    Bool.or(Bool.and(U32.is_ge(x, 48), U32.is_le(x, 57)), Bool.or(Bool.or(U32.is_eq(x, 45), U32.is_eq(x, 46)), Bool.or(U32.is_eq(x, 95), U32.is_eq(x, 126)))))

def nib(+d: U32) -> Char:
  Chr{Bool.pick(U32, U32.is_lt(d, 10), (d + 48 : U32), (d + 55 : U32))}

def pct.go(bs: List<&2, U32>, out: String) -> String:
  match bs:
    case Nil{}:
      out
    case Con{+b, t}:
      pct.go(t, SCon{nib((b .&. 15 : U32)), SCon{nib((b >> 4n : U32)), SCon{'%', out}}})

def enc.char(plain: Bool, space: Bool, +x: U32, out: String) -> String:
  match plain space:
    case True{} _:
      SCon{Chr{x}, out}
    case False{} True{}:
      SCon{'+', out}
    case False{} False{}:
      pct.go(U.encode(SCon{Chr{x}, SNil{}}), out)

# a component, reversed onto out
def enc.go(s: String, out: String) -> String:
  match s:
    case SNil{}:
      out
    case SCon{Chr{+x}, t}:
      enc.go(t, enc.char(unreserved(x), U32.is_eq(x, 32), x, out))

def form.sep(first: Bool, out: String) -> String:
  match first:
    case True{}:
      out
    case False{}:
      SCon{'&', out}

def form.go(kv: Kv(), first: Bool, out: String) -> String:
  match kv:
    case Nil{}:
      String.reverse(out)
    case Con{(k, v), t}:
      form.go(t, False{}, enc.go(v, SCon{'=', enc.go(k, form.sep(first, out))}))

# k=v&k=v: each byte outside the unreserved set as %XX of its UTF-8, a
# space as +, as application/x-www-form-urlencoded
def form.enc(kv: Kv()) -> String:
  form.go(kv, True{}, "")
