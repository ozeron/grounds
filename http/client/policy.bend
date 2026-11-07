import Base
import ../wire/http1.bend as H1
import ../core/text.bend as T
import ../core/headers.bend as H

# Client policies as plain values: which headers a caller may send, which
# statuses end an exchange, which headers a redirect keeps, and where a
# Location points. Apart from bend_client.bend so test.bend checks them
# without sockets or TLS. Long literals are compared with String.eq or
# T.same_ci in helpers, never matched as patterns (see BUILD_MEMORY.md).

# Headers
# -------

# a char a field value may hold: HTAB, SP, VCHAR or obs-text; never
# another control char or DEL (RFC 9110 §5.5)
def value.char(+x: U32) -> Bool:
  Bool.or(U32.is_eq(x, 9), Bool.and(U32.is_ge(x, 32), Bool.not(U32.is_eq(x, 127))))

def value.ok(s: String, ok: Bool) -> Bool:
  match s:
    case SNil{}:
      ok
    case SCon{Chr{+x}, t}:
      value.ok(t, Bool.and(ok, value.char(x)))

# a header the client writes: its name a token (no space, colon or
# separator, so no other name can be smuggled in), its value without
# control chars
def header.ok(n: String, v: String) -> Bool:
  Bool.and(H1.is_token.s(n), value.ok(v, True{}))

# a status that ends an exchange: 1xx are interim, and 101 switches away
# from HTTP, which this client never asks for; outside 100..599 is not a
# status (RFC 9110 §15)
def final(+c: U32) -> Bool:
  Bool.and(U32.is_ge(c, 200), U32.is_le(c, 599))

# the headers, then User-Agent: ua unless the caller set one the client
# sends (any case, a valid value); None adds none
def agent.add(found: Bool, ua: Maybe<&2, String>, hs: List<&2, H.Header>) -> List<&2, H.Header>:
  match found ua:
    case False{} Some{s}:
      List.append(&2, H.Header, hs, [H.Header{"user-agent", s}])
    case _ _:
      hs

def agent.go(hs: List<&2, H.Header>, acc: List<&2, H.Header>, found: Bool, ua: Maybe<&2, String>) -> List<&2, H.Header>:
  match hs:
    case Nil{}:
      agent.add(found, ua, List.reverse(&2, H.Header, acc))
    case Con{H.Header{+n, +v}, t}:
      agent.go(t, Con{H.Header{n, v}, acc}, Bool.or(found, Bool.and(T.same_ci(n, "user-agent", True{}), header.ok(n, v))), ua)

def agent(ua: Maybe<&2, String>, hs: List<&2, H.Header>) -> List<&2, H.Header>:
  agent.go(hs, [], False{}, ua)

# credentials for the origin they were sent to: a redirect to another
# origin drops them
def private(+n: String) -> Bool:
  Bool.or(T.same_ci(n, "authorization", True{}), Bool.or(T.same_ci(n, "cookie", True{}), T.same_ci(n, "proxy-authorization", True{})))

# headers that describe the body: a redirect that turns the request into a
# GET drops them with the body (RFC 9110 §15.4)
def content(+n: String) -> Bool:
  Bool.or(Bool.or(T.same_ci(n, "content-type", True{}), T.same_ci(n, "content-encoding", True{})),
    Bool.or(T.same_ci(n, "content-language", True{}), T.same_ci(n, "content-location", True{})))

# whether a redirect turns the method into GET: a 303 for any method but
# HEAD, and a 301 or 302 for POST (RFC 9110 §15.4.2–4)
def to_get(+c: U32, n: String, +head: Bool) -> Bool:
  Bool.and(Bool.not(head), Bool.or(U32.is_eq(c, 303), Bool.and(Bool.or(U32.is_eq(c, 301), U32.is_eq(c, 302)), String.eq(n, "POST"))))

# Locations (RFC 3986 §5)
# ---------

# s up to its first #: a fragment is never sent
def frag.go(s: String, acc: String) -> String:
  match s:
    case SNil{}:
      String.reverse(acc)
    case SCon{Chr{35}, _}:
      String.reverse(acc)
    case SCon{c, t}:
      frag.go(t, SCon{c, acc})

def frag.cut(s: String) -> String:
  frag.go(s, "")

# a path and its query (from the ?, kept with it)
type PQ is Data:
  PQ{path: String, query: String}

def pq.go(s: String, acc: String) -> PQ:
  match s:
    case SNil{}:
      PQ{String.reverse(acc), ""}
    case SCon{Chr{63}, t}:
      PQ{String.reverse(acc), SCon{Chr{63}, t}}
    case SCon{c, t}:
      pq.go(t, SCon{c, acc})

def pq(s: String) -> PQ:
  pq.go(s, "")

def pq.path(q: PQ) -> String:
  match q:
    case PQ{p, _}:
      p

# a path's segments, split at each /
def segs.go(s: String, cur: String, acc: List<&2, String>) -> List<&2, String>:
  match s:
    case SNil{}:
      List.reverse(&2, String, Con{String.reverse(cur), acc})
    case SCon{Chr{47}, t}:
      segs.go(t, "", Con{String.reverse(cur), acc})
    case SCon{c, t}:
      segs.go(t, SCon{c, cur}, acc)

def pop(out: List<&2, String>) -> List<&2, String>:
  match out:
    case Nil{}:
      []
    case Con{_, t}:
      t

# one segment onto the output, reversed: . is dropped, .. drops the one
# before; either as the last segment leaves the path ending in /
def dot.step(+one: Bool, +two: Bool, last: Bool, seg: String, out: List<&2, String>) -> List<&2, String>:
  match one two last:
    case True{} _ True{}:
      Con{"", out}
    case True{} _ False{}:
      out
    case False{} True{} True{}:
      Con{"", pop(out)}
    case False{} True{} False{}:
      pop(out)
    case False{} False{} _:
      Con{seg, out}

def empty(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{_, _}:
      False{}

def dots.go(ss: List<&2, String>, out: List<&2, String>) -> List<&2, String>:
  match ss:
    case Nil{}:
      List.reverse(&2, String, out)
    case Con{+seg, Nil{}}:
      List.reverse(&2, String, dot.step(String.eq(seg, "."), String.eq(seg, ".."), True{}, seg, out))
    case Con{+seg, t}:
      dots.go(t, dot.step(String.eq(seg, "."), String.eq(seg, ".."), False{}, seg, out))

def join(ss: List<&2, String>, acc: String) -> String:
  match ss:
    case Nil{}:
      acc
    case Con{x, t}:
      join(t, acc ++ "/" ++ x)

# an absolute path without its . and .. segments (RFC 3986 §5.2.4); the
# path starts with /
def dots(p: String) -> String:
  match p:
    case SCon{_, t}:
      join(dots.go(segs.go(t, "", []), []), "")
    case SNil{}:
      "/"

# the base path up to and including its last /
def dir.go(s: String, cur: String, out: String) -> String:
  match s:
    case SNil{}:
      String.reverse(out)
    case SCon{Chr{47}, t}:
      dir.go(t, "", SCon{'/', String.reverse.go(String.reverse(cur), out)})
    case SCon{c, t}:
      dir.go(t, SCon{c, cur}, out)

def dir(p: String) -> String:
  dir.go(p, "", "")

# where a Location points: a target on the same origin, an absolute
# http(s) url (scheme in lowercase), or nowhere the client follows
type Ref is Data:
  RSame{target: String}
  RAbs{url: String}
  RNone{}

def scheme.char(+x: U32) -> Bool:
  Bool.or(Bool.or(Bool.and(U32.is_ge(x, 97), U32.is_le(x, 122)), Bool.and(U32.is_ge(x, 65), U32.is_le(x, 90))),
    Bool.or(Bool.and(U32.is_ge(x, 48), U32.is_le(x, 57)), Bool.or(U32.is_eq(x, 43), Bool.or(U32.is_eq(x, 45), U32.is_eq(x, 46)))))

# a scheme, lowercased, and what follows its colon; None when the
# reference has no scheme (a relative reference)
type Sch is Data:
  Sch{name: String, rest: String}
  NoSch{}

def scheme.colon(none: Bool, acc: String, t: String) -> Sch:
  match none:
    case True{}:
      NoSch{}
    case False{}:
      Sch{String.reverse(acc), t}

# go: the chars so far may still be a scheme
def scheme.go(s: String, +acc: String, go: Bool) -> Sch:
  match s go:
    case SNil{} _:
      NoSch{}
    case _ False{}:
      NoSch{}
    case SCon{Chr{58}, t} True{}:
      scheme.colon(empty(acc), acc, t)
    case SCon{Chr{+x}, t} True{}:
      scheme.go(t, SCon{Chr{T.lower(x)}, acc}, scheme.char(x))

# an authority, and the path and query after it
type AP is Data:
  AP{auth: String, rest: String}

def auth.go(s: String, acc: String) -> AP:
  match s:
    case SNil{}:
      AP{String.reverse(acc), ""}
    case SCon{Chr{47}, t}:
      AP{String.reverse(acc), SCon{Chr{47}, t}}
    case SCon{Chr{63}, t}:
      AP{String.reverse(acc), SCon{Chr{63}, t}}
    case SCon{c, t}:
      auth.go(t, SCon{c, acc})

def net.pq(q: PQ) -> String:
  match q:
    case PQ{p, qs}:
      dots(p) ++ qs

# a path after the authority loses its . and .. segments; a query is kept
# as it is
def net.rest(r: String) -> String:
  match r:
    case SCon{Chr{47}, t}:
      net.pq(pq(SCon{Chr{47}, t}))
    case other:
      other

def net.ap(ap: AP) -> String:
  match ap:
    case AP{a, r}:
      "//" ++ a ++ net.rest(r)

# //authority/path?query, from what follows the //, with the path's dot
# segments removed (RFC 3986 §5.2.2, §5.2.4)
def net(s: String) -> String:
  net.ap(auth.go(s, ""))

def abs.rest(rest: String) -> String:
  match rest:
    case SCon{Chr{47}, SCon{Chr{47}, t}}:
      net(t)
    case other:
      other

def abs.of(+web: Bool, name: String, rest: String) -> Ref:
  match web:
    case True{}:
      RAbs{name ++ ":" ++ abs.rest(rest)}
    case False{}:
      RNone{}

def rel.path(q: PQ, base: String) -> Ref:
  match q:
    case PQ{p, qs}:
      RSame{dots(dir(pq.path(pq(base))) ++ p) ++ qs}

def rel.abs(q: PQ) -> Ref:
  match q:
    case PQ{p, qs}:
      RSame{dots(p) ++ qs}

# a reference without a scheme: //authority, /path, ?query or a path
# relative to the base's directory; an empty one is not followed
def rel.of(r: String, +tls: Bool, base: String) -> Ref:
  match r:
    case SNil{}:
      RNone{}
    case SCon{Chr{47}, SCon{Chr{47}, t}}:
      RAbs{Bool.pick(String, tls, "https:", "http:") ++ net(t)}
    case SCon{Chr{47}, t}:
      rel.abs(pq(SCon{Chr{47}, t}))
    case SCon{Chr{63}, t}:
      RSame{pq.path(pq(base)) ++ SCon{Chr{63}, t}}
    case other:
      rel.path(pq(other), base)

def abs(s: Sch, rel: String, +tls: Bool, base: String) -> Ref:
  match s:
    case Sch{+name, rest}:
      abs.of(Bool.or(String.eq(name, "http"), String.eq(name, "https")), name, rest)
    case NoSch{}:
      rel.of(rel, tls, base)

def resolve.go(+s: String, +tls: Bool, base: String) -> Ref:
  abs(scheme.go(s, "", True{}), s, tls, base)

# a Location, resolved against the request's target on its origin (tls:
# whether that origin is https), its fragment dropped
def resolve(loc: String, +tls: Bool, base: String) -> Ref:
  resolve.go(frag.cut(loc), tls, base)

# Origins
# -------

# hosts compare ignoring ASCII case (RFC 3986 §3.2.2)
def origin.same(+t1: Bool, h1: String, +p1: U32, +t2: Bool, h2: String, +p2: U32) -> Bool:
  Bool.and(Bool.and(Bool.or(Bool.and(t1, t2), Bool.and(Bool.not(t1), Bool.not(t2))), U32.is_eq(p1, p2)), T.same_ci(h1, h2, True{}))
