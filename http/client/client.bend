import Base
import ../../wire/wire.bend as W
import ../wire/http1.bend as H1
import ../wire/bytes.bend as B
import ../core/method.bend as M
import ../core/headers.bend as H
import ../core/status.bend as S
import ../core/response.bend as Res
import ../core/text.bend as T
import ../../utf8/utf8.bend as U
import ../../json/json.bend as J
import ../core/event.bend as Ev

# grounds-http-client: HTTP/1.1 requests to other services, over TCP or
# TLS.
#
#   r <- Client.get("http://orders:8080/orders/7")
#   match r: Done{res} ... Fail{e}: Client.show(e)
#
# get, post and request open a connection per request and close it after.
# A Pool keeps connections to one origin open between requests. Each
# request, redirects and retries included, has timeout_ms; a response
# past max_head_bytes or max_body_bytes is refused. download streams a
# body through a channel instead.

type Config is Data:
  Config{timeout_ms: U32, max_head_bytes: U32, max_body_bytes: U32, retries: U32, backoff_ms: U32, redirects: U32, idle_ms: U32}

# 10 s, 16 KiB of head, 8 MiB of body, no retries (100 ms apart once
# turned on), up to 5 redirects, and pooled connections idle up to 4 s
def default() -> Config:
  Config{10000, 16384, 8388608, 0, 100, 5, 4000}

def with_timeout(c: Config, ms: U32) -> Config:
  match c:
    case Config{_, mh, mb, rt, bo, rd, id}:
      Config{ms, mh, mb, rt, bo, rd, id}

def with_max_body(c: Config, n: U32) -> Config:
  match c:
    case Config{ms, mh, _, rt, bo, rd, id}:
      Config{ms, mh, n, rt, bo, rd, id}

# retry a request that is safe to repeat up to n more times, on a failed
# connection or a 502, 503 or 504: backoff_ms first, doubling up to 5 s
def with_retries(c: Config, n: U32, backoff_ms: U32) -> Config:
  match c:
    case Config{ms, mh, mb, _, _, rd, id}:
      Config{ms, mh, mb, n, backoff_ms, rd, id}

# follow up to n redirects; 0 hands a 3xx back as it is
def with_redirects(c: Config, n: U32) -> Config:
  match c:
    case Config{ms, mh, mb, rt, bo, _, id}:
      Config{ms, mh, mb, rt, bo, n, id}

# how long a pooled connection may sit idle before it is closed, not used
def with_idle(c: Config, ms: U32) -> Config:
  match c:
    case Config{t, mh, mb, rt, bo, rd, _}:
      Config{t, mh, mb, rt, bo, rd, ms}

# Requests and replies
# --------------------

# names and values: headers, query pairs and form fields
def Kv() -> Type:
  List<&1, String & String>

# a request's body; each sets its own Content-Type
type Body is Type:
  Empty{}
  Bytes{kind: String, bytes: List<&2, U32>}
  Text{text: String}
  Json{value: J.Json}
  Form{fields: Kv()}

def bytes(kind: String, bs: List<&2, U32>) -> Body:
  Bytes{kind, bs}

# Forms
# -----

# s in UTF-8, as text/plain; charset=utf-8
def text(s: String) -> Body:
  Text{s}

# the status, headers, and whether the connection may carry another request
type Meta is Data:
  Meta{code: U32, hs: List<&2, H.Header>, reuse: Bool}

# where the body goes: kept, pieces newest first; sent down a channel; or
# nowhere, once the channel's reader has closed it
type Out is Type:
  Keep{acc: List<&2, B.Bytes>}
  Each{}
  Stopped{}
  Sse{st: Ev.P, pend: List<&2, U32>, stop: Bool}

# a request, as a value: send runs it. key marks it safe to retry, and is
# sent as idempotency-key
type Req is Type:
  Req{method: M.Method, url: String, headers: Kv(), body: Body, key: Maybe<&2, String>}

def head(u: String) -> Req:
  Req{M.MHead{}, u, [], Empty{}, None{}}

# a streamed reply's start
type Head is Type:
  Head{status: U32, headers: Kv()}

# why a request got no response
type Err is Data:
  BadUrl{}            # not http[s]://host[:port][/path][?query]
  NoHost{}            # the host name did not resolve
  Refused{code: U32}  # the connection failed, with errno
  Tls{why: String}    # the TLS handshake failed: why, as OpenSSL says
  Timeout{}           # past timeout_ms
  Closed{}            # the server closed before the response was whole
  TooLarge{}          # past max_head_bytes or max_body_bytes
  BadResponse{}       # not HTTP/1.1 as RFC 9112 frames it
  Redirects{}         # more redirects than the config follows
  BadMethod{}         # a method name that is not a token
  Status{code: U32, body: String}  # send_ok, send_json, stream, events: not 2xx
  BadJson{err: J.Error}            # send_json: the body is not JSON
  BadValue{err: J.Access}          # send_json: the JSON is not the value asked for
  NotEvents{kind: String}          # events: the Content-Type is not text/event-stream

# a value, or why there is none
def R(-A: Type) -> Type:
  Result<&1, &1, Err, A>

# Copies
# ------
# A value used twice is shared, which makes its type reference counted in
# the whole program. A retry or a redirect sends a request again, so the
# request is copied instead: each dup reads a value once and builds two

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
  UBad{err: Err}

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

def url.auth(given: Bool, port: U32, h: String) -> String:
  match given:
    case True{}:
      h ++ ":" ++ U32.show(port)
    case False{}:
      h

def url.make(tls: Bool, auth: String, host: String, port: U32, target: String) -> Url:
  Url{tls, host, port, target, auth}

def url.done(ok: Bool, tls: Bool, +host: String, +port: U32, given: Bool, target: String) -> Url:
  match ok:
    case True{}:
      url.make(tls, url.auth(given, port, s.copy(host, "")), host, port, target)
    case False{}:
      UBad{BadUrl{}}

def url.tgt(g: Tgt, tls: Bool, host: String, port: U32, given: Bool) -> Url:
  match g:
    case Tgt{t, ok}:
      url.done(ok, tls, host, port, given, t)

def url.target(+tls: Bool, host: String, +port: U32, +given: Bool, t: String) -> Url:
  match t:
    case SNil{}:
      url.done(True{}, tls, host, port, given, "/")
    case SCon{Chr{63}, r}:
      url.tgt(target.go(r, "?/", True{}), tls, host, port, given)
    case SCon{Chr{47}, r}:
      url.tgt(target.go(r, "/", True{}), tls, host, port, given)
    case _:
      UBad{BadUrl{}}

def port.num(s: String, +n: Nat, ok: Bool, any: Bool) -> Maybe<&2, U32>:
  match s:
    case SNil{}:
      Bool.pick(Maybe<&2, U32>, Bool.and(Bool.and(ok, any), Bool.and(Nat.is_le(n, 65535n), Nat.is_le(1n, n))), Some{U32.from_nat(n)}, None{})
    case SCon{Chr{+x}, t}:
      port.num(t, Nat.add(Nat.mul(10n, n), Nat.sub(U32.to_nat(x), 48n)), Bool.and(ok, Bool.and(U32.is_ge(x, 48), Bool.and(U32.is_le(x, 57), Nat.is_le(n, 65535n)))), True{})

def url.port.end(m: Maybe<&2, U32>, tls: Bool, host: String, t: String) -> Url:
  match m:
    case Some{p}:
      url.target(tls, host, p, True{}, t)
    case None{}:
      UBad{BadUrl{}}

# the port's digits, up to / or ? or the end: 1 to 65535
def url.port(s: String, +tls: Bool, host: String, acc: String) -> Url:
  match s:
    case SNil{}:
      url.port.end(port.num(String.reverse(acc), 0n, True{}, False{}), tls, host, "")
    case SCon{Chr{47}, t}:
      url.port.end(port.num(String.reverse(acc), 0n, True{}, False{}), tls, host, SCon{Chr{47}, t})
    case SCon{Chr{63}, t}:
      url.port.end(port.num(String.reverse(acc), 0n, True{}, False{}), tls, host, SCon{Chr{63}, t})
    case SCon{c, t}:
      url.port(t, tls, host, SCon{c, acc})

def url.host.end(ok: Bool, +tls: Bool, host: String, s: String) -> Url:
  match ok s:
    case False{} _:
      UBad{BadUrl{}}
    case True{} SCon{Chr{58}, t}:
      url.port(t, tls, host, "")
    case True{} rest:
      url.target(tls, host, Bool.pick(U32, tls, 443, 80), False{}, rest)

# the host, reversed in acc, up to : or / or ? or the end
def url.host(s: String, +tls: Bool, acc: String, ok: Bool, any: Bool) -> Url:
  match s:
    case SNil{}:
      url.host.end(Bool.and(ok, any), tls, String.reverse(acc), "")
    case SCon{Chr{58}, t}:
      url.host.end(Bool.and(ok, any), tls, String.reverse(acc), SCon{Chr{58}, t})
    case SCon{Chr{47}, t}:
      url.host.end(Bool.and(ok, any), tls, String.reverse(acc), SCon{Chr{47}, t})
    case SCon{Chr{63}, t}:
      url.host.end(Bool.and(ok, any), tls, String.reverse(acc), SCon{Chr{63}, t})
    case SCon{Chr{+x}, t}:
      url.host(t, tls, SCon{Chr{x}, acc}, Bool.and(ok, host.char(x)), True{})

def url.raw(s: String) -> Url:
  match s:
    case SCon{'h', SCon{'t', SCon{'t', SCon{'p', SCon{':', SCon{'/', SCon{'/', rest}}}}}}}:
      url.host(rest, False{}, "", True{}, False{})
    case SCon{'h', SCon{'t', SCon{'t', SCon{'p', SCon{'s', SCon{':', SCon{'/', SCon{'/', rest}}}}}}}}:
      url.host(rest, True{}, "", True{}, False{})
    case _:
      UBad{BadUrl{}}

def url.final(bad: Bool, +tls: Bool, h: String, +port: U32, t: String, au: String) -> Url:
  match bad:
    case True{}:
      UBad{BadUrl{}}
    case False{}:
      Url{tls, h, port, t, au}

# a url is used only when its target and authority have no CR, LF or NUL:
# the parser already refuses them, and this check is what the laws read
def url.check(u: Url) -> Url:
  match u:
    case Url{+tls, h, +port, +t, +au}:
      url.final(Bool.or(H1.unsafe(t, False{}), H1.unsafe(au, False{})), tls, h, port, t, au)
    case UBad{e}:
      UBad{e}

# http[s]://host[:port][/path][?query], the scheme in lowercase. No user
# info, no IPv6 literal, no fragment
def url(s: String) -> Url:
  url.check(url.raw(s))

# a request as the client holds it between attempts; pool: its url is the
# pool's origin, so a Pool may carry it
type Spec is Data:
  Spec{verb: Verb, url: Url, hs: List<&2, H.Header>, body: B.Bytes, pool: Bool}

# the caller's headers, and whether they have a Content-Type and an Accept
type Mk is Data:
  Mk{hs: List<&2, H.Header>, ct: Bool, ac: Bool}

def kv.hs(kv: Kv(), ct: Bool, ac: Bool, acc: List<&2, H.Header>) -> Mk:
  match kv:
    case Nil{}:
      Mk{List.reverse(&2, H.Header, acc), ct, ac}
    case Con{(+n, v), t}:
      kv.hs(t, Bool.or(ct, T.same_ci(n, "content-type", True{})), Bool.or(ac, T.same_ci(n, "accept", True{})), Con{H.Header{n, v}, acc})

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

# j encoded, as application/json
def json(j: J.Json) -> Body:
  Json{j}

# a body's bytes, its Content-Type, and whether it is JSON
type Bd is Data:
  Bd{kind: Maybe<&2, String>, json: Bool, bytes: B.Bytes}

def body.of(b: Body) -> Bd:
  match b:
    case Empty{}:
      Bd{None{}, False{}, B.BNil{}}
    case Bytes{k, bs}:
      Bd{Some{k}, False{}, B.of_list(bs)}
    case Text{s}:
      Bd{Some{"text/plain; charset=utf-8"}, False{}, B.of_list(U.encode(s))}
    case Json{j}:
      Bd{Some{"application/json"}, True{}, B.of_list(U.encode(J.encode(j)))}
    case Form{kv}:
      Bd{Some{"application/x-www-form-urlencoded"}, False{}, B.of_list(U.encode(form.enc(kv)))}

def keyed(k: Maybe<&2, String>) -> Bool:
  match k:
    case Some{_}:
      True{}
    case None{}:
      False{}

type Key2 is Data:
  Key2{keyed: Bool, key: Maybe<&2, String>}

def key.of(k: Maybe<&2, String>) -> Key2:
  match k:
    case Some{x}:
      Key2{True{}, Some{x}}
    case None{}:
      Key2{False{}, None{}}

def hs.ct(ct: Bool, kind: Maybe<&2, String>) -> List<&2, H.Header>:
  match ct kind:
    case False{} Some{k}:
      [H.Header{"content-type", k}]
    case _ _:
      []

def hs.ac(ac: Bool, js: Bool) -> List<&2, H.Header>:
  match ac js:
    case False{} True{}:
      [H.Header{"accept", "application/json"}]
    case _ _:
      []

def hs.key(k: Maybe<&2, String>) -> List<&2, H.Header>:
  match k:
    case Some{x}:
      [H.Header{"idempotency-key", x}]
    case None{}:
      []

def spec.make(v: Maybe<&2, Verb>, u: Url, mk: Mk, bd: Bd, k: Key2) -> Result<&2, &2, Err, Spec>:
  match v mk bd k:
    case Some{Verb{n, h, z, g}} Mk{hs, ct, ac} Bd{kind, js, bs} Key2{kd, key}:
      Done{Spec{Verb{n, h, z, Bool.or(g, kd)}, u, List.append(&2, H.Header, hs, List.append(&2, H.Header, hs.ct(ct, kind), List.append(&2, H.Header, hs.ac(ac, js), hs.key(key)))), bs, False{}}}
    case None{} _ _ _:
      Fail{BadMethod{}}

# the request as the client holds it between tries
def spec.of(r: Req) -> Result<&2, &2, Err, Spec>:
  match r:
    case Req{m, u, kv, b, k}:
      spec.make(verb.check(verb(m)), url(u), kv.hs(kv, False{}, False{}, []), body.of(b), key.of(k))

# a connection, or why there is none
type Opened is Type:
  Opened{sock: Socket, tls: Bool}
  NotOpened{err: Err}

type Str2 is Data:
  Str2{a: String, b: String}

def s.dup.go(s: String, a: String, b: String) -> Str2:
  match s:
    case SNil{}:
      Str2{String.reverse(a), String.reverse(b)}
    case SCon{Chr{+x}, t}:
      s.dup.go(t, SCon{Chr{x}, a}, SCon{Chr{x}, b})

def s.dup(s: String) -> Str2:
  s.dup.go(s, "", "")

def left(dl: Nat, now: Nat) -> U32:
  U32.from_nat(Nat.sub(dl, now))

def etimedout(+c: U32) -> Bool:
  Bool.or(U32.is_eq(c, 60), U32.is_eq(c, 110))

def failed(+c: U32) -> Err:
  Bool.pick(Err, etimedout(c), Timeout{}, Refused{c})

def RU() -> Type:
  Socket & Result<&1, &1, U32 & String, Unit>

law shook:
  for m: RU()
  IO(Opened)

def shook.go(r: Result<&1, &1, U32 & String, Unit>, s: Socket) -> IO(Opened):
  match r:
    case Done{_}:
      IO.pure(Opened, Opened{s, True{}})
    case Fail{(c, why)}:
      IO.bind(Unit, Opened, W.wire_tls_close(s), u => IO.pure(Opened, NotOpened{Bool.pick(Err, etimedout(c), Timeout{}, Tls{why})}))

def shook(m):
  (s, r) = m
  shook.go(r, s)

def connected(r: Result<&1, &1, U32 & String, Socket>, tls: Bool, sni: String, dl: Nat) -> IO(Opened):
  match r tls:
    case Done{s} True{}:
      do IO<Opened>:
        +now : Nat <- IO.now()
        m : RU() <- W.wire_tls_connect(s, sni, left(dl, now))
        shook(m)
    case Done{s} False{}:
      IO.pure(Opened, Opened{s, False{}})
    case Fail{(c, _)} _:
      IO.pure(Opened, NotOpened{failed(c)})

def resolved(r: Result<&1, &1, U32 & String, String>, tls: Bool, sni: String, port: U32, +dl: Nat) -> IO(Opened):
  match r:
    case Done{ip}:
      do IO<Opened>:
        +now : Nat <- IO.now()
        c : Result<&1, &1, U32 & String, Socket> <- W.wire_connect_timeout(ip, port, left(dl, now))
        connected(c, tls, sni, dl)
    case Fail{_}:
      IO.pure(Opened, NotOpened{NoHost{}})

def open.go(tls: Bool, h: Str2, port: U32, dl: Nat) -> IO(Opened):
  match h:
    case Str2{a, b}:
      IO.bind(Result<&1, &1, U32 & String, String>, Opened, W.wire_resolve(a), r => resolved(r, tls, b, port, dl))

# resolve, connect, and for https the TLS handshake, by the deadline
def open(tls: Bool, host: String, port: U32, dl: Nat) -> IO(Opened):
  open.go(tls, s.dup(host), port, dl)

# Reading a response
# ------------------

# the caller's headers without Host, which the client writes from the url
def hs.clean.one(host: Bool, h: H.Header, acc: List<&2, H.Header>) -> List<&2, H.Header>:
  match host:
    case True{}:
      acc
    case False{}:
      Con{h, acc}

def hs.clean(hs: List<&2, H.Header>, acc: List<&2, H.Header>) -> List<&2, H.Header>:
  match hs:
    case Nil{}:
      List.reverse(&2, H.Header, acc)
    case Con{H.Header{+n, v}, t}:
      hs.clean(t, hs.clean.one(T.same_ci(n, "host", True{}), H.Header{n, v}, acc))

# One try
# -------

# what a read may do: the deadline, or ms per read when streaming; the
# head's limit, the body's, and whether the request was a HEAD
type Lim is Data:
  Lim{dl: Nat, ms: U32, stream: Bool, mh: U32, max: Nat, head: Bool}

def lim.left(l: Lim, now: Nat) -> U32:
  match l:
    case Lim{dl, ms, stream, _, _, _}:
      Bool.pick(U32, stream, ms, left(dl, now))

def send.of(tls: Bool, s: Socket, bs: List<&2, U32>, +ms: U32) -> IO(RU()):
  match tls:
    case True{}:
      W.wire_tls_send_timeout(s, bs, ms)
    case False{}:
      W.wire_send_timeout(s, bs, ms)

# a response head, the connection still open; or why not, the connection
# closed. stale: it failed before a byte of the response came, as a pooled
# connection the server has closed does
type Hd is Type:
  HGot{sock: Socket, tls: Bool, head: H1.Head}
  HLost{err: Err, stale: Bool}

def shut(tls: Bool, s: Socket) -> IO(Unit):
  match tls:
    case True{}:
      W.wire_tls_close(s)
    case False{}:
      W.close(s)

# an exchange's end: a response, the connection still open; or why not,
# the connection closed
type Ex is Type:
  Got{sock: Socket, tls: Bool, meta: Meta, out: Out}
  Lost{err: Err, stale: Bool, out: Out}

def lim.with_max(l: Lim, max: Nat) -> Lim:
  match l:
    case Lim{dl, ms, st, mh, _, h}:
      Lim{dl, ms, st, mh, max, h}

# data to a kept body
def keep.go(o: Out, bs: B.Bytes) -> IO(Out):
  match o:
    case Keep{acc}:
      IO.pure(Out, Keep{Con{bs, acc}})
    case other:
      IO.pure(Out, other)

def keep(o: Out, bs: B.Bytes) -> IO(Out):
  match bs:
    case B.BNil{}:
      IO.pure(Out, o)
    case B.BCon{b, t}:
      keep.go(o, B.BCon{b, t})

def each.on(go: Bool) -> Out:
  match go:
    case True{}:
      Each{}
    case False{}:
      Stopped{}

def each.go(~f: List<&2, U32> -> IO(Bool), o: Out, bs: B.Bytes) -> IO(Out):
  match o:
    case Each{}:
      IO.bind(Bool, Out, f(B.to_list(bs)), go => IO.pure(Out, each.on(go)))
    case other:
      IO.pure(Out, other)

# data to stream's callback; a callback that answers False stops the body
# there
def each(~f: List<&2, U32> -> IO(Bool), o: Out, bs: B.Bytes) -> IO(Out):
  match bs:
    case B.BNil{}:
      IO.pure(Out, o)
    case B.BCon{b, t}:
      each.go(~f, o, B.BCon{b, t})

def hs.kv(hs: List<&2, H.Header>, acc: Kv()) -> Kv():
  match hs:
    case Nil{}:
      List.reverse(&1, String & String, acc)
    case Con{H.Header{n, v}, t}:
      hs.kv(t, Con{(n, v), acc})

type Reply is Type:
  Reply{status: U32, headers: Kv(), body: List<&2, U32>}

# the bytes, oldest first, from pieces newest first
def flat(cs: List<&2, B.Bytes>, acc: B.Bytes) -> B.Bytes:
  match cs:
    case Nil{}:
      acc
    case Con{c, t}:
      flat(t, B.app(c, acc))

def response(m: Meta, o: Out) -> Reply:
  match m o:
    case Meta{c, hs, _} Keep{acc}:
      Reply{c, hs.kv(hs, []), B.to_list(flat(acc, B.BNil{}))}
    case Meta{c, hs, _} _:
      Reply{c, hs.kv(hs, []), []}

def RR() -> Type:
  Result<&1, &1, Err, Reply>

def text.of(t: U.Text) -> Maybe<&2, String>:
  match t:
    case U.TOk{s}:
      Some{s}
    case _:
      None{}

def ok.check(ok: Bool, c: U32, hs: Kv(), b: List<&2, U32>) -> RR():
  match ok:
    case True{}:
      Done{Reply{c, hs, b}}
    case False{}:
      Fail{Status{c, T.or(text.of(U.decode(b)), "")}}

def ok.of(r: RR()) -> RR():
  match r:
    case Done{Reply{+c, hs, b}}:
      ok.check(Bool.and(U32.is_ge(c, 200), U32.is_lt(c, 300)), c, hs, b)
    case Fail{e}:
      Fail{e}

def lim.max(l: Lim) -> Nat:
  match l:
    case Lim{_, _, _, _, max, _}:
      max

# where a body's framing is: bytes left, a chunked decoder, or to the close
type St is Data:
  BLen{left: Nat}
  BChunk{cs: H1.CS}
  BClose{}

def done.meta(m: Meta, extra: Bool) -> Meta:
  match m:
    case Meta{c, hs, r}:
      Meta{c, hs, Bool.and(r, Bool.not(extra))}

def done(o: Out, s: Socket, +tls: Bool, m: Meta) -> IO(Ex):
  match o:
    case Stopped{}:
      IO.pure(Ex, Got{s, tls, done.meta(m, True{}), Stopped{}})
    case Sse{st, p, True{}}:
      IO.pure(Ex, Got{s, tls, done.meta(m, True{}), Sse{st, p, True{}}})
    case other:
      IO.pure(Ex, Got{s, tls, m, other})

def lost(tls: Bool, s: Socket, e: Err, stale: Bool, o: Out) -> IO(Ex):
  IO.bind(Unit, Ex, shut(tls, s), u => IO.pure(Ex, Lost{e, stale, o}))

def count(bs: B.Bytes, +n: Nat) -> Nat:
  match bs:
    case B.BNil{}:
      n
    case B.BCon{_, t}:
      count(t, Nat.add(n, 1n))

# URLs
# ----

type Step is Data:
  SMore{st: St, data: B.Bytes}
  SDone{data: B.Bytes, extra: Bool}
  SBad{err: Err}

def BK() -> Type:
  Socket -> St -> B.Bytes -> Out -> Nat -> Meta -> IO(Ex)

# whether the reader went away, and the Out back
# whether a callback asked to stop, and the Out back
type Cutq is Type:
  Cutq{cut: Bool, out: Out}

def is_cut.keep(o: Out) -> Cutq:
  match o:
    case Stopped{}:
      Cutq{True{}, Stopped{}}
    case Sse{st, p, True{}}:
      Cutq{True{}, Sse{st, p, True{}}}
    case other:
      Cutq{False{}, other}

def lim.over(l: Lim, now: Nat) -> Bool:
  match l:
    case Lim{dl, _, stream, _, _, _}:
      Bool.and(Bool.not(stream), Nat.is_le(dl, now))

def RP() -> Type:
  Socket & Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>

def recv.of(tls: Bool, s: Socket, +ms: U32) -> IO(RP()):
  match tls:
    case True{}:
      W.wire_tls_recv_timeout(s, 65536, ms)
    case False{}:
      W.wire_recv_timeout(s, 65536, ms)

law bd.polled:
  for st: St
  for +tls: Bool
  for o: Out
  for +total: Nat
  for m: Meta
  for p: RP()
  for again: BK()
  IO(Ex)

def bd.eof(st: St, s: Socket, +tls: Bool, o: Out, m: Meta) -> IO(Ex):
  match st:
    case BClose{}:
      done(o, s, tls, done.meta(m, True{}))
    case _:
      lost(tls, s, Closed{}, False{}, o)

def bd.got(r: Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>, st: St, s: Socket, +tls: Bool, o: Out, total: Nat, m: Meta, again: BK()) -> IO(Ex):
  match r:
    case Done{Some{Con{b, t}}}:
      again(s, st, B.of_list(Con{b, t}), o, total, m)
    case Done{Some{Nil{}}}:
      bd.eof(st, s, tls, o, m)
    case Done{None{}}:
      lost(tls, s, Timeout{}, False{}, o)
    case Fail{_}:
      lost(tls, s, Closed{}, False{}, o)

def bd.polled(st, tls, o, total, m, p, again):
  (s, r) = p
  bd.got(r, st, s, tls, o, total, m, again)

def bd.read(over: Bool, now: Nat, st: St, s: Socket, +tls: Bool, o: Out, total: Nat, m: Meta, +lim: Lim, again: BK()) -> IO(Ex):
  match over:
    case True{}:
      lost(tls, s, Timeout{}, False{}, o)
    case False{}:
      IO.bind(RP(), Ex, recv.of(tls, s, lim.left(lim, now)), p => bd.polled(st, tls, o, total, m, p, again))

def bd.more.go(cut: Bool, big: Bool, st: St, s: Socket, +tls: Bool, o: Out, total: Nat, m: Meta, +lim: Lim, again: BK()) -> IO(Ex):
  match cut big:
    case True{} _:
      done(o, s, tls, m)
    case False{} True{}:
      lost(tls, s, TooLarge{}, False{}, o)
    case False{} False{}:
      do IO<Ex>:
        +now : Nat <- IO.now()
        bd.read(lim.over(lim, now), now, st, s, tls, o, total, m, lim, again)

def bd.cut(q: Cutq, st: St, s: Socket, tls: Bool, +total: Nat, m: Meta, +lim: Lim, again: BK()) -> IO(Ex):
  match q:
    case Cutq{cut, o}:
      bd.more.go(cut, Bool.not(Nat.is_le(total, lim.max(lim))), st, s, tls, o, total, m, lim, again)

def bd.more(o: Out, st: St, s: Socket, tls: Bool, total: Nat, m: Meta, lim: Lim, again: BK()) -> IO(Ex):
  bd.cut(is_cut.keep(o), st, s, tls, total, m, lim, again)

# the total counted before the data goes: counting after would read what
# deliver already took
def bd.counted(~dv: Out -> B.Bytes -> IO(Out), total: Nat, data: B.Bytes, st: St, s: Socket, tls: Bool, o: Out, m: Meta, lim: Lim, again: BK()) -> IO(Ex):
  IO.bind(Out, Ex, dv(o, data), o2 => bd.more(o2, st, s, tls, total, m, lim, again))

def bd.step(~dv: Out -> B.Bytes -> IO(Out), step: Step, s: Socket, +tls: Bool, o: Out, total: Nat, m: Meta, lim: Lim, again: BK()) -> IO(Ex):
  match step:
    case SMore{st, +data}:
      bd.counted(~dv, Nat.add(total, count(data, 0n)), data, st, s, tls, o, m, lim, again)
    case SDone{data, extra}:
      IO.bind(Out, Ex, dv(o, data), o2 => done(o2, s, tls, done.meta(m, extra)))
    case SBad{e}:
      lost(tls, s, e, False{}, o)

def copy(bs: B.Bytes, acc: B.Bytes) -> B.Bytes:
  match bs:
    case B.BNil{}:
      B.rev(acc)
    case B.BCon{b, t}:
      copy(t, B.BCon{b, acc})

def bad(e: H1.Err) -> Err:
  match e:
    case H1.BodyTooLarge{}:
      TooLarge{}
    case H1.HeadTooLarge{}:
      TooLarge{}
    case _:
      BadResponse{}

def feed.fed(f: H1.Fed) -> Step:
  match f:
    case H1.Fed{H1.CS{m, acc, total, budget}}:
      SMore{BChunk{H1.CS{m, B.BNil{}, total, budget}}, B.rev(acc)}
    case H1.Fed{_}:
      SBad{BadResponse{}}
    case H1.FedEnd{data, rest}:
      SDone{data, B.nonempty(rest)}
    case H1.FedBad{e}:
      SBad{bad(e)}

def feed.len(t: H1.Took, +p: B.Bytes, left: Nat) -> Step:
  match t:
    case H1.Took{got, rest}:
      SDone{got, B.nonempty(rest)}
    case H1.Short{}:
      SMore{BLen{Nat.sub(left, count(p, 0n))}, p}

# a read's bytes through the framing: the body's part of them, and
# whether the body ended (extra: bytes came after it)
def feed(st: St, +p: B.Bytes, max: Nat) -> Step:
  match st:
    case BLen{+left}:
      feed.len(H1.take(copy(p, B.BNil{}), left, B.BNil{}), p, left)
    case BChunk{cs}:
      feed.fed(H1.chunks.feed(p, cs, max))
    case BClose{}:
      SMore{BClose{}, p}

# the body: each read through the framing, its data to o; fuel bounds the
# reads, each at least a byte
def bd(~dv: Out -> B.Bytes -> IO(Out), fuel: Nat, s: Socket, +tls: Bool, st: St, piece: B.Bytes, o: Out, total: Nat, m: Meta, +lim: Lim) -> IO(Ex):
  match fuel:
    case 0n:
      lost(tls, s, TooLarge{}, False{}, o)
    case 1n+p:
      bd.step(~dv, feed(st, piece, lim.max(lim)), s, tls, o, total, m, lim, sk => st2 => pc => o2 => t2 => m2 => bd(~dv, p, sk, tls, st2, pc, o2, t2, m2, lim))

def body(~dv: Out -> B.Bytes -> IO(Out), fr: H1.Framing, s: Socket, +tls: Bool, rest: B.Bytes, o: Out, m: Meta, +lim: Lim) -> IO(Ex):
  match fr:
    case H1.FNone{}:
      done(o, s, tls, done.meta(m, B.nonempty(rest)))
    case H1.FLen{n}:
      bd(~dv, Nat.add(lim.max(lim), 131074n), s, tls, BLen{n}, rest, o, 0n, m, lim)
    case H1.FChunked{}:
      bd(~dv, Nat.add(lim.max(lim), 131074n), s, tls, BChunk{H1.chunks.start(lim.max(lim))}, rest, o, 0n, m, lim)
    case H1.FClose{}:
      bd(~dv, Nat.add(lim.max(lim), 131074n), s, tls, BClose{}, rest, o, 0n, m, lim)

def hd.lost(tls: Bool, s: Socket, e: Err, stale: Bool) -> IO(Hd):
  IO.bind(Unit, Hd, shut(tls, s), u => IO.pure(Hd, HLost{e, stale}))

def lim.mh(l: Lim) -> U32:
  match l:
    case Lim{_, _, _, mh, _, _}:
      mh

def lim.head(l: Lim) -> Bool:
  match l:
    case Lim{_, _, _, _, _, h}:
      h

def hd.parse(h: H1.Head, buf: B.Bytes, s: Socket, +tls: Bool, again: Socket -> B.Bytes -> IO(Hd)) -> IO(Hd):
  match h:
    case H1.Head{code, hs, fr, reuse, rest}:
      IO.pure(Hd, HGot{s, tls, H1.Head{code, hs, fr, reuse, rest}})
    case H1.HMore{}:
      again(s, buf)
    case H1.HBad{e}:
      hd.lost(tls, s, bad(e), False{})

def hd.try(+buf: B.Bytes, s: Socket, tls: Bool, +lim: Lim, again: Socket -> B.Bytes -> IO(Hd)) -> IO(Hd):
  hd.parse(H1.read_head(copy(buf, B.BNil{}), lim.mh(lim), lim.max(lim), lim.head(lim)), buf, s, tls, again)

law hd.polled:
  for +tls: Bool
  for +buf: B.Bytes
  for +lim: Lim
  for m: RP()
  for again: Socket -> B.Bytes -> IO(Hd)
  IO(Hd)

def hd.got(r: Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>, s: Socket, +tls: Bool, +buf: B.Bytes, lim: Lim, again: Socket -> B.Bytes -> IO(Hd)) -> IO(Hd):
  match r:
    case Done{Some{Con{b, t}}}:
      hd.try(B.app(buf, B.of_list(Con{b, t})), s, tls, lim, again)
    case Done{Some{Nil{}}}:
      hd.lost(tls, s, Closed{}, Bool.not(B.nonempty(buf)))
    case Done{None{}}:
      hd.lost(tls, s, Timeout{}, False{})
    case Fail{_}:
      hd.lost(tls, s, Closed{}, Bool.not(B.nonempty(buf)))

def hd.polled(tls, buf, lim, m, again):
  (s, r) = m
  hd.got(r, s, tls, buf, lim, again)

def hd.wait(over: Bool, now: Nat, s: Socket, +tls: Bool, buf: B.Bytes, +lim: Lim, again: Socket -> B.Bytes -> IO(Hd)) -> IO(Hd):
  match over:
    case True{}:
      hd.lost(tls, s, Timeout{}, False{})
    case False{}:
      IO.bind(RP(), Hd, recv.of(tls, s, lim.left(lim, now)), m => hd.polled(tls, buf, lim, m, again))

# read until the head is whole; fuel bounds the reads, each at least a byte
def hd(fuel: Nat, s: Socket, +tls: Bool, buf: B.Bytes, +lim: Lim) -> IO(Hd):
  match fuel:
    case 0n:
      hd.lost(tls, s, TooLarge{}, False{})
    case 1n+p:
      do IO<Hd>:
        +now : Nat <- IO.now()
        hd.wait(lim.over(lim, now), now, s, tls, buf, lim, sk => b => hd(p, sk, tls, b, lim))

def interim(+code: U32) -> Bool:
  Bool.and(U32.is_ge(code, 100), Bool.and(U32.is_lt(code, 200), Bool.not(U32.is_eq(code, 101))))

def heads.skip(skip: Bool, s: Socket, tls: Bool, h: H1.Head, k: Socket -> B.Bytes -> IO(Hd)) -> IO(Hd):
  match skip h:
    case True{} H1.Head{_, _, _, _, rest}:
      k(s, rest)
    case _ other:
      IO.pure(Hd, HGot{s, tls, other})

def heads.go(h: Hd, k: Socket -> B.Bytes -> IO(Hd)) -> IO(Hd):
  match h:
    case HGot{s, tls, H1.Head{+code, hs, fr, reuse, rest}}:
      heads.skip(interim(code), s, tls, H1.Head{code, hs, fr, reuse, rest}, k)
    case other:
      IO.pure(Hd, other)

# the head, past up to n 1xx heads, from buf and what comes after it
def heads(n: Nat, s: Socket, +tls: Bool, +buf: B.Bytes, +lim: Lim) -> IO(Hd):
  match n:
    case 0n:
      hd.try(buf, s, tls, lim, sk => b => hd(Nat.add(U32.to_nat(lim.mh(lim)), 2n), sk, tls, b, lim))
    case 1n+p:
      IO.bind(Hd, Hd, hd.try(buf, s, tls, lim, sk => b => hd(Nat.add(U32.to_nat(lim.mh(lim)), 2n), sk, tls, b, lim)), h => heads.go(h, sk => b => heads(p, sk, tls, b, lim)))

# Bodies
# ------

def stream.sent(r: Result<&1, &1, U32 & String, Unit>, s: Socket, +tls: Bool, +lim: Lim) -> IO(Hd):
  match r:
    case Done{_}:
      heads(8n, s, tls, B.BNil{}, lim)
    case Fail{(+c, _)}:
      hd.lost(tls, s, Bool.pick(Err, etimedout(c), Timeout{}, Closed{}), False{})

def stream.polled(+tls: Bool, +lim: Lim, m: RU()) -> IO(Hd):
  match m:
    case (s, r):
      stream.sent(r, s, tls, lim)

# any method by name; one that is not a token fails send with BadMethod
def method(name: String, u: String, b: Body) -> Req:
  Req{M.parse(name), u, [], b, None{}}

def get(u: String) -> Req:
  Req{M.MGet{}, u, [], Empty{}, None{}}

def delete(u: String) -> Req:
  Req{M.MDelete{}, u, [], Empty{}, None{}}

def post(u: String, b: Body) -> Req:
  Req{M.MPost{}, u, [], b, None{}}

def put(u: String, b: Body) -> Req:
  Req{M.MPut{}, u, [], b, None{}}

def patch(u: String, b: Body) -> Req:
  Req{M.MPatch{}, u, [], b, None{}}

# the headers added, in order
def with(r: Req, kv: Kv()) -> Req:
  match r:
    case Req{m, u, hs, b, k}:
      Req{m, u, List.append(&1, String & String, hs, kv), b, k}

def bearer(r: Req, token: String) -> Req:
  with(r, [("authorization", "Bearer " ++ token)])

# sent with idempotency-key: key, and safe to retry, as the server
# deduplicates on the key
def idempotent(r: Req, key: String) -> Req:
  match r:
    case Req{m, u, hs, b, _}:
      Req{m, u, hs, b, Some{key}}

def has_q(s: String, found: Bool) -> Bool:
  match s:
    case SNil{}:
      found
    case SCon{Chr{+x}, t}:
      has_q(t, Bool.or(found, U32.is_eq(x, 63)))

def url.query(u: Str2, q: String) -> String:
  match u q:
    case Str2{a, _} SNil{}:
      a
    case Str2{a, b} rest:
      b ++ Bool.pick(String, has_q(a, False{}), "&", "?") ++ rest

# the pairs added to the url's query, percent-encoded
def query(r: Req, kv: Kv()) -> Req:
  match r:
    case Req{m, u, hs, b, k}:
      Req{m, url.query(s.dup(u), form.enc(kv)), hs, b, k}

def empty() -> Body:
  Empty{}

# the pairs percent-encoded, as application/x-www-form-urlencoded
def form(kv: Kv()) -> Body:
  Form{kv}

def show(e: Err) -> String:
  match e:
    case BadUrl{}:
      "bad url: want http[s]://host[:port][/path]"
    case NoHost{}:
      "host not found"
    case Refused{c}:
      "connection failed: errno " ++ U32.show(c)
    case Tls{why}:
      "TLS: " ++ why
    case Timeout{}:
      "timed out"
    case Closed{}:
      "closed before the response was whole"
    case TooLarge{}:
      "response too large"
    case BadResponse{}:
      "bad response"
    case Redirects{}:
      "too many redirects"
    case BadMethod{}:
      "bad method: not a token"
    case Status{c, b}:
      "status " ++ U32.show(c) ++ ": " ++ b
    case BadJson{x}:
      "invalid JSON: " ++ J.message(x)
    case BadValue{x}:
      J.message_access(x)
    case NotEvents{k}:
      "not an event stream: " ++ k

type Hs2 is Data:
  Hs2{a: List<&2, H.Header>, b: List<&2, H.Header>}

type H2 is Data:
  H2{a: H.Header, b: H.Header}

def h2.of(n: Str2, v: Str2) -> H2:
  match n v:
    case Str2{na, nb} Str2{va, vb}:
      H2{H.Header{na, va}, H.Header{nb, vb}}

def hs.dups(hs: List<&2, H.Header>, acc: List<&2, H2>) -> List<&2, H2>:
  match hs:
    case Nil{}:
      acc
    case Con{H.Header{n, v}, t}:
      hs.dups(t, Con{h2.of(s.dup(n), s.dup(v)), acc})

# pairs newest first, back in order as two lists
def hs.unzip(ps: List<&2, H2>, a: List<&2, H.Header>, b: List<&2, H.Header>) -> Hs2:
  match ps:
    case Nil{}:
      Hs2{a, b}
    case Con{H2{x, y}, t}:
      hs.unzip(t, Con{x, a}, Con{y, b})

def hs.dup(hs: List<&2, H.Header>) -> Hs2:
  hs.unzip(hs.dups(hs, []), [], [])

type Bs2 is Data:
  Bs2{a: B.Bytes, b: B.Bytes}

def bs.dup.go(bs: B.Bytes, a: B.Bytes, b: B.Bytes) -> Bs2:
  match bs:
    case B.BNil{}:
      Bs2{B.rev(a), B.rev(b)}
    case B.BCon{+x, t}:
      bs.dup.go(t, B.BCon{x, a}, B.BCon{x, b})

def num.go(s: String, +n: Nat, ok: Bool) -> Maybe<&2, U32>:
  match s:
    case SNil{}:
      Bool.pick(Maybe<&2, U32>, ok, Some{U32.from_nat(n)}, None{})
    case SCon{Chr{+x}, t}:
      num.go(t, Nat.add(Nat.mul(10n, n), Nat.sub(U32.to_nat(x), 48n)), Bool.and(ok, Bool.and(U32.is_ge(x, 48), U32.is_le(x, 57))))

def num.of(m: Maybe<&2, U32>) -> U32:
  match m:
    case Some{n}:
      n
    case None{}:
      0

# a count from its decimal digits, for tests; 0 when it is not one
def port.num.of(s: String) -> U32:
  num.of(num.go(s, 0n, True{}))

type Url2 is Data:
  Url2{a: Url, b: Url}

def url.dup.go(+tls: Bool, h: Str2, +port: U32, t: Str2, au: Str2) -> Url2:
  match h t au:
    case Str2{ha, hb} Str2{ta, tb} Str2{aa, ab}:
      Url2{Url{tls, ha, port, ta, aa}, Url{tls, hb, port, tb, ab}}

def url.dup(u: Url) -> Url2:
  match u:
    case Url{tls, h, port, t, au}:
      url.dup.go(tls, s.dup(h), port, s.dup(t), s.dup(au))
    case UBad{e}:
      Url2{UBad{e}, UBad{BadUrl{}}}

# Connections
# -----------

def lim.dl(l: Lim) -> Nat:
  match l:
    case Lim{dl, _, _, _, _, _}:
      dl

def lim.with_head(l: Lim, h: Bool) -> Lim:
  match l:
    case Lim{dl, ms, st, mh, max, _}:
      Lim{dl, ms, st, mh, max, h}

def ex.head(h: Hd, lim: Lim, o: Out) -> IO(Ex):
  match h:
    case HLost{e, stale}:
      IO.pure(Ex, Lost{e, stale, o})
    case HGot{s, tls, H1.Head{code, hs, fr, reuse, rest}}:
      body(~keep, fr, s, tls, rest, o, Meta{code, hs, reuse}, lim)
    case HGot{s, tls, _}:
      lost(tls, s, BadResponse{}, False{}, o)

def ex.sent(r: Result<&1, &1, U32 & String, Unit>, s: Socket, +tls: Bool, +lim: Lim, o: Out) -> IO(Ex):
  match r:
    case Done{_}:
      IO.bind(Hd, Ex, heads(8n, s, tls, B.BNil{}, lim), h => ex.head(h, lim, o))
    case Fail{(+c, _)}:
      lost(tls, s, Bool.pick(Err, etimedout(c), Timeout{}, Closed{}), Bool.not(etimedout(c)), o)

law ex.polled:
  for +tls: Bool
  for +lim: Lim
  for o: Out
  for m: RU()
  IO(Ex)

def ex.polled(tls, lim, o, m):
  (s, r) = m
  ex.sent(r, s, tls, lim, o)

# one request on an open connection, and its response
def exchange(s: Socket, +tls: Bool, req: B.Bytes, +lim: Lim, o: Out) -> IO(Ex):
  do IO<Ex>:
    +now : Nat <- IO.now()
    m : RU() <- send.of(tls, s, B.to_list(req), lim.left(lim, now))
    ex.polled(tls, lim, o, m)

# Requests
# --------

type Verb2 is Data:
  Verb2{a: Verb, b: Verb}

def verb.dup.go(n: Str2, +h: Bool, +z: Bool, +g: Bool) -> Verb2:
  match n:
    case Str2{a, b}:
      Verb2{Verb{a, h, z, g}, Verb{b, h, z, g}}

def verb.dup(v: Verb) -> Verb2:
  match v:
    case Verb{n, h, z, g}:
      verb.dup.go(s.dup(n), h, z, g)

type Spec2 is Data:
  Spec2{a: Spec, b: Spec}

def spec.dup.go(v: Verb2, u: Url2, h: Hs2, b: Bs2, +pool: Bool) -> Spec2:
  match v u h b:
    case Verb2{va, vb} Url2{ua, ub} Hs2{ha, hb} Bs2{ba, bb}:
      Spec2{Spec{va, ua, ha, ba, pool}, Spec{vb, ub, hb, bb, pool}}

def spec.dup(s: Spec) -> Spec2:
  match s:
    case Spec{v, u, hs, b, pool}:
      spec.dup.go(verb.dup(v), url.dup(u), hs.dup(hs), bs.dup.go(b, B.BNil{}, B.BNil{}), pool)

# a response, its connection dealt with; or why there is none
type Hop is Type:
  HopGot{meta: Meta, out: Out}
  HopLost{err: Err}

def hop.end(e: Ex) -> IO(Hop):
  match e:
    case Got{s, tls, m, o}:
      IO.bind(Unit, Hop, shut(tls, s), u => IO.pure(Hop, HopGot{m, o}))
    case Lost{err, _, _}:
      IO.pure(Hop, HopLost{err})

def once.opened(o: Opened, req: B.Bytes, lim: Lim) -> IO(Hop):
  match o:
    case Opened{s, tls}:
      IO.bind(Ex, Hop, exchange(s, tls, req, lim, Keep{[]}), e => hop.end(e))
    case NotOpened{e}:
      IO.pure(Hop, HopLost{e})

def once.go(req: B.Bytes, tls: Bool, host: String, port: U32, +lim: Lim) -> IO(Hop):
  IO.bind(Opened, Hop, open(tls, host, port, lim.dl(lim)), o => once.opened(o, req, lim))

# a request on a connection of its own, closed after
def once(sp: Spec, +lim: Lim) -> IO(Hop):
  match sp:
    case Spec{Verb{name, head, sized, _}, Url{tls, host, port, target, auth}, hs, b, _}:
      once.go(H1.write_request(name, target, auth, hs.clean(hs, []), b, sized, True{}), tls, host, port, lim.with_head(lim, head))
    case Spec{_, UBad{e}, _, _, _}:
      IO.pure(Hop, HopLost{e})

# Pools
# -----

def req.of(sp: Spec, keep: Bool) -> B.Bytes:
  match sp:
    case Spec{Verb{name, _, sized, _}, Url{_, _, _, target, auth}, hs, b, _}:
      H1.write_request(name, target, auth, hs.clean(hs, []), b, sized, Bool.not(keep))
    case _:
      B.BNil{}

def head.of(sp: Spec) -> Bool:
  match sp:
    case Spec{Verb{_, h, _, _}, _, _, _, _}:
      h

type HSpec is Data:
  HSpec{head: Bool, spec: Spec}

def head.of.keep(sp: Spec) -> HSpec:
  match sp:
    case Spec{Verb{n, +h, z, g}, u, hs, b, pl}:
      HSpec{h, Spec{Verb{n, h, z, g}, u, hs, b, pl}}

def verb.again(sp: Spec) -> HSpec:
  match sp:
    case Spec{Verb{n, h, z, +g}, u, hs, b, pl}:
      HSpec{g, Spec{Verb{n, h, z, g}, u, hs, b, pl}}

# Redirects and retries
# ---------------------

def redirect(+c: U32) -> Bool:
  Bool.or(Bool.or(U32.is_eq(c, 301), U32.is_eq(c, 302)), Bool.or(U32.is_eq(c, 303), Bool.or(U32.is_eq(c, 307), U32.is_eq(c, 308))))

def retry.code(+c: U32) -> Bool:
  Bool.or(U32.is_eq(c, 502), Bool.or(U32.is_eq(c, 503), U32.is_eq(c, 504)))

type Left is Data:
  Left{tries: U32, redirs: U32, wait: U32, follow: Bool}

def DK() -> Type:
  Spec -> Left -> IO(RR())

def wait.more(+w: U32) -> U32:
  Bool.pick(U32, U32.is_lt(w, 2500), (w * 2 : U32), 5000)

def retry(sp: Spec, l: Left, k: DK()) -> IO(RR()):
  match l:
    case Left{t, r, +w, f}:
      IO.bind(Unit, RR(), IO.sleep(w), u => k(sp, Left{(t - 1 : U32), r, wait.more(w), f}))

# an error, and whether a retry may help it: a connection that failed or
# timed out
type ErrQ is Data:
  ErrQ{err: Err, retry: Bool}

def retry.err(e: Err) -> ErrQ:
  match e:
    case Refused{c}:
      ErrQ{Refused{c}, True{}}
    case Timeout{}:
      ErrQ{Timeout{}, True{}}
    case Closed{}:
      ErrQ{Closed{}, True{}}
    case other:
      ErrQ{other, False{}}

def can.retry(again: Bool, l: Left) -> Bool:
  match l:
    case Left{t, _, _, _}:
      Bool.and(again, U32.is_gt(t, 0))

def lost.go(go: Bool, e: Err, sp: Spec, l: Left, k: DK()) -> IO(RR()):
  match go:
    case True{}:
      retry(sp, l, k)
    case False{}:
      IO.pure(RR(), Fail{e})

def lost.check(q: ErrQ, again: Bool, sp: Spec, +l: Left, k: DK()) -> IO(RR()):
  match q:
    case ErrQ{e, r}:
      lost.go(Bool.and(r, can.retry(again, l)), e, sp, l, k)

# the headers, and the first Location among them, copied
type Loc is Data:
  Loc{hs: List<&2, H.Header>, at: Maybe<&2, String>}

type TSpec is Data:
  TSpec{tls: Bool, spec: Spec}

def spec.tls(sp: Spec) -> TSpec:
  match sp:
    case Spec{v, Url{+t, h, p, tg, au}, hs, b, pl}:
      TSpec{t, Spec{v, Url{t, h, p, tg, au}, hs, b, pl}}
    case other:
      TSpec{False{}, other}

# where a redirect goes: a path on the same origin, a url of its own, or
# nowhere the client follows: from https to http, which would send the
# next request in clear text, or not a url
type Next is Data:
  Same{target: String}
  Away{url: Url}
  Stay{}

def next.away(u: Url, +tls: Bool) -> Next:
  match u:
    case Url{+t, h, p, tg, au}:
      Bool.pick(Next, Bool.and(tls, Bool.not(t)), Stay{}, Away{Url{t, h, p, tg, au}})
    case UBad{_}:
      Stay{}

def next.same(g: Tgt) -> Next:
  match g:
    case Tgt{t, True{}}:
      Same{t}
    case Tgt{_, False{}}:
      Stay{}

def next.of(loc: String, tls: Bool) -> Next:
  match loc:
    case SCon{Chr{47}, SCon{Chr{47}, _}}:
      Stay{}
    case SCon{Chr{47}, r}:
      next.same(target.go(r, "/", True{}))
    case other:
      next.away(url(other), tls)

def body.after(sized: Bool, b: B.Bytes) -> B.Bytes:
  match sized:
    case True{}:
      b
    case False{}:
      B.BNil{}

def spec.shaped(v: Verb, u: Url, hs: List<&2, H.Header>, b: B.Bytes, pl: Bool) -> Spec:
  match v:
    case Verb{n, h, +z, g}:
      Spec{Verb{n, h, z, g}, u, hs, body.after(z, b), pl}

# Authorization and Cookie are for the host they were sent to; a redirect
# to a url of its own drops them
def hs.private(+n: String) -> Bool:
  Bool.or(T.same_ci(n, "authorization", True{}), T.same_ci(n, "cookie", True{}))

def hs.drop.one(p: Bool, h: H.Header, acc: List<&2, H.Header>) -> List<&2, H.Header>:
  match p:
    case True{}:
      acc
    case False{}:
      Con{h, acc}

def hs.public(hs: List<&2, H.Header>, acc: List<&2, H.Header>) -> List<&2, H.Header>:
  match hs:
    case Nil{}:
      List.reverse(&2, H.Header, acc)
    case Con{H.Header{+n, v}, t}:
      hs.public(t, hs.drop.one(hs.private(n), H.Header{n, v}, acc))

def redirs.dec(l: Left) -> Left:
  match l:
    case Left{t, r, w, f}:
      Left{t, (r - 1 : U32), w, f}

def verb.after.go(to_get: Bool, n: String, h: Bool, z: Bool, g: Bool) -> Verb:
  match to_get:
    case True{}:
      Verb{"GET", False{}, False{}, True{}}
    case False{}:
      Verb{n, h, z, g}

# the method after a redirect: a 303 turns any method but HEAD into GET, as
# does a 301 or 302 a POST, dropping the body; 307 and 308 keep both
def verb.after(+c: U32, v: Verb) -> Verb:
  match v:
    case Verb{+n, +h, z, g}:
      verb.after.go(Bool.and(Bool.not(h), Bool.or(U32.is_eq(c, 303), Bool.and(Bool.or(U32.is_eq(c, 301), U32.is_eq(c, 302)), T.same(n, "POST", True{})))), n, h, z, g)

def spec.same(sp: Spec, t: String, c: U32) -> Spec:
  match sp:
    case Spec{v, Url{tls, h, p, _, au}, hs, b, pl}:
      spec.shaped(verb.after(c, v), url.check(Url{tls, h, p, t, au}), hs, b, pl)
    case other:
      other

def spec.away(sp: Spec, u: Url, c: U32) -> Spec:
  match sp:
    case Spec{v, _, hs, b, _}:
      spec.shaped(verb.after(c, v), u, hs.public(hs, []), b, False{})

def followed(n: Next, sp: Spec, +c: U32, l: Left, m: Meta, o: Out, k: DK()) -> IO(RR()):
  match n l:
    case Stay{} _:
      IO.pure(RR(), Done{response(m, o)})
    case _ Left{_, 0, _, True{}}:
      IO.pure(RR(), Fail{Redirects{}})
    case _ Left{_, 0, _, False{}}:
      IO.pure(RR(), Done{response(m, o)})
    case Same{t} other:
      k(spec.same(sp, t, c), redirs.dec(other))
    case Away{u} other:
      k(spec.away(sp, u, c), redirs.dec(other))

def located(lc: Loc, sp: TSpec, +c: U32, l: Left, rest: Meta, o: Out, k: DK()) -> IO(RR()):
  match lc sp rest:
    case Loc{hs, Some{at}} TSpec{tls, s} Meta{_, _, r}:
      followed(next.of(at, tls), s, c, l, Meta{c, hs, r}, o, k)
    case Loc{hs, None{}} _ Meta{_, _, r}:
      IO.pure(RR(), Done{response(Meta{c, hs, r}, o)})

def loc.step(hit: Bool, n: String, v: Str2, l: Loc) -> Loc:
  match hit v l:
    case True{} Str2{a, b} Loc{acc, None{}}:
      Loc{Con{H.Header{n, a}, acc}, Some{b}}
    case _ Str2{a, _} Loc{acc, at}:
      Loc{Con{H.Header{n, a}, acc}, at}

def loc.end(l: Loc) -> Loc:
  match l:
    case Loc{acc, at}:
      Loc{List.reverse(&2, H.Header, acc), at}

# the headers, and the first Location's value, copied
def loc.scan(hs: List<&2, H.Header>, l: Loc) -> Loc:
  match hs:
    case Nil{}:
      loc.end(l)
    case Con{H.Header{+n, v}, t}:
      loc.scan(t, loc.step(T.same_ci(n, "location", True{}), n, s.dup(v), l))

def got.redirect(hit: Bool, m: Meta, o: Out, sp: Spec, l: Left, k: DK()) -> IO(RR()):
  match hit m:
    case True{} Meta{+c, hs, r}:
      located(loc.scan(hs, Loc{[], None{}}), spec.tls(sp), c, l, Meta{c, [], r}, o, k)
    case False{} other:
      IO.pure(RR(), Done{response(other, o)})

def got.go(re: Bool, m: Meta, o: Out, sp: Spec, +l: Left, k: DK()) -> IO(RR()):
  match re m:
    case True{} _:
      retry(sp, l, k)
    case False{} Meta{+c, hs, r}:
      got.redirect(redirect(c), Meta{c, hs, r}, o, sp, l, k)

def hopped(h: Hop, sp: HSpec, +l: Left, k: DK()) -> IO(RR()):
  match h sp:
    case HopGot{Meta{+c, hs, r}, o} HSpec{again, s}:
      got.go(Bool.and(retry.code(c), can.retry(again, l)), Meta{c, hs, r}, o, s, l, k)
    case HopLost{e} HSpec{again, s}:
      lost.check(retry.err(e), again, s, l, k)

def pool.of(sp: Spec) -> HSpec:
  match sp:
    case Spec{v, u, hs, b, +pl}:
      HSpec{pl, Spec{v, u, hs, b, pl}}

def drive.go(sp2: Spec2, l: Left, +lim: Lim, k: DK()) -> IO(RR()):
  match sp2:
    case Spec2{a, b}:
      IO.bind(Hop, RR(), once(a, lim), h => hopped(h, verb.again(b), l, k))

# a request, then its redirects and retries; fuel bounds them
def drive(fuel: Nat, sp: Spec, l: Left, +lim: Lim) -> IO(RR()):
  match fuel:
    case 0n:
      IO.pure(RR(), Fail{Redirects{}})
    case 1n+p:
      drive.go(spec.dup(sp), l, lim, s => l2 => drive(p, s, l2, lim))

def left.of(+rt: U32, +rd: U32, bo: U32) -> Left:
  Left{rt, rd, bo, U32.is_gt(rd, 0)}

def lim.of(+now: Nat, +ms: U32, mh: U32, mb: U32) -> Lim:
  Lim{Nat.add(now, U32.to_nat(ms)), ms, False{}, mh, U32.to_nat(mb), False{}}

def fuel.of(rt: U32, rd: U32) -> Nat:
  Nat.add(U32.to_nat(rt), Nat.add(U32.to_nat(rd), 2n))

def start(cfg: Config, sp: Spec) -> IO(RR()):
  match cfg:
    case Config{+ms, mh, mb, +rt, bo, +rd, _}:
      do IO<RR()>:
        +now : Nat <- IO.now()
        drive(fuel.of(rt, rd), sp, left.of(rt, rd, bo), lim.of(now, ms, mh, mb))

def url.tls(u: Url) -> Bool:
  match u:
    case Url{t, _, _, _, _}:
      t
    case UBad{_}:
      False{}

def tries.dec(l: Left) -> Left:
  match l:
    case Left{t, r, w, f}:
      Left{(t - 1 : U32), r, wait.more(w), f}

# Sending
# -------

def send.go(c: Config, s: Result<&2, &2, Err, Spec>) -> IO(RR()):
  match s:
    case Done{sp}:
      start(c, sp)
    case Fail{e}:
      IO.pure(RR(), Fail{e})

# the request, with c's timeout, limits, retries and redirects: a reply
# with any status, or why there is none
def send(c: Config, r: Req) -> IO(RR()):
  send.go(c, spec.of(r))

# as send, but a status other than 2xx is Status{code, body}
def send_ok(c: Config, r: Req) -> IO(RR()):
  IO.bind(RR(), RR(), send(c, r), x => IO.pure(RR(), ok.of(x)))

def json.value(-A: Data, r: Result<&2, &2, J.Access, A>) -> R(A):
  match r:
    case Done{a}:
      Done{a}
    case Fail{e}:
      Fail{BadValue{e}}

def json.parsed(-A: Data, r: Result<&2, &2, J.Error, J.Json>, dec: J.Json -> Result<&2, &2, J.Access, A>) -> R(A):
  match r:
    case Done{j}:
      json.value(A, dec(j))
    case Fail{e}:
      Fail{BadJson{e}}

def json.empty(bs: List<&2, U32>) -> Result<&2, &2, J.Error, J.Json>:
  match bs:
    case Nil{}:
      Done{J.JNull{}}
    case other:
      J.parse_bytes(other)

def json.of(-A: Data, r: RR(), dec: J.Json -> Result<&2, &2, J.Access, A>) -> R(A):
  match r:
    case Done{Reply{_, _, b}}:
      json.parsed(A, json.empty(b), dec)
    case Fail{e}:
      Fail{e}

# as send_ok, then the body decoded by dec; an empty body reads as null
def send_json(-A: Data, c: Config, r: Req, dec: J.Json -> Result<&2, &2, J.Access, A>) -> IO(R(A)):
  IO.bind(RR(), R(A), send_ok(c, r), x => IO.pure(R(A), json.of(A, x, dec)))

def fetch(u: String) -> IO(RR()):
  send_ok(default(), get(u))

def fetch_json(-A: Data, u: String, dec: J.Json -> Result<&2, &2, J.Access, A>) -> IO(R(A)):
  send_json(A, default(), get(u), dec)

# Reading replies
# ---------------

# a reply's body as text, when it is UTF-8
def utf8(r: Reply) -> Maybe<&2, String>:
  match r:
    case Reply{_, _, b}:
      text.of(U.decode(b))

def header.hit(hit: Bool, v: String, found: Maybe<&2, String>) -> Maybe<&2, String>:
  match hit found:
    case True{} None{}:
      Some{v}
    case _ other:
      other

def header.go(kv: Kv(), +name: String, found: Maybe<&2, String>) -> Maybe<&2, String>:
  match kv:
    case Nil{}:
      found
    case Con{(n, v), t}:
      header.go(t, name, header.hit(T.same_ci(n, name, True{}), v, found))

# the first value of a header, its name compared ignoring case
def header(kv: Kv(), +name: String) -> Maybe<&2, String>:
  header.go(kv, name, None{})

# Streaming
# ---------

# Streaming
# ---------

# an exchange's connection, if it is still open, and whether it may carry
# another request
type Conn is Type:
  Conn{sock: Socket, tls: Bool, reuse: Bool}
  NoConn{}

type Part is Type:
  Part{res: R(Head), conn: Conn}

def ok.head(r: RR()) -> R(Head):
  match r:
    case Done{Reply{c, hs, _}}:
      Done{Head{c, hs}}
    case Fail{e}:
      Fail{e}

# a streamed exchange's end: its Head, or why not, and its connection
def stream.part(e: Ex) -> Part:
  match e:
    case Got{s, tls, Meta{c, hs, r}, Each{}}:
      Part{Done{Head{c, hs.kv(hs, [])}}, Conn{s, tls, r}}
    case Got{s, tls, Meta{c, hs, r}, Stopped{}}:
      Part{Done{Head{c, hs.kv(hs, [])}}, Conn{s, tls, r}}
    case Got{s, tls, Meta{c, hs, r}, o}:
      Part{ok.head(ok.of(Done{response(Meta{c, hs, False{}}, o)})), Conn{s, tls, r}}
    case Lost{err, _, _}:
      Part{Fail{err}, NoConn{}}

# a 2xx body goes to f; another's is kept, up to 1 MiB, for Status
def stream.body(~f: List<&2, U32> -> IO(Bool), ok: Bool, fr: H1.Framing, s: Socket, +tls: Bool, rest: B.Bytes, m: Meta, +lim: Lim) -> IO(Ex):
  match ok:
    case True{}:
      body(~each(~f), fr, s, tls, rest, Each{}, m, lim)
    case False{}:
      body(~keep, fr, s, tls, rest, Keep{[]}, m, lim.with_max(lim, 1048576n))

def stream.hx(~f: List<&2, U32> -> IO(Bool), h: Hd, +lim: Lim) -> IO(Ex):
  match h:
    case HGot{s, +tls, H1.Head{+code, hs, fr, reuse, rest}}:
      stream.body(~f, Bool.and(U32.is_ge(code, 200), U32.is_lt(code, 300)), fr, s, tls, rest, Meta{code, hs, reuse}, lim)
    case HGot{s, +tls, _}:
      lost(tls, s, BadResponse{}, False{}, Keep{[]})
    case HLost{e, st}:
      IO.pure(Ex, Lost{e, st, Keep{[]}})

# one streamed request on an open connection
def stream.x(~f: List<&2, U32> -> IO(Bool), s: Socket, +tls: Bool, req: B.Bytes, +lim: Lim) -> IO(Ex):
  do IO<Ex>:
    +now : Nat <- IO.now()
    m : RU() <- send.of(tls, s, B.to_list(req), lim.left(lim, now))
    h : Hd <- stream.polled(tls, lim, m)
    stream.hx(~f, h, lim)

def conn.close(c: Conn) -> IO(Unit):
  match c:
    case Conn{s, tls, _}:
      shut(tls, s)
    case NoConn{}:
      IO.pure(Unit, Unit{})

def stream.done(p: Part) -> IO(R(Head)):
  match p:
    case Part{res, c}:
      IO.bind(Unit, R(Head), conn.close(c), u => IO.pure(R(Head), res))

def stream.opened(~f: List<&2, U32> -> IO(Bool), o: Opened, req: B.Bytes, +lim: Lim) -> IO(R(Head)):
  match o:
    case Opened{s, +tls}:
      IO.bind(Ex, R(Head), stream.x(~f, s, tls, req, lim), e => stream.done(stream.part(e)))
    case NotOpened{e}:
      IO.pure(R(Head), Fail{e})

# a streamed request's limits: timeout_ms per read, no body limit
def lim.stream(+dl: Nat, +ms: U32, mh: U32, +head: Bool) -> Lim:
  Lim{dl, ms, True{}, mh, Nat.mul(256n, 4294967295n), head}

def stream.spec(~f: List<&2, U32> -> IO(Bool), s: Result<&2, &2, Err, Spec>, +ms: U32, mh: U32, +dl: Nat) -> IO(R(Head)):
  match s:
    case Done{Spec{Verb{name, +head, sized, _}, Url{+tls, host, +port, target, auth}, hs, b, _}}:
      IO.bind(Opened, R(Head), open(tls, host, port, dl), o => stream.opened(~f, o, H1.write_request(name, target, auth, hs.clean(hs, []), b, sized, True{}), lim.stream(dl, ms, mh, head)))
    case Done{Spec{_, UBad{e}, _, _, _}}:
      IO.pure(R(Head), Fail{e})
    case Fail{e}:
      IO.pure(R(Head), Fail{e})

# the request, its body handed to f as it is read, a piece at a time: for
# bodies too large to hold. f answers True to go on, False to stop. A
# status other than 2xx is Status{code, body}, and f is not called. No
# body limit; timeout_ms is per read, and redirects are not followed
def stream(~f: List<&2, U32> -> IO(Bool), c: Config, r: Req) -> IO(R(Head)):
  match c:
    case Config{+ms, mh, _, _, _, _, _}:
      do IO<R(Head)>:
        +now : Nat <- IO.now()
        stream.spec(~f, spec.of(r), ms, mh, Nat.add(now, U32.to_nat(ms)))

# a spec's origin, as a pool keys its connections, and the spec back
type Orig is Data:
  Orig{key: String, spec: Spec}

def origin.key(+tls: Bool, h: String, +port: U32) -> String:
  Bool.pick(String, tls, "https://", "http://") ++ h ++ ":" ++ U32.show(port)

def origin.of(k: Str2, v: Verb, +tls: Bool, +port: U32, t: String, au: String, hs: List<&2, H.Header>, b: B.Bytes, +pl: Bool) -> Orig:
  match k:
    case Str2{a, h}:
      Orig{origin.key(tls, a, port), Spec{v, Url{tls, h, port, t, au}, hs, b, pl}}

def spec.origin(sp: Spec) -> Orig:
  match sp:
    case Spec{v, Url{+tls, h, +port, t, au}, hs, b, +pl}:
      origin.of(s.dup(h), v, tls, port, t, au, hs, b, pl)
    case Spec{v, UBad{e}, hs, b, pl}:
      Orig{"", Spec{v, UBad{e}, hs, b, pl}}

# Server-sent events
# ------------------

# the end of an event stream: the last id it sent, and how many times it
# was reconnected
type Ended is Data:
  Ended{last_id: Maybe<&2, String>, reconnects: U32}

def event.name(e: Ev.Message) -> String:
  Ev.name(e)

def event.data(e: Ev.Message) -> String:
  Ev.data(e)

def event.id(e: Ev.Message) -> Maybe<&2, String>:
  Ev.id(e)

# the bytes up to the last line end, and the rest: a line end byte is
# never inside a UTF-8 char, so the first part decodes whole
type Cutb is Data:
  Cutb{done: List<&2, U32>, rest: List<&2, U32>}

def cut.into(found: Bool, +b: U32, rest: List<&2, U32>, done: List<&2, U32>) -> Cutb:
  match found:
    case True{}:
      Cutb{Con{b, done}, rest}
    case False{}:
      Cutb{done, Con{b, rest}}

# walking back from the last byte: those before the last line end, and it,
# are done; those after it are the rest
def cut.go(rev: List<&2, U32>, c: Cutb, +found: Bool) -> Cutb:
  match rev c:
    case Nil{} _:
      c
    case Con{+b, t} Cutb{done, rest}:
      cut.go(t, cut.into(Bool.or(found, Bool.or(U32.is_eq(b, 10), U32.is_eq(b, 13))), b, rest, done), Bool.or(found, Bool.or(U32.is_eq(b, 10), U32.is_eq(b, 13))))

def cut.back(rev: List<&2, U32>, rest: List<&2, U32>) -> Cutb:
  cut.go(rev, Cutb{[], rest}, False{})

def decoded(t: U.Text) -> String:
  match t:
    case U.TOk{s}:
      s
    case U.TBad{_, before}:
      String.reverse(before)

# each event to on, in order, until on answers False
def sse.each(~on: Ev.Message -> IO(Bool), es: List<&2, Ev.Message>, go: Bool) -> IO(Bool):
  match es go:
    case Nil{} g:
      IO.pure(Bool, g)
    case Con{e, t} True{}:
      IO.bind(Bool, Bool, on(e), g => sse.each(~on, t, g))
    case Con{_, _} False{}:
      IO.pure(Bool, False{})

def sse.sent(go: Bool, st: Ev.P, rest: List<&2, U32>) -> Out:
  Sse{st, rest, Bool.not(go)}

def sse.fed(~on: Ev.Message -> IO(Bool), f: Ev.Fed, rest: List<&2, U32>) -> IO(Out):
  match f:
    case Ev.Fed{st, es}:
      IO.bind(Bool, Out, sse.each(~on, es, True{}), go => IO.pure(Out, sse.sent(go, st, rest)))

def sse.cut(~on: Ev.Message -> IO(Bool), c: Cutb, st: Ev.P) -> IO(Out):
  match c:
    case Cutb{done, rest}:
      sse.fed(~on, Ev.feed(decoded(U.decode(done)), st), rest)

# data through the event parser, its events to on
def sse(~on: Ev.Message -> IO(Bool), o: Out, bs: B.Bytes) -> IO(Out):
  match o:
    case Sse{st, pend, False{}}:
      sse.cut(~on, cut.back(List.reverse(&2, U32, List.append(&2, U32, pend, B.to_list(bs))), []), st)
    case other:
      IO.pure(Out, other)

# a head's Content-Type, copied, and the headers back
type Ct is Data:
  Ct{hs: List<&2, H.Header>, kind: Maybe<&2, String>}

def ct.step(hit: Bool, n: String, v: Str2, c: Ct) -> Ct:
  match hit v c:
    case True{} Str2{a, b} Ct{acc, None{}}:
      Ct{Con{H.Header{n, a}, acc}, Some{b}}
    case _ Str2{a, _} Ct{acc, k}:
      Ct{Con{H.Header{n, a}, acc}, k}

def ct.end(c: Ct) -> Ct:
  match c:
    case Ct{acc, k}:
      Ct{List.reverse(&2, H.Header, acc), k}

def ct.scan(hs: List<&2, H.Header>, c: Ct) -> Ct:
  match hs:
    case Nil{}:
      ct.end(c)
    case Con{H.Header{+n, v}, t}:
      ct.scan(t, ct.step(T.same_ci(n, "content-type", True{}), n, s.dup(v), c))

def starts.ci(s: String, p: String) -> Bool:
  match s p:
    case _ SNil{}:
      True{}
    case SCon{Chr{+x}, st} SCon{Chr{+y}, pt}:
      Bool.and(U32.is_eq(H1.lower(x), H1.lower(y)), starts.ci(st, pt))
    case SNil{} SCon{_, _}:
      False{}

type Ck is Data:
  Ck{ok: Bool, kind: String}

def ck.of(k: Maybe<&2, String>) -> Ck:
  match k:
    case Some{+s}:
      Ck{starts.ci(s, "text/event-stream"), s}
    case None{}:
      Ck{False{}, "(none)"}

def ev.typed(~on: Ev.Message -> IO(Bool), k: Ck, hs: List<&2, H.Header>, fr: H1.Framing, s: Socket, +tls: Bool, rest: B.Bytes, +code: U32, +reuse: Bool, +lim: Lim) -> IO(Ex):
  match k:
    case Ck{True{}, _}:
      body(~sse(~on), fr, s, tls, rest, Sse{Ev.start(), [], False{}}, Meta{code, hs, reuse}, lim)
    case Ck{False{}, kind}:
      lost(tls, s, NotEvents{kind}, False{}, Keep{[]})

def ev.body(~on: Ev.Message -> IO(Bool), ok: Bool, c: Ct, fr: H1.Framing, s: Socket, +tls: Bool, rest: B.Bytes, +code: U32, +reuse: Bool, +lim: Lim) -> IO(Ex):
  match ok c:
    case False{} Ct{hs, _}:
      body(~keep, fr, s, tls, rest, Keep{[]}, Meta{code, hs, reuse}, lim.with_max(lim, 1048576n))
    case True{} Ct{hs, k}:
      ev.typed(~on, ck.of(k), hs, fr, s, tls, rest, code, reuse, lim)

def ev.hx(~on: Ev.Message -> IO(Bool), h: Hd, +lim: Lim) -> IO(Ex):
  match h:
    case HGot{s, +tls, H1.Head{+code, hs, fr, +reuse, rest}}:
      ev.body(~on, Bool.and(U32.is_ge(code, 200), U32.is_lt(code, 300)), ct.scan(hs, Ct{[], None{}}), fr, s, tls, rest, code, reuse, lim)
    case HGot{s, +tls, _}:
      lost(tls, s, BadResponse{}, False{}, Keep{[]})
    case HLost{e, st}:
      IO.pure(Ex, Lost{e, st, Keep{[]}})

# one event stream on an open connection
def ev.x(~on: Ev.Message -> IO(Bool), s: Socket, +tls: Bool, req: B.Bytes, +lim: Lim) -> IO(Ex):
  do IO<Ex>:
    +now : Nat <- IO.now()
    m : RU() <- send.of(tls, s, B.to_list(req), lim.left(lim, now))
    h : Hd <- stream.polled(tls, lim, m)
    ev.hx(~on, h, lim)

# how one try at an event stream ended: an error or None when the stream
# ended; the last id and retry it sent; whether on asked to stop
type Try is Data:
  Try{err: Maybe<&2, Err>, last: Maybe<&2, String>, retry: Maybe<&2, Nat>, stopped: Bool}

type EvPart is Type:
  EvPart{try: Try, conn: Conn}

def ok.err(r: RR()) -> Maybe<&2, Err>:
  match r:
    case Done{_}:
      Some{BadResponse{}}
    case Fail{e}:
      Some{e}

def ev.try(t: Ev.Tail, e: Maybe<&2, Err>, +stop: Bool) -> Try:
  match t:
    case Ev.Tail{l, r}:
      Try{e, l, r, stop}

def ev.part(e: Ex) -> EvPart:
  match e:
    case Got{s, tls, Meta{_, _, r}, Sse{st, _, +stop}}:
      EvPart{ev.try(Ev.tail(st), None{}, stop), Conn{s, tls, Bool.and(r, Bool.not(stop))}}
    case Got{s, tls, Meta{c, hs, _}, o}:
      EvPart{Try{ok.err(ok.of(Done{response(Meta{c, hs, False{}}, o)})), None{}, None{}, False{}}, Conn{s, tls, False{}}}
    case Lost{err, _, Sse{st, _, _}}:
      EvPart{ev.try(Ev.tail(st), Some{err}, False{}), NoConn{}}
    case Lost{err, _, _}:
      EvPart{Try{Some{err}, None{}, None{}, False{}}, NoConn{}}

def ev.done(p: EvPart) -> IO(Try):
  match p:
    case EvPart{t, c}:
      IO.bind(Unit, Try, conn.close(c), u => IO.pure(Try, t))

def ev.opened(~on: Ev.Message -> IO(Bool), o: Opened, req: B.Bytes, +lim: Lim) -> IO(Try):
  match o:
    case Opened{s, +tls}:
      IO.bind(Ex, Try, ev.x(~on, s, tls, req, lim), e => ev.done(ev.part(e)))
    case NotOpened{e}:
      IO.pure(Try, Try{Some{e}, None{}, None{}, False{}})

# the request an event stream sends: text/event-stream, no cache, and the
# id to resume from
def ev.hs(last: Maybe<&2, String>) -> List<&2, H.Header>:
  match last:
    case Some{i}:
      [H.Header{"accept", "text/event-stream"}, H.Header{"cache-control", "no-cache"}, H.Header{"last-event-id", i}]
    case None{}:
      [H.Header{"accept", "text/event-stream"}, H.Header{"cache-control", "no-cache"}]

def ev.spec(~on: Ev.Message -> IO(Bool), sp: Spec, last: Maybe<&2, String>, +ms: U32, mh: U32, +dl: Nat) -> IO(Try):
  match sp:
    case Spec{Verb{name, +head, sized, _}, Url{+tls, host, +port, target, auth}, hs, b, _}:
      IO.bind(Opened, Try, open(tls, host, port, dl), o => ev.opened(~on, o, H1.write_request(name, target, auth, List.append(&2, H.Header, hs.clean(hs, []), ev.hs(last)), b, sized, True{}), lim.stream(dl, ms, mh, head)))
    case Spec{_, UBad{e}, _, _, _}:
      IO.pure(Try, Try{Some{e}, None{}, None{}, False{}})

def ev.end(t: Try, +n: U32) -> R(Ended):
  match t:
    case Try{None{}, last, _, _}:
      Done{Ended{last, n}}
    case Try{Some{e}, _, _, _}:
      Fail{e}

def ev.once(~on: Ev.Message -> IO(Bool), s: Result<&2, &2, Err, Spec>, +ms: U32, mh: U32) -> IO(R(Ended)):
  match s:
    case Done{sp}:
      do IO<R(Ended)>:
        +now : Nat <- IO.now()
        t : Try <- ev.spec(~on, sp, None{}, ms, mh, Nat.add(now, U32.to_nat(ms)))
        return ev.end(t, 0)
    case Fail{e}:
      IO.pure(R(Ended), Fail{e})

# the request's event stream, each event to on, until the stream ends or
# on answers False. A status other than 2xx is Status{code, body}, and a
# Content-Type other than text/event-stream is NotEvents; on is not called
# then. timeout_ms is per read
def events(~on: Ev.Message -> IO(Bool), c: Config, r: Req) -> IO(R(Ended)):
  match c:
    case Config{+ms, mh, _, _, _, _, _}:
      ev.once(~on, spec.of(r), ms, mh)

def keep.last(new: Maybe<&2, String>, old: Maybe<&2, String>) -> Maybe<&2, String>:
  match new:
    case Some{s}:
      Some{s}
    case None{}:
      old

def wait.of(r: Maybe<&2, Nat>, +w: U32) -> U32:
  match r:
    case Some{n}:
      U32.from_nat(n)
    case None{}:
      w

type Rt is Data:
  Rt{last: Maybe<&2, String>, n: U32, wait: U32}

def rt.step(t: Try, rt: Rt, left: Bool) -> Rt:
  match t rt:
    case Try{_, l, r, _} Rt{last, +n, +w}:
      Rt{keep.last(l, last), (n + 1 : U32), wait.of(r, w)}

def rt.done(t: Try, rt: Rt) -> R(Ended):
  match t rt:
    case Try{Some{e}, _, _, _} _:
      Fail{e}
    case Try{None{}, l, _, _} Rt{last, +n, _}:
      Done{Ended{keep.last(l, last), n}}

def rt.last(rt: Rt) -> Maybe<&2, String>:
  match rt:
    case Rt{last, _, _}:
      last

type RtK is Data:
  RtK{rt: Rt, last: Maybe<&2, String>}

type Mm is Data:
  Mm{a: Maybe<&2, String>, b: Maybe<&2, String>}

def rt.split.go(m: Mm, +n: U32, +w: U32) -> RtK:
  match m:
    case Mm{a, b}:
      RtK{Rt{a, n, w}, b}

def m.dup.of(d: Str2) -> Mm:
  match d:
    case Str2{a, b}:
      Mm{Some{a}, Some{b}}

def m.dup.s(m: Maybe<&2, String>) -> Mm:
  match m:
    case Some{s}:
      m.dup.of(s.dup(s))
    case None{}:
      Mm{None{}, None{}}

def rt.split(rt: Rt) -> RtK:
  match rt:
    case Rt{last, +n, +w}:
      rt.split.go(m.dup.s(last), n, w)

def rt.wait(rt: Rt, again: Rt -> IO(R(Ended))) -> IO(R(Ended)):
  match rt:
    case Rt{last, n, +w}:
      IO.bind(Unit, R(Ended), IO.sleep(w), u => again(Rt{last, n, wait.more(w)}))

def rt.decide(t: Try, go: Bool, +left: U32, rt: Rt, again: Rt -> IO(R(Ended))) -> IO(R(Ended)):
  match go:
    case True{}:
      rt.wait(rt.step(t, rt, True{}), again)
    case False{}:
      IO.pure(R(Ended), rt.done(t, rt))

type TryQ is Data:
  TryQ{go: Bool, try: Try}

type ErrGo is Data:
  ErrGo{go: Bool, err: Maybe<&2, Err>}

def try.q(+stop: Bool, q: ErrGo, l: Maybe<&2, String>, r: Maybe<&2, Nat>) -> TryQ:
  match q:
    case ErrGo{go, e}:
      TryQ{Bool.and(Bool.not(stop), go), Try{e, l, r, stop}}

def again.err.keep(m: Maybe<&2, Err>) -> ErrGo:
  match m:
    case None{}:
      ErrGo{True{}, None{}}
    case Some{Closed{}}:
      ErrGo{True{}, Some{Closed{}}}
    case Some{Timeout{}}:
      ErrGo{True{}, Some{Timeout{}}}
    case Some{Refused{c}}:
      ErrGo{True{}, Some{Refused{c}}}
    case Some{NoHost{}}:
      ErrGo{True{}, Some{NoHost{}}}
    case Some{other}:
      ErrGo{False{}, Some{other}}

def try.go(t: Try) -> TryQ:
  match t:
    case Try{e, l, r, +stop}:
      try.q(stop, again.err.keep(e), l, r)

def rt.tried(q: TryQ, +left: U32, rt: Rt, again: Rt -> IO(R(Ended))) -> IO(R(Ended)):
  match q:
    case TryQ{go, t}:
      rt.decide(t, Bool.and(go, U32.is_gt(left, 0)), left, rt, again)

def ev.retry.try(~on: Ev.Message -> IO(Bool), sp2: Spec2, k: RtK, +left: U32, +ms: U32, +mh: U32, again: Spec -> Rt -> IO(R(Ended))) -> IO(R(Ended)):
  match sp2 k:
    case Spec2{a, b} RtK{rt, last}:
      do IO<R(Ended)>:
        +now : Nat <- IO.now()
        t : Try <- ev.spec(~on, a, last, ms, mh, Nat.add(now, U32.to_nat(ms)))
        rt.tried(try.go(t), left, rt, r => again(b, r))

def ev.retry.go(~on: Ev.Message -> IO(Bool), fuel: Nat, sp: Spec, rt: Rt, +left: U32, +ms: U32, +mh: U32) -> IO(R(Ended)):
  match fuel:
    case 0n:
      IO.pure(R(Ended), Done{Ended{rt.last(rt), 0}})
    case 1n+f:
      ev.retry.try(~on, spec.dup(sp), rt.split(rt), left, ms, mh, s => r => ev.retry.go(~on, f, s, r, (left - 1 : U32), ms, mh))

def ev.retry(~on: Ev.Message -> IO(Bool), s: Result<&2, &2, Err, Spec>, +n: U32, +ms: U32, mh: U32, +bo: U32) -> IO(R(Ended)):
  match s:
    case Done{sp}:
      ev.retry.go(~on, Nat.add(U32.to_nat(n), 1n), sp, Rt{None{}, 0, bo}, n, ms, mh)
    case Fail{e}:
      IO.pure(R(Ended), Fail{e})

# as events, reconnecting up to n times when the stream ends or the
# connection fails, with Last-Event-ID; it waits the server's retry:, or
# backoff_ms doubling up to 5 s. No reconnect after on answers False, a
# status, or a wrong Content-Type
def events_retry(~on: Ev.Message -> IO(Bool), c: Config, r: Req, +n: U32) -> IO(R(Ended)):
  match c:
    case Config{+ms, mh, _, _, +bo, _, _}:
      ev.retry(~on, spec.of(r), n, ms, mh, bo)
