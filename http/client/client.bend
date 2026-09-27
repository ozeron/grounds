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

def etimedout(+c: U32) -> Bool:
  Bool.or(U32.is_eq(c, 60), U32.is_eq(c, 110))

# the status, headers, and whether the connection may carry another request
type Meta is Data:
  Meta{code: U32, hs: List<&2, H.Header>, reuse: Bool}

# the bytes, oldest first, from pieces newest first
def flat(cs: List<&2, B.Bytes>, acc: B.Bytes) -> B.Bytes:
  match cs:
    case Nil{}:
      acc
    case Con{c, t}:
      flat(t, B.app(c, acc))

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

# where the body goes: kept, pieces newest first; sent down a channel; or
# nowhere, once the channel's reader has closed it
type Out is Type:
  Keep{acc: List<&2, B.Bytes>}
  Each{code: U32}
  Stopped{}

def response(m: Meta, o: Out) -> Res.Response:
  match m o:
    case Meta{c, hs, _} Keep{acc}:
      Res.Response{S.Status{c}, hs, B.to_list(flat(acc, B.BNil{}))}
    case Meta{c, hs, _} _:
      Res.Response{S.Status{c}, hs, []}

def failed(+c: U32) -> Err:
  Bool.pick(Err, etimedout(c), Timeout{}, Refused{c})

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

def R() -> Type:
  Result<&1, &1, Err, Res.Response>

# Copies
# ------
# A value used twice is shared, which makes its type reference counted in
# the whole program. A retry or a redirect sends a request again, so the
# request is copied instead: each dup reads a value once and builds two

def s.copy(s: String, acc: String) -> String:
  match s:
    case SNil{}:
      String.reverse(acc)
    case SCon{Chr{x}, t}:
      s.copy(t, SCon{Chr{(x + 0 : U32)}, acc})

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

def copy(bs: B.Bytes, acc: B.Bytes) -> B.Bytes:
  match bs:
    case B.BNil{}:
      B.rev(acc)
    case B.BCon{b, t}:
      copy(t, B.BCon{b, acc})

def count(bs: B.Bytes, +n: Nat) -> Nat:
  match bs:
    case B.BNil{}:
      n
    case B.BCon{_, t}:
      count(t, Nat.add(n, 1n))

# URLs
# ----

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

def bad(e: H1.Err) -> Err:
  match e:
    case H1.BodyTooLarge{}:
      TooLarge{}
    case H1.HeadTooLarge{}:
      TooLarge{}
    case _:
      BadResponse{}

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

def RP() -> Type:
  Socket & Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>

def RU() -> Type:
  Socket & Result<&1, &1, U32 & String, Unit>

def shut(tls: Bool, s: Socket) -> IO(Unit):
  match tls:
    case True{}:
      W.wire_tls_close(s)
    case False{}:
      W.close(s)

def recv.of(tls: Bool, s: Socket, +ms: U32) -> IO(RP()):
  match tls:
    case True{}:
      W.wire_tls_recv_timeout(s, 65536, ms)
    case False{}:
      W.wire_recv_timeout(s, 65536, ms)

def send.of(tls: Bool, s: Socket, bs: List<&2, U32>, +ms: U32) -> IO(RU()):
  match tls:
    case True{}:
      W.wire_tls_send_timeout(s, bs, ms)
    case False{}:
      W.wire_send_timeout(s, bs, ms)

# a connection, or why there is none
type Opened is Type:
  Opened{sock: Socket, tls: Bool}
  NotOpened{err: Err}

def left(dl: Nat, now: Nat) -> U32:
  U32.from_nat(Nat.sub(dl, now))

def shook.go(r: Result<&1, &1, U32 & String, Unit>, s: Socket) -> IO(Opened):
  match r:
    case Done{_}:
      IO.pure(Opened, Opened{s, True{}})
    case Fail{(c, why)}:
      IO.bind(Unit, Opened, W.wire_tls_close(s), u => IO.pure(Opened, NotOpened{Bool.pick(Err, etimedout(c), Timeout{}, Tls{why})}))

law shook:
  for m: RU()
  IO(Opened)

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

# what a read may do: the deadline, or ms per read when streaming; the
# head's limit, the body's, and whether the request was a HEAD
type Lim is Data:
  Lim{dl: Nat, ms: U32, stream: Bool, mh: U32, max: Nat, head: Bool}

def lim.left(l: Lim, now: Nat) -> U32:
  match l:
    case Lim{dl, ms, stream, _, _, _}:
      Bool.pick(U32, stream, ms, left(dl, now))

def lim.over(l: Lim, now: Nat) -> Bool:
  match l:
    case Lim{dl, _, stream, _, _, _}:
      Bool.and(Bool.not(stream), Nat.is_le(dl, now))

def lim.dl(l: Lim) -> Nat:
  match l:
    case Lim{dl, _, _, _, _, _}:
      dl

def lim.mh(l: Lim) -> U32:
  match l:
    case Lim{_, _, _, mh, _, _}:
      mh

def lim.max(l: Lim) -> Nat:
  match l:
    case Lim{_, _, _, _, max, _}:
      max

def lim.head(l: Lim) -> Bool:
  match l:
    case Lim{_, _, _, _, _, h}:
      h

def lim.with_head(l: Lim, h: Bool) -> Lim:
  match l:
    case Lim{dl, ms, st, mh, max, _}:
      Lim{dl, ms, st, mh, max, h}

# a response head, the connection still open; or why not, the connection
# closed. stale: it failed before a byte of the response came, as a pooled
# connection the server has closed does
type Hd is Type:
  HGot{sock: Socket, tls: Bool, head: H1.Head}
  HLost{err: Err, stale: Bool}

def hd.lost(tls: Bool, s: Socket, e: Err, stale: Bool) -> IO(Hd):
  IO.bind(Unit, Hd, shut(tls, s), u => IO.pure(Hd, HLost{e, stale}))

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

law hd.polled:
  for +tls: Bool
  for +buf: B.Bytes
  for +lim: Lim
  for m: RP()
  for again: Socket -> B.Bytes -> IO(Hd)
  IO(Hd)

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

def each.on(go: Bool, +c: U32) -> Out:
  match go:
    case True{}:
      Each{c}
    case False{}:
      Stopped{}

def each.go(~f: U32 -> List<&2, U32> -> IO(Bool), o: Out, bs: B.Bytes) -> IO(Out):
  match o:
    case Each{+c}:
      IO.bind(Bool, Out, f(c, B.to_list(bs)), go => IO.pure(Out, each.on(go, c)))
    case other:
      IO.pure(Out, other)

# data to download's callback, with the status; a callback that answers
# False stops the body there
def each(~f: U32 -> List<&2, U32> -> IO(Bool), o: Out, bs: B.Bytes) -> IO(Out):
  match bs:
    case B.BNil{}:
      IO.pure(Out, o)
    case B.BCon{b, t}:
      each.go(~f, o, B.BCon{b, t})

# where a body's framing is: bytes left, a chunked decoder, or to the close
type St is Data:
  BLen{left: Nat}
  BChunk{cs: H1.CS}
  BClose{}

type Step is Data:
  SMore{st: St, data: B.Bytes}
  SDone{data: B.Bytes, extra: Bool}
  SBad{err: Err}

# an exchange's end: a response, the connection still open; or why not,
# the connection closed
type Ex is Type:
  Got{sock: Socket, tls: Bool, meta: Meta, out: Out}
  Lost{err: Err, stale: Bool, out: Out}

def done.meta(m: Meta, extra: Bool) -> Meta:
  match m:
    case Meta{c, hs, r}:
      Meta{c, hs, Bool.and(r, Bool.not(extra))}

def lost(tls: Bool, s: Socket, e: Err, stale: Bool, o: Out) -> IO(Ex):
  IO.bind(Unit, Ex, shut(tls, s), u => IO.pure(Ex, Lost{e, stale, o}))

def done(o: Out, s: Socket, +tls: Bool, m: Meta) -> IO(Ex):
  match o:
    case Stopped{}:
      IO.pure(Ex, Got{s, tls, done.meta(m, True{}), Stopped{}})
    case other:
      IO.pure(Ex, Got{s, tls, m, other})

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
    case other:
      Cutq{False{}, other}

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

# an idle connection, with TLS or not, and when it was last used; or room
# for one to be opened
type Idle is Type:
  Idle{sock: Socket, tls: Bool, last: Nat}

def Slot() -> Type:
  Maybe<&1, Idle>

# connections to one origin, kept open between requests: size at most,
# each idle up to cfg's idle_ms
type Pool is Data:
  Pool{cfg: Config, tls: Bool, host: String, port: U32, authority: String, slots: Chan(Slot()), size: U32}

def pool.fill(n: Nat, +ch: Chan(Slot())) -> IO(Unit):
  match n:
    case 0n:
      IO.pure(Unit, Unit{})
    case 1n+m:
      IO.bind(Bool, Unit, Chan.send(Slot(), ch, None{}), x => pool.fill(m, ch))

def pool.made(u: Url, cfg: Config, +n: U32) -> IO(Result<&1, &1, Err, Pool>):
  match u:
    case Url{tls, h, port, _, au}:
      do IO<Result<&1, &1, Err, Pool>>:
        +ch : Chan(Slot()) <- Chan.new(Slot(), n)
        x : Unit <- pool.fill(U32.to_nat(n), ch)
        return Done{Pool{cfg, tls, h, port, au, ch, n}}
    case UBad{e}:
      IO.pure(Result<&1, &1, Err, Pool>, Fail{e})

# a pool of up to n connections to base's origin (http[s]://host[:port]),
# opened as they are first needed
def pool(cfg: Config, base: String, n: U32) -> IO(Result<&1, &1, Err, Pool>):
  pool.made(url(base), cfg, n)

# a request as the client holds it between attempts; pool: its url is the
# pool's origin, so a Pool may carry it
type Spec is Data:
  Spec{verb: Verb, url: Url, hs: List<&2, H.Header>, body: B.Bytes, pool: Bool}

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

def give.keep(reuse: Bool, s: Socket, +tls: Bool, +ch: Chan(Slot())) -> IO(Unit):
  match reuse:
    case True{}:
      do IO<Unit>:
        +now : Nat <- IO.now()
        x : Bool <- Chan.send(Slot(), ch, Some{Idle{s, tls, now}})
        return Unit{}
    case False{}:
      do IO<Unit>:
        x : Unit <- shut(tls, s)
        y : Bool <- Chan.send(Slot(), ch, None{})
        return Unit{}

# the exchange's connection back to the pool if it may carry another
# request, else closed and its room given back
def give(e: Ex, +ch: Chan(Slot())) -> IO(Hop):
  match e:
    case Got{s, tls, Meta{c, hs, +reuse}, o}:
      IO.bind(Unit, Hop, give.keep(reuse, s, tls, ch), u => IO.pure(Hop, HopGot{Meta{c, hs, reuse}, o}))
    case Lost{err, _, _}:
      IO.bind(Bool, Hop, Chan.send(Slot(), ch, None{}), x => IO.pure(Hop, HopLost{err}))

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

def fresh.opened(o: Opened, req: B.Bytes, +ch: Chan(Slot()), lim: Lim) -> IO(Hop):
  match o:
    case Opened{s, tls}:
      IO.bind(Ex, Hop, exchange(s, tls, req, lim, Keep{[]}), e => give(e, ch))
    case NotOpened{e}:
      IO.bind(Bool, Hop, Chan.send(Slot(), ch, None{}), x => IO.pure(Hop, HopLost{e}))

type HSpec is Data:
  HSpec{head: Bool, spec: Spec}

def head.of.keep(sp: Spec) -> HSpec:
  match sp:
    case Spec{Verb{n, +h, z, g}, u, hs, b, pl}:
      HSpec{h, Spec{Verb{n, h, z, g}, u, hs, b, pl}}

def fresh.go(hsp: HSpec, tls: Bool, host: String, port: U32, ch: Chan(Slot()), +lim: Lim) -> IO(Hop):
  match hsp:
    case HSpec{h, sp}:
      IO.bind(Opened, Hop, open(tls, host, port, lim.dl(lim)), o => fresh.opened(o, req.of(sp, True{}), ch, lim.with_head(lim, h)))

# on a new connection, holding the pool's room for it
def fresh(sp: Spec, p: Pool, lim: Lim) -> IO(Hop):
  match p:
    case Pool{_, tls, h, port, _, ch, _}:
      fresh.go(head.of.keep(sp), tls, s.copy(h, ""), port, ch, lim)

def pool.give(e: Ex, p: Pool) -> IO(Hop):
  match p:
    case Pool{_, _, _, _, _, ch, _}:
      give(e, ch)

# after a try on a kept connection: a connection the server had closed is
# tried once more on a new one, if the request is safe to repeat
def reused.after(e: Ex, spare: Spec, again: Bool, +p: Pool, lim: Lim) -> IO(Hop):
  match e again:
    case Lost{_, True{}, _} True{}:
      fresh(spare, p, lim)
    case other _:
      pool.give(other, p)

def verb.again(sp: Spec) -> HSpec:
  match sp:
    case Spec{Verb{n, h, z, +g}, u, hs, b, pl}:
      HSpec{g, Spec{Verb{n, h, z, g}, u, hs, b, pl}}

def reused.run(ha: HSpec, gb: HSpec, s: Socket, tls: Bool, p: Pool, +lim: Lim) -> IO(Hop):
  match ha gb:
    case HSpec{h, a} HSpec{g, b}:
      IO.bind(Ex, Hop, exchange(s, tls, req.of(a, True{}), lim.with_head(lim, h), Keep{[]}), e => reused.after(e, b, g, p, lim))

def reused.go(sp2: Spec2, s: Socket, tls: Bool, p: Pool, lim: Lim) -> IO(Hop):
  match sp2:
    case Spec2{a, b}:
      reused.run(head.of.keep(a), verb.again(b), s, tls, p, lim)

def idle(now: Nat, last: Nat, ms: U32) -> Bool:
  Bool.not(Nat.is_le(now, Nat.add(last, U32.to_nat(ms))))

def pool.idle_ms(p: Pool) -> U32:
  match p:
    case Pool{Config{_, _, _, _, _, _, id}, _, _, _, _, _, _}:
      id

def pooled.kept(old: Bool, s: Socket, +tls: Bool, sp: Spec, +p: Pool, +lim: Lim) -> IO(Hop):
  match old:
    case True{}:
      IO.bind(Unit, Hop, shut(tls, s), u => fresh(sp, p, lim))
    case False{}:
      reused.go(spec.dup(sp), s, tls, p, lim)

def pooled.slot(sl: Maybe<&1, Slot()>, sp: Spec, +p: Pool, +lim: Lim) -> IO(Hop):
  match sl:
    case Some{Some{Idle{s, tls, last}}}:
      do IO<Hop>:
        +now : Nat <- IO.now()
        pooled.kept(idle(now, last, pool.idle_ms(p)), s, tls, sp, p, lim)
    case Some{None{}}:
      fresh(sp, p, lim)
    case None{}:
      IO.pure(Hop, HopLost{Closed{}})

# a request through the pool: a kept connection, or a new one when none
# is free and there is room, else waiting for one to come back
def pooled(sp: Spec, +p: Pool, lim: Lim) -> IO(Hop):
  match p:
    case Pool{_, _, _, _, _, ch, _}:
      IO.bind(Maybe<&1, Slot()>, Hop, Chan.recv(Slot(), ch), sl => pooled.slot(sl, sp, p, lim))

def pool.drain.slot(s: Maybe<&1, Slot()>, k: Unit -> IO(Unit)) -> IO(Unit):
  match s:
    case Some{Some{Idle{sk, tls, _}}}:
      IO.bind(Unit, Unit, shut(tls, sk), k)
    case _:
      k(Unit{})

def pool.drain(n: Nat, +ch: Chan(Slot())) -> IO(Unit):
  match n:
    case 0n:
      Chan.close(Slot(), ch)
    case 1n+m:
      IO.bind(Maybe<&1, Slot()>, Unit, Chan.recv(Slot(), ch), s => pool.drain.slot(s, x => pool.drain(m, ch)))

# close the pool and its connections, once each one in use comes back
def pool.close(p: Pool) -> IO(Unit):
  match p:
    case Pool{_, _, _, _, _, ch, n}:
      pool.drain(U32.to_nat(n), ch)

# Redirects and retries
# ---------------------

def redirect(+c: U32) -> Bool:
  Bool.or(Bool.or(U32.is_eq(c, 301), U32.is_eq(c, 302)), Bool.or(U32.is_eq(c, 303), Bool.or(U32.is_eq(c, 307), U32.is_eq(c, 308))))

def retry.code(+c: U32) -> Bool:
  Bool.or(U32.is_eq(c, 502), Bool.or(U32.is_eq(c, 503), U32.is_eq(c, 504)))

type Left is Data:
  Left{tries: U32, redirs: U32, wait: U32, follow: Bool}

def DK() -> Type:
  Spec -> Left -> IO(R())

def wait.more(+w: U32) -> U32:
  Bool.pick(U32, U32.is_lt(w, 2500), (w * 2 : U32), 5000)

def retry(sp: Spec, l: Left, k: DK()) -> IO(R()):
  match l:
    case Left{t, r, +w, f}:
      IO.bind(Unit, R(), IO.sleep(w), u => k(sp, Left{(t - 1 : U32), r, wait.more(w), f}))

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

def lost.go(go: Bool, e: Err, sp: Spec, l: Left, k: DK()) -> IO(R()):
  match go:
    case True{}:
      retry(sp, l, k)
    case False{}:
      IO.pure(R(), Fail{e})

def lost.check(q: ErrQ, again: Bool, sp: Spec, +l: Left, k: DK()) -> IO(R()):
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

# where a redirect goes: a path on the same origin, a url of its own on the
# same scheme, or nowhere the client follows (another scheme, or not a url)
type Next is Data:
  Same{target: String}
  Away{url: Url}
  Stay{}

def next.away(u: Url, +tls: Bool) -> Next:
  match u:
    case Url{+t, h, p, tg, au}:
      Bool.pick(Next, Bool.and(t, Bool.not(tls)), Stay{}, Away{Url{t, h, p, tg, au}})
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

def followed(n: Next, sp: Spec, +c: U32, l: Left, m: Meta, o: Out, k: DK()) -> IO(R()):
  match n l:
    case Stay{} _:
      IO.pure(R(), Done{response(m, o)})
    case _ Left{_, 0, _, True{}}:
      IO.pure(R(), Fail{Redirects{}})
    case _ Left{_, 0, _, False{}}:
      IO.pure(R(), Done{response(m, o)})
    case Same{t} other:
      k(spec.same(sp, t, c), redirs.dec(other))
    case Away{u} other:
      k(spec.away(sp, u, c), redirs.dec(other))

def located(lc: Loc, sp: TSpec, +c: U32, l: Left, rest: Meta, o: Out, k: DK()) -> IO(R()):
  match lc sp rest:
    case Loc{hs, Some{at}} TSpec{tls, s} Meta{_, _, r}:
      followed(next.of(at, tls), s, c, l, Meta{c, hs, r}, o, k)
    case Loc{hs, None{}} _ Meta{_, _, r}:
      IO.pure(R(), Done{response(Meta{c, hs, r}, o)})

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

def got.redirect(hit: Bool, m: Meta, o: Out, sp: Spec, l: Left, k: DK()) -> IO(R()):
  match hit m:
    case True{} Meta{+c, hs, r}:
      located(loc.scan(hs, Loc{[], None{}}), spec.tls(sp), c, l, Meta{c, [], r}, o, k)
    case False{} other:
      IO.pure(R(), Done{response(other, o)})

def got.go(re: Bool, m: Meta, o: Out, sp: Spec, +l: Left, k: DK()) -> IO(R()):
  match re m:
    case True{} _:
      retry(sp, l, k)
    case False{} Meta{+c, hs, r}:
      got.redirect(redirect(c), Meta{c, hs, r}, o, sp, l, k)

def hopped(h: Hop, sp: HSpec, +l: Left, k: DK()) -> IO(R()):
  match h sp:
    case HopGot{Meta{+c, hs, r}, o} HSpec{again, s}:
      got.go(Bool.and(retry.code(c), can.retry(again, l)), Meta{c, hs, r}, o, s, l, k)
    case HopLost{e} HSpec{again, s}:
      lost.check(retry.err(e), again, s, l, k)

def pool.of(sp: Spec) -> HSpec:
  match sp:
    case Spec{v, u, hs, b, +pl}:
      HSpec{pl, Spec{v, u, hs, b, pl}}

def drive.go(sp2: Spec2, l: Left, +lim: Lim, k: DK()) -> IO(R()):
  match sp2:
    case Spec2{a, b}:
      IO.bind(Hop, R(), once(a, lim), h => hopped(h, verb.again(b), l, k))

# a request, then its redirects and retries; fuel bounds them
def drive(fuel: Nat, sp: Spec, l: Left, +lim: Lim) -> IO(R()):
  match fuel:
    case 0n:
      IO.pure(R(), Fail{Redirects{}})
    case 1n+p:
      drive.go(spec.dup(sp), l, lim, s => l2 => drive(p, s, l2, lim))

def hop.via(sp: HSpec, +p: Pool, +lim: Lim) -> IO(Hop):
  match sp:
    case HSpec{True{}, s}:
      pooled(s, p, lim)
    case HSpec{False{}, s}:
      once(s, lim)

def drive.p.go(sp2: Spec2, l: Left, +p: Pool, +lim: Lim, k: DK()) -> IO(R()):
  match sp2:
    case Spec2{a, b}:
      IO.bind(Hop, R(), hop.via(pool.of(a), p, lim), h => hopped(h, verb.again(b), l, k))

# drive through a pool. A drive of its own: sharing the pool shares its
# Strings, and a program without one keeps them uncounted
def drive.p(fuel: Nat, sp: Spec, l: Left, +p: Pool, +lim: Lim) -> IO(R()):
  match fuel:
    case 0n:
      IO.pure(R(), Fail{Redirects{}})
    case 1n+n:
      drive.p.go(spec.dup(sp), l, p, lim, s => l2 => drive.p(n, s, l2, p, lim))

def left.of(+rt: U32, +rd: U32, bo: U32) -> Left:
  Left{rt, rd, bo, U32.is_gt(rd, 0)}

def lim.of(+now: Nat, +ms: U32, mh: U32, mb: U32) -> Lim:
  Lim{Nat.add(now, U32.to_nat(ms)), ms, False{}, mh, U32.to_nat(mb), False{}}

def fuel.of(rt: U32, rd: U32) -> Nat:
  Nat.add(U32.to_nat(rt), Nat.add(U32.to_nat(rd), 2n))

def start(cfg: Config, sp: Spec) -> IO(R()):
  match cfg:
    case Config{+ms, mh, mb, +rt, bo, +rd, _}:
      do IO<R()>:
        +now : Nat <- IO.now()
        drive(fuel.of(rt, rd), sp, left.of(rt, rd, bo), lim.of(now, ms, mh, mb))

def start.p(cfg: Config, sp: Spec, +p: Pool) -> IO(R()):
  match cfg:
    case Config{+ms, mh, mb, +rt, bo, +rd, _}:
      do IO<R()>:
        +now : Nat <- IO.now()
        drive.p(fuel.of(rt, rd), sp, left.of(rt, rd, bo), p, lim.of(now, ms, mh, mb))

# a request: method, url, headers (Host, Content-Length, Transfer-Encoding
# and Connection are the client's own), and body
def request.go(cfg: Config, v: Maybe<&2, Verb>, u: String, hs: List<&2, H.Header>, body: List<&2, U32>) -> IO(R()):
  match v:
    case Some{vb}:
      start(cfg, Spec{vb, url(u), hs, B.of_list(body), False{}})
    case None{}:
      IO.pure(R(), Fail{BadMethod{}})

def request(cfg: Config, m: M.Method, u: String, hs: List<&2, H.Header>, body: List<&2, U32>) -> IO(R()):
  request.go(cfg, verb.check(verb(m)), u, hs, body)

def get(u: String) -> IO(R()):
  request(default(), M.MGet{}, u, [], [])

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

# a POST with a body of the given content type
def post(u: String, kind: String, body: List<&2, U32>) -> IO(R()):
  request(default(), M.MPost{}, u, [H.Header{"content-type", kind}], body)

def pool.url(tls: Bool, h: String, port: U32, au: String, g: Tgt) -> Url:
  match g:
    case Tgt{t, True{}}:
      url.check(Url{tls, h, port, t, au})
    case Tgt{_, False{}}:
      UBad{BadUrl{}}

def pool.path(p: String) -> Tgt:
  match p:
    case SCon{Chr{47}, r}:
      target.go(r, "/", True{})
    case _:
      Tgt{"", False{}}

def send.spec(p: Pool, v: Verb, path: String, hs: List<&2, H.Header>, body: B.Bytes) -> Spec:
  match p:
    case Pool{_, tls, h, port, au, _, _}:
      Spec{v, pool.url(tls, s.copy(h, ""), port, s.copy(au, ""), pool.path(path)), hs, body, True{}}

def pool.cfg(p: Pool) -> Config:
  match p:
    case Pool{Config{a, b, c, d, e, f, g}, _, _, _, _, _, _}:
      Config{a, b, c, d, e, f, g}

# a request through the pool, to a path (/orders/7?full=1) on its origin
def send.go(+p: Pool, v: Maybe<&2, Verb>, path: String, hs: List<&2, H.Header>, body: List<&2, U32>) -> IO(R()):
  match v:
    case Some{vb}:
      start.p(pool.cfg(p), send.spec(p, vb, path, hs, B.of_list(body)), p)
    case None{}:
      IO.pure(R(), Fail{BadMethod{}})

def send(+p: Pool, m: M.Method, path: String, hs: List<&2, H.Header>, body: List<&2, U32>) -> IO(R()):
  send.go(p, verb.check(verb(m)), path, hs, body)

def pool.get(p: Pool, path: String) -> IO(R()):
  send(p, M.MGet{}, path, [], [])

# Bodies as text and JSON
# -----------------------

def text.of(t: U.Text) -> Maybe<&2, String>:
  match t:
    case U.TOk{s}:
      Some{s}
    case _:
      None{}

# a response's body as text, when it is UTF-8
def text(r: Res.Response) -> Maybe<&2, String>:
  match r:
    case Res.Response{_, _, b}:
      text.of(U.decode(b))

# why a JSON call gave no value
type JErr is Data:
  JHttp{err: Err}                  # no response
  JStatus{code: U32, body: String} # a status other than 2xx, and the body as text
  JBad{err: J.Error}               # the body is not JSON
  JValue{err: J.Access}            # the JSON is not the value asked for

def jshow(e: JErr) -> String:
  match e:
    case JHttp{x}:
      show(x)
    case JStatus{c, b}:
      "status " ++ U32.show(c) ++ ": " ++ b
    case JBad{x}:
      "invalid JSON: " ++ J.message(x)
    case JValue{x}:
      J.message_access(x)

def JR(-A: Data) -> Data:
  Result<&2, &2, JErr, A>

def json.value(-A: Data, r: Result<&2, &2, J.Access, A>) -> JR(A):
  match r:
    case Done{a}:
      Done{a}
    case Fail{e}:
      Fail{JValue{e}}

def json.parsed(-A: Data, r: Result<&2, &2, J.Error, J.Json>, dec: J.Json -> Result<&2, &2, J.Access, A>) -> JR(A):
  match r:
    case Done{j}:
      json.value(A, dec(j))
    case Fail{e}:
      Fail{JBad{e}}

def json.empty(bs: List<&2, U32>) -> Result<&2, &2, J.Error, J.Json>:
  match bs:
    case Nil{}:
      Done{J.JNull{}}
    case other:
      J.parse_bytes(other)

def json.ok(-A: Data, ok: Bool, c: U32, b: List<&2, U32>, dec: J.Json -> Result<&2, &2, J.Access, A>) -> JR(A):
  match ok:
    case True{}:
      json.parsed(A, json.empty(b), dec)
    case False{}:
      Fail{JStatus{c, T.or(text.of(U.decode(b)), "(not UTF-8)")}}

def json.of(-A: Data, r: R(), dec: J.Json -> Result<&2, &2, J.Access, A>) -> JR(A):
  match r:
    case Done{Res.Response{S.Status{+c}, _, b}}:
      json.ok(A, Bool.and(U32.is_ge(c, 200), U32.is_lt(c, 300)), c, b, dec)
    case Fail{e}:
      Fail{JHttp{e}}

# GET a url and read its JSON body with dec: a status other than 2xx, a
# body that is not JSON, or JSON that dec refuses fail with why
def get_json(-A: Data, u: String, dec: J.Json -> Result<&2, &2, J.Access, A>) -> IO(JR(A)):
  IO.bind(R(), JR(A), request(default(), M.MGet{}, u, [H.Header{"accept", "application/json"}], []), r => IO.pure(JR(A), json.of(A, r, dec)))

def as_json(j: J.Json) -> Result<&2, &2, J.Access, J.Json>:
  Done{j}

# POST value, as JSON by enc, and read the JSON the server answers; an
# empty body reads as null
def post_json(-A: Data, u: String, enc: A -> J.Json, v: A) -> IO(JR(J.Json)):
  IO.bind(R(), JR(J.Json), request(default(), M.MPost{}, u, [H.Header{"content-type", "application/json"}, H.Header{"accept", "application/json"}], U.encode(J.encode(enc(v)))), r => IO.pure(JR(J.Json), json.of(J.Json, r, as_json)))

# Streaming
# ---------

def dl.end(e: Ex) -> IO(R()):
  match e:
    case Got{s, +tls, Meta{+c, hs, _}, _}:
      IO.bind(Unit, R(), shut(tls, s), u => IO.pure(R(), Done{Res.Response{S.Status{c}, hs, []}}))
    case Lost{err, _, _}:
      IO.pure(R(), Fail{err})

def dl.head(~f: U32 -> List<&2, U32> -> IO(Bool), h: Hd, +lim: Lim) -> IO(R()):
  match h:
    case HGot{s, +tls, H1.Head{+code, hs, fr, _, rest}}:
      IO.bind(Ex, R(), body(~each(~f), fr, s, tls, rest, Each{code}, Meta{code, hs, False{}}, lim), e => dl.end(e))
    case HGot{s, +tls, _}:
      IO.bind(Unit, R(), shut(tls, s), u => IO.pure(R(), Fail{BadResponse{}}))
    case HLost{e, _}:
      IO.pure(R(), Fail{e})

def dl.sent(r: Result<&1, &1, U32 & String, Unit>, s: Socket, +tls: Bool, +lim: Lim) -> IO(Hd):
  match r:
    case Done{_}:
      heads(8n, s, tls, B.BNil{}, lim)
    case Fail{(+c, _)}:
      hd.lost(tls, s, Bool.pick(Err, etimedout(c), Timeout{}, Closed{}), False{})

law dl.polled:
  for +tls: Bool
  for +lim: Lim
  for m: RU()
  IO(Hd)

def dl.polled(tls, lim, m):
  (s, r) = m
  dl.sent(r, s, tls, lim)

def dl.opened(~f: U32 -> List<&2, U32> -> IO(Bool), o: Opened, req: B.Bytes, +lim: Lim) -> IO(R()):
  match o:
    case Opened{s, +tls}:
      do IO<R()>:
        m : RU() <- send.of(tls, s, B.to_list(req), lim.left(lim, 0n))
        h : Hd <- dl.polled(tls, lim, m)
        dl.head(~f, h, lim)
    case NotOpened{e}:
      IO.pure(R(), Fail{e})

def dl.open(~f: U32 -> List<&2, U32> -> IO(Bool), req: B.Bytes, +tls: Bool, host: String, +port: U32, +ms: U32, mh: U32, +dl: Nat) -> IO(R()):
  IO.bind(Opened, R(), open(tls, host, port, dl), o => dl.opened(~f, o, req, Lim{dl, ms, True{}, mh, Nat.mul(256n, 4294967295n), False{}}))

def dl.go(~f: U32 -> List<&2, U32> -> IO(Bool), u: Url, hs: List<&2, H.Header>, +ms: U32, mh: U32, +dl: Nat) -> IO(R()):
  match u:
    case Url{+tls, host, +port, target, auth}:
      dl.open(~f, H1.write_request("GET", target, auth, hs.clean(hs, []), B.BNil{}, False{}, True{}), tls, host, port, ms, mh, dl)
    case UBad{e}:
      IO.pure(R(), Fail{e})

# GET a url and hand its body to f as it is read, a piece at a time, with
# the status: for bodies too large to hold. f answers True to go on, False
# to stop. The result is the response with an empty body. No body limit;
# timeout_ms is per read, and redirects are not followed
def download(~f: U32 -> List<&2, U32> -> IO(Bool), cfg: Config, u: String, hs: List<&2, H.Header>) -> IO(R()):
  match cfg:
    case Config{+ms, mh, _, _, _, _, _}:
      do IO<R()>:
        +now : Nat <- IO.now()
        dl.go(~f, url(u), hs, ms, mh, Nat.add(now, U32.to_nat(ms)))
