import Base
import ../../wire/wire.bend as W
import ../wire/http1.bend as H1
import ../wire/bytes.bend as B
import ../core/method.bend as M
import ../core/headers.bend as H
import ../core/status.bend as S
import ../core/response.bend as Res
import ../../utf8/utf8.bend as U

# grounds-http-client: HTTP/1.1 requests to other services.
#
#   r <- Client.get("http://orders:8080/orders/7")
#   match r: Done{res} ... Fail{e}: Client.show(e)
#
# One connection per request, closed after it (connection: close). The
# whole request, from resolving the host to the last byte of the body,
# has timeout_ms; a response past max_head_bytes or max_body_bytes is
# refused. Plain http only: https needs TLS, which this client has not.

type Config is Data:
  Config{timeout_ms: U32, max_head_bytes: U32, max_body_bytes: U32}

# 10 s, 16 KiB of head, 8 MiB of body
def default() -> Config:
  Config{10000, 16384, 8388608}

def with_timeout(c: Config, +ms: U32) -> Config:
  match c:
    case Config{_, mh, mb}:
      Config{ms, mh, mb}

def with_max_body(c: Config, +n: U32) -> Config:
  match c:
    case Config{ms, mh, _}:
      Config{ms, mh, n}

# why a request got no response
type Err is Data:
  BadUrl{}            # not http://host[:port][/path][?query]
  Https{}             # https://: needs TLS
  NoHost{}            # the host name did not resolve
  Refused{code: U32}  # the connection failed, with errno
  Timeout{}           # past timeout_ms
  Closed{}            # the server closed before the response was whole
  TooLarge{}          # past max_head_bytes or max_body_bytes
  BadResponse{}       # not HTTP/1.1 as RFC 9112 frames it

def show(e: Err) -> String:
  match e:
    case BadUrl{}:
      "bad url: want http://host[:port][/path]"
    case Https{}:
      "https is not supported: no TLS"
    case NoHost{}:
      "host not found"
    case Refused{+c}:
      "connection failed: errno " ++ U32.show(c)
    case Timeout{}:
      "timed out"
    case Closed{}:
      "closed before the response was whole"
    case TooLarge{}:
      "response too large"
    case BadResponse{}:
      "bad response"

def R() -> Type:
  Result<&1, &1, Err, Res.Response>

# URLs
# ----

# host, port, the target to send (origin-form: /path?query), and the Host
# header's value
type Url is Data:
  Url{host: String, port: U32, target: String, authority: String}
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

# the text of s, copied char by char: a reader, so host can be used after
def s.copy(s: String, acc: String) -> String:
  match s:
    case SNil{}:
      String.reverse(acc)
    case SCon{Chr{x}, t}:
      s.copy(t, SCon{Chr{(x + 0 : U32)}, acc})

def url.auth(given: Bool, +port: U32, h: String) -> String:
  match given:
    case True{}:
      h ++ ":" ++ U32.show(port)
    case False{}:
      h

def url.make(auth: String, host: String, +port: U32, target: String) -> Url:
  Url{host, port, target, auth}

def url.done(ok: Bool, +host: String, +port: U32, +given: Bool, target: String) -> Url:
  match ok:
    case True{}:
      url.make(url.auth(given, port, s.copy(host, "")), host, port, target)
    case False{}:
      UBad{BadUrl{}}

def url.tgt(g: Tgt, host: String, +port: U32, +given: Bool) -> Url:
  match g:
    case Tgt{t, ok}:
      url.done(ok, host, port, given, t)

def url.target(host: String, +port: U32, +given: Bool, t: String) -> Url:
  match t:
    case SNil{}:
      url.done(True{}, host, port, given, "/")
    case SCon{Chr{63}, r}:
      url.tgt(target.go(r, "?/", True{}), host, port, given)
    case SCon{Chr{47}, r}:
      url.tgt(target.go(r, "/", True{}), host, port, given)
    case _:
      UBad{BadUrl{}}

def url.empty(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case _:
      False{}

def port.num(s: String, +n: Nat, ok: Bool, any: Bool) -> Maybe<&2, U32>:
  match s:
    case SNil{}:
      Bool.pick(Maybe<&2, U32>, Bool.and(Bool.and(ok, any), Bool.and(Nat.is_le(n, 65535n), Nat.is_le(1n, n))), Some{U32.from_nat(n)}, None{})
    case SCon{Chr{+x}, t}:
      port.num(t, Nat.add(Nat.mul(10n, n), Nat.sub(U32.to_nat(x), 48n)), Bool.and(ok, Bool.and(U32.is_ge(x, 48), Bool.and(U32.is_le(x, 57), Nat.is_le(n, 65535n)))), True{})

def url.port.end(m: Maybe<&2, U32>, host: String, t: String) -> Url:
  match m:
    case Some{+p}:
      url.target(host, p, True{}, t)
    case None{}:
      UBad{BadUrl{}}

# the port's digits, up to / or ? or the end: 1 to 65535
def url.port(s: String, host: String, acc: String) -> Url:
  match s:
    case SNil{}:
      url.port.end(port.num(String.reverse(acc), 0n, True{}, False{}), host, "")
    case SCon{Chr{47}, t}:
      url.port.end(port.num(String.reverse(acc), 0n, True{}, False{}), host, SCon{Chr{47}, t})
    case SCon{Chr{63}, t}:
      url.port.end(port.num(String.reverse(acc), 0n, True{}, False{}), host, SCon{Chr{63}, t})
    case SCon{c, t}:
      url.port(t, host, SCon{c, acc})

def url.host.end(ok: Bool, host: String, s: String) -> Url:
  match ok s:
    case False{} _:
      UBad{BadUrl{}}
    case True{} SCon{Chr{58}, t}:
      url.port(t, host, "")
    case True{} rest:
      url.target(host, 80, False{}, rest)

# the host, reversed in acc, up to : or / or ? or the end
def url.host(s: String, acc: String, ok: Bool, any: Bool) -> Url:
  match s:
    case SNil{}:
      url.host.end(Bool.and(ok, any), String.reverse(acc), "")
    case SCon{Chr{58}, t}:
      url.host.end(Bool.and(ok, any), String.reverse(acc), SCon{Chr{58}, t})
    case SCon{Chr{47}, t}:
      url.host.end(Bool.and(ok, any), String.reverse(acc), SCon{Chr{47}, t})
    case SCon{Chr{63}, t}:
      url.host.end(Bool.and(ok, any), String.reverse(acc), SCon{Chr{63}, t})
    case SCon{Chr{+x}, t}:
      url.host(t, SCon{Chr{x}, acc}, Bool.and(ok, host.char(x)), True{})

# http://host[:port][/path][?query]; the scheme in lowercase. No user info,
# no IPv6 literal, no fragment
def url(s: String) -> Url:
  match s:
    case SCon{'h', SCon{'t', SCon{'t', SCon{'p', SCon{':', SCon{'/', SCon{'/', rest}}}}}}}:
      url.host(rest, "", True{}, False{})
    case SCon{'h', SCon{'t', SCon{'t', SCon{'p', SCon{'s', SCon{':', SCon{'/', SCon{'/', _}}}}}}}}:
      UBad{Https{}}
    case _:
      UBad{BadUrl{}}

# Reading the response
# --------------------

def etimedout(+c: U32) -> Bool:
  Bool.or(U32.is_eq(c, 60), U32.is_eq(c, 110))

def failed(+c: U32) -> Err:
  Bool.pick(Err, etimedout(c), Timeout{}, Refused{c})

def fail(s: Socket, e: Err) -> IO(R()):
  IO.bind(Unit, R(), W.close(s), u => IO.pure(R(), Fail{e}))

# the bytes so far, oldest first, from chunks newest first
def flat(cs: List<&2, B.Bytes>, acc: B.Bytes) -> B.Bytes:
  match cs:
    case Nil{}:
      acc
    case Con{c, t}:
      flat(t, B.app(c, acc))

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

def bad(e: H1.Err) -> Err:
  match e:
    case H1.BodyTooLarge{}:
      TooLarge{}
    case H1.HeadTooLarge{}:
      TooLarge{}
    case _:
      BadResponse{}

# where a read stands: the chunks so far (newest first), their total, and
# the total at which to try a parse next. Trying at double the last total
# keeps the parses, each over all the bytes, to twice the bytes in all
type Rd is Type:
  Rd{sock: Socket, chunks: List<&2, B.Bytes>, total: Nat, try_at: Nat}

def interim(+code: U32) -> Bool:
  Bool.and(U32.is_ge(code, 100), Bool.and(U32.is_lt(code, 200), Bool.not(U32.is_eq(code, 101))))

def rd.of(+total: Nat, rest: B.Bytes, s: Socket) -> Rd:
  Rd{s, [rest], total, 0n}

def parsed.whole(skip: Bool, +code: U32, hs: List<&2, H.Header>, body: B.Bytes, +rest: B.Bytes, s: Socket, again: Rd -> IO(R())) -> IO(R()):
  match skip:
    case True{}:
      again(rd.of(count(rest, 0n), rest, s))
    case False{}:
      IO.bind(Unit, R(), W.close(s), u => IO.pure(R(), Done{Res.Response{S.Status{code}, hs, B.to_list(body)}}))

# a parse's outcome: a response (after a 1xx, the next one), more to read,
# or refused
def parsed(p: H1.RParsed, eof: Bool, +buf: B.Bytes, +total: Nat, s: Socket, again: Rd -> IO(R())) -> IO(R()):
  match p eof:
    case H1.RParsed{+code, hs, body, rest} _:
      parsed.whole(interim(code), code, hs, body, rest, s, again)
    case H1.RMore{} False{}:
      again(Rd{s, [buf], total, Nat.add(total, total)})
    case H1.RMore{} True{}:
      fail(s, Closed{})
    case H1.RBad{e} _:
      fail(s, bad(e))

def parsed.at(+buf: B.Bytes, +eof: Bool, +total: Nat, s: Socket, +mh: U32, +mb: U32, +head: Bool, again: Rd -> IO(R())) -> IO(R()):
  parsed(H1.read_response(copy(buf, B.BNil{}), mh, mb, eof, head), eof, buf, total, s, again)

def attempt(go: Bool, +eof: Bool, cs: List<&2, B.Bytes>, +total: Nat, +try_at: Nat, s: Socket, +mh: U32, +mb: U32, +head: Bool, again: Rd -> IO(R())) -> IO(R()):
  match go:
    case True{}:
      parsed.at(flat(cs, B.BNil{}), eof, total, s, mh, mb, head, again)
    case False{}:
      again(Rd{s, cs, total, try_at})

def got.fits(fits: Bool, +bs: B.Bytes, cs: List<&2, B.Bytes>, +total: Nat, +try_at: Nat, s: Socket, +mh: U32, +mb: U32, +head: Bool, again: Rd -> IO(R())) -> IO(R()):
  match fits:
    case True{}:
      attempt(Nat.is_le(try_at, total), False{}, Con{bs, cs}, total, try_at, s, mh, mb, head, again)
    case False{}:
      fail(s, TooLarge{})

def got.bytes(+bs: B.Bytes, cs: List<&2, B.Bytes>, +total: Nat, +try_at: Nat, +cap: Nat, s: Socket, +mh: U32, +mb: U32, +head: Bool, again: Rd -> IO(R())) -> IO(R()):
  got.fits(Nat.is_le(Nat.add(total, count(bs, 0n)), cap), bs, cs, Nat.add(total, count(bs, 0n)), try_at, s, mh, mb, head, again)

def got(r: Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>, cs: List<&2, B.Bytes>, +total: Nat, +try_at: Nat, +cap: Nat, s: Socket, +mh: U32, +mb: U32, +head: Bool, again: Rd -> IO(R())) -> IO(R()):
  match r:
    case Done{Some{Nil{}}}:
      attempt(True{}, True{}, cs, total, try_at, s, mh, mb, head, again)
    case Done{Some{Con{b, t}}}:
      got.bytes(B.of_list(Con{b, t}), cs, total, try_at, cap, s, mh, mb, head, again)
    case Done{None{}}:
      fail(s, Timeout{})
    case Fail{_}:
      fail(s, Closed{})

def RP() -> Type:
  Socket & Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>

law polled:
  for cs: List<&2, B.Bytes>
  for +total: Nat
  for +try_at: Nat
  for +cap: Nat
  for +mh: U32
  for +mb: U32
  for +head: Bool
  for m: RP()
  for again: Rd -> IO(R())
  IO(R())

def polled(cs, total, try_at, cap, mh, mb, head, m, again):
  (s, r) = m
  got(r, cs, total, try_at, cap, s, mh, mb, head, again)

def read.go(over: Bool, +dl: Nat, +now: Nat, k: Rd, +cap: Nat, +mh: U32, +mb: U32, +head: Bool, again: Rd -> IO(R())) -> IO(R()):
  match over k:
    case True{} Rd{s, _, _, _}:
      fail(s, Timeout{})
    case False{} Rd{s, cs, +total, +try_at}:
      IO.bind(RP(), R(), W.wire_recv_timeout(s, 65536, U32.from_nat(Nat.sub(dl, now))), m => polled(cs, total, try_at, cap, mh, mb, head, m, again))

# read until the response is whole; fuel bounds the reads, each at least
# a byte, by the bytes allowed
def read(+fuel: Nat, k: Rd, +dl: Nat, +cap: Nat, +mh: U32, +mb: U32, +head: Bool) -> IO(R()):
  match fuel k:
    case 0n Rd{s, _, _, _}:
      fail(s, TooLarge{})
    case 1n+p k:
      do IO<R()>:
        +now : Nat <- IO.now()
        read.go(Nat.is_le(dl, now), dl, now, k, cap, mh, mb, head, k2 => read(p, k2, dl, cap, mh, mb, head))

# Sending
# -------

def RU() -> Type:
  Socket & Result<&1, &1, U32 & String, Unit>

def sent.go(r: Result<&1, &1, U32 & String, Unit>, s: Socket, +dl: Nat, +cap: Nat, +mh: U32, +mb: U32, +head: Bool) -> IO(R()):
  match r:
    case Done{_}:
      read(cap, Rd{s, [], 0n, 0n}, dl, cap, mh, mb, head)
    case Fail{(+c, _)}:
      fail(s, Bool.pick(Err, etimedout(c), Timeout{}, Closed{}))

law sent:
  for +dl: Nat
  for +cap: Nat
  for +mh: U32
  for +mb: U32
  for +head: Bool
  for m: RU()
  IO(R())

def sent(dl, cap, mh, mb, head, m):
  (s, r) = m
  sent.go(r, s, dl, cap, mh, mb, head)

def left(+dl: Nat, +now: Nat) -> U32:
  U32.from_nat(Nat.sub(dl, now))

def connected(r: Result<&1, &1, U32 & String, Socket>, req: B.Bytes, +dl: Nat, +cap: Nat, +mh: U32, +mb: U32, +head: Bool) -> IO(R()):
  match r:
    case Done{s}:
      do IO<R()>:
        +now : Nat <- IO.now()
        m : RU() <- W.wire_send_timeout(s, B.to_list(req), left(dl, now))
        sent(dl, cap, mh, mb, head, m)
    case Fail{(+c, _)}:
      IO.pure(R(), Fail{failed(c)})

def resolved(r: Result<&1, &1, U32 & String, String>, +port: U32, req: B.Bytes, +dl: Nat, +cap: Nat, +mh: U32, +mb: U32, +head: Bool) -> IO(R()):
  match r:
    case Done{ip}:
      do IO<R()>:
        +now : Nat <- IO.now()
        c : Result<&1, &1, U32 & String, Socket> <- W.wire_connect_timeout(ip, port, left(dl, now))
        connected(c, req, dl, cap, mh, mb, head)
    case Fail{_}:
      IO.pure(R(), Fail{NoHost{}})

# a method's name, whether it is HEAD, and whether it expects a body
type Verb is Data:
  Verb{name: String, head: Bool, sized: Bool}

def verb(m: M.Method) -> Verb:
  match m:
    case M.MHead{}:
      Verb{"HEAD", True{}, False{}}
    case M.MPost{}:
      Verb{"POST", False{}, True{}}
    case M.MPut{}:
      Verb{"PUT", False{}, True{}}
    case M.MPatch{}:
      Verb{"PATCH", False{}, True{}}
    case other:
      Verb{M.show(other), False{}, False{}}

def go(v: Verb, u: Url, hs: List<&2, H.Header>, body: List<&2, U32>, +ms: U32, +mh: U32, +mb: U32) -> IO(R()):
  match v u:
    case Verb{name, +head, sized} Url{host, +port, target, auth}:
      do IO<R()>:
        +now : Nat <- IO.now()
        r : Result<&1, &1, U32 & String, String> <- W.wire_resolve(host)
        resolved(r, port, H1.write_request(name, target, auth, H.remove(hs, "host"), B.of_list(body), sized), Nat.add(now, U32.to_nat(ms)), Nat.add(Nat.add(U32.to_nat(mh), 65536n), Nat.add(U32.to_nat(mb), U32.to_nat(mb))), mh, mb, head)
    case _ UBad{e}:
      IO.pure(R(), Fail{e})

# a request: method, url, headers (Host, Content-Length, Transfer-Encoding
# and Connection are the client's own), and body
def request(cfg: Config, m: M.Method, u: String, hs: List<&2, H.Header>, body: List<&2, U32>) -> IO(R()):
  match cfg:
    case Config{+ms, +mh, +mb}:
      go(verb(m), url(u), hs, body, ms, mh, mb)

def get(u: String) -> IO(R()):
  request(default(), M.MGet{}, u, [], [])

# a POST with a body of the given content type
def post(u: String, kind: String, body: List<&2, U32>) -> IO(R()):
  request(default(), M.MPost{}, u, [H.Header{"content-type", kind}], body)

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
