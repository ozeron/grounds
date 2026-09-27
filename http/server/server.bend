import Base
import ../../wire/wire.bend as W
import ../wire/http1.bend as H1
import ../wire/bytes.bend as B
import ../core/request.bend as Req
import ../core/response.bend as Res
import ../core/status.bend as S
import ../core/headers.bend as H
import ../../utf8/utf8.bend as U

# grounds-http-server: serve(handler, config) answers HTTP/1.1 requests on a
# port. Each connection runs on its own (IO.spawn), reads requests one after
# another (keep-alive), and closes on Connection: close, on a refused
# request, after max_requests, or when the client does.
#
# Timeouts: a connection with no request under way closes after idle_ms
# without a byte; once a request's first bytes come, its head and body
# must all come within request_ms, else it gets 408 and the connection
# closes. A client trickling a byte at a time cannot hold a connection. A
# response must be taken within request_ms per write.
#
# Shutdown: on SIGTERM or SIGINT the server stops accepting, closes idle
# connections, lets requests under way finish (their responses say
# connection: close), and returns once none is left, or exits after
# drain_ms.

type Config is Data:
  Config{port: U32, max_head_bytes: U32, max_body_bytes: U32, max_requests: U32, idle_ms: U32, request_ms: U32, drain_ms: U32}

def default(port: U32) -> Config:
  Config{port, 16384, 1048576, 100, 5000, 10000, 10000}

# Config from the environment
# ---------------------------

def env.digits(s: String, +n: Nat, ok: Bool) -> Maybe<&2, U32>:
  match s:
    case SNil{}:
      Bool.pick(Maybe<&2, U32>, ok, Some{U32.from_nat(n)}, None{})
    case SCon{Chr{+x}, t}:
      env.digits(t, Nat.add(Nat.mul(10n, n), Nat.sub(U32.to_nat(x), 48n)), Bool.and(ok, Bool.and(Bool.and(U32.is_ge(x, 48), U32.is_le(x, 57)), Nat.is_le(Nat.add(Nat.mul(10n, n), Nat.sub(U32.to_nat(x), 48n)), 4294967295n))))

def env.some(s: String) -> Bool:
  match s:
    case SNil{}:
      False{}
    case _:
      True{}

def env.num(m: Maybe<&2, U32>, name: String) -> IO(U32):
  match m:
    case Some{n}:
      IO.pure(U32, n)
    case None{}:
      IO.die(U32, 1, name ++ ": not a number from 0 to 4294967295")

def env.got(r: Result<&1, &1, U32 & String, String>, name: String, +d: U32) -> IO(U32):
  match r:
    case Done{+v}:
      env.num(env.digits(v, 0n, env.some(v)), name)
    case Fail{_}:
      IO.pure(U32, d)

# a number from the environment, or d when it is not set; one that is set
# but not a number stops the program, naming it (label is the same name:
# one String read twice would be shared)
def env.u32(name: String, label: String, +d: U32) -> IO(U32):
  IO.bind(Result<&1, &1, U32 & String, String>, U32, IO.get_env(name), r => env.got(r, label, d))

# cfg with what the environment sets: PORT, HTTP_MAX_HEAD_BYTES,
# HTTP_MAX_BODY_BYTES, HTTP_MAX_REQUESTS, HTTP_IDLE_MS, HTTP_REQUEST_MS,
# HTTP_DRAIN_MS
def from_env(cfg: Config) -> IO(Config):
  match cfg:
    case Config{+port, +mh, +mb, +mr, +ims, +rms, +dms}:
      do IO<Config>:
        +p : U32 <- env.u32("PORT", "PORT", port)
        +a : U32 <- env.u32("HTTP_MAX_HEAD_BYTES", "HTTP_MAX_HEAD_BYTES", mh)
        +b : U32 <- env.u32("HTTP_MAX_BODY_BYTES", "HTTP_MAX_BODY_BYTES", mb)
        +c : U32 <- env.u32("HTTP_MAX_REQUESTS", "HTTP_MAX_REQUESTS", mr)
        +i : U32 <- env.u32("HTTP_IDLE_MS", "HTTP_IDLE_MS", ims)
        +q : U32 <- env.u32("HTTP_REQUEST_MS", "HTTP_REQUEST_MS", rms)
        +d : U32 <- env.u32("HTTP_DRAIN_MS", "HTTP_DRAIN_MS", dms)
        return Config{p, a, b, c, i, q, d}

# Streamed responses
# ------------------

# where a streamed body goes: the connection, whether every write so far
# went through, and how long a write may wait
type Sink is Type:
  Sink{sock: Socket, ok: Bool, ms: U32}

# what a handler answers: a whole response, or a status and headers whose
# body the function writes through a Sink, in chunks
type Out is Type:
  Whole{res: Res.Response}
  Stream{status: S.Status, headers: List<&2, H.Header>, body: Sink -> IO(Sink)}

def RP() -> Type:
  Socket & Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>

def RU() -> Type:
  Socket & Result<&1, &1, U32 & String, Unit>

def sink.of(r: Result<&1, &1, U32 & String, Unit>, s: Socket, +ms: U32) -> IO(Sink):
  match r:
    case Done{_}:
      IO.pure(Sink, Sink{s, True{}, ms})
    case Fail{_}:
      IO.pure(Sink, Sink{s, False{}, ms})

law sink.sent:
  for +ms: U32
  for m: RU()
  IO(Sink)

def sink.sent(ms, m):
  (s, r) = m
  sink.of(r, s, ms)

def send.go(ok: Bool, s: Socket, +ms: U32, bs: B.Bytes) -> IO(Sink):
  match ok:
    case True{}:
      IO.bind(RU(), Sink, W.wire_send_timeout(s, B.to_list(H1.chunk(bs)), ms), m => sink.sent(ms, m))
    case False{}:
      IO.pure(Sink, Sink{s, False{}, ms})

# bytes as the next part of the body; once a write fails, the rest are
# dropped and the connection closes after the handler returns
def send(k: Sink, bs: List<&2, U32>) -> IO(Sink):
  match k:
    case Sink{s, ok, +ms}:
      send.go(ok, s, ms, B.of_list(bs))

# text as the next part of the body, in UTF-8
def send_text(k: Sink, t: String) -> IO(Sink):
  send(k, U.encode(t))

def sse.go(s: String, acc: String) -> String:
  match s:
    case SNil{}:
      String.reverse(String.reverse.go("\n\n", acc))
    case SCon{Chr{10}, t}:
      sse.go(t, String.reverse.go("\ndata: ", acc))
    case SCon{c, t}:
      sse.go(t, SCon{c, acc})

# a server-sent event: each line of data as a data: line, then a blank line
def event(k: Sink, data: String) -> IO(Sink):
  send_text(k, sse.go(data, String.reverse("data: ")))

# a server-sent event with a name: an event: line first
def named(k: Sink, name: String, data: String) -> IO(Sink):
  send_text(k, "event: " ++ name ++ "\n" ++ sse.go(data, String.reverse("data: ")))

# 200 with a text/event-stream body the function writes, event by event
def sse(body: Sink -> IO(Sink)) -> Out:
  Stream{S.ok(), [H.Header{"content-type", "text/event-stream"}, H.Header{"cache-control", "no-cache"}], body}

# Health
# ------

# whether the target's path, before any ?, is w
def path.is(t: String, w: String, ok: Bool) -> Bool:
  match t w:
    case SNil{} SNil{}:
      ok
    case SCon{Chr{63}, _} SNil{}:
      ok
    case SCon{x, tt} SCon{y, wt}:
      path.is(tt, wt, Bool.and(ok, Char.is_eq(x, y)))
    case _ _:
      False{}

def ready(+stop: U32) -> Out:
  match stop:
    case 0:
      Whole{Res.ok("ready\n")}
    case _:
      Whole{Res.text(S.service_unavailable(), "stopping\n")}

def health.go(~next: Req.Request -> IO(Out), live: Bool, rd: Bool, r: Req.Request) -> IO(Out):
  match live rd:
    case True{} _:
      IO.pure(Out, Whole{Res.ok("ok\n")})
    case False{} True{}:
      IO.bind(U32, Out, W.wire_stopping(), stop => IO.pure(Out, ready(stop)))
    case False{} False{}:
      next(r)

# /healthz answers 200 while the process runs; /readyz answers 200, or 503
# once a stop has begun, so a load balancer sends no new requests
def health(~next: Req.Request -> IO(Out), r: Req.Request) -> IO(Out):
  match r:
    case Req.Request{m, +t, hs, b}:
      health.go(~next, path.is(t, "/healthz", True{}), path.is(t, "/readyz", True{}), Req.Request{m, t, hs, b})

# Connections
# -----------

def copy(bs: B.Bytes, acc: B.Bytes) -> B.Bytes:
  match bs:
    case B.BNil{}:
      B.rev(acc)
    case B.BCon{b, t}:
      copy(t, B.BCon{b, acc})

# a refused request's answer: its status, with the reason as the text
def refuse(st: S.Status) -> Res.Response:
  match st:
    case S.Status{+c}:
      Res.text(S.Status{c}, S.reason(S.Status{c}))

# after a response is sent: close, or go on with the bytes after the request
law sent:
  for close: Bool
  for rest: B.Bytes
  for m: RU()
  for next: B.Bytes -> Nat -> Socket -> IO(Unit)
  IO(Unit)

# a new request starts with no deadline: its first bytes set one
def sent(close, rest, m, next):
  match close:
    case True{}:
      (s, _) = m
      W.close(s)
    case False{}:
      (s, _) = m
      next(rest, 0n, s)

def finish(k: Sink, close: Bool, rest: B.Bytes, next: B.Bytes -> Nat -> Socket -> IO(Unit)) -> IO(Unit):
  match k:
    case Sink{s, True{}, +ms}:
      IO.bind(RU(), Unit, W.wire_send_timeout(s, B.to_list(H1.last_chunk()), ms), m => sent(close, rest, m, next))
    case Sink{s, False{}, _}:
      W.close(s)

def streamed.go(r: Result<&1, &1, U32 & String, Unit>, close: Bool, rest: B.Bytes, body: Sink -> IO(Sink), s: Socket, +ms: U32, next: B.Bytes -> Nat -> Socket -> IO(Unit)) -> IO(Unit):
  match r:
    case Done{_}:
      IO.bind(Sink, Unit, body(Sink{s, True{}, ms}), k => finish(k, close, rest, next))
    case Fail{_}:
      W.close(s)

# the head went out: the handler writes the body, then the last chunk
law streamed:
  for close: Bool
  for rest: B.Bytes
  for body: Sink -> IO(Sink)
  for +ms: U32
  for m: RU()
  for next: B.Bytes -> Nat -> Socket -> IO(Unit)
  IO(Unit)

def streamed(close, rest, body, ms, m, next):
  (s, r) = m
  streamed.go(r, close, rest, body, s, ms, next)

def respond(out: Out, +close: Bool, s: Socket, +ms: U32, rest: B.Bytes, next: B.Bytes -> Nat -> Socket -> IO(Unit)) -> IO(Unit):
  match out:
    case Whole{res}:
      IO.bind(RU(), Unit, W.wire_send_timeout(s, B.to_list(H1.write(res, close)), ms), m => sent(close, rest, m, next))
    case Stream{S.Status{+c}, hs, body}:
      IO.bind(RU(), Unit, W.wire_send_timeout(s, B.to_list(H1.write_head(c, hs, close)), ms), m => streamed(close, rest, body, ms, m, next))

def got.go(done: Bool, acc: B.Bytes, bs: List<&2, U32>, +dl: Nat, s: Socket, next: B.Bytes -> Nat -> Socket -> IO(Unit)) -> IO(Unit):
  match done:
    case True{}:
      W.close(s)
    case False{}:
      next(B.app(acc, B.of_list(bs)), dl, s)

def empty(bs: List<&2, U32>) -> Bool:
  match bs:
    case Nil{}:
      True{}
    case _:
      False{}

law late:
  for m: RU()
  IO(Unit)

def late(m):
  (s, _) = m
  W.close(s)

# the deadline passed mid-request: 408, then close
def timed_out(s: Socket, +ms: U32) -> IO(Unit):
  do IO<Unit>:
    m : RU() <- W.wire_send_timeout(s, B.to_list(H1.write(refuse(S.request_timeout()), True{})), ms)
    late(m)

def polled.fold(r: Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>, acc: B.Bytes, +dl: Nat, s: Socket, +ms: U32, next: B.Bytes -> Nat -> Socket -> IO(Unit)) -> IO(Unit):
  match r:
    case Done{Some{+bs}}:
      got.go(empty(bs), acc, bs, dl, s, next)
    case Done{None{}}:
      timed_out(s, ms)
    case Fail{_}:
      W.close(s)

# more bytes of a request came: go on with them, or close if the client has
law polled:
  for acc: B.Bytes
  for +dl: Nat
  for +ms: U32
  for m: RP()
  for next: B.Bytes -> Nat -> Socket -> IO(Unit)
  IO(Unit)

def polled(acc, dl, ms, m, next):
  (s, r) = m
  polled.fold(r, acc, dl, s, ms, next)

# the deadline: set by the first read of a request, kept after
def deadline(+dl: Nat, +now: Nat, +ms: U32) -> Nat:
  match dl:
    case 0n:
      Nat.add(now, U32.to_nat(ms))
    case _:
      dl

def wait.go(over: Bool, +dl: Nat, +now: Nat, +ms: U32, acc: B.Bytes, s: Socket, next: B.Bytes -> Nat -> Socket -> IO(Unit)) -> IO(Unit):
  match over:
    case True{}:
      timed_out(s, ms)
    case False{}:
      IO.bind(RP(), Unit, W.wire_recv_timeout(s, 65536, U32.from_nat(Nat.sub(dl, now))), m => polled(acc, dl, ms, m, next))

# a request under way waits until its deadline
def wait(+rms: U32, +dl: Nat, acc: B.Bytes, s: Socket, next: B.Bytes -> Nat -> Socket -> IO(Unit)) -> IO(Unit):
  do IO<Unit>:
    +now : Nat <- IO.now()
    wait.go(Nat.is_le(deadline(dl, now, rms), now), deadline(dl, now, rms), now, rms, acc, s, next)

# Idle connections
# ----------------

# an idle connection reads in slices of 200 ms, so it sees a stop soon;
# it ends with a request's first bytes, or closed
type Idle is Type:
  Came{sock: Socket, bytes: List<&2, U32>}
  Gone{}

def gone(s: Socket) -> IO(Idle):
  IO.bind(Unit, Idle, W.close(s), u => IO.pure(Idle, Gone{}))

def idle.more(over: Bool, +left: U32, s: Socket, again: U32 -> Socket -> IO(Idle)) -> IO(Idle):
  match over:
    case True{}:
      gone(s)
    case False{}:
      again((left - 200 : U32), s)

def idle.fold(r: Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>, +left: U32, s: Socket, again: U32 -> Socket -> IO(Idle)) -> IO(Idle):
  match r:
    case Done{Some{bs}}:
      IO.pure(Idle, Came{s, bs})
    case Done{None{}}:
      idle.more(U32.is_le(left, 200), left, s, again)
    case Fail{_}:
      gone(s)

law idle.polled:
  for +left: U32
  for m: RP()
  for again: U32 -> Socket -> IO(Idle)
  IO(Idle)

def idle.polled(left, m, again):
  (s, r) = m
  idle.fold(r, left, s, again)

def idle.go(on: Bool, +left: U32, s: Socket, again: U32 -> Socket -> IO(Idle)) -> IO(Idle):
  match on:
    case True{}:
      IO.bind(RP(), Idle, W.wire_recv_timeout(s, 65536, Bool.pick(U32, U32.is_lt(left, 200), left, 200)), m => idle.polled(left, m, again))
    case False{}:
      gone(s)

# wait up to left ms for a request to start; close on a stop
def idle(+fuel: Nat, +left: U32, s: Socket) -> IO(Idle):
  match fuel:
    case 0n:
      gone(s)
    case 1n+p:
      do IO<Idle>:
        +stop : U32 <- W.wire_stopping()
        idle.go(U32.is_eq(stop, 0), left, s, l => sk => idle(p, l, sk))

def idle.done(i: Idle, next: B.Bytes -> Nat -> Socket -> IO(Unit)) -> IO(Unit):
  match i:
    case Came{s, +bs}:
      got.go(empty(bs), B.BNil{}, bs, 0n, s, next)
    case Gone{}:
      IO.pure(Unit, Unit{})

def reading(quiet: Bool, +ims: U32, +rms: U32, +dl: Nat, acc: B.Bytes, s: Socket, next: B.Bytes -> Nat -> Socket -> IO(Unit)) -> IO(Unit):
  match quiet:
    case True{}:
      IO.bind(Idle, Unit, idle(Nat.add(U32.to_nat((ims / 200 : U32)), 2n), ims, s), i => idle.done(i, next))
    case False{}:
      wait(rms, dl, acc, s, next)

# the last allowed request closes the connection, and so does a stop
def closing(+close: Bool, +left: Nat, +stop: U32) -> Bool:
  match left:
    case 0n:
      True{}
    case _:
      Bool.or(close, Bool.not(U32.is_eq(stop, 0)))

# one parse of what has come so far, and what to do with it
def step(~h: Req.Request -> IO(Out), p: H1.Parsed, +acc: B.Bytes, s: Socket, +left: Nat, +ims: U32, +rms: U32, +dl: Nat, next: B.Bytes -> Nat -> Socket -> IO(Unit)) -> IO(Unit):
  match p:
    case H1.Parsed{req, +close, rest}:
      do IO<Unit>:
        out : Out <- h(req)
        +stop : U32 <- W.wire_stopping()
        respond(out, closing(close, left, stop), s, rms, rest, next)
    case H1.More{}:
      reading(Bool.not(B.nonempty(acc)), ims, rms, dl, acc, s, next)
    case H1.Bad{e}:
      do IO<Unit>:
        m : RU() <- W.wire_send_timeout(s, B.to_list(H1.write(refuse(H1.status(e)), True{})), rms)
        sent(True{}, B.BNil{}, m, next)

# a connection: acc is what has come and is not yet a request; fuel counts
# the requests it may still serve
def conn(~h: Req.Request -> IO(Out), +fuel: Nat, +mh: U32, +mb: U32, +ims: U32, +rms: U32, +acc: B.Bytes, +dl: Nat, s: Socket) -> IO(Unit):
  match fuel:
    case 0n:
      W.close(s)
    case 1n+p:
      step(~h, H1.parse(copy(acc, B.BNil{}), mh, mb), acc, s, p, ims, rms, dl, b => d => sk => conn(~h, p, mh, mb, ims, rms, b, d, sk))

# a connection, counted live while it runs
def served(act: IO(Unit)) -> IO(Unit):
  do IO<Unit>:
    x : Unit <- act
    n : U32 <- W.wire_live(4294967295)
    return Unit{}

# Shutdown
# --------

def drain.go(done: Bool, over: Bool, +live: U32, again: Unit -> IO(Unit)) -> IO(Unit):
  match done over:
    case True{} _:
      IO.print_err("http: stopped, every connection done")
    case False{} True{}:
      IO.die(Unit, 0, "http: stopped at the drain deadline, " ++ U32.show(live) ++ " connections cut")
    case False{} False{}:
      again(Unit{})

# wait for the live connections to finish, up to the deadline
def drain(+fuel: Nat, +until: Nat) -> IO(Unit):
  match fuel:
    case 0n:
      IO.die(Unit, 0, "http: stopped at the drain deadline")
    case 1n+p:
      do IO<Unit>:
        +live : U32 <- W.wire_live(0)
        +now : Nat <- IO.now()
        drain.go(U32.is_eq(live, 0), Nat.is_le(until, now), live, u => IO.bind(Unit, Unit, IO.sleep(50), v => drain(p, until)))

def shutdown(l: Listener, +dms: U32) -> IO(Unit):
  do IO<Unit>:
    x : Unit <- W.close_listener(l)
    +now : Nat <- IO.now()
    drain(Nat.add(U32.to_nat((dms / 50 : U32)), 2n), Nat.add(now, U32.to_nat(dms)))

# Accepting
# ---------

def RA() -> Type:
  Listener & Result<&1, &1, U32 & String, Maybe<&1, Socket>>

def check.stop(+stop: U32, l: Listener, +dms: U32, k: Listener -> IO(Unit)) -> IO(Unit):
  match stop:
    case 0:
      k(l)
    case _:
      shutdown(l, dms)

# an accepted connection runs on its own; the loop goes on accepting, and
# between connections it looks for a stop
def accepted(~h: Req.Request -> IO(Out), r: Result<&1, &1, U32 & String, Maybe<&1, Socket>>, l: Listener, +mh: U32, +mb: U32, +ims: U32, +rms: U32, +dms: U32, +mr: Nat, k: Listener -> IO(Unit)) -> IO(Unit):
  match r:
    case Done{Some{s}}:
      do IO<Unit>:
        n : U32 <- W.wire_live(1)
        x : Unit <- IO.spawn(Unit, served(conn(~h, mr, mh, mb, ims, rms, B.BNil{}, 0n, s)))
        k(l)
    case Done{None{}}:
      do IO<Unit>:
        +stop : U32 <- W.wire_stopping()
        check.stop(stop, l, dms, k)
    case Fail{_}:
      do IO<Unit>:
        x : Unit <- IO.sleep(10)
        +stop : U32 <- W.wire_stopping()
        check.stop(stop, l, dms, k)

# fuel bounds the turns of the loop: a server's loop is bounded by the
# outside world, which Bend's termination check sees as a count
def accept.loop(~h: Req.Request -> IO(Out), +fuel: Nat, +mh: U32, +mb: U32, +ims: U32, +rms: U32, +dms: U32, +mr: Nat, m: RA()) -> IO(Unit):
  match fuel:
    case 0n:
      (l, _) = m
      W.close_listener(l)
    case 1n+p:
      (l, r) = m
      accepted(~h, r, l, mh, mb, ims, rms, dms, mr, l2 => IO.bind(RA(), Unit, W.wire_accept_timeout(l2, 250), m2 => accept.loop(~h, p, mh, mb, ims, rms, dms, mr, m2)))

# answer requests on cfg's port with h, one at a time per connection, many
# connections at once; h may stream a body
def serve_out(~h: Req.Request -> IO(Out), cfg: Config) -> IO(Unit):
  match cfg:
    case Config{port, +mh, +mb, mr, +ims, +rms, +dms}:
      do IO<Unit>:
        x : Unit <- W.wire_on_stop()
        l : Listener <- IO.try(Listener, W.listen(port))
        m : RA() <- W.wire_accept_timeout(l, 250)
        accept.loop(~h, 4294967295n, mh, mb, ims, rms, dms, U32.to_nat(mr), m)

def whole(~h: Req.Request -> IO(Res.Response), r: Req.Request) -> IO(Out):
  IO.bind(Res.Response, Out, h(r), res => IO.pure(Out, Whole{res}))

# serve_out for a handler that answers whole responses
def serve(~h: Req.Request -> IO(Res.Response), cfg: Config) -> IO(Unit):
  serve_out(~whole(~h), cfg)

def lift(~h: Req.Request -> Res.Response, r: Req.Request) -> IO(Res.Response):
  IO.pure(Res.Response, h(r))

# serve for a handler that does no IO: it returns a Response, not IO
def serve_pure(~h: Req.Request -> Res.Response, cfg: Config) -> IO(Unit):
  serve(~lift(~h), cfg)
