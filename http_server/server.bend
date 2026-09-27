import Base
import ../wire/wire.bend as W
import ../http1/http1.bend as H1
import ../http1/bytes.bend as B
import ../http/request.bend as Req
import ../http/response.bend as Res
import ../http/status.bend as S

# grounds-http-server: serve(handler, config) answers HTTP/1.1 requests on a
# port. Each connection runs on its own (IO.spawn), reads requests one after
# another (keep-alive), and closes on Connection: close, on a refused
# request, after max_requests, or when the client does.
#
# Timeouts: a connection with no request under way closes after idle_ms
# without a byte; once a request's first bytes come, its head and body
# must all come within request_ms, else it gets 408 and the connection
# closes. A client trickling a byte at a time cannot hold a connection.

type Config is Data:
  Config{port: U32, max_head_bytes: U32, max_body_bytes: U32, max_requests: U32, idle_ms: U32, request_ms: U32}

def default(port: U32) -> Config:
  Config{port, 16384, 1048576, 100, 5000, 10000}

def RP() -> Type:
  Socket & Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>

def RU() -> Type:
  Socket & Result<&1, &1, U32 & String, Unit>

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
def timed_out(s: Socket) -> IO(Unit):
  do IO<Unit>:
    m : RU() <- W.wire_send(s, B.to_list(H1.write(refuse(S.request_timeout()), True{})))
    late(m)

# nothing came in time: an idle connection closes quietly, one mid-request
# is told why
def quiet(idle: Bool, s: Socket) -> IO(Unit):
  match idle:
    case True{}:
      W.close(s)
    case False{}:
      timed_out(s)

def polled.fold(idle: Bool, r: Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>, acc: B.Bytes, +dl: Nat, s: Socket, next: B.Bytes -> Nat -> Socket -> IO(Unit)) -> IO(Unit):
  match r:
    case Done{Some{+bs}}:
      got.go(empty(bs), acc, bs, dl, s, next)
    case Done{None{}}:
      quiet(idle, s)
    case Fail{_}:
      W.close(s)

# more bytes came: go on with them, or close if the client has
law polled:
  for idle: Bool
  for acc: B.Bytes
  for +dl: Nat
  for m: RP()
  for next: B.Bytes -> Nat -> Socket -> IO(Unit)
  IO(Unit)

def polled(idle, acc, dl, m, next):
  (s, r) = m
  polled.fold(idle, r, acc, dl, s, next)

# the deadline: set by the first read of a request, kept after
def deadline(+dl: Nat, +now: Nat, +ms: U32) -> Nat:
  match dl:
    case 0n:
      Nat.add(now, U32.to_nat(ms))
    case _:
      dl

def wait.go(over: Bool, +dl: Nat, +now: Nat, acc: B.Bytes, s: Socket, next: B.Bytes -> Nat -> Socket -> IO(Unit)) -> IO(Unit):
  match over:
    case True{}:
      timed_out(s)
    case False{}:
      IO.bind(RP(), Unit, W.wire_recv_timeout(s, 65536, U32.from_nat(Nat.sub(dl, now))), m => polled(False{}, acc, dl, m, next))

def wait.left(+dl: Nat, +now: Nat, acc: B.Bytes, s: Socket, next: B.Bytes -> Nat -> Socket -> IO(Unit)) -> IO(Unit):
  wait.go(Nat.is_le(dl, now), dl, now, acc, s, next)

# read on: an idle connection waits idle_ms; a request under way waits
# until its deadline
def wait(idle: Bool, +ims: U32, +rms: U32, +dl: Nat, acc: B.Bytes, s: Socket, next: B.Bytes -> Nat -> Socket -> IO(Unit)) -> IO(Unit):
  match idle:
    case True{}:
      IO.bind(RP(), Unit, W.wire_recv_timeout(s, 65536, ims), m => polled(True{}, acc, 0n, m, next))
    case False{}:
      do IO<Unit>:
        +now : Nat <- IO.now()
        wait.left(deadline(dl, now, rms), now, acc, s, next)

# the last allowed request closes the connection
def closing(+close: Bool, +left: Nat) -> Bool:
  match left:
    case 0n:
      True{}
    case _:
      close

# one parse of what has come so far, and what to do with it
def step(~h: Req.Request -> IO(Res.Response), p: H1.Parsed, +acc: B.Bytes, s: Socket, +left: Nat, +ims: U32, +rms: U32, +dl: Nat, next: B.Bytes -> Nat -> Socket -> IO(Unit)) -> IO(Unit):
  match p:
    case H1.Parsed{req, +close, rest}:
      do IO<Unit>:
        res : Res.Response <- h(req)
        m : RU() <- W.wire_send(s, B.to_list(H1.write(res, closing(close, left))))
        sent(closing(close, left), rest, m, next)
    case H1.More{}:
      wait(Bool.not(B.nonempty(acc)), ims, rms, dl, acc, s, next)
    case H1.Bad{e}:
      do IO<Unit>:
        m : RU() <- W.wire_send(s, B.to_list(H1.write(refuse(H1.status(e)), True{})))
        sent(True{}, B.BNil{}, m, next)

# a connection: acc is what has come and is not yet a request; fuel counts
# the requests it may still serve
def conn(~h: Req.Request -> IO(Res.Response), +fuel: Nat, +mh: U32, +mb: U32, +ims: U32, +rms: U32, +acc: B.Bytes, +dl: Nat, s: Socket) -> IO(Unit):
  match fuel:
    case 0n:
      W.close(s)
    case 1n+p:
      step(~h, H1.parse(copy(acc, B.BNil{}), mh, mb), acc, s, p, ims, rms, dl, b => d => sk => conn(~h, p, mh, mb, ims, rms, b, d, sk))

def RA() -> Type:
  Listener & Result<&1, &1, U32 & String, Socket>

# an accepted connection runs on its own; the loop goes on accepting
def accepted(~h: Req.Request -> IO(Res.Response), r: Result<&1, &1, U32 & String, Socket>, l: Listener, +mh: U32, +mb: U32, +ims: U32, +rms: U32, +mr: Nat, k: Listener -> IO(Unit)) -> IO(Unit):
  match r:
    case Done{s}:
      do IO<Unit>:
        x : Unit <- IO.spawn(Unit, conn(~h, mr, mh, mb, ims, rms, B.BNil{}, 0n, s))
        k(l)
    case Fail{_}:
      k(l)

# fuel bounds the connections served: a server's loop is bounded by the
# outside world, which Bend's termination check sees as a count
def accept.loop(~h: Req.Request -> IO(Res.Response), +fuel: Nat, +mh: U32, +mb: U32, +ims: U32, +rms: U32, +mr: Nat, m: RA()) -> IO(Unit):
  match fuel:
    case 0n:
      (l, _) = m
      IO.pure(Unit, Unit{})
    case 1n+p:
      (l, r) = m
      accepted(~h, r, l, mh, mb, ims, rms, mr, l2 => IO.bind(RA(), Unit, W.accept(l2), m2 => accept.loop(~h, p, mh, mb, ims, rms, mr, m2)))

# answer requests on cfg's port with h, one connection at a time each, many
# connections at once
def serve(~h: Req.Request -> IO(Res.Response), cfg: Config) -> IO(Unit):
  match cfg:
    case Config{port, +mh, +mb, mr, +ims, +rms}:
      do IO<Unit>:
        l : Listener <- IO.try(Listener, W.listen(port))
        m : RA() <- W.accept(l)
        accept.loop(~h, 4294967295n, mh, mb, ims, rms, U32.to_nat(mr), m)
