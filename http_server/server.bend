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

type Config is Data:
  Config{port: U32, max_head_bytes: U32, max_body_bytes: U32, max_requests: U32}

def default(port: U32) -> Config:
  Config{port, 16384, 1048576, 100}

def RB() -> Type:
  Socket & Result<&1, &1, U32 & String, List<&2, U32>>

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
  for next: B.Bytes -> Socket -> IO(Unit)
  IO(Unit)

def sent(close, rest, m, next):
  match close:
    case True{}:
      (s, _) = m
      W.close(s)
    case False{}:
      (s, _) = m
      next(rest, s)

# more bytes came: go on with them, or close if the client has
law got:
  for acc: B.Bytes
  for m: RB()
  for next: B.Bytes -> Socket -> IO(Unit)
  IO(Unit)

def got.go(done: Bool, acc: B.Bytes, bs: List<&2, U32>, s: Socket, next: B.Bytes -> Socket -> IO(Unit)) -> IO(Unit):
  match done:
    case True{}:
      W.close(s)
    case False{}:
      next(B.app(acc, B.of_list(bs)), s)

def empty(bs: List<&2, U32>) -> Bool:
  match bs:
    case Nil{}:
      True{}
    case _:
      False{}

def got.fold(r: Result<&1, &1, U32 & String, List<&2, U32>>, acc: B.Bytes, s: Socket, next: B.Bytes -> Socket -> IO(Unit)) -> IO(Unit):
  match r:
    case Done{+bs}:
      got.go(empty(bs), acc, bs, s, next)
    case Fail{_}:
      W.close(s)

def got(acc, m, next):
  (s, r) = m
  got.fold(r, acc, s, next)

# the last allowed request closes the connection
def closing(+close: Bool, +left: Nat) -> Bool:
  match left:
    case 0n:
      True{}
    case _:
      close

# one parse of what has come so far, and what to do with it
def step(~h: Req.Request -> IO(Res.Response), p: H1.Parsed, acc: B.Bytes, s: Socket, +left: Nat, next: B.Bytes -> Socket -> IO(Unit)) -> IO(Unit):
  match p:
    case H1.Parsed{req, +close, rest}:
      do IO<Unit>:
        res : Res.Response <- h(req)
        m : RU() <- W.wire_send(s, B.to_list(H1.write(res, closing(close, left))))
        sent(closing(close, left), rest, m, next)
    case H1.More{}:
      do IO<Unit>:
        m : RB() <- W.wire_recv(s, 65536)
        got(acc, m, next)
    case H1.Bad{e}:
      do IO<Unit>:
        m : RU() <- W.wire_send(s, B.to_list(H1.write(refuse(H1.status(e)), True{})))
        sent(True{}, B.BNil{}, m, next)

# a connection: acc is what has come and is not yet a request; fuel counts
# the requests it may still serve
def conn(~h: Req.Request -> IO(Res.Response), +fuel: Nat, +mh: U32, +mb: U32, +acc: B.Bytes, s: Socket) -> IO(Unit):
  match fuel:
    case 0n:
      W.close(s)
    case 1n+p:
      step(~h, H1.parse(copy(acc, B.BNil{}), mh, mb), acc, s, p, b => sk => conn(~h, p, mh, mb, b, sk))

def RA() -> Type:
  Listener & Result<&1, &1, U32 & String, Socket>

# an accepted connection runs on its own; the loop goes on accepting
def accepted(~h: Req.Request -> IO(Res.Response), r: Result<&1, &1, U32 & String, Socket>, l: Listener, +mh: U32, +mb: U32, +mr: Nat, k: Listener -> IO(Unit)) -> IO(Unit):
  match r:
    case Done{s}:
      do IO<Unit>:
        x : Unit <- IO.spawn(Unit, conn(~h, mr, mh, mb, B.BNil{}, s))
        k(l)
    case Fail{_}:
      k(l)

# fuel bounds the connections served: a server's loop is bounded by the
# outside world, which Bend's termination check sees as a count
def accept.loop(~h: Req.Request -> IO(Res.Response), +fuel: Nat, +mh: U32, +mb: U32, +mr: Nat, m: RA()) -> IO(Unit):
  match fuel:
    case 0n:
      (l, _) = m
      IO.pure(Unit, Unit{})
    case 1n+p:
      (l, r) = m
      accepted(~h, r, l, mh, mb, mr, l2 => IO.bind(RA(), Unit, W.accept(l2), m2 => accept.loop(~h, p, mh, mb, mr, m2)))

# answer requests on cfg's port with h, one connection at a time each, many
# connections at once
def serve(~h: Req.Request -> IO(Res.Response), cfg: Config) -> IO(Unit):
  match cfg:
    case Config{port, +mh, +mb, mr}:
      do IO<Unit>:
        l : Listener <- IO.try(Listener, W.listen(port))
        m : RA() <- W.accept(l)
        accept.loop(~h, 4294967295n, mh, mb, U32.to_nat(mr), m)
