import Base
import ../server.bend as Server
import ../../core/status.bend as S
import ../../core/request.bend as Req
import ../../core/response.bend as Res
import ../../core/event.bend as Ev

# streamed bodies, health, and graceful stop, on PORT or 8083:
#   /events   three server-sent events, 100 ms apart
#   /big?n=N  N chunks of 64 KiB, streamed
#   /slow     answers after 1.5 s, to see a stop wait for it
#   /feed     three events with ids, after Last-Event-ID when a client resumes
#   /hb       heartbeats every 50 ms, until the client goes
#   /healthz  /readyz

def kib(n: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      kib(p, Con{120, acc})

def ticks(n: Nat, +i: U32, k: Server.Sink) -> IO(Server.Sink):
  match n:
    case 0n:
      IO.pure(Server.Sink, k)
    case 1n+p:
      do IO<Server.Sink>:
        k2 : Server.Sink <- Server.event(k, "tick " ++ U32.show(i))
        x : Unit <- IO.sleep(100)
        ticks(p, (i + 1 : U32), k2)

def chunks(n: Nat, k: Server.Sink) -> IO(Server.Sink):
  match n:
    case 0n:
      IO.pure(Server.Sink, k)
    case 1n+p:
      IO.bind(Server.Sink, Server.Sink, Server.send(k, kib(65536n, [])), k2 => chunks(p, k2))

def num(m: Maybe<&2, U32>) -> Nat:
  match m:
    case Some{n}:
      U32.to_nat(n)
    case None{}:
      16n

def count(m: Maybe<&2, String>) -> Nat:
  match m:
    case Some{s}:
      num(Server.env.digits(s, 0n, True{}))
    case None{}:
      16n

def num0(m: Maybe<&2, U32>) -> Nat:
  match m:
    case Some{n}:
      U32.to_nat(n)
    case None{}:
      0n

def after(m: Maybe<&2, String>) -> Nat:
  match m:
    case Some{s}:
      num0(Server.env.digits(s, 0n, True{}))
    case None{}:
      0n

def feed(n: Nat, +i: Nat, k: Server.Sink) -> IO(Server.Sink):
  match n:
    case 0n:
      IO.pure(Server.Sink, k)
    case 1n+p:
      IO.bind(Server.Sink, Server.Sink, Server.emit(k, Ev.Message{"feed", "item " ++ Nat.show(Nat.add(i, 1n)) ++ "\nsecond line", Some{Nat.show(Nat.add(i, 1n))}}), k2 => feed(p, Nat.add(i, 1n), k2))

def feed.start(+from: Nat, k: Server.Sink) -> IO(Server.Sink):
  IO.bind(Server.Sink, Server.Sink, Server.retry(k, 20), k2 => feed(3n, from, k2))

# a tick that writes nothing: sse.every sends a heartbeat instead
def quiet(k: Server.Sink) -> IO(Server.Sink):
  IO.pure(Server.Sink, k)

def route.more(fd: Bool, hb: Bool, r: Req.Request) -> IO(Server.Out):
  match fd hb:
    case True{} _:
      IO.pure(Server.Out, Server.sse(k => feed.start(after(Server.last_id(r)), k)))
    case False{} True{}:
      IO.pure(Server.Out, Server.sse(k => Server.sse.every(~quiet, 50, k)))
    case False{} False{}:
      IO.pure(Server.Out, Server.Whole{Res.not_found()})

def route(ev: Bool, big: Bool, slow: Bool, fd: Bool, hb: Bool, r: Req.Request) -> IO(Server.Out):
  match ev big slow:
    case True{} _ _:
      IO.pure(Server.Out, Server.sse(k => ticks(3n, 1, k)))
    case False{} True{} _:
      IO.pure(Server.Out, Server.Stream{S.ok(), [], k => chunks(count(Req.param(r, "n")), k)})
    case False{} False{} True{}:
      IO.bind(Unit, Server.Out, IO.sleep(1500), u => IO.pure(Server.Out, Server.Whole{Res.ok("slow done\n")}))
    case False{} False{} False{}:
      route.more(fd, hb, r)

def app(r: Req.Request) -> IO(Server.Out):
  match r:
    case Req.Request{m, +t, hs, b}:
      route(Server.path.is(t, "/events", True{}), Server.path.is(t, "/big", True{}), Server.path.is(t, "/slow", True{}), Server.path.is(t, "/feed", True{}), Server.path.is(t, "/hb", True{}), Req.Request{m, t, hs, b})

def main() -> IO(Unit):
  do IO<Unit>:
    cfg : Server.Config <- Server.from_env(Server.default(8083))
    Server.serve_out(~Server.health(~app), cfg)
