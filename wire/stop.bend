import Base
import ./wire.bend as W

# wire_accept_timeout, wire_on_stop, wire_stopping, wire_live: waits on
# port 7201 until SIGTERM, then prints what it saw. check.sh sends it one
# connection, then SIGTERM

def RA() -> Type:
  Listener & Result<&1, &1, U32 & String, Maybe<&1, Socket>>

def got(r: Result<&1, &1, U32 & String, Maybe<&1, Socket>>, +n: U32) -> IO(U32):
  match r:
    case Done{Some{s}}:
      do IO<U32>:
        x : Unit <- W.close(s)
        return (n + 1 : U32)
    case _:
      IO.pure(U32, n)

def loop.stop(+stop: U32, l: Listener, +n: U32, k: Listener -> U32 -> IO(Unit)) -> IO(Unit):
  match stop:
    case 0:
      k(l, n)
    case _:
      do IO<Unit>:
        x : Unit <- W.close_listener(l)
        live : U32 <- W.wire_live(0)
        IO.print("stopped: " ++ U32.show(n) ++ " accepted, live " ++ U32.show(live))

law step:
  for +fuel: Nat
  for +seen: U32
  for m: RA()
  IO(Unit)

def step(fuel, seen, m):
  match fuel:
    case 0n:
      (l, _) = m
      W.close_listener(l)
    case 1n+p:
      (l, r) = m
      do IO<Unit>:
        n : U32 <- got(r, seen)
        stop : U32 <- W.wire_stopping()
        loop.stop(stop, l, n, l2 => n2 => IO.bind(RA(), Unit, W.wire_accept_timeout(l2, 100), m2 => step(p, n2, m2)))

def main() -> IO(Unit):
  do IO<Unit>:
    x : Unit <- W.wire_on_stop()
    a : U32 <- W.wire_live(1)
    b : U32 <- W.wire_live(1)
    c : U32 <- W.wire_live(4294967295)
    l : Listener <- IO.try(Listener, W.listen(7201))
    IO.print("ready, live " ++ U32.show(c))
    m : RA() <- W.wire_accept_timeout(l, 100)
    step(600n, 0, m)
