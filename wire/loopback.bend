import Base
import ./wire.bend as W

# a loopback test: every byte value, 0 to 255, through a TCP connection to
# ourselves and back, must arrive unchanged

def RB() -> Type:
  Socket & Result<&1, &1, U32 & String, List<&2, U32>>

def RU() -> Type:
  Socket & Result<&1, &1, U32 & String, Unit>

def upto(n: Nat, +i: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      List.reverse(&2, U32, acc)
    case 1n+p:
      upto(p, (i + 1 : U32), Con{i, acc})

def all_bytes() -> List<&2, U32>:
  upto(256n, 0, [])

def same(a: List<&2, U32>, b: List<&2, U32>, ok: Bool) -> Bool:
  match a b:
    case Nil{} Nil{}:
      ok
    case Con{+x, at} Con{+y, bt}:
      same(at, bt, Bool.and(ok, U32.is_eq(x, y)))
    case _ _:
      False{}

def count(xs: List<&2, U32>, +n: U32) -> U32:
  match xs:
    case Nil{}:
      n
    case Con{_, t}:
      count(t, (n + 1 : U32))

def R2() -> Type:
  Socket & List<&2, U32>

# done: hand back what came (acc is reversed); else k reads on
def gather.pick(done: Bool, acc: List<&2, U32>, s: Socket, k: List<&2, U32> -> Socket -> IO(R2())) -> IO(R2()):
  match done:
    case True{}:
      IO.pure(R2(), (s, List.reverse(&2, U32, acc)))
    case False{}:
      k(acc, s)

# receive until want bytes have come
law gather:
  for fuel: Nat
  for +want: U32
  for acc: List<&2, U32>
  for +have: U32
  for m: RB()
  IO(R2())

def gather(fuel, want, acc, have, m):
  match fuel:
    case 0n:
      (s, _) = m
      IO.pure(R2(), (s, List.reverse(&2, U32, acc)))
    case 1n+p:
      (s, r) = m
      do IO<R2()>:
        +bs : List<&2, U32> <- IO.pass(List<&2, U32>, r)
        +h : U32 = count(bs, have)
        gather.pick(U32.is_ge(h, want), List.reverse.go(&2, U32, bs, acc), s, a => sk => IO.bind(RB(), R2(), W.wire_recv(sk, 4096), x => gather(p, want, a, h, x)))

law echo.send:
  for m: RU()
  IO(Socket)

def echo.send(m):
  (s, r) = m
  do IO<Socket>:
    x : Unit <- IO.pass(Unit, r)
    return s

def serve.back(got: R2()) -> IO(Unit):
  match got:
    case (s, bs):
      do IO<Unit>:
        m : RU() <- W.wire_send(s, bs)
        s2 : Socket <- echo.send(m)
        W.close(s2)

def verdict.say(ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.print("wire: 256 byte values went out and came back unchanged")
    case False{}:
      IO.die(Unit, 1, "wire: the bytes came back changed")

def verdict(got: R2()) -> IO(Unit):
  match got:
    case (s, bs):
      do IO<Unit>:
        x : Unit <- W.close(s)
        verdict.say(same(bs, all_bytes(), True{}))

law serve.side:
  for m: Listener & Result<&1, &1, U32 & String, Socket>
  IO(Unit)

# the server side: accept, read the 256 bytes, send them back
def serve.side(m):
  (l, r) = m
  do IO<Unit>:
    s : Socket <- IO.pass(Socket, r)
    first : RB() <- W.wire_recv(s, 4096)
    got : R2() <- gather(1000n, 256, [], 0, first)
    back : Unit <- serve.back(got)
    return Unit{}

law client.side:
  for l: Listener
  for c: Socket
  IO(Unit)

def client.side(l, c):
  do IO<Unit>:
    sent : RU() <- W.wire_send(c, all_bytes())
    c2 : Socket <- echo.send(sent)
    acc : Listener & Result<&1, &1, U32 & String, Socket> <- W.accept(l)
    x : Unit <- serve.side(acc)
    first : RB() <- W.wire_recv(c2, 4096)
    got : R2() <- gather(1000n, 256, [], 0, first)
    verdict(got)

def main() -> IO(Unit):
  do IO<Unit>:
    l : Listener <- IO.try(Listener, W.listen(47831))
    c : Socket <- IO.try(Socket, W.connect("127.0.0.1", 47831))
    client.side(l, c)
