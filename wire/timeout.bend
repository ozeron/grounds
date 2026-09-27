import Base
import ./wire.bend as W

# wire_recv_timeout: nothing sent answers None{} after the deadline; bytes
# sent answer Some{bytes}

def RP() -> Type:
  Socket & Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>

def RU() -> Type:
  Socket & Result<&1, &1, U32 & String, Unit>

def says(m: Maybe<&1, List<&2, U32>>) -> String:
  match m:
    case None{}:
      "none"
    case Some{Nil{}}:
      "closed"
    case Some{Con{_, _}}:
      "bytes"

law polled:
  for m: RP()
  IO(Socket & String)

def polled(m):
  (s, r) = m
  do IO<Socket & String>:
    got : Maybe<&1, List<&2, U32>> <- IO.pass(Maybe<&1, List<&2, U32>>, r)
    return (s, says(got))

law sent:
  for m: RU()
  IO(Socket)

def sent(m):
  (s, r) = m
  do IO<Socket>:
    x : Unit <- IO.pass(Unit, r)
    return s

def same(a: String, b: String) -> Bool:
  match a b:
    case SNil{} SNil{}:
      True{}
    case SCon{x, at} SCon{y, bt}:
      Bool.and(Char.is_eq(x, y), same(at, bt))
    case _ _:
      False{}

def check.go(ok: Bool, got: String) -> IO(Unit):
  match ok:
    case True{}:
      IO.print("wire_recv_timeout: " ++ got)
    case False{}:
      IO.die(Unit, 1, "wire_recv_timeout: got " ++ got)

def check(want: String, +got: String) -> IO(Unit):
  check.go(same(want, got), got)

law step3:
  for m: Socket & String
  IO(Unit)

def step3(m):
  (s, d) = m
  do IO<Unit>:
    w : Unit <- check("closed", d)
    W.close(s)

law step2:
  for c: Socket
  for m: Socket & String
  IO(Unit)

# after bytes: close the client, and the server sees the close
def step2(c, m):
  (s, b) = m
  do IO<Unit>:
    y : Unit <- check("bytes", b)
    z : Unit <- W.close(c)
    p : RP() <- W.wire_recv_timeout(s, 64, 1000)
    got : Socket & String <- polled(p)
    step3(got)

law step1:
  for c: Socket
  for m: Socket & String
  IO(Unit)

# after nothing came: send three bytes, and they arrive
def step1(c, m):
  (s, a) = m
  do IO<Unit>:
    x : Unit <- check("none", a)
    m2 : RU() <- W.wire_send(c, [1, 2, 3])
    c2 : Socket <- sent(m2)
    p : RP() <- W.wire_recv_timeout(s, 64, 1000)
    got : Socket & String <- polled(p)
    step2(c2, got)

law sides:
  for c: Socket
  for m: Listener & Result<&1, &1, U32 & String, Socket>
  IO(Unit)

# nothing sent: the poll gives up after 100 ms
def sides(c, m):
  (l, r) = m
  do IO<Unit>:
    s : Socket <- IO.pass(Socket, r)
    p : RP() <- W.wire_recv_timeout(s, 64, 100)
    got : Socket & String <- polled(p)
    step1(c, got)

def main() -> IO(Unit):
  do IO<Unit>:
    l : Listener <- IO.try(Listener, W.listen(47832))
    c : Socket <- IO.try(Socket, W.connect("127.0.0.1", 47832))
    acc : Listener & Result<&1, &1, U32 & String, Socket> <- W.accept(l)
    sides(c, acc)
