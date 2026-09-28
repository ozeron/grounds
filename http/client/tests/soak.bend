import Base
import ../client.bend as C
import ../pool.bend as Pool
import ../../../json/json.bend as J

# tests/soak.py's client: ROUNDS rounds, each a one-shot GET, three GETs
# through an http pool and one through an https pool, a get_json, a
# post_json and a streamed download; "round N" every 500 rounds, for the
# driver to sample memory and sockets at, and the failures at the end.
# The pool holds the http and the https connections both

def ok(r: C.R(C.Reply)) -> Nat:
  match r:
    case Done{C.Reply{200, _, _}}:
      0n
    case Done{C.Reply{201, _, _}}:
      0n
    case _:
      1n

def hok(r: C.R(C.Head)) -> Nat:
  match r:
    case Done{C.Head{200, _}}:
      0n
    case _:
      1n

def jok(r: C.R(String)) -> Nat:
  match r:
    case Done{_}:
      0n
    case Fail{_}:
      1n

def pok(r: C.R(J.Json)) -> Nat:
  match r:
    case Done{_}:
      0n
    case Fail{_}:
      1n

def name(j: J.Json) -> Result<&2, &2, J.Access, String>:
  J.string_at(j, [J.Name{"name"}])

def order(n: U32) -> J.Json:
  J.JObj{[J.Field{"n", J.num_u32(n)}]}

def as_json(j: J.Json) -> Result<&2, &2, J.Access, J.Json>:
  Done{j}

def skip(bs: List<&2, U32>) -> IO(Bool):
  IO.pure(Bool, True{})

def round(+p: Pool.Pool) -> IO(Nat):
  do IO<Nat>:
    +a : Nat <- IO.bind(C.R(C.Reply), Nat, C.send(C.default(), C.get("http://127.0.0.1:8086/healthz")), r => IO.pure(Nat, ok(r)))
    +b : Nat <- IO.bind(C.R(C.Reply), Nat, Pool.send(p, C.get("http://127.0.0.1:7311/a")), r => IO.pure(Nat, ok(r)))
    +c : Nat <- IO.bind(C.R(C.Reply), Nat, Pool.send(p, C.get("http://127.0.0.1:7311/b")), r => IO.pure(Nat, ok(r)))
    +d : Nat <- IO.bind(C.R(C.Reply), Nat, Pool.send(p, C.get("http://127.0.0.1:7311/c")), r => IO.pure(Nat, ok(r)))
    +e : Nat <- IO.bind(C.R(C.Reply), Nat, Pool.send(p, C.get("https://localhost:7315/")), r => IO.pure(Nat, ok(r)))
    +f : Nat <- IO.bind(C.R(String), Nat, C.fetch_json(String, "http://127.0.0.1:7316/item", name), r => IO.pure(Nat, jok(r)))
    +g : Nat <- IO.bind(C.R(J.Json), Nat, Pool.send_json(J.Json, p, C.post("http://127.0.0.1:7316/echo", C.json(order(7))), as_json), r => IO.pure(Nat, pok(r)))
    +h : Nat <- IO.bind(C.R(C.Head), Nat, C.stream(~skip, C.default(), C.get("http://127.0.0.1:8086/big?n=2")), r => IO.pure(Nat, hok(r)))
    return Nat.add(a, Nat.add(b, Nat.add(c, Nat.add(d, Nat.add(e, Nat.add(f, Nat.add(g, h)))))))

def tick.go(at: Bool, +i: Nat) -> IO(Unit):
  match at:
    case True{}:
      IO.print("round " ++ Nat.show(i))
    case False{}:
      IO.pure(Unit, Unit{})

def tick(+i: Nat) -> IO(Unit):
  tick.go(Nat.is_eq(Nat.mod(i, 500n), 0n), i)

def rounds(n: Nat, +i: Nat, +p: Pool.Pool, +bad: Nat) -> IO(Nat):
  match n:
    case 0n:
      IO.pure(Nat, bad)
    case 1n+m:
      do IO<Nat>:
        +k : Nat <- round(p)
        x : Unit <- tick(i)
        rounds(m, Nat.add(i, 1n), p, Nat.add(bad, k))

def soaked(+p: Pool.Pool, n: Nat) -> IO(Unit):
  do IO<Unit>:
    +bad : Nat <- rounds(n, 1n, p, 0n)
    IO.print("done: " ++ Nat.show(bad) ++ " failed")

def count(a: List<String>) -> Nat:
  match a:
    case Con{s, _}:
      U32.to_nat(C.port.num.of(s))
    case Nil{}:
      1000n

def main() -> IO(Unit):
  do IO<Unit>:
    a : List<String> <- IO.args()
    Pool.with(Unit, C.default(), 4, p => soaked(p, count(a)))
