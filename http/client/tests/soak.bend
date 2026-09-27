import Base
import ../client.bend as C
import ../../../json/json.bend as J
import ../../core/method.bend as M
import ../../core/response.bend as Res
import ../../core/status.bend as S

# tests/soak.py's client: ROUNDS rounds, each a one-shot GET, three GETs
# through an http pool and one through an https pool, a get_json, a
# post_json and a streamed download; "round N" every 500 rounds, for the
# driver to sample memory and sockets at, and the failures at the end

def ok(r: C.R()) -> Nat:
  match r:
    case Done{Res.Response{S.Status{200}, _, _}}:
      0n
    case Done{Res.Response{S.Status{201}, _, _}}:
      0n
    case _:
      1n

def jok(r: C.JR(String)) -> Nat:
  match r:
    case Done{_}:
      0n
    case Fail{_}:
      1n

def pok(r: C.JR(J.Json)) -> Nat:
  match r:
    case Done{_}:
      0n
    case Fail{_}:
      1n

def name(j: J.Json) -> Result<&2, &2, J.Access, String>:
  J.string_at(j, [J.Name{"name"}])

def order(n: U32) -> J.Json:
  J.JObj{[J.Field{"n", J.num_u32(n)}]}

def skip(c: U32, bs: List<&2, U32>) -> IO(Bool):
  IO.pure(Bool, True{})

def round(+p: C.Pool, +t: C.Pool) -> IO(Nat):
  do IO<Nat>:
    +a : Nat <- IO.bind(C.R(), Nat, C.get("http://127.0.0.1:8086/healthz"), r => IO.pure(Nat, ok(r)))
    +b : Nat <- IO.bind(C.R(), Nat, C.pool.get(p, "/a"), r => IO.pure(Nat, ok(r)))
    +c : Nat <- IO.bind(C.R(), Nat, C.pool.get(p, "/b"), r => IO.pure(Nat, ok(r)))
    +d : Nat <- IO.bind(C.R(), Nat, C.pool.get(p, "/c"), r => IO.pure(Nat, ok(r)))
    +e : Nat <- IO.bind(C.R(), Nat, C.pool.get(t, "/"), r => IO.pure(Nat, ok(r)))
    +f : Nat <- IO.bind(C.JR(String), Nat, C.get_json(String, "http://127.0.0.1:7316/item", name), r => IO.pure(Nat, jok(r)))
    +g : Nat <- IO.bind(C.JR(J.Json), Nat, C.post_json(U32, "http://127.0.0.1:7316/echo", order, 7), r => IO.pure(Nat, pok(r)))
    +h : Nat <- IO.bind(C.R(), Nat, C.download(~skip, C.default(), "http://127.0.0.1:8086/big?n=2", []), r => IO.pure(Nat, ok(r)))
    return Nat.add(a, Nat.add(b, Nat.add(c, Nat.add(d, Nat.add(e, Nat.add(f, Nat.add(g, h)))))))

def tick.go(at: Bool, +i: Nat) -> IO(Unit):
  match at:
    case True{}:
      IO.print("round " ++ Nat.show(i))
    case False{}:
      IO.pure(Unit, Unit{})

def tick(+i: Nat) -> IO(Unit):
  tick.go(Nat.is_eq(Nat.mod(i, 500n), 0n), i)

def rounds(n: Nat, +i: Nat, +p: C.Pool, +t: C.Pool, +bad: Nat) -> IO(Nat):
  match n:
    case 0n:
      IO.pure(Nat, bad)
    case 1n+m:
      do IO<Nat>:
        +k : Nat <- round(p, t)
        x : Unit <- tick(i)
        rounds(m, Nat.add(i, 1n), p, t, Nat.add(bad, k))

def both(r: Result<&1, &1, C.Err, C.Pool>, s: Result<&1, &1, C.Err, C.Pool>, n: Nat) -> IO(Unit):
  match r s:
    case Done{+p} Done{+t}:
      do IO<Unit>:
        +bad : Nat <- rounds(n, 1n, p, t, 0n)
        x : Unit <- C.pool.close(p)
        y : Unit <- C.pool.close(t)
        IO.print("done: " ++ Nat.show(bad) ++ " failed")
    case _ _:
      IO.print("pool: bad url")

def count(a: List<String>) -> Nat:
  match a:
    case Con{s, _}:
      U32.to_nat(C.port.num.of(s))
    case Nil{}:
      1000n

def main() -> IO(Unit):
  do IO<Unit>:
    a : List<String> <- IO.args()
    r : Result<&1, &1, C.Err, C.Pool> <- C.pool(C.default(), "http://127.0.0.1:7311", 2)
    s : Result<&1, &1, C.Err, C.Pool> <- C.pool(C.default(), "https://localhost:7315", 2)
    both(r, s, count(a))
