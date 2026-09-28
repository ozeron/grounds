import Base
import ../client.bend as C
import ../pool.bend as Pool
import ../../../wire/wire.bend as W
import ../../../json/json.bend as J

# the pool, retries, redirects, JSON, streams and TLS, against tests/fake.py (7311
# on, TLS on 7315) and examples/stream (8086): one line per case, which
# check.sh compares with tests/more.out

def line.text(+code: U32, m: Maybe<&2, String>) -> String:
  match m:
    case Some{t}:
      U32.show(code) ++ " " ++ t
    case None{}:
      U32.show(code) ++ " (not UTF-8)"

def says(r: C.R(C.Reply)) -> String:
  match r:
    case Done{C.Reply{+c, hs, b}}:
      line.text(c, C.utf8(C.Reply{c, hs, b}))
    case Fail{e}:
      "error: " ++ C.show(e)

def one(name: String, act: IO(C.R(C.Reply))) -> IO(Unit):
  IO.bind(C.R(C.Reply), Unit, act, r => IO.print(name ++ ": " ++ says(r)))

def cfg() -> C.Config:
  C.with_timeout(C.default(), 3000)

def retrying() -> C.Config:
  C.with_retries(cfg(), 3, 50)

def secret() -> C.Kv():
  [("Authorization", "secret")]

def x() -> C.Body:
  C.bytes("text/plain", [120])

def hi() -> C.Body:
  C.bytes("text/plain", [104, 105])

# JSON
# ----

def name(j: J.Json) -> Result<&2, &2, J.Access, String>:
  J.string_at(j, [J.Name{"name"}])

def as_json(j: J.Json) -> Result<&2, &2, J.Access, J.Json>:
  Done{j}

def jsaid(r: C.R(String)) -> String:
  match r:
    case Done{s}:
      s
    case Fail{e}:
      "error: " ++ C.show(e)

def jechoed(r: C.R(J.Json)) -> String:
  match r:
    case Done{j}:
      J.encode(j)
    case Fail{e}:
      "error: " ++ C.show(e)

def order(n: U32) -> J.Json:
  J.JObj{[J.Field{"n", J.num_u32(n)}, J.Field{"item", J.JStr{"cup"}}]}

def jone(label: String, act: IO(C.R(String))) -> IO(Unit):
  IO.bind(C.R(String), Unit, act, r => IO.print(label ++ ": " ++ jsaid(r)))

# Streams
# -------

def count(bs: List<&2, U32>, +n: U32) -> U32:
  match bs:
    case Nil{}:
      n
    case Con{_, t}:
      count(t, (n + 1 : U32))

# counts the bytes on wire's process-wide counter: a callback has no state
# of its own
def tally(bs: List<&2, U32>) -> IO(Bool):
  IO.bind(U32, Bool, W.wire_live(count(bs, 0)), n => IO.pure(Bool, True{}))

def first(bs: List<&2, U32>) -> IO(Bool):
  IO.pure(Bool, False{})

def streamed(r: C.R(C.Head), +n: U32) -> String:
  match r:
    case Done{C.Head{+c, _}}:
      U32.show(c) ++ ", " ++ U32.show(n) ++ " bytes streamed"
    case Fail{e}:
      "error: " ++ C.show(e)

# Pools
# -----

def kept(+p: Pool.Pool) -> IO(Unit):
  do IO<Unit>:
    a : Unit <- one("pool 1", Pool.send(p, C.get("http://127.0.0.1:7311/a")))
    b : Unit <- one("pool 2", Pool.send(p, C.get("http://127.0.0.1:7311/b")))
    one("pool 3", Pool.send(p, C.get("http://127.0.0.1:7311/c")))

def idle(+p: Pool.Pool) -> IO(Unit):
  do IO<Unit>:
    a : Unit <- one("idle before", Pool.send(p, C.get("http://127.0.0.1:7311/a")))
    x : Unit <- IO.sleep(300)
    one("idle after 300 ms", Pool.send(p, C.get("http://127.0.0.1:7311/b")))

def stale(+p: Pool.Pool) -> IO(Unit):
  do IO<Unit>:
    a : Unit <- one("stale first", Pool.send(p, C.get("http://127.0.0.1:7312/a")))
    b : Unit <- one("stale GET retried", Pool.send(p, C.get("http://127.0.0.1:7312/b")))
    z : Unit <- IO.sleep(300)
    one("stale POST not retried", Pool.send(p, C.post("http://127.0.0.1:7312/c", x())))

def origins(+p: Pool.Pool) -> IO(Unit):
  do IO<Unit>:
    a : Unit <- one("two origins, first", Pool.send(p, C.get("http://127.0.0.1:7311/a")))
    b : Unit <- jone("two origins, second", Pool.send_json(String, p, C.get("http://127.0.0.1:7316/item"), name))
    one("two origins, first again", Pool.send(p, C.get("http://127.0.0.1:7311/b")))

def evict(+p: Pool.Pool) -> IO(Unit):
  do IO<Unit>:
    a : Unit <- one("pool of 1, first", Pool.send(p, C.get("http://127.0.0.1:7311/a")))
    b : Unit <- jone("pool of 1, another origin", Pool.send_json(String, p, C.get("http://127.0.0.1:7316/item"), name))
    one("pool of 1, first again", Pool.send(p, C.get("http://127.0.0.1:7311/b")))

def pstream(+p: Pool.Pool) -> IO(Unit):
  do IO<Unit>:
    ac : U32 <- W.wire_live(0)
    ad : C.R(C.Head) <- Pool.stream(~tally, p, C.get("http://127.0.0.1:8086/big?n=2"))
    +ae : U32 <- W.wire_live(0)
    x : Unit <- IO.print("pool stream: " ++ streamed(ad, (ae - ac : U32)))
    one("pool, after a stream", Pool.send(p, C.get("http://127.0.0.1:8086/healthz")))

def ok(r: C.R(C.Reply)) -> Nat:
  match r:
    case Done{C.Reply{200, _, _}}:
      1n
    case _:
      0n

def task(n: Nat, +p: Pool.Pool, +got: Nat) -> IO(Nat):
  match n:
    case 0n:
      IO.pure(Nat, got)
    case 1n+m:
      IO.bind(C.R(C.Reply), Nat, Pool.send(p, C.get("http://127.0.0.1:7311/t")), r => task(m, p, Nat.add(got, ok(r))))

def forks(n: Nat, +p: Pool.Pool, acc: List<&2, Chan(Nat)>) -> IO(List<&2, Chan(Nat)>):
  match n:
    case 0n:
      IO.pure(List<&2, Chan(Nat)>, acc)
    case 1n+m:
      IO.bind(Chan(Nat), List<&2, Chan(Nat)>, IO.fork(Nat, task(5n, p, 0n)), c => forks(m, p, Con{c, acc}))

def joins(cs: List<&2, Chan(Nat)>, +got: Nat) -> IO(Nat):
  match cs:
    case Nil{}:
      IO.pure(Nat, got)
    case Con{+c, t}:
      IO.bind(Nat, Nat, IO.join(Nat, c), n => joins(t, Nat.add(got, n)))

def busy(+p: Pool.Pool) -> IO(Unit):
  do IO<Unit>:
    cs : List<&2, Chan(Nat)> <- forks(8n, p, [])
    +n : Nat <- joins(cs, 0n)
    IO.print("pool of 2 under 8 tasks: " ++ Nat.show(n) ++ " of 40 answered 200")

def tkept(+p: Pool.Pool) -> IO(Unit):
  do IO<Unit>:
    a : Unit <- one("pool 1", Pool.send(p, C.get("https://localhost:7315/a")))
    b : Unit <- one("pool 2", Pool.send(p, C.get("https://localhost:7315/b")))
    one("pool 3", Pool.send(p, C.get("https://localhost:7315/c")))

def main() -> IO(Unit):
  do IO<Unit>:
    pa : Unit <- Pool.with(Unit, cfg(), 1, p => kept(p))
    pb : Unit <- Pool.with(Unit, C.with_idle(cfg(), 100), 1, p => idle(p))
    pc : Unit <- Pool.with(Unit, cfg(), 1, p => stale(p))
    pd : Unit <- Pool.with(Unit, cfg(), 2, p => busy(p))
    pe : Unit <- Pool.with(Unit, cfg(), 2, p => origins(p))
    pf : Unit <- Pool.with(Unit, cfg(), 1, p => evict(p))
    pg : Unit <- Pool.with(Unit, cfg(), 1, p => pstream(p))
    e : Unit <- one("retry GET on 503", C.send(retrying(), C.get("http://127.0.0.1:7313/2/a")))
    f : Unit <- one("no retry for POST", C.send(retrying(), C.post("http://127.0.0.1:7313/2/b", C.empty())))
    fa : Unit <- one("retry an idempotent POST", C.send(retrying(), C.idempotent(C.post("http://127.0.0.1:7313/2/e", C.empty()), "k1")))
    g : Unit <- one("retries run out", C.send(retrying(), C.get("http://127.0.0.1:7313/9/c")))
    h : Unit <- one("off by default", C.send(cfg(), C.get("http://127.0.0.1:7313/1/d")))
    ha : Unit <- one("send_ok on a 503", C.send_ok(cfg(), C.get("http://127.0.0.1:7313/1/f")))
    i : Unit <- one("301", C.send(cfg(), C.with(C.get("http://127.0.0.1:7314/r/301"), secret())))
    j : Unit <- one("302 POST", C.send(cfg(), C.post("http://127.0.0.1:7314/r/302", x())))
    k : Unit <- one("303 POST", C.send(cfg(), C.post("http://127.0.0.1:7314/r/303", x())))
    l : Unit <- one("307 POST", C.send(cfg(), C.post("http://127.0.0.1:7314/r/307", hi())))
    m : Unit <- one("308 PUT", C.send(cfg(), C.put("http://127.0.0.1:7314/r/308", hi())))
    n : Unit <- one("to another url", C.send(cfg(), C.with(C.get("http://127.0.0.1:7314/abs"), secret())))
    o : Unit <- one("redirect loop", C.send(cfg(), C.get("http://127.0.0.1:7314/loop")))
    q : Unit <- one("not followed with 0", C.send(C.with_redirects(cfg(), 0), C.get("http://127.0.0.1:7314/r/301")))
    r : Unit <- one("http to https followed", C.send(cfg(), C.get("http://127.0.0.1:7314/tls")))
    rr : Unit <- one("never from https to http", C.send(cfg(), C.get("https://localhost:7315/down")))
    s : Unit <- jone("send_json", C.fetch_json(String, "http://127.0.0.1:7316/item", name))
    u : Unit <- jone("send_json, not JSON", C.fetch_json(String, "http://127.0.0.1:7316/bad", name))
    w : Unit <- jone("send_json, 404", C.fetch_json(String, "http://127.0.0.1:7316/missing", name))
    aa : String <- IO.bind(C.R(J.Json), String, C.send_json(J.Json, cfg(), C.post("http://127.0.0.1:7316/echo", C.json(order(3))), as_json), y => IO.pure(String, jechoed(y)))
    ab : Unit <- IO.print("send_json POST: " ++ aa)
    ac : U32 <- W.wire_live(0)
    ad : C.R(C.Head) <- C.stream(~tally, cfg(), C.get("http://127.0.0.1:8086/big?n=160"))
    +ae : U32 <- W.wire_live(0)
    af : Unit <- IO.print("stream 10 MiB, past max_body: " ++ streamed(ad, (ae - ac : U32)))
    ag : C.R(C.Head) <- C.stream(~first, cfg(), C.get("http://127.0.0.1:8086/big?n=160"))
    ah : Unit <- IO.print("stream, stopped at once: " ++ streamed(ag, 0))
    ai : C.R(C.Head) <- C.stream(~tally, cfg(), C.get("http://127.0.0.1:7314/missing"))
    aj : Unit <- IO.print("stream of a 404: " ++ streamed(ai, 0))
    ak : Unit <- one("https", C.send(cfg(), C.get("https://localhost:7315/")))
    Pool.with(Unit, cfg(), 1, p => tkept(p))
