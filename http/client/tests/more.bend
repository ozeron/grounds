import Base
import ../client.bend as C
import ../../../wire/wire.bend as W
import ../../../json/json.bend as J
import ../../core/method.bend as M
import ../../core/headers.bend as H
import ../../core/response.bend as Res
import ../../core/status.bend as S

# the pool, retries, redirects, JSON, downloads and TLS, against
# tests/fake.py (7311 on, TLS on 7315) and examples/stream (8086): one line
# per case, which check.sh compares with tests/more.out

def count(bs: List<&2, U32>, +n: U32) -> U32:
  match bs:
    case Nil{}:
      n
    case Con{_, t}:
      count(t, (n + 1 : U32))

def line.text(+code: U32, m: Maybe<&2, String>) -> String:
  match m:
    case Some{t}:
      U32.show(code) ++ " " ++ t
    case None{}:
      U32.show(code) ++ " (not UTF-8)"

def says(r: C.R()) -> String:
  match r:
    case Done{Res.Response{S.Status{+c}, hs, b}}:
      line.text(c, C.text(Res.Response{S.Status{c}, hs, b}))
    case Fail{e}:
      "error: " ++ C.show(e)

def one(name: String, act: IO(C.R())) -> IO(Unit):
  IO.bind(C.R(), Unit, act, r => IO.print(name ++ ": " ++ says(r)))

def cfg() -> C.Config:
  C.with_timeout(C.default(), 3000)

# Pools
# -----

def pooled(name: String, p: IO(C.R())) -> IO(Unit):
  one(name, p)

def kept(+p: C.Pool) -> IO(Unit):
  do IO<Unit>:
    a : Unit <- pooled("pool 1", C.pool.get(p, "/a"))
    b : Unit <- pooled("pool 2", C.pool.get(p, "/b"))
    pooled("pool 3", C.pool.get(p, "/c"))

def idle(+p: C.Pool) -> IO(Unit):
  do IO<Unit>:
    a : Unit <- pooled("idle before", C.pool.get(p, "/a"))
    x : Unit <- IO.sleep(300)
    pooled("idle after 300 ms", C.pool.get(p, "/b"))

def stale(+p: C.Pool) -> IO(Unit):
  do IO<Unit>:
    a : Unit <- pooled("stale first", C.pool.get(p, "/a"))
    b : Unit <- pooled("stale GET retried", C.pool.get(p, "/b"))
    x : Unit <- IO.sleep(300)
    pooled("stale POST not retried", C.send(p, M.MPost{}, "/c", [], [120]))

def ok(r: C.R()) -> Nat:
  match r:
    case Done{Res.Response{S.Status{200}, _, _}}:
      1n
    case _:
      0n

def task(n: Nat, +p: C.Pool, +got: Nat) -> IO(Nat):
  match n:
    case 0n:
      IO.pure(Nat, got)
    case 1n+m:
      IO.bind(C.R(), Nat, C.pool.get(p, "/t"), r => task(m, p, Nat.add(got, ok(r))))

def forks(n: Nat, +p: C.Pool, acc: List<&2, Chan(Nat)>) -> IO(List<&2, Chan(Nat)>):
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

def busy(+p: C.Pool) -> IO(Unit):
  do IO<Unit>:
    cs : List<&2, Chan(Nat)> <- forks(8n, p, [])
    +n : Nat <- joins(cs, 0n)
    IO.print("pool of 2 under 8 tasks: " ++ Nat.show(n) ++ " of 40 answered 200")

def made(r: Result<&1, &1, C.Err, C.Pool>, k: C.Pool -> IO(Unit)) -> IO(Unit):
  match r:
    case Done{+p}:
      do IO<Unit>:
        x : Unit <- k(p)
        C.pool.close(p)
    case Fail{e}:
      IO.print("pool: " ++ C.show(e))

def with_pool(c: C.Config, base: String, +n: U32, k: C.Pool -> IO(Unit)) -> IO(Unit):
  IO.bind(Result<&1, &1, C.Err, C.Pool>, Unit, C.pool(c, base, n), r => made(r, k))

# Retries and redirects
# ---------------------

def retrying() -> C.Config:
  C.with_retries(cfg(), 3, 50)

def req(c: C.Config, m: M.Method, u: String, hs: List<&2, H.Header>, b: List<&2, U32>) -> IO(C.R()):
  C.request(c, m, u, hs, b)

def secret() -> List<&2, H.Header>:
  [H.Header{"Authorization", "secret"}]

# JSON
# ----

def name(j: J.Json) -> Result<&2, &2, J.Access, String>:
  J.string_at(j, [J.Name{"name"}])

def jsaid(r: C.JR(String)) -> String:
  match r:
    case Done{s}:
      s
    case Fail{e}:
      "error: " ++ C.jshow(e)

def jechoed(r: C.JR(J.Json)) -> String:
  match r:
    case Done{j}:
      J.encode(j)
    case Fail{e}:
      "error: " ++ C.jshow(e)

def order(n: U32) -> J.Json:
  J.JObj{[J.Field{"n", J.num_u32(n)}, J.Field{"item", J.JStr{"cup"}}]}

# Downloads
# ---------

# counts the bytes on wire's process-wide counter: a callback has no state
# of its own
def tally(c: U32, bs: List<&2, U32>) -> IO(Bool):
  IO.bind(U32, Bool, W.wire_live(count(bs, 0)), n => IO.pure(Bool, True{}))

def first(c: U32, bs: List<&2, U32>) -> IO(Bool):
  IO.pure(Bool, False{})

def streamed(r: C.R(), +n: U32) -> String:
  match r:
    case Done{Res.Response{S.Status{+c}, _, _}}:
      U32.show(c) ++ ", " ++ U32.show(n) ++ " bytes streamed"
    case Fail{e}:
      "error: " ++ C.show(e)

def main() -> IO(Unit):
  do IO<Unit>:
    a : Unit <- with_pool(cfg(), "http://127.0.0.1:7311", 1, p => kept(p))
    b : Unit <- with_pool(C.with_idle(cfg(), 100), "http://127.0.0.1:7311", 1, p => idle(p))
    c : Unit <- with_pool(cfg(), "http://127.0.0.1:7312", 1, p => stale(p))
    d : Unit <- with_pool(cfg(), "http://127.0.0.1:7311", 2, p => busy(p))
    e : Unit <- one("retry GET on 503", req(retrying(), M.MGet{}, "http://127.0.0.1:7313/2/a", [], []))
    f : Unit <- one("no retry for POST", req(retrying(), M.MPost{}, "http://127.0.0.1:7313/2/b", [], []))
    g : Unit <- one("retries run out", req(retrying(), M.MGet{}, "http://127.0.0.1:7313/9/c", [], []))
    h : Unit <- one("off by default", req(cfg(), M.MGet{}, "http://127.0.0.1:7313/1/d", [], []))
    i : Unit <- one("301", req(cfg(), M.MGet{}, "http://127.0.0.1:7314/r/301", secret(), []))
    j : Unit <- one("302 POST", req(cfg(), M.MPost{}, "http://127.0.0.1:7314/r/302", [], [120]))
    k : Unit <- one("303 POST", req(cfg(), M.MPost{}, "http://127.0.0.1:7314/r/303", [], [120]))
    l : Unit <- one("307 POST", req(cfg(), M.MPost{}, "http://127.0.0.1:7314/r/307", [], [104, 105]))
    m : Unit <- one("308 PUT", req(cfg(), M.MPut{}, "http://127.0.0.1:7314/r/308", [], [104, 105]))
    n : Unit <- one("to another url", req(cfg(), M.MGet{}, "http://127.0.0.1:7314/abs", secret(), []))
    o : Unit <- one("redirect loop", req(cfg(), M.MGet{}, "http://127.0.0.1:7314/loop", [], []))
    q : Unit <- one("not followed with 0", req(C.with_redirects(cfg(), 0), M.MGet{}, "http://127.0.0.1:7314/r/301", [], []))
    r : Unit <- one("never from http to https", req(cfg(), M.MGet{}, "http://127.0.0.1:7314/tls", [], []))
    s : String <- IO.bind(C.JR(String), String, C.get_json(String, "http://127.0.0.1:7316/item", name), x => IO.pure(String, jsaid(x)))
    t : Unit <- IO.print("get_json: " ++ s)
    u : String <- IO.bind(C.JR(String), String, C.get_json(String, "http://127.0.0.1:7316/bad", name), x => IO.pure(String, jsaid(x)))
    v : Unit <- IO.print("get_json, not JSON: " ++ u)
    w : String <- IO.bind(C.JR(String), String, C.get_json(String, "http://127.0.0.1:7316/missing", name), x => IO.pure(String, jsaid(x)))
    y : Unit <- IO.print("get_json, 404: " ++ w)
    aa : String <- IO.bind(C.JR(J.Json), String, C.post_json(U32, "http://127.0.0.1:7316/echo", order, 3), x => IO.pure(String, jechoed(x)))
    ab : Unit <- IO.print("post_json: " ++ aa)
    ac : U32 <- W.wire_live(0)
    ad : C.R() <- C.download(~tally, cfg(), "http://127.0.0.1:8086/big?n=160", [])
    +ae : U32 <- W.wire_live(0)
    af : Unit <- IO.print("download 10 MiB, past max_body: " ++ streamed(ad, (ae - ac : U32)))
    ag : C.R() <- C.download(~first, cfg(), "http://127.0.0.1:8086/big?n=160", [])
    ah : Unit <- IO.print("download, stopped at once: " ++ streamed(ag, 0))
    ai : Unit <- one("https", C.get("https://localhost:7315/"))
    with_pool(cfg(), "https://localhost:7315", 1, p => kept(p))
