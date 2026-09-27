import Base
import ../redis.bend as Redis
import ../resp.bend as R

# against a real Redis on 127.0.0.1:6379: binary and 5 MB values, a
# 1000-command pipeline, SELECT, RESP3, the reply cap, and a pool under 40
# concurrent tasks (tests/auth.bend covers AUTH)

def same(a: String, b: String) -> Bool:
  match a b:
    case SNil{} SNil{}:
      True{}
    case SCon{x, at} SCon{y, bt}:
      Bool.and(Char.is_eq(x, y), same(at, bt))
    case _ _:
      False{}

def verdict(ok: Bool, name: String, got: String, k: Unit -> IO(Unit)) -> IO(Unit):
  match ok:
    case True{}:
      IO.bind(Unit, Unit, IO.print("ok " ++ name ++ ": " ++ got), k)
    case False{}:
      IO.die(Unit, 1, "FAIL " ++ name ++ ": " ++ got)

def plain() -> Redis.Config:
  Redis.config("127.0.0.1", 6379)

def authed() -> Redis.Config:
  Redis.config("127.0.0.1", 6380)

def down(+name: String, d: Redis.Down) -> IO(Unit):
  IO.die(Unit, 1, "FAIL " ++ name ++ ": " ++ Redis.down.show(d))

def opened(+name: String, r: Result<&1, &1, Redis.Down, Redis.Client()>, k: Redis.Client() -> IO(Unit)) -> IO(Unit):
  match r:
    case Done{c}:
      k(c)
    case Fail{d}:
      down(name, d)

# open cfg, go on with the client
def opening(+name: String, cfg: Redis.Config, k: Redis.Client() -> IO(Unit)) -> IO(Unit):
  IO.bind(Result<&1, &1, Redis.Down, Redis.Client()>, Unit, Redis.open(cfg), r => opened(name, r, k))

def shown(+name: String, +want: String, +got: String, c: Redis.Client(), k: Redis.Client() -> IO(Unit)) -> IO(Unit):
  verdict(same(got, want), name, got, u => k(c))

def asked(+name: String, +want: String, g: Redis.Got(R.Reply), k: Redis.Client() -> IO(Unit)) -> IO(Unit):
  match g:
    case Done{(c, r)}:
      shown(name, want, R.show(r), c, k)
    case Fail{d}:
      down(name, d)

# a command whose reply must print as want
def ask(+name: String, c: Redis.Client(), args: List<&2, String>, +want: String, k: Redis.Client() -> IO(Unit)) -> IO(Unit):
  IO.bind(Redis.Got(R.Reply), Unit, Redis.command(c, args), g => asked(name, want, g, k))

def closing(k: Unit -> IO(Unit), c: Redis.Client()) -> IO(Unit):
  IO.bind(Unit, Unit, Redis.close(c), k)

# Bytes
# -----

def upto(n: Nat, +i: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      List.reverse(&2, U32, acc)
    case 1n+m:
      upto(m, (i + 1 : U32), Con{i, acc})

# every byte value, then CR LF and a command inside the value
def binary() -> List<&2, U32>:
  List.append(&2, U32, upto(256n, 0, []), [13, 10, 42, 49, 13, 10, 36, 52, 13, 10, 80, 73, 78, 71, 13, 10])

def bytes_eq(a: List<&2, U32>, b: List<&2, U32>) -> Bool:
  match a b:
    case Nil{} Nil{}:
      True{}
    case Con{+x, at} Con{+y, bt}:
      Bool.and(U32.is_eq(x, y), bytes_eq(at, bt))
    case _ _:
      False{}

def cycle(n: Nat, +i: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+m:
      cycle(m, ((i + 7 : U32) % 251 : U32), Con{i, acc})

def big() -> List<&2, U32>:
  cycle(5000000n, 0, [])

def got_bytes.cmp(+name: String, ok: Bool, c: Redis.Client(), k: Redis.Client() -> IO(Unit)) -> IO(Unit):
  verdict(ok, name, "same bytes back", u => k(c))

def got_bytes(+name: String, want: List<&2, U32>, g: Redis.Got(Redis.Res(Maybe<&2, List<&2, U32>>)), k: Redis.Client() -> IO(Unit)) -> IO(Unit):
  match g:
    case Done{(c, Done{Some{bs}})}:
      got_bytes.cmp(name, bytes_eq(want, bs), c, k)
    case Done{(c, r)}:
      IO.bind(Unit, Unit, Redis.close(c), x => IO.die(Unit, 1, "FAIL " ++ name ++ ": not the bytes"))
    case Fail{d}:
      down(name, d)

def set_ok(+name: String, g: Redis.Got(Redis.Res(Unit)), k: Redis.Client() -> IO(Unit)) -> IO(Unit):
  match g:
    case Done{(c, Done{_})}:
      k(c)
    case Done{(c, Fail{e})}:
      IO.bind(Unit, Unit, Redis.close(c), x => IO.die(Unit, 1, "FAIL " ++ name ++ ": " ++ e))
    case Fail{d}:
      down(name, d)

# a value set as bytes and read back
def roundtrip(+name: String, c: Redis.Client(), +key: List<&2, U32>, +value: List<&2, U32>, k: Redis.Client() -> IO(Unit)) -> IO(Unit):
  IO.bind(Redis.Got(Redis.Res(Unit)), Unit, Redis.set_bytes(c, key, value), g => set_ok(name, g, c2 =>
  IO.bind(Redis.Got(Redis.Res(Maybe<&2, List<&2, U32>>)), Unit, Redis.get_bytes(c2, key), g2 => got_bytes(name, value, g2, k))))

# Pipeline
# --------

def incrs(n: Nat, acc: List<&2, List<&2, String>>) -> List<&2, List<&2, String>>:
  match n:
    case 0n:
      acc
    case 1n+m:
      incrs(m, Con{["INCR", "grounds:pipe"], acc})

def last(xs: List<&2, R.Reply>, +n: Nat, l: String) -> String:
  match xs:
    case Nil{}:
      Nat.show(n) ++ " replies, the last " ++ l
    case Con{x, t}:
      last(t, 1n+n, R.show(x))

def piped(+name: String, +want: String, g: Redis.Got(List<&2, R.Reply>), k: Redis.Client() -> IO(Unit)) -> IO(Unit):
  match g:
    case Done{(c, xs)}:
      shown(name, want, last(xs, 0n, ""), c, k)
    case Fail{d}:
      down(name, d)

# The cap
# -------

def capped(+name: String, g: Redis.Got(R.Reply), k: Unit -> IO(Unit)) -> IO(Unit):
  match g:
    case Done{(c, r)}:
      IO.bind(Unit, Unit, Redis.close(c), x => IO.die(Unit, 1, "FAIL " ++ name ++ ": a reply"))
    case Fail{Redis.TooLarge{}}:
      verdict(True{}, name, "too large, closed", k)
    case Fail{d}:
      down(name, d)

# Load
# ----

def RZ() -> Type:
  Result<&1, &1, Redis.Down, Redis.Res(Redis.Z)>

def counted(r: RZ(), +bad: Nat) -> Nat:
  match r:
    case Done{Done{_}}:
      bad
    case _:
      1n+bad

# n INCRs, one at a time through the pool; how many failed
def task(n: Nat, +p: Redis.Pool, +bad: Nat) -> IO(Nat):
  match n:
    case 0n:
      IO.pure(Nat, bad)
    case 1n+m:
      IO.bind(RZ(), Nat, Redis.with(Redis.Res(Redis.Z), p, c => Redis.incr(c, "grounds:load")), r => task(m, p, counted(r, bad)))

def forks(n: Nat, +p: Redis.Pool, acc: List<&2, Chan(Nat)>) -> IO(List<&2, Chan(Nat)>):
  match n:
    case 0n:
      IO.pure(List<&2, Chan(Nat)>, acc)
    case 1n+m:
      IO.bind(Chan(Nat), List<&2, Chan(Nat)>, IO.fork(Nat, task(250n, p, 0n)), ch => forks(m, p, Con{ch, acc}))

def joins(xs: List<&2, Chan(Nat)>, +bad: Nat) -> IO(Nat):
  match xs:
    case Nil{}:
      IO.pure(Nat, bad)
    case Con{+ch, t}:
      IO.bind(Nat, Nat, IO.join(Nat, ch), b => joins(t, Nat.add(bad, b)))

def loaded(+bad: Nat, +ms: Nat, k: Unit -> IO(Unit)) -> IO(Unit):
  verdict(Nat.is_eq(bad, 0n), "40 tasks x 250 INCR through a pool of 8", Nat.show(bad) ++ " failed, " ++ Nat.show(Nat.div(Nat.mul(10000n, 1000n), Nat.add(ms, 1n))) ++ " ops/s", k)

def load(k: Unit -> IO(Unit)) -> IO(Unit):
  do IO<Unit>:
    +p : Redis.Pool <- Redis.pool(plain(), 8)
    +t0 : Nat <- IO.now()
    chs : List<&2, Chan(Nat)> <- forks(40n, p, [])
    +bad : Nat <- joins(chs, 0n)
    +t1 : Nat <- IO.now()
    x : Unit <- Redis.pool.close(p, 8)
    loaded(bad, Nat.sub(t1, t0), k)

# Steps
# -----

def s_done(u: Unit) -> IO(Unit):
  IO.print("live: all ok")

def s_load(u: Unit) -> IO(Unit):
  opening("load", plain(), c => ask("reset the counter", c, ["SET", "grounds:load", "0"], "OK", c2 => closing(v => load(w => opening("load", plain(), c3 => ask("the counter after the load", c3, ["GET", "grounds:load"], "\"10000\"", c4 => closing(s_done, c4)))), c2)))

def s_cap(u: Unit) -> IO(Unit):
  opening("cap", Redis.with_max_reply(plain(), 1000), c =>
  IO.bind(Redis.Got(R.Reply), Unit, Redis.command(c, ["GET", "grounds:big"]), g => capped("a 5 MB value past a 1000-byte cap", g, s_load)))

def s_resp3(u: Unit) -> IO(Unit):
  opening("resp3", Redis.with_resp3(plain()), c =>
  ask("HSET", c, ["HSET", "grounds:h", "a", "1", "b", "2"], "2", c2 =>
  ask("HGETALL as a RESP3 map", c2, ["HGETALL", "grounds:h"], "[\"a\", \"1\", \"b\", \"2\"]", c3 =>
  ask("DEL", c3, ["DEL", "grounds:h"], "1", c4 => closing(s_cap, c4)))))

def s_select(u: Unit) -> IO(Unit):
  opening("select 1", Redis.with_db(plain(), 1), c =>
  ask("SET in db 1", c, ["SET", "grounds:db", "one"], "OK", c2 => closing(v =>
  opening("select 0", plain(), c3 =>
  ask("not in db 0", c3, ["GET", "grounds:db"], "(nil)", c4 => closing(w =>
  opening("select 1 again", Redis.with_db(plain(), 1), c5 =>
  ask("in db 1", c5, ["GETDEL", "grounds:db"], "\"one\"", c6 => closing(s_resp3, c6))), c4))), c2)))

def s_error(c: Redis.Client()) -> IO(Unit):
  ask("SET a string", c, ["SET", "grounds:s", "x"], "OK", c2 =>
  ask("INCR it: an error reply", c2, ["INCR", "grounds:s"], "(error) ERR value is not an integer or out of range", c3 =>
  ask("the client still answers", c3, ["PING"], "PONG", c4 => closing(s_select, c4))))

def s_pipe(c: Redis.Client()) -> IO(Unit):
  ask("reset", c, ["SET", "grounds:pipe", "0"], "OK", c2 =>
  IO.bind(Redis.Got(List<&2, R.Reply>), Unit, Redis.pipeline(c2, incrs(1000n, [])), g => piped("1000 INCR in one pipeline", "1000 replies, the last 1000", g, s_error)))

def s_big(c: Redis.Client()) -> IO(Unit):
  roundtrip("a 5 MB value", c, [103, 114, 111, 117, 110, 100, 115, 58, 98, 105, 103], big(), s_pipe)

def main() -> IO(Unit):
  opening("open", plain(), c => roundtrip("every byte value, CR LF and a command inside", c, [103, 114, 111, 117, 110, 100, 115, 58, 98, 105, 110], binary(), s_big))
