import Base
import ../redis.bend as Redis
import ../resp.bend as R

# against tests/fake.py: every fault ends in its Down, promptly; replies
# that come split, after a push, or two in one read, come out right

def same(a: String, b: String) -> Bool:
  match a b:
    case SNil{} SNil{}:
      True{}
    case SCon{x, at} SCon{y, bt}:
      Bool.and(Char.is_eq(x, y), same(at, bt))
    case _ _:
      False{}

def kind(d: Redis.Down) -> String:
  match d:
    case Redis.Timeout{}:
      "timeout"
    case Redis.Closed{}:
      "closed"
    case Redis.TooLarge{}:
      "too large"
    case Redis.Protocol{_}:
      "protocol"
    case Redis.Io{_}:
      "io"
    case Redis.Rejected{_}:
      "rejected"

# 500 ms per reply, replies up to 1 MiB
def cfg(port: U32) -> Redis.Config:
  Redis.with_max_reply(Redis.with_timeout(Redis.config("127.0.0.1", port), 500), 1048576)

def verdict(ok: Bool, name: String, got: String, k: Unit -> IO(Unit)) -> IO(Unit):
  match ok:
    case True{}:
      IO.bind(Unit, Unit, IO.print("ok " ++ name ++ ": " ++ got), k)
    case False{}:
      IO.die(Unit, 1, "FAIL " ++ name ++ ": " ++ got)

def downed(name: String, +want: String, +t0: Nat, +limit: Nat, +now: Nat, +d: Redis.Down, k: Unit -> IO(Unit)) -> IO(Unit):
  verdict(Bool.and(same(kind(d), want), Nat.is_le(Nat.sub(now, t0), limit)), name, kind(d) ++ " after " ++ Nat.show(Nat.sub(now, t0)) ++ " ms", k)

def down.got(name: String, +want: String, +t0: Nat, +limit: Nat, g: Redis.Got(R.Reply), k: Unit -> IO(Unit)) -> IO(Unit):
  match g:
    case Done{(c, r)}:
      IO.bind(Unit, Unit, Redis.close(c), x => verdict(False{}, name, "a reply: " ++ R.show(r), k))
    case Fail{d}:
      IO.bind(Nat, Unit, IO.now(), now => downed(name, want, t0, limit, now, d, k))

def down.opened(name: String, +want: String, +t0: Nat, +limit: Nat, r: Result<&1, &1, Redis.Down, Redis.Client()>, act: Redis.Client() -> IO(Redis.Got(R.Reply)), k: Unit -> IO(Unit)) -> IO(Unit):
  match r:
    case Done{c}:
      IO.bind(Redis.Got(R.Reply), Unit, act(c), g => down.got(name, want, t0, limit, g, k))
    case Fail{d}:
      verdict(False{}, name, "open: " ++ Redis.down.show(d), k)

# act on a fresh client to port: it must end in want within limit ms
def expect_down.cfg(name: String, c: Redis.Config, +want: String, +limit: Nat, act: Redis.Client() -> IO(Redis.Got(R.Reply)), k: Unit -> IO(Unit)) -> IO(Unit):
  do IO<Unit>:
    +t0 : Nat <- IO.now()
    r : Result<&1, &1, Redis.Down, Redis.Client()> <- Redis.open(c)
    down.opened(name, want, t0, limit, r, act, k)

def expect_down(name: String, +port: U32, +want: String, +limit: Nat, act: Redis.Client() -> IO(Redis.Got(R.Reply)), k: Unit -> IO(Unit)) -> IO(Unit):
  expect_down.cfg(name, cfg(port), want, limit, act, k)

def ping(c: Redis.Client()) -> IO(Redis.Got(R.Reply)):
  Redis.command(c, ["PING"])

def big(n: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+m:
      big(m, Con{120, acc})

# 4 MB fills the local socket while keeping list construction below the
# 3-second assertion, whose clock starts before the command is built.
def flood_send(c: Redis.Client()) -> IO(Redis.Got(R.Reply)):
  Redis.command_bytes(c, [[83, 69, 84], [107], big(4000000n, [])])

def replied.shown(name: String, +want: String, +got: String, c: Redis.Client(), k: Redis.Client() -> IO(Unit)) -> IO(Unit):
  verdict(same(got, want), name, got, u => k(c))

def replied(name: String, +want: String, g: Redis.Got(R.Reply), k: Redis.Client() -> IO(Unit)) -> IO(Unit):
  match g:
    case Done{(c, r)}:
      replied.shown(name, want, R.show(r), c, k)
    case Fail{d}:
      verdict(False{}, name, Redis.down.show(d), u => IO.pure(Unit, Unit{}))

def reply.opened(name: String, +want: String, r: Result<&1, &1, Redis.Down, Redis.Client()>, k: Redis.Client() -> IO(Unit)) -> IO(Unit):
  match r:
    case Done{c}:
      IO.bind(Redis.Got(R.Reply), Unit, ping(c), g => replied(name, want, g, k))
    case Fail{d}:
      verdict(False{}, name, "open: " ++ Redis.down.show(d), u => IO.pure(Unit, Unit{}))

# a fresh client to port answers PING with want, then goes on with k
def expect_reply(name: String, +port: U32, +want: String, k: Redis.Client() -> IO(Unit)) -> IO(Unit):
  IO.bind(Result<&1, &1, Redis.Down, Redis.Client()>, Unit, Redis.open(cfg(port)), r => reply.opened(name, want, r, k))

def then(name: String, +want: String, k: Unit -> IO(Unit), c: Redis.Client()) -> IO(Unit):
  IO.bind(Redis.Got(R.Reply), Unit, ping(c), g => replied(name, want, g, c2 => IO.bind(Unit, Unit, Redis.close(c2), k)))

def closing(k: Unit -> IO(Unit), c: Redis.Client()) -> IO(Unit):
  IO.bind(Unit, Unit, Redis.close(c), k)

def pooled(+ok: Nat, r: Result<&1, &1, Redis.Down, R.Reply>, k: Nat -> IO(Unit)) -> IO(Unit):
  match r:
    case Done{_}:
      k(1n+ok)
    case Fail{_}:
      k(ok)

# n PINGs through a pool whose server closes after each reply, one retry each
def pings(n: Nat, +p: Redis.Pool, +ok: Nat, k: Nat -> IO(Unit)) -> IO(Unit):
  match n:
    case 0n:
      k(ok)
    case 1n+m:
      IO.bind(Result<&1, &1, Redis.Down, R.Reply>, Unit, Redis.run(1n, p, ["PING"]), r => pooled(ok, r, o => pings(m, p, o, k)))

def repeat(n: Nat, +c: Char, acc: String) -> String:
  match n:
    case 0n:
      acc
    case 1n+m:
      repeat(m, c, SCon{c, acc})

def down.after(name: String, +want: String, g: Redis.Got(R.Reply), k: Unit -> IO(Unit)) -> IO(Unit):
  match g:
    case Done{(c, r)}:
      IO.bind(Unit, Unit, Redis.close(c), x => verdict(False{}, name, "a reply: " ++ R.show(r), k))
    case Fail{+d}:
      verdict(same(kind(d), want), name, kind(d), k)

def sized.shown(ok: Bool, c: Redis.Client(), k: Redis.Client() -> IO(Unit)) -> IO(Unit):
  verdict(ok, "984 bytes, under a 1000-byte cap", "the 984 bytes", u => k(c))

def sized.first(g: Redis.Got(R.Reply), k: Unit -> IO(Unit)) -> IO(Unit):
  match g:
    case Done{(c, r)}:
      sized.shown(same(R.show(r), "\"" ++ repeat(984n, 'a', "") ++ "\""), c, c2 => IO.bind(Redis.Got(R.Reply), Unit, ping(c2), g2 => down.after("1000 bytes, past it: refused as declared", "too large", g2, k)))
    case Fail{d}:
      verdict(False{}, "984 bytes", Redis.down.show(d), k)

def sized.opened(r: Result<&1, &1, Redis.Down, Redis.Client()>, k: Unit -> IO(Unit)) -> IO(Unit):
  match r:
    case Done{c}:
      IO.bind(Redis.Got(R.Reply), Unit, ping(c), g => sized.first(g, k))
    case Fail{d}:
      verdict(False{}, "sized", Redis.down.show(d), k)

def shows(xs: List<&2, R.Reply>, out: String) -> String:
  match xs:
    case Nil{}:
      out
    case Con{x, t}:
      shows(t, out ++ R.show(x) ++ ";")

def pipe.shown(+got: String, k: Unit -> IO(Unit)) -> IO(Unit):
  verdict(same(got, "A;B;"), "a push between two pipelined replies, skipped", got, k)

def piped(g: Redis.Got(List<&2, R.Reply>), k: Unit -> IO(Unit)) -> IO(Unit):
  match g:
    case Done{(c, xs)}:
      IO.bind(Unit, Unit, Redis.close(c), x => pipe.shown(shows(xs, ""), k))
    case Fail{d}:
      verdict(False{}, "push between pipelined replies", Redis.down.show(d), k)

def pipe.opened(r: Result<&1, &1, Redis.Down, Redis.Client()>, k: Unit -> IO(Unit)) -> IO(Unit):
  match r:
    case Done{c}:
      IO.bind(Redis.Got(List<&2, R.Reply>), Unit, Redis.pipeline(c, [["PING"], ["PING"]]), g => piped(g, k))
    case Fail{d}:
      verdict(False{}, "push between", Redis.down.show(d), k)

def big_pipe(c: Redis.Client()) -> IO(Redis.Got(R.Reply)):
  Redis.command_bytes(c, [[83, 69, 84], [107], big(4000000n, [])])

def RP() -> Type:
  Result<&1, &1, Redis.Down, R.Reply>

def pool.down(name: String, r: RP(), +want: String, k: Unit -> IO(Unit)) -> IO(Unit):
  match r:
    case Done{x}:
      verdict(False{}, name, "a reply: " ++ R.show(x), k)
    case Fail{+d}:
      verdict(same(kind(d), want), name, kind(d), k)

def conn.timed(+t0: Nat, +now: Nat, got: String, k: Unit -> IO(Unit)) -> IO(Unit):
  verdict(Nat.is_le(Nat.sub(now, t0), 1500n), "connect to an address that drops packets", got ++ " after " ++ Nat.show(Nat.sub(now, t0)) ++ " ms", k)

def conn.done(+t0: Nat, r: Result<&1, &1, Redis.Down, Redis.Client()>, k: Unit -> IO(Unit)) -> IO(Unit):
  match r:
    case Done{c}:
      IO.bind(Unit, Unit, Redis.close(c), x => k(Unit{}))
    case Fail{d}:
      IO.bind(Nat, Unit, IO.now(), now => conn.timed(t0, now, kind(d), k))

def f18(u: Unit) -> IO(Unit):
  do IO<Unit>:
    +t0 : Nat <- IO.now()
    r : Result<&1, &1, Redis.Down, Redis.Client()> <- Redis.open(Redis.with_timeout(Redis.config("10.255.255.1", 6379), 300))
    conn.done(t0, r, x => IO.print("faults: all ok"))

def f17(u: Unit) -> IO(Unit):
  do IO<Unit>:
    +p : Redis.Pool <- Redis.pool(cfg(7999), 1)
    r1 : RP() <- Redis.with(R.Reply, p, c => ping(c))
    x1 : Unit <- pool.down("a pool whose server is down", r1, "io", u1 => IO.pure(Unit, Unit{}))
    r2 : RP() <- Redis.with(R.Reply, p, c => ping(c))
    x2 : Unit <- pool.down("and again: its slot came back", r2, "io", u2 => IO.pure(Unit, Unit{}))
    x3 : Unit <- Redis.pool.close(p)
    r3 : RP() <- Redis.with(R.Reply, p, c => ping(c))
    pool.down("after pool.close", r3, "closed", f18)

def f16(u: Unit) -> IO(Unit):
  expect_down("4 MB to a server that closes at once: an error, not a crash", 7015, "io", 3000n, big_pipe, f17)

def f15(u: Unit) -> IO(Unit):
  IO.bind(Result<&1, &1, Redis.Down, Redis.Client()>, Unit, Redis.open(cfg(7014)), r => pipe.opened(r, f16))

def f14(u: Unit) -> IO(Unit):
  IO.bind(Result<&1, &1, Redis.Down, Redis.Client()>, Unit, Redis.open(Redis.with_max_reply(cfg(7013), 1000)), r => sized.opened(r, f15))

def f13(u: Unit) -> IO(Unit):
  expect_down.cfg("a line past the default 8 MiB cap, in time", Redis.config("127.0.0.1", 7004), "too large", 5000n, ping, f14)

def reconnected(+ok: Nat) -> IO(Unit):
  verdict(Nat.is_eq(ok, 10n), "a pool through a server that closes after each reply", Nat.show(ok) ++ " of 10 PINGs answered, reconnecting", f13)

def f12(u: Unit) -> IO(Unit):
  do IO<Unit>:
    +p : Redis.Pool <- Redis.pool(cfg(7012), 2)
    pings(10n, p, 0n, o => reconnected(o))

def f11(u: Unit) -> IO(Unit):
  expect_reply("two replies in one read", 7011, "FIRST", c => then("the second kept, with nothing more sent", "SECOND", f12, c))

def f10(u: Unit) -> IO(Unit):
  expect_reply("error reply keeps the client", 7010, "(error) ERR wrong kind", c => then("and it answers the next command", "PONG", f11, c))

def f9(u: Unit) -> IO(Unit):
  expect_reply("one byte at a time", 7009, "[\"hello\", 42]", c => closing(f10, c))

def f8(u: Unit) -> IO(Unit):
  expect_reply("push skipped", 7008, "OK", c => closing(f9, c))

def f7(u: Unit) -> IO(Unit):
  expect_down("server that reads nothing", 7007, "timeout", 3000n, flood_send, f8)

def f6(u: Unit) -> IO(Unit):
  expect_down("trickling reply", 7006, "timeout", 1500n, ping, f7)

def f5(u: Unit) -> IO(Unit):
  expect_down("garbage", 7005, "protocol", 1500n, ping, f6)

def f4(u: Unit) -> IO(Unit):
  expect_down("line past the byte cap", 7004, "too large", 3000n, ping, f5)

def f3(u: Unit) -> IO(Unit):
  expect_down("declared too large", 7003, "too large", 1500n, ping, f4)

def f2(u: Unit) -> IO(Unit):
  expect_down("closed mid-reply", 7002, "closed", 1500n, ping, f3)

def main() -> IO(Unit):
  expect_down("stalled server", 7001, "timeout", 1500n, ping, f2)
