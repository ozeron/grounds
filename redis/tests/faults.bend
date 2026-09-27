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
def expect_down(name: String, +port: U32, +want: String, +limit: Nat, act: Redis.Client() -> IO(Redis.Got(R.Reply)), k: Unit -> IO(Unit)) -> IO(Unit):
  do IO<Unit>:
    +t0 : Nat <- IO.now()
    r : Result<&1, &1, Redis.Down, Redis.Client()> <- Redis.open(cfg(port))
    down.opened(name, want, t0, limit, r, act, k)

def ping(c: Redis.Client()) -> IO(Redis.Got(R.Reply)):
  Redis.command(c, ["PING"])

def big(n: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+m:
      big(m, Con{120, acc})

# 20 MB to a server that reads nothing: the send must time out
def flood_send(c: Redis.Client()) -> IO(Redis.Got(R.Reply)):
  Redis.command_bytes(c, [[83, 69, 84], [107], big(20000000n, [])])

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

def reconnected(+ok: Nat) -> IO(Unit):
  verdict(Nat.is_eq(ok, 10n), "a pool through a server that closes after each reply", Nat.show(ok) ++ " of 10 PINGs answered, reconnecting", x => IO.print("faults: all ok"))

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
