import Base
import ../redis.bend as Redis
import ../resp.bend as R

# a soak test, by hand (not in check.sh): 20000 rounds of SET and GET of a
# 10 KB value on one client, a client opened and closed, and a pool call;
# watch its memory (footprint PID) and sockets (lsof -p PID): both stay flat.
#
# n rounds: SET/GET a 10 KB value on one client, then open and close a new
# client, then a pool call; memory and file descriptors must stay flat

def val(n: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+m:
      val(m, Con{120, acc})

def round.got(g: Redis.Got(Redis.Res(Maybe<&2, List<&2, U32>>)), k: Redis.Client() -> IO(Unit)) -> IO(Unit):
  match g:
    case Done{(c, _)}:
      k(c)
    case Fail{d}:
      IO.die(Unit, 1, Redis.down.show(d))

def round.set(g: Redis.Got(Redis.Res(Unit)), k: Redis.Client() -> IO(Unit)) -> IO(Unit):
  match g:
    case Done{(c, _)}:
      IO.bind(Redis.Got(Redis.Res(Maybe<&2, List<&2, U32>>)), Unit, Redis.get_bytes(c, [107]), g2 => round.got(g2, k))
    case Fail{d}:
      IO.die(Unit, 1, Redis.down.show(d))

def fresh(r: Result<&1, &1, Redis.Down, Redis.Client()>, k: Unit -> IO(Unit)) -> IO(Unit):
  match r:
    case Done{c}:
      IO.bind(Unit, Unit, Redis.close(c), k)
    case Fail{d}:
      IO.die(Unit, 1, Redis.down.show(d))

def pooled(r: Result<&1, &1, Redis.Down, R.Reply>, k: Unit -> IO(Unit)) -> IO(Unit):
  match r:
    case Done{_}:
      k(Unit{})
    case Fail{d}:
      IO.die(Unit, 1, Redis.down.show(d))

def rounds(n: Nat, +p: Redis.Pool, c: Redis.Client()) -> IO(Unit):
  match n:
    case 0n:
      Redis.close(c)
    case 1n+m:
      IO.bind(Redis.Got(Redis.Res(Unit)), Unit, Redis.set_bytes(c, [107], val(10000n, [])), g => round.set(g, c2 =>
      IO.bind(Result<&1, &1, Redis.Down, Redis.Client()>, Unit, Redis.open(Redis.config("127.0.0.1", 6379)), r => fresh(r, u =>
      IO.bind(Result<&1, &1, Redis.Down, R.Reply>, Unit, Redis.run(0n, p, ["PING"]), q => pooled(q, v => rounds(m, p, c2)))))))

def opened(r: Result<&1, &1, Redis.Down, Redis.Client()>, +p: Redis.Pool) -> IO(Unit):
  match r:
    case Done{c}:
      rounds(20000n, p, c)
    case Fail{d}:
      IO.die(Unit, 1, Redis.down.show(d))

def main() -> IO(Unit):
  do IO<Unit>:
    +p : Redis.Pool <- Redis.pool(Redis.config("127.0.0.1", 6379), 4)
    r : Result<&1, &1, Redis.Down, Redis.Client()> <- Redis.open(Redis.config("127.0.0.1", 6379))
    x : Unit <- opened(r, p)
    Redis.pool.close(p)
