import Base
import ../redis.bend as Redis
import ../resp.bend as R

# the client side of tests/fuzz.py: FUZZ on a new connection each time;
# a reply goes back re-encoded in GOT, a client gone goes on to the next

def got.sent(g: Redis.Got(R.Reply), k: Unit -> IO(Unit)) -> IO(Unit):
  match g:
    case Done{(c, _)}:
      IO.bind(Unit, Unit, Redis.close(c), k)
    case Fail{_}:
      k(Unit{})

def fuzzed(g: Redis.Got(R.Reply), k: Unit -> IO(Unit)) -> IO(Unit):
  match g:
    case Done{(c, r)}:
      IO.bind(Redis.Got(R.Reply), Unit, Redis.command_bytes(c, [[71, 79, 84], R.write(r)]), g2 => got.sent(g2, k))
    case Fail{_}:
      k(Unit{})

def opened(r: Result<&1, &1, Redis.Down, Redis.Client()>, k: Unit -> IO(Unit)) -> IO(Unit):
  match r:
    case Done{c}:
      IO.bind(Redis.Got(R.Reply), Unit, Redis.command(c, ["FUZZ"]), g => fuzzed(g, k))
    case Fail{_}:
      IO.pure(Unit, Unit{})

def cases(n: Nat) -> IO(Unit):
  match n:
    case 0n:
      IO.pure(Unit, Unit{})
    case 1n+m:
      IO.bind(Result<&1, &1, Redis.Down, Redis.Client()>, Unit, Redis.open(Redis.config("127.0.0.1", 7100)), r => opened(r, u => cases(m)))

# cases until the server, done with its own count, stops taking connections
def main() -> IO(Unit):
  cases(4294967295n)
