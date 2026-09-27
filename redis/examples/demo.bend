import Base
import ../redis.bend as Redis
import ../resp.bend as R

# SET, GET, INCR, DEL and a pipeline against a Redis on 127.0.0.1:6379

def text(r: Redis.Res(Maybe<&2, String>)) -> String:
  match r:
    case Done{Some{s}}:
      "\"" ++ s ++ "\""
    case Done{None{}}:
      "(nil)"
    case Fail{e}:
      "(error) " ++ e

def ok(r: Redis.Res(Unit)) -> String:
  match r:
    case Done{_}:
      "OK"
    case Fail{e}:
      "(error) " ++ e

def int(r: Redis.Res(Redis.Z)) -> String:
  match r:
    case Done{Redis.Z{True{}, n}}:
      "-" ++ Nat.show(n)
    case Done{Redis.Z{False{}, n}}:
      Nat.show(n)
    case Fail{e}:
      "(error) " ++ e

def nat(r: Redis.Res(Nat)) -> String:
  match r:
    case Done{n}:
      Nat.show(n)
    case Fail{e}:
      "(error) " ++ e

def replies(xs: List<&2, R.Reply>, out: String) -> String:
  match xs:
    case Nil{}:
      out
    case Con{x, t}:
      replies(t, out ++ " " ++ R.show(x))

def all(r: Redis.Res(List<&2, R.Reply>)) -> String:
  match r:
    case Done{xs}:
      replies(xs, "pipeline:")
    case Fail{e}:
      e

def piped(g: Redis.Got(List<&2, R.Reply>)) -> Redis.Got(Redis.Res(List<&2, R.Reply>)):
  match g:
    case Done{(c, xs)}:
      Done{(c, Done{xs})}
    case Fail{d}:
      Fail{d}

# print an answer, then go on with the client; stop at a client gone
def then(-A: Data, g: Redis.Got(Redis.Res(A)), show: Redis.Res(A) -> String, k: Redis.Client() -> IO(Unit)) -> IO(Unit):
  match g:
    case Done{(c, r)}:
      IO.bind(Unit, Unit, IO.print(show(r)), x => k(c))
    case Fail{d}:
      IO.print("down: " ++ Redis.down.show(d))

def run(c: Redis.Client()) -> IO(Unit):
  IO.bind(Redis.Got(Redis.Res(Unit)), Unit, Redis.set(c, "grounds:demo", "brewed"), g => then(Unit, g, ok, c1 =>
  IO.bind(Redis.Got(Redis.Res(Maybe<&2, String>)), Unit, Redis.get(c1, "grounds:demo"), g1 => then(Maybe<&2, String>, g1, text, c2 =>
  IO.bind(Redis.Got(Redis.Res(Redis.Z)), Unit, Redis.incr(c2, "grounds:count"), g2 => then(Redis.Z, g2, int, c3 =>
  IO.bind(Redis.Got(List<&2, R.Reply>), Unit, Redis.pipeline(c3, [["INCR", "grounds:count"], ["GET", "grounds:missing"], ["PING"]]), g3 => then(List<&2, R.Reply>, piped(g3), all, c4 =>
  IO.bind(Redis.Got(Redis.Res(Nat)), Unit, Redis.del(c4, ["grounds:demo", "grounds:count"]), g4 => then(Nat, g4, nat, Redis.close))))))))))

def opened(r: Result<&1, &1, Redis.Down, Redis.Client()>) -> IO(Unit):
  match r:
    case Done{c}:
      run(c)
    case Fail{d}:
      IO.die(Unit, 1, "down: " ++ Redis.down.show(d))

def main() -> IO(Unit):
  IO.bind(Result<&1, &1, Redis.Down, Redis.Client()>, Unit, Redis.open(Redis.config("127.0.0.1", 6379)), opened)
