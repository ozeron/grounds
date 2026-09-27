import Base
import ../redis.bend as Redis
import ../resp.bend as R

# against a Redis on 127.0.0.1:6380 with password s3cret: AUTH, a user,
# RESP3 with AUTH, and a wrong password

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

# Auth
# ----

def rejected(+name: String, r: Result<&1, &1, Redis.Down, Redis.Client()>, k: Unit -> IO(Unit)) -> IO(Unit):
  match r:
    case Fail{Redis.Rejected{why}}:
      verdict(True{}, name, "rejected: " ++ why, k)
    case Fail{d}:
      down(name, d)
    case Done{c}:
      IO.bind(Unit, Unit, Redis.close(c), x => IO.die(Unit, 1, "FAIL " ++ name ++ ": opened"))

def s_done(u: Unit) -> IO(Unit):
  IO.print("auth: all ok")

def s_auth_resp3(u: Unit) -> IO(Unit):
  opening("RESP3 with AUTH", Redis.with_resp3(Redis.with_password(authed(), "s3cret")), c =>
  ask("HELLO 3 with AUTH, then PING", c, ["PING"], "PONG", c2 => closing(s_done, c2)))

def s_auth_user(u: Unit) -> IO(Unit):
  opening("AUTH as a user", Redis.with_user(authed(), "default", "s3cret"), c =>
  ask("AUTH default s3cret, then PING", c, ["PING"], "PONG", c2 => closing(s_auth_resp3, c2)))

def s_auth_ok(u: Unit) -> IO(Unit):
  opening("AUTH", Redis.with_password(authed(), "s3cret"), c =>
  ask("AUTH s3cret, then PING", c, ["PING"], "PONG", c2 => closing(s_auth_user, c2)))

def s_auth_wrong(u: Unit) -> IO(Unit):
  IO.bind(Result<&1, &1, Redis.Down, Redis.Client()>, Unit, Redis.open(Redis.with_password(authed(), "wrong")), r => rejected("a wrong password", r, s_auth_ok))

def s_auth_none(u: Unit) -> IO(Unit):
  opening("no password", authed(), c =>
  ask("no password: NOAUTH, as a reply", c, ["PING"], "(error) NOAUTH Authentication required.", c2 => closing(s_auth_wrong, c2)))

def main() -> IO(Unit):
  s_auth_none(Unit{})
