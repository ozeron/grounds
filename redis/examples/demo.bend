import Base
import ../redis.bend as Redis
import ../resp.bend as R

# SET, GET, INCR, DEL and PING against a Redis on 127.0.0.1:6379; each
# reply prints as redis-cli would

def said(r: Result<&1, &1, String, R.Reply>) -> String:
  match r:
    case Done{x}:
      R.show(x)
    case Fail{why}:
      "failed: " ++ why

law last:
  for m: Redis.Reply()
  IO(Unit)

def last(m):
  (s, r) = m
  do IO<Unit>:
    x : Unit <- IO.print(said(r))
    Redis.close(s)

# print a reply, then run the next command on the same connection
law then:
  for m: Redis.Reply()
  for args: List<&2, String>
  for k: Redis.Reply() -> IO(Unit)
  IO(Unit)

def then(m, args, k):
  (s, r) = m
  do IO<Unit>:
    x : Unit <- IO.print(said(r))
    n : Redis.Reply() <- Redis.command(s, args)
    k(n)

def main() -> IO(Unit):
  do IO<Unit>:
    s : Socket <- IO.try(Socket, Redis.connect("127.0.0.1", 6379))
    a : Redis.Reply() <- Redis.set(s, "grounds:demo", "brewed")
    then(a, ["GET", "grounds:demo"], b => then(b, ["INCR", "grounds:count"], c => then(c, ["DEL", "grounds:demo", "grounds:count"], d => then(d, ["PING"], last))))
