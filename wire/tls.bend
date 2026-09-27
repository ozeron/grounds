import Base
import ./wire.bend as W

# wire_tls_*: a GET over TLS to tls.py on 7202, whose certificate is for
# localhost and trusted through GROUNDS_TLS_CA; prints what came back.
# check.sh also connects with the wrong host name, which must fail

def RU() -> Type:
  Socket & Result<&1, &1, U32 & String, Unit>

def RP() -> Type:
  Socket & Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>

def text(bs: List<&2, U32>, acc: String) -> String:
  match bs:
    case Nil{}:
      String.reverse(acc)
    case Con{b, t}:
      text(t, SCon{Chr{b}, acc})

def says(m: Maybe<&1, List<&2, U32>>) -> String:
  match m:
    case Some{bs}:
      text(bs, "")
    case None{}:
      "(timed out)"

law got:
  for m: RP()
  IO(Unit)

def got(m):
  (s, r) = m
  do IO<Unit>:
    x : Unit <- W.wire_tls_close(s)
    bs : Maybe<&1, List<&2, U32>> <- IO.pass(Maybe<&1, List<&2, U32>>, r)
    IO.print(says(bs))

law sent:
  for m: RU()
  IO(Unit)

def sent(m):
  (s, r) = m
  do IO<Unit>:
    x : Unit <- IO.pass(Unit, r)
    p : RP() <- W.wire_tls_recv_timeout(s, 4096, 2000)
    got(p)

law shook:
  for m: RU()
  IO(Unit)

def shook(m):
  (s, r) = m
  do IO<Unit>:
    x : Unit <- IO.pass(Unit, r)
    u : RU() <- W.wire_tls_send_timeout(s, [71, 69, 84, 10], 2000)
    sent(u)

def host(a: List<String>) -> String:
  match a:
    case Con{h, _}:
      h
    case Nil{}:
      "localhost"

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    s : Socket <- IO.try(Socket, W.wire_connect_timeout("127.0.0.1", 7202, 2000))
    m : RU() <- W.wire_tls_connect(s, host(args), 2000)
    shook(m)
