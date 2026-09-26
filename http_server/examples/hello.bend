import Base
import ../server.bend as Server
import ../../http/text.bend as T
import ../../http/query.bend as Q
import ../../http/status.bend as S
import ../../http/request.bend as Req
import ../../http/response.bend as Res

# curl 'localhost:8080/?name=x' answers "hello, x"

def found(hit: Bool, v: String, rest: Maybe<&2, String>) -> Maybe<&2, String>:
  match hit rest:
    case True{} None{}:
      Some{v}
    case _ r:
      r

def name.go(ps: List<&2, Q.Param>, acc: Maybe<&2, String>) -> Maybe<&2, String>:
  match ps:
    case Nil{}:
      acc
    case Con{Q.Param{k, v}, t}:
      name.go(t, found(T.same(k, "name", True{}), v, acc))

def greet(m: Maybe<&2, String>) -> String:
  match m:
    case Some{n}:
      "hello, " ++ n ++ "\n"
    case None{}:
      "hello\n"

def hello(r: Req.Request) -> IO(Res.Response):
  IO.pure(Res.Response, Res.text(S.ok(), greet(name.go(Req.query(r), None{}))))

def main() -> IO(Unit):
  Server.serve(~hello, Server.default(8080))
