import Base
import ../server.bend as Server
import ../../http/text.bend as T
import ../../http/request.bend as Req
import ../../http/response.bend as Res

# curl 'localhost:8080/?name=x' answers "hello, x"

def hello(r: Req.Request) -> Res.Response:
  Res.ok("hello, " ++ T.or(Req.param(r, "name"), "world") ++ "\n")

def main() -> IO(Unit):
  Server.serve_pure(~hello, Server.default(8080))
