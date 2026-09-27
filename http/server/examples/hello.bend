import Base
import ../server.bend as Server
import ../../core/text.bend as T
import ../../core/request.bend as Req
import ../../core/response.bend as Res

# curl 'localhost:8080/?name=x' answers "hello, x"

def hello(r: Req.Request) -> Res.Response:
  Res.ok("hello, " ++ T.or(Req.param(r, "name"), "world") ++ "\n")

def main() -> IO(Unit):
  Server.serve_pure(~hello, Server.default(8080))
