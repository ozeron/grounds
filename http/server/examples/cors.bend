import Base
import ../server.bend as Server
import ../middleware.bend as Mw
import ../../core/cors.bend as Cors
import ../../core/request.bend as Req
import ../../core/response.bend as Res

def policy() -> Cors.Policy:
  Cors.Policy{["https://app.example"], True{}, ["GET", "POST"], ["content-type", "x-token"], 600}

def app(r: Req.Request) -> IO(Res.Response):
  IO.pure(Res.Response, Res.header(Res.ok("app"), "access-control-allow-origin", "https://wrong.example"))

def main() -> IO(Unit):
  Server.serve(~Mw.cors(~policy, ~app), Server.default(8093))
