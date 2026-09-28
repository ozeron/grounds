import Base
import ../server.bend as Server
import ../../core/request.bend as Req
import ../../core/response.bend as Res

# Use only behind a proxy that removes incoming X-Forwarded-Proto and sets
# its own. This example lets the check exercise the trust_proxy switch.
def answer(on: Bool) -> Res.Response:
  match on:
    case True{}:
      Res.ok("secure\n")
    case False{}:
      Res.ok("insecure\n")

def app(r: Req.Request) -> Res.Response:
  answer(Server.secure(r))

def main() -> IO(Unit):
  Server.serve_pure(~app, Server.with_trust_proxy(Server.default(8090), True{}))
