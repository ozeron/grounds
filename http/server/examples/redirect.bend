import Base
import ../server.bend as Server
import ../../core/request.bend as Req
import ../../core/response.bend as Res

# An HTTP listener that sends requests to the TLS example on 8088.
def app(r: Req.Request) -> Res.Response:
  Server.redirect_https("localhost:8088", r)

def main() -> IO(Unit):
  Server.serve_pure(~app, Server.default(8089))
