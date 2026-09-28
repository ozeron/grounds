import Base
import ../server.bend as Server
import ../middleware.bend as Mw
import ../../core/request.bend as Req
import ../../core/response.bend as Res

# Serve on PORT or 8088. Set HTTP_TLS_CERT and HTTP_TLS_KEY for HTTPS;
# otherwise this serves HTTP, so the forwarded-protocol handling is testable.
def answer(on: Bool) -> Res.Response:
  match on:
    case True{}:
      Res.ok("secure\n")
    case False{}:
      Res.ok("insecure\n")

def app(r: Req.Request) -> IO(Res.Response):
  IO.pure(Res.Response, answer(Server.secure(r)))

def main() -> IO(Unit):
  do IO<Unit>:
    cfg : Server.Config <- Server.from_env(Server.default(8088))
    Server.serve(~Mw.hsts(~app), cfg)
