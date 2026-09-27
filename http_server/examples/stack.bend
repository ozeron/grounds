import Base
import ../server.bend as Server
import ../middleware.bend as Mw
import ../../http/text.bend as T
import ../../http/status.bend as S
import ../../http/request.bend as Req
import ../../http/response.bend as Res

# a middleware stack on port 8082: logger, request id, body limit, recover.
# /fail fails, and recover answers 500; a body over 16 bytes gets 413

def small() -> U32:
  16

def answer(fail: Bool) -> Result<&1, &1, String, Res.Response>:
  match fail:
    case True{}:
      Fail{"the handler failed on purpose"}
    case False{}:
      Done{Res.text(S.ok(), "ok\n")}

def app(r: Req.Request) -> IO(Result<&1, &1, String, Res.Response>):
  IO.pure(Result<&1, &1, String, Res.Response>, answer(T.same(Req.path(r), "/fail", True{})))

def main() -> IO(Unit):
  Server.serve(~Mw.logger(~Mw.request_id(~Mw.body_limit(~small, ~Mw.recover(~app)))), Server.default(8082))
