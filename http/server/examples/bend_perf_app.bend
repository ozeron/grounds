import Base
import ../../core/request.bend as Req
import ../../core/response.bend as Res

# Exactly the same handler is imported by both server engines. Synthetic only.
def app(r: Req.Request) -> IO(Res.Response):
  IO.pure(Res.Response,Res.ok("perf ok\n"))
