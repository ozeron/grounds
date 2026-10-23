import Base
import ../bend_server.bend as Server
import ./bend_perf_app.bend as App
import ./bend_tls.bend as Options
import ../../core/request.bend as Req
import ../../core/response.bend as Res

def app(context: Unit, r: Req.Request) -> IO(Server.Out):
  IO.bind(Res.Response,Server.Out,App.app(r),response => IO.pure(Server.Out,Server.Whole{response}))

def main() -> IO(Unit):
  do IO<Unit>:
    suite : Result<&1,&1,U32 & String,String> <- IO.get_env("HTTP_BEND_TLS_SUITE")
    selected : List<&2,U32> <- Options.suites(suite)
    cfg : Server.Config <- Server.from_env(Server.with_bend_tls_chain(Server.default(8090),[""],"",selected))
    Server.serve_bend_out_context(~Unit,~app,Unit{},cfg)
