import Base
import ../server.bend as Server
import ../../core/request.bend as Req
import ../../core/response.bend as Res
import ../../core/status.bend as Status

type Context is Data:
  Context{token: String}

def chunks(+token: String, sink: Server.Sink) -> IO(Server.Sink):
  do IO<Server.Sink>:
    a : Server.Sink <- Server.send_text(sink, token)
    b : Server.Sink <- Server.send_text(a, ":")
    Server.send_text(b, token)

def answer(context: Context, request: Req.Request) -> IO(Server.Out):
  match context request:
    case Context{token} Req.Request{_, "/stream", _, _}:
      IO.pure(Server.Out, Server.Stream{Status.ok(), [], sink => chunks(token, sink)})
    case Context{token} Req.Request{_, path, _, _}:
      IO.pure(Server.Out, Server.Whole{Res.ok(token ++ ":" ++ path)})

def main() -> IO(Unit):
  do IO<Unit>:
    +random : U32 <- IO.try(U32, IO.random_u32())
    x : Unit <- IO.print("context:" ++ U32.show(random))
    cfg : Server.Config <- Server.from_env(Server.default(8086))
    Server.serve_out_context(~Context, ~answer, Context{U32.show(random)}, cfg)
