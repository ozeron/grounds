import Base
import ../server.bend as Server
import ../websocket.bend as Ws
import ../websocket_conn.bend as Conn
import ../../core/request.bend as Req
import ../../core/response.bend as Res
import ../../core/status.bend as Status

def echo(message: Conn.Message) -> IO(Maybe<&2, Conn.Message>):
  IO.pure(Maybe<&2, Conn.Message>, Some{message})

def upgraded(accept: Maybe<&2, String>) -> IO(Server.Out):
  match accept:
    case Some{key}:
      IO.pure(Server.Out, Server.Upgrade{key, s => buffered => Conn.session(~echo, 30000, s, buffered)})
    case None{}:
      IO.pure(Server.Out, Server.Whole{Res.text(Status.bad_request(), "invalid WebSocket handshake")})

def app(r: Req.Request) -> IO(Server.Out):
  upgraded(Ws.accept(r))

def main() -> IO(Unit):
  do IO<Unit>:
    cfg : Server.Config <- Server.from_env(Server.default(8088))
    Server.serve_out(~app, cfg)
