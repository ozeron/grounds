import Base
import ../bend_server.bend as Server
import ../websocket.bend as Ws
import ../websocket_transport.bend as Conn
import ./bend_tls.bend as Http
import ../../core/request.bend as Req
import ../../core/response.bend as Res
import ../../core/status.bend as Status
import ../../core/headers.bend as H
import ../../core/cookie.bend as Jar
import ../../core/cookie_bend.bend as Cookie
import ../../core/text.bend as Text

type Context is Data:
  Context{key: Cookie.SigningKey, origin: String}

def echo(message: Conn.Message) -> IO(Maybe<&2,Conn.Message>):
  IO.pure(Maybe<&2,Conn.Message>,Some{message})

def upgraded(value: Maybe<&2,String>) -> IO(Server.Out):
  match value:
    case Some{accept}: IO.pure(Server.Out,Server.TransportUpgrade{accept,s => buffered => Conn.session(~echo,3000,s,buffered)})
    case None{}: IO.pure(Server.Out,Server.Whole{Res.text(Status.bad_request(),"invalid WebSocket handshake")})

def authenticated(cookie: Maybe<&2,String>, +r: Req.Request) -> IO(Server.Out):
  match cookie:
    case Some{"m4a.synthetic.session"}: upgraded(Ws.accept(r))
    case _: IO.pure(Server.Out,Server.Whole{Res.text(Status.unauthorized(),"cookie required")})

def authorized(ok: Bool, key: Cookie.SigningKey, +r: Req.Request) -> IO(Server.Out):
  match ok:
    case True{}:
      do IO<Server.Out>:
        value : Maybe<&2,String> <- IO.try(Maybe<&2,String>,Cookie.verify_owned(key,Text.or(Jar.get(r,"grounds"),"")))
        authenticated(value,r)
    case False{}: IO.pure(Server.Out,Server.Whole{Res.text(Status.unauthorized(),"bearer required")})

def origin(ok: Bool, key: Cookie.SigningKey, +r: Req.Request) -> IO(Server.Out):
  match ok:
    case True{}: authorized(String.eq(Text.or(Req.header(r,"authorization"),""),"Bearer synthetic"),key,r)
    case False{}: IO.pure(Server.Out,Server.Whole{Res.text(Status.forbidden(),"origin denied")})

def app(context: Context, r: Req.Request) -> IO(Server.Out):
  match context r:
    case Context{key,expected} Req.Request{m,+target,+hs,body}:
      match target:
        case "/ws": origin(String.eq(Text.or(H.get(hs,"origin"),""),expected),key,Req.Request{m,target,hs,body})
        case _: Http.app(key,Req.Request{m,target,hs,body})

def origin_env(value: Result<&1,&1,U32 & String,String>) -> String:
  match value:
    case Done{s}: s
    case Fail{_}: "https://grounds.test"

def main() -> IO(Unit):
  do IO<Unit>:
    cfg : Server.Config <- Server.from_env(Server.with_bend_tls(Server.default(8090),"",""))
    secret : String <- IO.try(String,IO.get_env("HTTP_COOKIE_KEY"))
    expected : Result<&1,&1,U32 & String,String> <- IO.get_env("HTTP_WS_ORIGIN")
    Server.serve_bend_out_context(~Context,~app,Context{Cookie.SigningKey{secret},origin_env(expected)},cfg)
