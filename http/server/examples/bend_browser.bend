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
import ./bend_wss.bend as Echo

# Browser WebSocket APIs send Origin and cookies, but cannot set Authorization.
# Synthetic-key fixture: reuse the native TLS, cookie and frame implementations.
def authenticated(value: Maybe<&2,String>, r: Req.Request) -> IO(Server.Out):
  match value:
    case Some{"m4a.synthetic.session"}: Echo.upgraded(Ws.accept(r))
    case _: IO.pure(Server.Out,Server.Whole{Res.text(Status.unauthorized(),"cookie required")})

def origin(ok: Bool, key: Cookie.SigningKey, +r: Req.Request) -> IO(Server.Out):
  match ok:
    case True{}:
      do IO<Server.Out>:
        value : Maybe<&2,String> <- IO.try(Maybe<&2,String>,Cookie.verify_owned(key,Text.or(Jar.get(r,"grounds"),"")))
        authenticated(value,r)
    case False{}: IO.pure(Server.Out,Server.Whole{Res.text(Status.forbidden(),"origin denied")})

def app(context: Echo.Context, r: Req.Request) -> IO(Server.Out):
  match context r:
    case Echo.Context{key,expected} Req.Request{m,+target,+hs,body}:
      match target:
        case "/": IO.pure(Server.Out,Server.Whole{Res.html(Status.ok(),"<!doctype html><title>Grounds native browser</title><p id=ready>native Bend HTTPS</p>")})
        case "/ws": origin(String.eq(Text.or(H.get(hs,"origin"),""),expected),key,Req.Request{m,target,hs,body})
        case _: Http.app(key,Req.Request{m,target,hs,body})

def main() -> IO(Unit):
  do IO<Unit>:
    preference : Result<&1,&1,U32 & String,String> <- IO.get_env("HTTP_BEND_TLS_SUITE")
    selected : List<&2,U32> <- Http.suites(preference)
    cfg : Server.Config <- Server.from_env(Server.with_bend_tls_chain(Server.default(8090),[""],"",selected))
    secret : String <- IO.try(String,IO.get_env("HTTP_COOKIE_KEY"))
    expected : String <- IO.try(String,IO.get_env("HTTP_WS_ORIGIN"))
    Server.serve_bend_out_context(~Echo.Context,~app,Echo.Context{Cookie.SigningKey{secret},expected},cfg)
