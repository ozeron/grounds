import Base
import ../server.bend as Server
import ../../core/cookie_bend.bend as Cookie
import ../../core/cookie.bend as Jar
import ../../core/request.bend as Req
import ../../core/response.bend as Res
import ../../core/status.bend as Status
import ../../core/headers.bend as H
import ../../core/text.bend as Text
import ../../../wire/wire.bend as W

# Synthetic-key example only. A host-created key enters the explicit immutable
# handler context; selecting the signer is an application choice, independent
# of the TLS engine. No legacy cookie effect is imported.
def cookie_response(value: String) -> Server.Out:
  Server.Whole{Res.new(Status.ok(),[H.Header{"set-cookie","grounds=" ++ value ++ "; Path=/; Secure; HttpOnly; SameSite=Strict"}],[])}

def checked(value: Maybe<&2,String>) -> Server.Out:
  match value:
    case Some{"m4a.synthetic.session"}: Server.Whole{Res.ok("cookie ok\n")}
    case _: Server.Whole{Res.text(Status.unauthorized(),"cookie rejected\n")}

def stream(k: Server.Sink) -> IO(Server.Sink):
  do IO<Server.Sink>:
    k1 : Server.Sink <- Server.send_text(k,"first\n")
    IO.sleep(30)
    Server.send_text(k1,"second\n")

def slow(k: Server.Sink) -> IO(Server.Sink):
  do IO<Server.Sink>:
    k1 : Server.Sink <- Server.send_text(k,"started\n")
    IO.sleep(500)
    Server.send_text(k1,"finished\n")

def app(key: Cookie.SigningKey, r: Req.Request) -> IO(Server.Out):
  match r:
    case Req.Request{m,+target,+headers,body}:
      match target:
        case "/mint":
          do IO<Server.Out>:
            value : String <- IO.try(String,Cookie.sign_owned(key,"m4a.synthetic.session"))
            IO.pure(Server.Out,cookie_response(value))
        case "/cookie":
          do IO<Server.Out>:
            value : Maybe<&2,String> <- IO.try(Maybe<&2,String>,Cookie.verify_owned(key,Text.or(Jar.get(Req.Request{m,target,headers,body},"grounds"),"")))
            IO.pure(Server.Out,checked(value))
        case "/stream": IO.pure(Server.Out,Server.Stream{Status.ok(),[],stream})
        case "/slow": IO.pure(Server.Out,Server.Stream{Status.ok(),[],slow})
        case "/echo": IO.pure(Server.Out,Server.Whole{Res.new(Status.ok(),[],body)})
        case "/healthz": IO.pure(Server.Out,Server.Whole{Res.ok("ok\n")})
        case "/readyz":
          do IO<Server.Out>:
            +stop : U32 <- W.wire_stopping()
            IO.pure(Server.Out,Server.ready(stop))
        case _: IO.pure(Server.Out,Server.Whole{Res.ok(Bool.pick(String,Server.secure(Req.Request{m,target,headers,body}),"secure\n","insecure\n"))})

def suites(value: Result<&1,&1,U32 & String,String>) -> IO(List<&2,U32>):
  match value:
    case Fail{_}: IO.pure(List<&2,U32>,[4865,4867])
    case Done{"aes"}: IO.pure(List<&2,U32>,[4865])
    case Done{"chacha"}: IO.pure(List<&2,U32>,[4867])
    case _: IO.die(List<&2,U32>,1,"HTTP_BEND_TLS_SUITE must be aes|chacha")

def main() -> IO(Unit):
  do IO<Unit>:
    preference : Result<&1,&1,U32 & String,String> <- IO.get_env("HTTP_BEND_TLS_SUITE")
    selected : List<&2,U32> <- suites(preference)
    cfg : Server.Config <- Server.from_env(Server.with_bend_tls_chain(Server.default(8090),[""],"",selected))
    secret : String <- IO.try(String,IO.get_env("HTTP_COOKIE_KEY"))
    Server.serve_bend_out_context(~Cookie.SigningKey,~app,Cookie.SigningKey{secret},cfg)
