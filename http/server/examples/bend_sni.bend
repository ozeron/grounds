import Base
import ../bend_server.bend as Server
import ../tls_config.bend as BT
import ../websocket.bend as Ws
import ../websocket_transport.bend as Conn
import ../../core/request.bend as Req
import ../../core/response.bend as Res
import ../../core/status.bend as Status
import ../../core/text.bend as Text

# SNI multi-certificate fixture (synthetic keys only). HTTP_SNI_FIXTURES names
# a directory of PEM pairs; HTTP_SNI_MODE picks the host set:
#   full (default)  a.sni.test P-256 + RSA, b.sni.test, *.wild.sni.test,
#                   c.sni.test by explicit name, and a default credential
#   nodefault       the same hosts without a default
#   duplicate       b.sni.test twice for one key type (startup refusal)
#   badname         an explicit "*.test" wildcard (startup refusal)
#   toomany         65 credentials (startup refusal)
type Mode is Data:
  Full{}
  NoDefault{}
  Duplicate{}
  BadName{}
  TooMany{}

def mode.of(value: Result<&1,&1,U32 & String,String>) -> Mode:
  match value:
    case Done{+s}:
      Bool.pick(Mode,String.eq(s,"nodefault"),NoDefault{},
        Bool.pick(Mode,String.eq(s,"duplicate"),Duplicate{},
          Bool.pick(Mode,String.eq(s,"badname"),BadName{},
            Bool.pick(Mode,String.eq(s,"toomany"),TooMany{},Full{}))))
    case Fail{_}: Full{}

def pem(+dir: String, +name: String) -> BT.Host:
  Server.tls_host_pem(dir ++ "/" ++ name ++ ".pem",dir ++ "/" ++ name ++ ".key")

def named(+dir: String, names: List<&2,String>, +name: String) -> BT.Host:
  Server.tls_host(names,[dir ++ "/" ++ name ++ ".pem"],dir ++ "/" ++ name ++ ".key")

def base(+dir: String) -> List<&2,BT.Host>:
  [pem(dir,"a-rsa"),pem(dir,"a-ecdsa"),pem(dir,"b"),pem(dir,"wild"),named(dir,["c.sni.test"],"c")]

def repeated(+count: Nat, +dir: String) -> List<&2,BT.Host>:
  match count:
    case 0n: []
    case 1n+p: Con{pem(dir,"b"),repeated(p,dir)}

def hosts(+mode: Mode, +dir: String, cfg: Server.Config) -> Server.Config:
  match mode:
    case Full{}: Server.with_bend_tls_hosts(cfg,base(dir),Some{pem(dir,"default")})
    case NoDefault{}: Server.with_bend_tls_hosts(cfg,base(dir),None{})
    case Duplicate{}: Server.with_bend_tls_hosts(cfg,Con{pem(dir,"b"),base(dir)},Some{pem(dir,"default")})
    case BadName{}: Server.with_bend_tls_hosts(cfg,[named(dir,["*.test"],"b")],Some{pem(dir,"default")})
    case TooMany{}: Server.with_bend_tls_hosts(cfg,repeated(64n,dir),Some{pem(dir,"default")})

def echo(message: Conn.Message) -> IO(Maybe<&2,Conn.Message>):
  IO.pure(Maybe<&2,Conn.Message>,Some{message})

def upgraded(value: Maybe<&2,String>) -> IO(Server.Out):
  match value:
    case Some{accept}: IO.pure(Server.Out,Server.TransportUpgrade{accept,s => buffered => Conn.session(~echo,3000,s,buffered)})
    case None{}: IO.pure(Server.Out,Server.Whole{Res.text(Status.bad_request(),"invalid WebSocket handshake")})

def whoami(+r: Req.Request) -> String:
  "sni=" ++ Text.or(Server.tls_server_name(r),"-") ++ "\ncredential=" ++ Text.or(Server.tls_credential(r),"-") ++ "\n"

def page(+r: Req.Request) -> String:
  "<!doctype html><title>Grounds SNI</title><pre id=who>" ++ whoami(r) ++ "</pre>"

def app(context: Unit, r: Req.Request) -> IO(Server.Out):
  match r:
    case Req.Request{m,+target,+hs,body}:
      match target:
        case "/whoami": IO.pure(Server.Out,Server.Whole{Res.text(Status.ok(),whoami(Req.Request{m,target,hs,body}))})
        case "/ws": upgraded(Ws.accept(Req.Request{m,target,hs,body}))
        case "/": IO.pure(Server.Out,Server.Whole{Res.html(Status.ok(),page(Req.Request{m,target,hs,body}))})
        case _: IO.pure(Server.Out,Server.Whole{Res.text(Status.not_found(),"not found")})

def main() -> IO(Unit):
  do IO<Unit>:
    dir : String <- IO.try(String,IO.get_env("HTTP_SNI_FIXTURES"))
    value : Result<&1,&1,U32 & String,String> <- IO.get_env("HTTP_SNI_MODE")
    cfg : Server.Config <- Server.from_env(hosts(mode.of(value),dir,Server.default(8091)))
    Server.serve_bend_out_context(~Unit,~app,Unit{},cfg)
