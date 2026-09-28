import Base
import ../server.bend as Server
import ../middleware.bend as Mw
import ../../core/auth.bend as Auth
import ../../core/request.bend as Req
import ../../core/response.bend as Res
import ../../core/text.bend as T

def verify(credential: Auth.Credential) -> IO(Maybe<&2, Auth.Principal>):
  match credential:
    case Auth.Bearer{"good-token"}:
      IO.pure(Maybe<&2, Auth.Principal>, Some{Auth.Principal{"bearer-user", [Auth.Claim{"role", "reader"}]}})
    case Auth.Basic{"test", "123£"}:
      IO.pure(Maybe<&2, Auth.Principal>, Some{Auth.Principal{"basic-user", []}})
    case _:
      IO.pure(Maybe<&2, Auth.Principal>, None{})

def app(principal: Auth.Principal, req: Req.Request) -> IO(Res.Response):
  match principal:
    case Auth.Principal{subject, _}:
      IO.pure(Res.Response, Res.ok(subject ++ "; authorization=" ++ T.or(Req.header(req, "authorization"), "absent")))

def main() -> IO(Unit):
  Server.serve(~Mw.auth(~verify, ~app), Server.default(8092))
