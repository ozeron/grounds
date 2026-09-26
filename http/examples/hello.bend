import Base
import ../method.bend as M
import ../status.bend as S
import ../headers.bend as H
import ../request.bend as Req
import ../response.bend as Res

# a handler's shape before there is a server: read the request's parts,
# answer with text. ../json/scripts/cold.py checks it shares no String

def greet(name: Maybe<&2, String>) -> String:
  match name:
    case Some{n}:
      "hello, " ++ n
    case None{}:
      "hello"

def handle(r: Req.Request) -> Res.Response:
  match r:
    case Req.Request{_, _, hs, _}:
      Res.header(Res.text(S.ok(), greet(H.get(hs, "x-name"))), "cache-control", "no-store")

def show(r: Res.Response) -> String:
  match r:
    case Res.Response{S.Status{+c}, hs, b}:
      U32.show(c) ++ " " ++ S.reason(S.Status{c}) ++ ", " ++ U32.show(U32.from_nat(List.length(&2, H.Header, hs))) ++ " headers, " ++ U32.show(U32.from_nat(List.length(&2, U32, b))) ++ " bytes"

def main() -> IO(Unit):
  do IO<Unit>:
    IO.print(show(handle(Req.Request{M.MGet{}, "/?a=1", [H.Header{"X-Name", "Alex"}], []})))
