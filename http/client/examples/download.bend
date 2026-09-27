import Base
import ../client.bend as Client
import ../../core/response.bend as Res
import ../../core/status.bend as S

# streams a body to stdout a piece at a time, however large

def out(bs: List<&2, U32>, acc: String) -> String:
  match bs:
    case Nil{}:
      String.reverse(acc)
    case Con{b, t}:
      out(t, SCon{Chr{b}, acc})

def piece(code: U32, bs: List<&2, U32>) -> IO(Bool):
  IO.bind(Unit, Bool, IO.write(out(bs, "")), u => IO.pure(Bool, True{}))

def said(r: Client.R()) -> String:
  match r:
    case Done{Res.Response{S.Status{+c}, _, _}}:
      "status " ++ U32.show(c)
    case Fail{e}:
      Client.show(e)

def main() -> IO(Unit):
  IO.bind(Client.R(), Unit, Client.download(~piece, Client.default(), "http://127.0.0.1:8086/events", []), r => IO.print_err(said(r)))
