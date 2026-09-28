import Base
import ../client.bend as C

# streams a body to stdout a piece at a time, however large

def out(bs: List<&2, U32>, acc: String) -> String:
  match bs:
    case Nil{}:
      String.reverse(acc)
    case Con{b, t}:
      out(t, SCon{Chr{b}, acc})

def piece(bs: List<&2, U32>) -> IO(Bool):
  IO.bind(Unit, Bool, IO.write(out(bs, "")), u => IO.pure(Bool, True{}))

def said(r: C.R(C.Head)) -> String:
  match r:
    case Done{C.Head{+c, _}}:
      "status " ++ U32.show(c)
    case Fail{e}:
      C.show(e)

def main() -> IO(Unit):
  IO.bind(C.R(C.Head), Unit, C.stream(~piece, C.default(), C.get("http://127.0.0.1:8086/events")), r => IO.print_err(said(r)))
