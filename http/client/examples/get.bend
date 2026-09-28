import Base
import ../client.bend as C
import ../../core/text.bend as T

# GETs the local server and prints the body

def said(r: C.R(C.Reply)) -> String:
  match r:
    case Done{rep}:
      T.or(C.utf8(rep), "(not UTF-8)")
    case Fail{e}:
      C.show(e)

def main() -> IO(Unit):
  IO.bind(C.R(C.Reply), Unit, C.fetch("http://localhost:8080/?name=client"), r => IO.print(said(r)))
