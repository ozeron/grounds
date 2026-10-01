import Base
import ../method.bend as M
import ../../../crypto/bytes.bend as B
import ../../../utf8/utf8.bend as U
import ../../../json/json.bend as J
import ../../../io/io.bend as Io

def classified(value: M.Method) -> IO(Unit):
  match value:
    case M.MGet{}: IO.print("GET")
    case M.MHead{}: IO.print("HEAD")
    case M.MPost{}: IO.print("POST")
    case M.MPut{}: IO.print("PUT")
    case M.MDelete{}: IO.print("DELETE")
    case M.MConnect{}: IO.print("CONNECT")
    case M.MOptions{}: IO.print("OPTIONS")
    case M.MTrace{}: IO.print("TRACE")
    case M.MPatch{}: IO.print("PATCH")
    case M.MOther{name}: IO.print("other:" ++ B.hex(U.encode(name)))

def values(items: List<&2, J.Json>) -> IO(Unit):
  match items:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{J.JStr{text}, tail}:
      do IO<Unit>:
        x : Unit <- classified(M.parse(text))
        values(tail)
    case _: IO.die(Unit, 2, "bad fixture")

def parsed(value: Result<&2, &2, J.Error, J.Json>) -> IO(Unit):
  match value:
    case Done{J.JArr{items}}: values(items)
    case _: IO.die(Unit, 2, "bad fixture")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [path]:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        parsed(J.parse_bytes(bytes))
    case _: IO.die(Unit, 2, "usage: method <fixture.json>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
