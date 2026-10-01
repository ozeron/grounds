import Base
import ../base64.bend as B64
import ../../../crypto/bytes.bend as B
import ../../../json/json.bend as J
import ../../../io/io.bend as Io

def decoded(value: Maybe<&2, List<&2, U32>>) -> IO(Unit):
  match value:
    case Some{bytes}: IO.print("ok:" ++ B.hex(bytes))
    case None{}: IO.print("invalid")

def values(items: List<&2, J.Json>) -> IO(Unit):
  match items:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{J.JStr{text}, tail}:
      do IO<Unit>:
        x : Unit <- decoded(B64.b64_go(4294967295n, text, []))
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
    case _: IO.die(Unit, 2, "usage: base64 <fixture.json>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
