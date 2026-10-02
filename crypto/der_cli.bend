import Base
import ./der.bend as D
import ./bytes.bend as B
import ../io/io.bend as Io

def show_der(value: Maybe<&1, D.Element>) -> String:
  match value:
    case Some{D.Element{tag, body, rest, encoded}}:
      String.concat([U32.show(tag), ":", B.hex(body), ":", B.hex(rest), ":", B.hex(encoded)])
    case _:
      "none"

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{file, tail}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(file)
        value : Maybe<&1, D.Element> = D.decode(bytes)
        output : String = show_der(value)
        IO.print(output)
        dispatch(tail)

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
