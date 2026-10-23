import Base
import ./pem.bend as P
import ./bytes.bend as B
import ../io/io.bend as Io

def kind(label: P.Label) -> String:
  match label:
    case P.Pkcs8{}:
      "pkcs8"
    case P.Sec1{}:
      "sec1"
    case P.Pkcs1{}:
      "pkcs1"
    case P.Certificate{}:
      "certificate"

def show(value: Result<&2, &1, P.Error, P.Block>) -> String:
  match value:
    case Fail{P.Encrypted{}}:
      "encrypted"
    case Fail{P.TooLarge{}}:
      "large"
    case Fail{_}:
      "none"
    case Done{P.Block{label, bytes}}:
      String.concat([kind(label), ":", B.hex(bytes)])

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{path, rest}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(show(P.decode(bytes)))
        dispatch(rest)

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- Io.args()
    dispatch(args)
