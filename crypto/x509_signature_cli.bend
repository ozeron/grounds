import Base
import ./x509_algorithm.bend as X
import ./der.bend as D
import ./bytes.bend as B
import ../io/io.bend as Io

def show_signature(value: Maybe<&1, X.Signature>) -> String:
  match value:
    case Some{X.RsaPss256{}}:
      "pss256"
    case Some{X.RsaV15256{}}:
      "v15256"
    case Some{X.Ecdsa256{}}:
      "ecdsa256"
    case _:
      "none"

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{file, tail}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(file)
        value : Maybe<&1, X.Signature> = X.signature(bytes)
        output : String = show_signature(value)
        IO.print(output)
        dispatch(tail)

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
