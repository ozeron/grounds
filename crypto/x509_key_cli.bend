import Base
import ./x509_algorithm.bend as X
import ./der.bend as D
import ./bytes.bend as B
import ../io/io.bend as Io

def show_key(value: Maybe<&1, X.Key>) -> String:
  match value:
    case Some{X.Rsa{}}:
      "rsa"
    case Some{X.PssAny{}}:
      "pss-any"
    case Some{X.Pss256{salt}}:
      String.concat(["pss256-", U32.show(salt)])
    case Some{X.P256{}}:
      "p256"
    case _:
      "none"

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{file, tail}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(file)
        value : Maybe<&1, X.Key> = X.key(bytes)
        output : String = show_key(value)
        IO.print(output)
        dispatch(tail)

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
