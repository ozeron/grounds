import Base
import ./x509_algorithm.bend as X
import ./der.bend as D
import ./bytes.bend as B
import ../io/io.bend as Io

def show_compatible(key: Maybe<&1, X.Key>, signature: Maybe<&1, X.Signature>) -> String:
  match key signature:
    case Some{key} Some{signature}:
      Bool.pick(String, X.compatible(key, signature), "true", "false")
    case _ _:
      "false"

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{file, Con{other, tail}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(file)
        signature : List<&2, U32> <- Io.read_bytes(other)
        IO.print(show_compatible(X.key(bytes), X.signature(signature)))
        dispatch(tail)
    case _:
      IO.die(Unit, 2, "usage: x509_binding_cli <key> <signature>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
