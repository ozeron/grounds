import Base
import ./credential.bend as C
import ./pem.bend as P
import ../io/io.bend as Io

def show(value: Result<&2, &1, P.Error, C.Credential>) -> String:
  match value:
    case Done{_}:
      "ok"
    case Fail{P.Encrypted{}}:
      "encrypted"
    case Fail{_}:
      "none"

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{leaf_path, Con{key_path, rest}}:
      do IO<Unit>:
        leaf : List<&2, U32> <- Io.read_bytes(leaf_path)
        private : List<&2, U32> <- Io.read_bytes(key_path)
        IO.print(show(C.import_pem(leaf, private)))
        dispatch(rest)
    case _:
      IO.die(Unit, 2, "usage: credential_cli <leaf.der> <key.pem> ...")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- Io.args()
    dispatch(args)
