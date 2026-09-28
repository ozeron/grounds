import Base
import ./x25519.bend as X
import ./bytes.bend as B
import ../io/io.bend as Io

def emit(result: Maybe<&2, List<&2, U32>>) -> IO(Unit):
  match result:
    case None{}:
      IO.die(Unit, 1, "invalid X25519 input or all-zero shared secret")
    case Some{bytes}:
      IO.print(B.hex(bytes))

def public_file(scalar_path: String) -> IO(Unit):
  do IO<Unit>:
    scalar : List<&2, U32> <- Io.read_bytes(scalar_path)
    emit(X.public_key(scalar))

def pair_run(mode: String, scalar: List<&2, U32>, u: List<&2, U32>) -> IO(Unit):
  match mode:
    case "mult":
      emit(X.scalar_mult(scalar, u))
    case "shared":
      emit(X.shared(scalar, u))
    case _:
      IO.die(Unit, 2, "unknown X25519 operation")

def pair_files(mode: String, scalar_path: String, u_path: String) -> IO(Unit):
  do IO<Unit>:
    scalar : List<&2, U32> <- Io.read_bytes(scalar_path)
    u : List<&2, U32> <- Io.read_bytes(u_path)
    pair_run(mode, scalar, u)

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{"public", Con{scalar, Nil{}}}:
      public_file(scalar)
    case Con{mode, Con{scalar, Con{u, Nil{}}}}:
      pair_files(mode, scalar, u)
    case _:
      IO.die(Unit, 2, "usage: x25519_cli public <scalar> | mult|shared <scalar> <u>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
