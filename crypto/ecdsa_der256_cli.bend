import Base
import ./ecdsa_der256.bend as D
import ./bytes.bend as B
import ../io/io.bend as Io

def result(value: Maybe<&1, List<&2, U32>>) -> IO(Unit):
  match value:
    case None{}:
      IO.print("invalid")
    case Some{value}:
      IO.print(B.hex(value))

def encoded.valid(encoded: List<&2, U32>, decoded: Maybe<&1, List<&2, U32>>) -> IO(Unit):
  match decoded:
    case None{}:
      IO.print("invalid")
    case Some{_}:
      IO.print(B.hex(encoded))

def encode.result(+bytes: List<&2, U32>) -> IO(Unit):
  encoded.valid(bytes, D.decode(bytes))

def encode.checked(valid: Bool, bytes: List<&2, U32>) -> IO(Unit):
  match valid:
    case False{}:
      IO.print("invalid")
    case True{}:
      encode.result(D.encode(bytes))

def operation(mode: String, +bytes: List<&2, U32>) -> IO(Unit):
  match mode:
    case "encode":
      encode.checked(Bool.and(Nat.is_eq(B.length(bytes), 64n), B.valid(bytes)), bytes)
    case "decode":
      result(D.decode(bytes))
    case _:
      IO.die(Unit, 2, "unknown DER operation")

def read(mode: String, path: String) -> IO(Unit):
  do IO<Unit>:
    bytes : List<&2, U32> <- Io.read_bytes(path)
    operation(mode, bytes)

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{mode, Con{path, tail}}:
      do IO<Unit>:
        read(mode, path)
        dispatch(tail)
    case _:
      IO.die(Unit, 2, "usage: ecdsa_der256_cli <encode|decode> <file>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
