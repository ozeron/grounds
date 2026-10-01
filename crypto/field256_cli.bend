import Base
import ./field256.bend as F
import ./bytes.bend as B
import ../io/io.bend as Io

def run_operation(mode: F.Mode, op: String, a: Array<U32>, b: Array<U32>) -> IO(Unit):
  match op:
    case "add":
      IO.print(B.hex(F.encode(F.add(mode, a, b))))
    case "sub":
      IO.print(B.hex(F.encode(F.sub(mode, a, b))))
    case "mul":
      IO.print(B.hex(F.encode(F.mul(mode, a, b))))
    case "ref":
      IO.print(B.hex(F.encode(F.binary_mul(mode, a, b))))
    case _:
      IO.die(Unit, 2, "unknown field operation")

def checked(ok: Bool, +mode: F.Mode, op: String, a: List<&2, U32>, b: List<&2, U32>) -> IO(Unit):
  match ok:
    case False{}:
      IO.die(Unit, 2, "field operands must be 32 bytes")
    case True{}:
      run_operation(mode, op, F.decode(mode, a), F.decode(mode, b))

def check_input(+mode: F.Mode, op: String, +a: List<&2, U32>, +b: List<&2, U32>) -> IO(Unit):
  checked(Bool.and(Bool.and(Nat.is_eq(B.length(a), 32n), B.valid(a)),
    Bool.and(Nat.is_eq(B.length(b), 32n), B.valid(b))), mode, op, a, b)

def read_inputs(mode: F.Mode, op: String, a_path: String, b_path: String) -> IO(Unit):
  do IO<Unit>:
    a : List<&2, U32> <- Io.read_bytes(a_path)
    b : List<&2, U32> <- Io.read_bytes(b_path)
    check_input(mode, op, a, b)

def wide.checked(ok: Bool, mode: F.Mode, bytes: List<&2, U32>) -> IO(Unit):
  match ok:
    case False{}:
      IO.die(Unit, 2, "wide operand must be 64 bytes")
    case True{}:
      IO.print(B.hex(F.encode(F.decode_wide(mode, bytes))))

def wide.read(mode: F.Mode, path: String) -> IO(Unit):
  do IO<Unit>:
    +bytes : List<&2, U32> <- Io.read_bytes(path)
    wide.checked(Bool.and(Nat.is_eq(B.length(bytes), 64n), B.valid(bytes)), mode, bytes)

def result(value: Maybe<&1, Array<U32>>) -> IO(Unit):
  match value:
    case None{}:
      IO.print("invalid")
    case Some{value}:
      IO.print(B.hex(F.encode(value)))

def invert.checked(valid: Bool, +mode: F.Mode, bytes: List<&2, U32>) -> IO(Unit):
  match valid:
    case False{}:
      IO.die(Unit, 2, "inverse operand must be 32 bytes")
    case True{}:
      result(F.invert(mode, F.decode(mode, bytes)))

def invert.read(mode: F.Mode, path: String) -> IO(Unit):
  do IO<Unit>:
    +bytes : List<&2, U32> <- Io.read_bytes(path)
    invert.checked(Bool.and(Nat.is_eq(B.length(bytes), 32n), B.valid(bytes)), mode, bytes)

def canonical.read(mode: F.Mode, path: String) -> IO(Unit):
  do IO<Unit>:
    bytes : List<&2, U32> <- Io.read_bytes(path)
    result(F.decode_canonical(mode, bytes))

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{"p", Con{"inv", Con{a, tail}}}:
      do IO<Unit>:
        invert.read(F.Field{}, a)
        dispatch(tail)
    case Con{"p", Con{"check", Con{a, tail}}}:
      do IO<Unit>:
        canonical.read(F.Field{}, a)
        dispatch(tail)
    case Con{"n", Con{"inv", Con{a, tail}}}:
      do IO<Unit>:
        invert.read(F.Scalar{}, a)
        dispatch(tail)
    case Con{"n", Con{"check", Con{a, tail}}}:
      do IO<Unit>:
        canonical.read(F.Scalar{}, a)
        dispatch(tail)
    case Con{"p", Con{"wide", Con{a, tail}}}:
      do IO<Unit>:
        wide.read(F.Field{}, a)
        dispatch(tail)
    case Con{"n", Con{"wide", Con{a, tail}}}:
      do IO<Unit>:
        wide.read(F.Scalar{}, a)
        dispatch(tail)
    case Con{"p", Con{op, Con{a, Con{b, tail}}}}:
      do IO<Unit>:
        read_inputs(F.Field{}, op, a, b)
        dispatch(tail)
    case Con{"n", Con{op, Con{a, Con{b, tail}}}}:
      do IO<Unit>:
        read_inputs(F.Scalar{}, op, a, b)
        dispatch(tail)
    case _:
      IO.die(Unit, 2, "usage: field256_cli <p|n> <add|sub|mul|ref> <a-file> <b-file>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
