import Base
import ./field256.bend as F
import ./bytes.bend as B
import ../io/io.bend as Io

def print_value(value: Array<U32>) -> IO(Unit):
  IO.print(B.hex(F.encode(value)))

def run_operation(mode: F.Mode, op: String, a: Array<U32>, b: Array<U32>) -> IO(Unit):
  match op:
    case "add":
      print_value(F.add(mode, a, b))
    case "sub":
      print_value(F.sub(mode, a, b))
    case "mul":
      print_value(F.mul(mode, a, b))
    case "ref":
      print_value(F.binary_mul(mode, a, b))
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
      print_value(F.decode_wide(mode, bytes))

def wide.read(mode: F.Mode, path: String) -> IO(Unit):
  do IO<Unit>:
    +bytes : List<&2, U32> <- Io.read_bytes(path)
    wide.checked(Bool.and(Nat.is_eq(B.length(bytes), 64n), B.valid(bytes)), mode, bytes)

def result(value: Maybe<&1, Array<U32>>) -> IO(Unit):
  match value:
    case None{}:
      IO.print("invalid")
    case Some{value}:
      print_value(value)

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

# Parse mode, operation and operand arity once. Return the unconsumed batch
# tail rather than duplicating every nested argument pattern for p and n.
def unary.read(mode: F.Mode, op: String, path: String) -> IO(Unit):
  match op:
    case "inv":
      invert.read(mode, path)
    case "check":
      canonical.read(mode, path)
    case _:
      wide.read(mode, path)

def consume.unary(mode: F.Mode, op: String, args: List<String>) -> IO(List<String>):
  match args:
    case Con{path, tail}:
      do IO<List<String>>:
        unary.read(mode, op, path)
        IO.pure(List<String>, tail)
    case _:
      IO.die(List<String>, 2, "field operation needs one operand file")

def consume.binary(mode: F.Mode, op: String, args: List<String>) -> IO(List<String>):
  match args:
    case Con{a, Con{b, tail}}:
      do IO<List<String>>:
        read_inputs(mode, op, a, b)
        IO.pure(List<String>, tail)
    case _:
      IO.die(List<String>, 2, "field operation needs two operand files")

def consume.operation(mode: F.Mode, +op: String, args: List<String>) -> IO(List<String>):
  match op:
    case "inv":
      consume.unary(mode, "inv", args)
    case "check":
      consume.unary(mode, "check", args)
    case "wide":
      consume.unary(mode, "wide", args)
    case _:
      consume.binary(mode, op, args)

def consume.mode(mode: String, op: String, args: List<String>) -> IO(List<String>):
  match mode:
    case "p":
      consume.operation(F.Field{}, op, args)
    case "n":
      consume.operation(F.Scalar{}, op, args)
    case _:
      IO.die(List<String>, 2, "unknown field modulus")

def dispatch(left: Nat, args: List<String>) -> IO(Unit):
  match left args:
    case _ Nil{}:
      IO.pure(Unit, Unit{})
    case Succ{left} Con{mode, Con{op, tail}}:
      do IO<Unit>:
        remaining : List<String> <- consume.mode(mode, op, tail)
        dispatch(left, remaining)
    case _ _:
      IO.die(Unit, 2, "usage: field256_cli <p|n> <operation> <operand-files>")

# More operations than can fit in an OS argument vector; explicit fuel keeps
# the loop checked when an IO helper returns the remaining arguments.
def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(1048576n, args)
