import Base
import ./field25519.bend as F
import ./bytes.bend as B
import ../io/io.bend as Io

def run_operation(op: String, a: Array<U32>, b: Array<U32>) -> IO(Unit):
  match op:
    case "add":
      IO.print(B.hex(F.encode(F.add(a, b))))
    case "sub":
      IO.print(B.hex(F.encode(F.sub(a, b))))
    case "mul":
      IO.print(B.hex(F.encode(F.mul(a, b))))
    case _:
      IO.die(Unit, 2, "unknown field operation")

def checked(ok: Bool, op: String, a: List<&2, U32>, b: List<&2, U32>) -> IO(Unit):
  match ok:
    case False{}:
      IO.die(Unit, 2, "field operands must be 32 bytes")
    case True{}:
      run_operation(op, F.decode(a), F.decode(b))

def check_input(op: String, +a: List<&2, U32>, +b: List<&2, U32>) -> IO(Unit):
  checked(Bool.and(Bool.and(Nat.is_eq(B.length(a), 32n), B.valid(a)),
    Bool.and(Nat.is_eq(B.length(b), 32n), B.valid(b))), op, a, b)

def read_inputs(op: String, a_path: String, b_path: String) -> IO(Unit):
  do IO<Unit>:
    a : List<&2, U32> <- Io.read_bytes(a_path)
    b : List<&2, U32> <- Io.read_bytes(b_path)
    check_input(op, a, b)

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{op, Con{a, Con{b, Nil{}}}}:
      read_inputs(op, a, b)
    case _:
      IO.die(Unit, 2, "usage: field_cli <add|sub|mul> <a-file> <b-file>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
