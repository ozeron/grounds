import Base
import ./x25519.bend as X
import ./bytes.bend as B
import ../io/io.bend as Io

type Operation is Data:
  Public{}
  Mult{}
  Shared{}
  Unknown{}

# Consume operation names instead of expanding long String literal patterns.
def operation.step(equal: Bool, next: Unit -> Operation) -> Operation:
  match equal:
    case False{}:
      Unknown{}
    case True{}:
      next(Unit{})

def operation.word(expected: String, actual: String, known: Operation) -> Operation:
  match expected actual:
    case SNil{} SNil{}:
      known
    case SCon{a, expected} SCon{b, actual}:
      operation.step(Char.is_eq(a, b), _ => operation.word(expected, actual, known))
    case _ _:
      Unknown{}

def operation(mode: String) -> Operation:
  match mode:
    case SCon{'p', tail}:
      operation.word("ublic", tail, Public{})
    case SCon{'m', tail}:
      operation.word("ult", tail, Mult{})
    case SCon{'s', tail}:
      operation.word("hared", tail, Shared{})
    case _:
      Unknown{}

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

def pair_kind(mode: Operation, scalar: List<&2, U32>, u: List<&2, U32>) -> IO(Unit):
  match mode:
    case Mult{}:
      emit(X.scalar_mult(scalar, u))
    case Shared{}:
      emit(X.shared(scalar, u))
    case _:
      IO.die(Unit, 2, "unknown X25519 operation")

def pair_run(mode: String, scalar: List<&2, U32>, u: List<&2, U32>) -> IO(Unit):
  pair_kind(operation(mode), scalar, u)

def pair_files(mode: String, scalar_path: String, u_path: String) -> IO(Unit):
  do IO<Unit>:
    scalar : List<&2, U32> <- Io.read_bytes(scalar_path)
    u : List<&2, U32> <- Io.read_bytes(u_path)
    pair_run(mode, scalar, u)

def public_kind(mode: Operation, scalar: String) -> IO(Unit):
  match mode:
    case Public{}:
      public_file(scalar)
    case _:
      IO.die(Unit, 2, "usage: x25519_cli public <scalar> | mult|shared <scalar> <u>")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{mode, Con{scalar, Nil{}}}:
      public_kind(operation(mode), scalar)
    case Con{mode, Con{scalar, Con{u, Nil{}}}}:
      pair_files(mode, scalar, u)
    case _:
      IO.die(Unit, 2, "usage: x25519_cli public <scalar> | mult|shared <scalar> <u>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
