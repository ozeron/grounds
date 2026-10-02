import Base
import ./rsa_integer.bend as R
import ./bytes.bend as B
import ../io/io.bend as Io

def emit(bytes: List<&2, U32>) -> IO(Unit):
  IO.print(B.hex(bytes))

def emit_maybe(value: Maybe<&2, List<&2, U32>>) -> IO(Unit):
  match value:
    case None{}:
      IO.print("invalid")
    case Some{bytes}:
      emit(bytes)

def mont.low(+length: Nat, +limbs: Nat, a: Array<U32>, b: Array<U32>, pair: Array<U32> & U32) -> IO(Unit):
  (modulus, low) = pair
  emit(R.result.encode(length, R.mont(limbs, R.inverse_low(low), modulus, a, b)))

def mont(modulus_path: String, a_path: String, b_path: String) -> IO(Unit):
  do IO<Unit>:
    +modulus : List<&2, U32> <- Io.read_bytes(modulus_path)
    a : List<&2, U32> <- Io.read_bytes(a_path)
    b : List<&2, U32> <- Io.read_bytes(b_path)
    mont.low(B.length(modulus), Nat.div(Nat.add(R.bit_length(modulus), 14n), 15n), R.decode(a), R.decode(b), Array.get(U32, R.decode(modulus), 0))

def r_squared(path: String) -> IO(Unit):
  do IO<Unit>:
    +modulus : List<&2, U32> <- Io.read_bytes(path)
    emit(R.result.encode(B.length(modulus), R.r2(R.bit_length(modulus), Nat.div(Nat.add(R.bit_length(modulus), 14n), 15n), R.decode(modulus))))

def operation(minimum: Nat, modulus_path: String, exponent_path: String, representative_path: String) -> IO(Unit):
  do IO<Unit>:
    modulus : List<&2, U32> <- Io.read_bytes(modulus_path)
    exponent : List<&2, U32> <- Io.read_bytes(exponent_path)
    representative : List<&2, U32> <- Io.read_bytes(representative_path)
    emit_maybe(R.operation(minimum, modulus, exponent, representative))

def inverse.got(pair: Array<U32> & U32) -> IO(Unit):
  (_, value) = pair
  IO.print(U32.show(R.inverse_low(value)))

def inverse(path: String) -> IO(Unit):
  do IO<Unit>:
    bytes : List<&2, U32> <- Io.read_bytes(path)
    inverse.got(Array.get(U32, R.decode(bytes), 0))

def round_trip(path: String) -> IO(Unit):
  do IO<Unit>:
    +bytes : List<&2, U32> <- Io.read_bytes(path)
    emit(R.encode(B.length(bytes), R.decode(bytes)))

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{"0", Con{path, tail}}:
      do IO<Unit>:
        round_trip(path)
        dispatch(tail)
    case Con{"1", Con{path, tail}}:
      do IO<Unit>:
        inverse(path)
        dispatch(tail)
    case Con{"2", Con{n, Con{a, Con{b, tail}}}}:
      do IO<Unit>:
        mont(n, a, b)
        dispatch(tail)
    case Con{"3", Con{n, tail}}:
      do IO<Unit>:
        r_squared(n)
        dispatch(tail)
    case Con{"4", Con{n, Con{e, Con{s, tail}}}}:
      do IO<Unit>:
        operation(2048n, n, e, s)
        dispatch(tail)
    case Con{"5", Con{n, Con{e, Con{s, tail}}}}:
      do IO<Unit>:
        operation(2n, n, e, s)
        dispatch(tail)
    case _:
      IO.die(Unit, 2, "usage: rsa_integer_cli <operation> <files>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
