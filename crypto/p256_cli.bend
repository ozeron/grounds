import Base
import ./p256.bend as P
import ./field256.bend as F
import ./bytes.bend as B
import ../io/io.bend as Io

def result(value: Maybe<&1, List<&2, U32>>) -> IO(Unit):
  match value:
    case None{}:
      IO.print("invalid")
    case Some{bytes}:
      IO.print(B.hex(bytes))

def public.read(path: String) -> IO(Unit):
  do IO<Unit>:
    bytes : List<&2, U32> <- Io.read_bytes(path)
    result(P.public_key(bytes))

def shared.read(private_path: String, peer_path: String) -> IO(Unit):
  do IO<Unit>:
    private : List<&2, U32> <- Io.read_bytes(private_path)
    peer : List<&2, U32> <- Io.read_bytes(peer_path)
    result(P.shared(private, peer))

def check.result(point: Maybe<&1, P.Point>) -> IO(Unit):
  match point:
    case None{}:
      IO.print("invalid")
    case Some{point}:
      result(P.encode(point))

def check.read(path: String) -> IO(Unit):
  do IO<Unit>:
    bytes : List<&2, U32> <- Io.read_bytes(path)
    check.result(P.decode(bytes))

# Synthetic group-test adapter: 00 denotes infinity only for add/mul input.
# Public SEC1 decoding never accepts this test-only encoding.
def group.decode(bytes: List<&2, U32>) -> Maybe<&1, P.Point>:
  match bytes:
    case Con{0, Nil{}}:
      Some{P.infinity()}
    case bytes:
      P.decode(bytes)

def add.points(first: Maybe<&1, P.Point>, second: Maybe<&1, P.Point>) -> IO(Unit):
  match first second:
    case Some{first} Some{second}:
      result(P.encode(P.add(first, second)))
    case _ _:
      IO.print("invalid")

def add.read(first_path: String, second_path: String) -> IO(Unit):
  do IO<Unit>:
    first : List<&2, U32> <- Io.read_bytes(first_path)
    second : List<&2, U32> <- Io.read_bytes(second_path)
    add.points(group.decode(first), group.decode(second))

def multiply.points(valid: Bool, scalar: List<&2, U32>, point: Maybe<&1, P.Point>) -> IO(Unit):
  match valid point:
    case True{} Some{point}:
      result(P.encode(P.multiply(scalar, point)))
    case _ _:
      IO.print("invalid")

def multiply.read(scalar_path: String, peer_path: String) -> IO(Unit):
  do IO<Unit>:
    +scalar : List<&2, U32> <- Io.read_bytes(scalar_path)
    peer : List<&2, U32> <- Io.read_bytes(peer_path)
    multiply.points(Bool.and(Nat.is_eq(B.length(scalar), 32n), B.valid(scalar)), scalar, group.decode(peer))

# Projective inputs are exactly X_BE32 || Y_BE32 || Z_BE32. Only this
# arithmetic test adapter exposes them; the checker supplies valid curve
# representatives, including nonzero rescalings of infinity.
def projective.coordinates(x: Maybe<&1, Array<U32>>, y: Maybe<&1, Array<U32>>,
                           z: Maybe<&1, Array<U32>>) -> Maybe<&1, P.Point>:
  match x y z:
    case Some{x} Some{y} Some{z}:
      Some{P.Point{P.to_mont(x), P.to_mont(y), P.to_mont(z)}}
    case _ _ _:
      None{}

def projective.y(x: List<&2, U32>, pair: List<&2, U32> & List<&2, U32>) -> Maybe<&1, P.Point>:
  (y, z) = pair
  projective.coordinates(F.decode_canonical(F.Field{}, x), F.decode_canonical(F.Field{}, y),
    F.decode_canonical(F.Field{}, List.reverse(&2, U32, z)))

def projective.x(pair: List<&2, U32> & List<&2, U32>) -> Maybe<&1, P.Point>:
  (x, rest) = pair
  projective.y(x, P.split_x(32n, rest, []))

def projective.checked(valid: Bool, bytes: List<&2, U32>) -> Maybe<&1, P.Point>:
  match valid:
    case False{}:
      None{}
    case True{}:
      projective.x(P.split_x(32n, bytes, []))

def projective.decode(+bytes: List<&2, U32>) -> Maybe<&1, P.Point>:
  projective.checked(Bool.and(Nat.is_eq(B.length(bytes), 96n), B.valid(bytes)), bytes)

def projective.read(first_path: String, second_path: String) -> IO(Unit):
  do IO<Unit>:
    first : List<&2, U32> <- Io.read_bytes(first_path)
    second : List<&2, U32> <- Io.read_bytes(second_path)
    add.points(projective.decode(first), projective.decode(second))

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{"pub", Con{path, tail}}:
      do IO<Unit>:
        public.read(path)
        dispatch(tail)
    case Con{"check", Con{path, tail}}:
      do IO<Unit>:
        check.read(path)
        dispatch(tail)
    case Con{"shared", Con{a, Con{b, tail}}}:
      do IO<Unit>:
        shared.read(a, b)
        dispatch(tail)
    case Con{"add", Con{a, Con{b, tail}}}:
      do IO<Unit>:
        add.read(a, b)
        dispatch(tail)
    case Con{"projective", Con{a, Con{b, tail}}}:
      do IO<Unit>:
        projective.read(a, b)
        dispatch(tail)
    case Con{"mul", Con{a, Con{b, tail}}}:
      do IO<Unit>:
        multiply.read(a, b)
        dispatch(tail)
    case _:
      IO.die(Unit, 2, "usage: p256_cli <pub|check|shared|add|projective|mul> <files>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
