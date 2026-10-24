import Base
import ./ecdsa_der.bend as D
import ./p256.bend as P
import ./bytes.bend as B

# Shared strict DER parser plus this curve's nonzero scalar range check.
def scalar_ok(value: Maybe<&1, List<&2, U32>>) -> Bool:
  match value:
    case None{}: False{}
    case Some{_}: True{}

def checked(valid: Bool, bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid:
    case False{}: None{}
    case True{}: Some{bytes}

def parts(+bytes: List<&2, U32>, pair: List<&2, U32> & List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  (r, s) = pair
  checked(Bool.and(scalar_ok(P.private_scalar(List.reverse(&2, U32, r))),
    scalar_ok(P.private_scalar(s))), bytes)

def parsed(value: Maybe<&1, List<&2, U32>>) -> Maybe<&1, List<&2, U32>>:
  match value:
    case None{}: None{}
    case Some{+bytes}: parts(bytes, P.split_x(32n, bytes, []))

def decode(bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  parsed(D.decode(32n, bytes))

# Encoding requires validated 32-byte BE scalars from signature generation.
def trim(bytes: List<&2, U32>) -> List<&2, U32>:
  match bytes:
    case Con{0, tail}:
      trim(tail)
    case bytes:
      bytes

def integer.sign(pad: Bool, bytes: List<&2, U32>) -> List<&2, U32>:
  match pad:
    case False{}:
      bytes
    case True{}:
      Con{0, bytes}

def integer.encode(bytes: List<&2, U32>) -> List<&2, U32>:
  match bytes:
    case Con{+first, +tail}:
      integer.sign(U32.is_ge(first, 128), Con{first, tail})
    case Nil{}:
      [0]

def encoded.integer(+bytes: List<&2, U32>) -> List<&2, U32>:
  Con{2, Con{U32.from_nat(B.length(bytes)), bytes}}

def encoded.sequence(+bytes: List<&2, U32>) -> List<&2, U32>:
  Con{48, Con{U32.from_nat(B.length(bytes)), bytes}}

def encode.parts(first: List<&2, U32>, second: List<&2, U32>) -> List<&2, U32>:
  encoded.sequence(B.append(encoded.integer(integer.encode(trim(first))), encoded.integer(integer.encode(trim(second)))))

def encode.split(pair: List<&2, U32> & List<&2, U32>) -> List<&2, U32>:
  (first, second) = pair
  encode.parts(List.reverse(&2, U32, first), second)

def encode(signature: List<&2, U32>) -> List<&2, U32>:
  encode.split(P.split_x(32n, signature, []))
