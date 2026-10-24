import Base
import ./ecdsa_der.bend as D
import ./p384.bend as P
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
  checked(Bool.and(scalar_ok(P.scalar(List.reverse(&2, U32, r))),
    scalar_ok(P.scalar(s))), bytes)

def parsed(value: Maybe<&1, List<&2, U32>>) -> Maybe<&1, List<&2, U32>>:
  match value:
    case None{}: None{}
    case Some{+bytes}: parts(bytes, P.split_x(48n, bytes, []))

def decode(bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  parsed(D.decode(48n, bytes))
