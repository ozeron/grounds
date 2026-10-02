import Base
import ./p256.bend as P
import ./field256.bend as F
import ./bytes.bend as B

# ECDSA P-256 digest verification. Internal signatures are r_BE32 || s_BE32;
# the TLS/certificate DER boundary is a separate parser. Both integers must
# lie in 1..n-1. The public key uses strict uncompressed SEC1 validation.
# Fixed point schedules are not a generated-code timing/erasure certification.

def scalar.bytes(value: Maybe<&1, List<&2, U32>>) -> Maybe<&1, Array<U32>>:
  match value:
    case None{}:
      None{}
    case Some{bytes}:
      Some{F.decode(F.Scalar{}, bytes)}

def scalar.strict(bytes: List<&2, U32>) -> Maybe<&1, Array<U32>>:
  scalar.bytes(P.private_scalar(bytes))

def verify.x(r: Array<U32>, pair: List<&2, U32> & List<&2, U32>) -> Bool:
  (x, _) = pair
  P.difference.zero(F.zero.go(32n, 0, F.ZeroScan{F.sub(F.Scalar{}, F.decode(F.Scalar{}, x), r), 0}))

def verify.point(r: Array<U32>, encoded: Maybe<&1, List<&2, U32>>) -> Bool:
  match encoded:
    case Some{Con{4, coordinates}}:
      verify.x(r, P.split_x(32n, coordinates, []))
    case _:
      False{}

def verify.products(r: Array<U32>, first: Array<U32>, second: Array<U32>, peer: P.Point) -> Bool:
  verify.point(r, P.encode(P.add(P.multiply(F.encode(first), P.generator()), P.multiply(F.encode(second), peer))))

def verify.scalars(r_pair: Array<U32> & Array<U32>, digest: Array<U32>, peer: P.Point,
                   w_pair: Array<U32> & Array<U32>) -> Bool:
  (r, r_product) = r_pair
  (w_first, w_second) = w_pair
  verify.products(r, F.mul(F.Scalar{}, digest, w_first), F.mul(F.Scalar{}, r_product, w_second), peer)

def verify.inverse(r: Array<U32>, digest: Array<U32>, peer: P.Point, w: Maybe<&1, Array<U32>>) -> Bool:
  match w:
    case None{}:
      False{}
    case Some{w}:
      verify.scalars(Array.clone(U32, r), digest, peer, Array.clone(U32, w))

def verify.validated(peer: Maybe<&1, P.Point>, r: Maybe<&1, Array<U32>>,
                     s: Maybe<&1, Array<U32>>, digest: List<&2, U32>) -> Bool:
  match peer r s:
    case Some{peer} Some{r} Some{s}:
      verify.inverse(r, F.decode(F.Scalar{}, List.reverse(&2, U32, digest)), peer, F.invert(F.Scalar{}, s))
    case _ _ _:
      False{}

def verify.signature(peer: List<&2, U32>, digest: List<&2, U32>,
                     pair: List<&2, U32> & List<&2, U32>) -> Bool:
  (r_reversed, s) = pair
  verify.validated(P.decode(peer), scalar.strict(List.reverse(&2, U32, r_reversed)), scalar.strict(s), digest)

def verify.profile(valid: Bool, peer: List<&2, U32>, digest: List<&2, U32>, signature: List<&2, U32>) -> Bool:
  match valid:
    case False{}:
      False{}
    case True{}:
      verify.signature(peer, digest, P.split_x(32n, signature, []))

# SHA-256 digest is exactly 32 valid bytes. Its integer may be >=n; ECDSA
# scalar arithmetic reduces it, while signature/private scalars never alias.
def verify_digest(peer: List<&2, U32>, +digest: List<&2, U32>, +signature: List<&2, U32>) -> Bool:
  verify.profile(Bool.and(Bool.and(Nat.is_eq(B.length(digest), 32n), B.valid(digest)),
    Bool.and(Nat.is_eq(B.length(signature), 64n), B.valid(signature))), peer, digest, signature)
