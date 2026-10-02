import Base
import ./p256.bend as P
import ./field256.bend as F
import ./bytes.bend as B
import ./hmac.bend as H

# Deterministic ECDSA P-256/SHA-256 (RFC 6979 section 3.2). All inputs here
# are synthetic until optimized runtime/JIT timing and erasure are resolved.
# Candidate/retry and nonzero-result branches are algorithmically required;
# they are recorded timing-review findings, not a constant-time claim.
# Signatures use the internal fixed r_BE32 || s_BE32 representation.

def finish.valid(valid: Bool, r: Array<U32>, s: Array<U32>) -> Maybe<&1, List<&2, U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      Some{B.append(List.reverse(&2, U32, F.encode(r)), List.reverse(&2, U32, F.encode(s)))}

def finish.scanned(r: Array<U32>, pair: Array<U32> & U32) -> Maybe<&1, List<&2, U32>>:
  (s, difference) = pair
  finish.valid(U32.is_ne(difference, 0), r, s)

def finish.products(r_pair: Array<U32> & Array<U32>, private: Array<U32>,
                    digest: Array<U32>, inverse: Array<U32>) -> Maybe<&1, List<&2, U32>>:
  (r, for_product) = r_pair
  s = F.mul(F.Scalar{}, inverse, F.add(F.Scalar{}, digest, F.mul(F.Scalar{}, for_product, private)))
  finish.scanned(r, F.zero.go(32n, 0, F.ZeroScan{s, 0}))

def sign.inverse(r: Array<U32>, private: List<&2, U32>, digest: List<&2, U32>,
                 inverse: Maybe<&1, Array<U32>>) -> Maybe<&1, List<&2, U32>>:
  match inverse:
    case None{}:
      None{}
    case Some{inverse}:
      finish.products(Array.clone(U32, r), F.decode(F.Scalar{}, private),
        F.decode(F.Scalar{}, List.reverse(&2, U32, digest)), inverse)

def sign.nonzero(valid: Bool, r: Array<U32>, private: List<&2, U32>,
                 digest: List<&2, U32>, k: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      sign.inverse(r, private, digest, F.invert(F.Scalar{}, F.decode(F.Scalar{}, k)))

def sign.scanned(private: List<&2, U32>, digest: List<&2, U32>, k: List<&2, U32>,
                 pair: Array<U32> & U32) -> Maybe<&1, List<&2, U32>>:
  (r, difference) = pair
  sign.nonzero(U32.is_ne(difference, 0), r, private, digest, k)

def sign.x(private: List<&2, U32>, digest: List<&2, U32>, k: List<&2, U32>,
           pair: List<&2, U32> & List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  (x, _) = pair
  sign.scanned(private, digest, k, F.zero.go(32n, 0, F.ZeroScan{F.decode(F.Scalar{}, x), 0}))

def sign.point(private: List<&2, U32>, digest: List<&2, U32>, k: List<&2, U32>,
               encoded: Maybe<&1, List<&2, U32>>) -> Maybe<&1, List<&2, U32>>:
  match encoded:
    case Some{Con{4, coordinates}}:
      sign.x(private, digest, k, P.split_x(32n, coordinates, []))
    case _:
      None{}

# Internal precondition: private and k are canonical nonzero 32-byte LE
# scalars and digest is 32 valid BE bytes. Only the validated search calls it.
def sign.raw(private: List<&2, U32>, digest: List<&2, U32>, +k: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  sign.point(private, digest, k, P.encode(P.multiply(k, P.generator())))

type Nonce is Data:
  Nonce{key: List<&2, U32>, value: List<&2, U32>}

def reject.value(key: List<&2, U32>, value: Maybe<&2, List<&2, U32>>) -> Maybe<&2, Nonce>:
  match value:
    case None{}:
      None{}
    case Some{value}:
      Some{Nonce{key, value}}

def reject.key(value: List<&2, U32>, key: Maybe<&2, List<&2, U32>>) -> Maybe<&2, Nonce>:
  match key:
    case None{}:
      None{}
    case Some{+key}:
      reject.value(key, H.digest(key, value))

# RFC 6979 3.2(h.3), also used for the ECDSA r=0 or s=0 rejection.
def rejected(state: Nonce) -> Maybe<&2, Nonce>:
  match state:
    case Nonce{key, +value}:
      reject.key(value, H.digest(key, B.append(value, [0])))

type Search is Type:
  SignAgain{state: Nonce}
  SignDone{signature: List<&2, U32>}
  SignFailed{}

def search.rejected(state: Maybe<&2, Nonce>) -> Search:
  match state:
    case None{}:
      SignFailed{}
    case Some{state}:
      SignAgain{state}

def search.signature(state: Nonce, signature: Maybe<&1, List<&2, U32>>) -> Search:
  match signature:
    case None{}:
      search.rejected(rejected(state))
    case Some{signature}:
      SignDone{signature}

def search.candidate(state: Nonce, private: List<&2, U32>, digest: List<&2, U32>,
                     k: Maybe<&1, List<&2, U32>>) -> Search:
  match k:
    case None{}:
      search.rejected(rejected(state))
    case Some{k}:
      search.signature(state, sign.raw(private, digest, k))

def search.value(key: List<&2, U32>, private: List<&2, U32>, digest: List<&2, U32>,
                 value: Maybe<&2, List<&2, U32>>) -> Search:
  match value:
    case None{}:
      SignFailed{}
    case Some{+value}:
      search.candidate(Nonce{key, value}, private, digest, P.private_scalar(value))

# Bounded fail-closed rejection search; no candidate is reduced modulo n.
# Exhaustion returns None. This bound is not an excuse to skip rejection tests.
def search.go(left: Nat, +private: List<&2, U32>, +digest: List<&2, U32>, state: Search) -> Maybe<&1, List<&2, U32>>:
  match left state:
    case _ SignDone{signature}:
      Some{signature}
    case 1n+p SignAgain{Nonce{+key, value}}:
      search.go(p, private, digest, search.value(key, private, digest, H.digest(key, value)))
    case _ _:
      None{}

def initialized(private: List<&2, U32>, digest: List<&2, U32>, state: Maybe<&2, Nonce>) -> Maybe<&1, List<&2, U32>>:
  match state:
    case None{}:
      None{}
    case Some{state}:
      search.go(128n, private, digest, SignAgain{state})

def initialize.v2(key: List<&2, U32>, value: Maybe<&2, List<&2, U32>>) -> Maybe<&2, Nonce>:
  match value:
    case None{}:
      None{}
    case Some{value}:
      Some{Nonce{key, value}}

def initialize.k2(value: List<&2, U32>, key: Maybe<&2, List<&2, U32>>) -> Maybe<&2, Nonce>:
  match key:
    case None{}:
      None{}
    case Some{+key}:
      initialize.v2(key, H.digest(key, value))

def initialize.v1(key: List<&2, U32>, seed: List<&2, U32>, value: Maybe<&2, List<&2, U32>>) -> Maybe<&2, Nonce>:
  match value:
    case None{}:
      None{}
    case Some{+value}:
      initialize.k2(value, H.digest(key, B.append(value, Con{1, seed})))

def initialize.k1(seed: List<&2, U32>, key: Maybe<&2, List<&2, U32>>) -> Maybe<&2, Nonce>:
  match key:
    case None{}:
      None{}
    case Some{+key}:
      initialize.v1(key, seed, H.digest(key, List.replicate(U32, 32n, 1)))

def initialize(+seed: List<&2, U32>) -> Maybe<&2, Nonce>:
  initialize.k1(seed, H.digest(List.replicate(U32, 32n, 0),
    B.append(List.replicate(U32, 32n, 1), Con{0, seed})))

def sign.validated(+digest: List<&2, U32>, private: Maybe<&1, List<&2, U32>>) -> Maybe<&1, List<&2, U32>>:
  match private:
    case None{}:
      None{}
    case Some{+private}:
      private_be = List.reverse(&2, U32, private)
      reduced = List.reverse(&2, U32, F.encode(F.decode(F.Scalar{}, List.reverse(&2, U32, digest))))
      initialized(private, digest, initialize(B.append(private_be, reduced)))

def sign.profile(valid: Bool, private: List<&2, U32>, digest: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      sign.validated(digest, P.private_scalar(private))

def sign_digest(private: List<&2, U32>, +digest: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  sign.profile(Bool.and(Nat.is_eq(B.length(digest), 32n), B.valid(digest)), private, digest)
