import Base
import ./bytes.bend as B
import ./der.bend as D
import ./x509_algorithm.bend as A
import ./rsa_integer.bend as R
import ./p256.bend as P

# Public SPKI decoding/admission only; no certificate trust or private material.
# RSA algorithm restrictions survive INTEGER normalization. EC points use the
# existing canonical, non-infinity P-256 curve validator.
type PublicKey is Data:
  Rsa{algorithm: A.Key, modulus: List<&2, U32>, exponent: List<&2, U32>}
  P256{encoded: List<&2, U32>}

def positive.checked(valid: Bool, bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid:
    case True{}:
      Some{bytes}
    case False{}:
      None{}

# Minimal positive ASN.1 INTEGER to canonical unsigned big-endian octets.
# A leading zero is allowed only when needed to suppress the sign bit.
def positive(bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match bytes:
    case Con{0, Con{+first, tail}}:
      positive.checked(U32.is_ge(first, 128), Con{first, tail})
    case Con{+first, tail}:
      positive.checked(Bool.and(U32.is_ne(first, 0), U32.is_lt(first, 128)), Con{first, tail})
    case _:
      None{}

def rsa.checked(valid: Bool, algorithm: A.Key, modulus: List<&2, U32>, exponent: List<&2, U32>) -> Maybe<&1, PublicKey>:
  match valid:
    case True{}:
      Some{Rsa{algorithm, modulus, exponent}}
    case False{}:
      None{}

# Match rsa_integer.public_operation's public modulus/exponent admission.
# No fake representative or public exponentiation is needed to decode a key.
def rsa.modulus_valid(+modulus: List<&2, U32>) -> Bool:
  Bool.and(Bool.and(B.valid(modulus), R.canonical_bytes(modulus)),
    Bool.and(Bool.and(Nat.is_ge(R.bit_length(modulus), 2048n), Nat.is_le(R.bit_length(modulus), 4096n)),
      U32.is_eq(U32.and(R.last_byte(modulus, 0), 1), 1)))

def rsa.exponent_valid(+modulus: List<&2, U32>, +exponent: List<&2, U32>) -> Bool:
  Bool.and(Bool.and(B.valid(exponent), R.canonical_bytes(exponent)),
    Bool.and(Bool.and(R.less([1], exponent), R.less(exponent, modulus)),
      U32.is_eq(U32.and(R.last_byte(exponent, 0), 1), 1)))

def rsa.valid(algorithm: A.Key, +modulus: List<&2, U32>, +exponent: List<&2, U32>) -> Maybe<&1, PublicKey>:
  rsa.checked(Bool.and(rsa.modulus_valid(modulus), rsa.exponent_valid(modulus, exponent)),
    algorithm, modulus, exponent)

def rsa.normalized(algorithm: A.Key, modulus: Maybe<&1, List<&2, U32>>, exponent: Maybe<&1, List<&2, U32>>) -> Maybe<&1, PublicKey>:
  match modulus exponent:
    case Some{modulus} Some{exponent}:
      rsa.valid(algorithm, modulus, exponent)
    case _ _:
      None{}

def rsa.exponent(algorithm: A.Key, modulus: List<&2, U32>, element: Maybe<&1, D.Element>) -> Maybe<&1, PublicKey>:
  match element:
    case Some{D.Element{2, exponent, Nil{}, _}}:
      rsa.normalized(algorithm, positive(modulus), positive(exponent))
    case _:
      None{}

def rsa.modulus(algorithm: A.Key, element: Maybe<&1, D.Element>) -> Maybe<&1, PublicKey>:
  match element:
    case Some{D.Element{2, modulus, rest, _}}:
      rsa.exponent(algorithm, modulus, D.read(rest))
    case _:
      None{}

def rsa.body(algorithm: A.Key, body: Maybe<&1, List<&2, U32>>) -> Maybe<&1, PublicKey>:
  match body:
    case Some{bytes}:
      rsa.modulus(algorithm, D.read(bytes))
    case _:
      None{}

def ec.point(point: Maybe<&1, P.Point>, encoded: List<&2, U32>) -> Maybe<&1, PublicKey>:
  match point:
    case Some{_}:
      Some{P256{encoded}}
    case None{}:
      None{}

def bits(algorithm: A.Key, +bytes: List<&2, U32>) -> Maybe<&1, PublicKey>:
  match algorithm:
    case A.P256{}:
      ec.point(P.decode(bytes), bytes)
    case A.Rsa{}:
      rsa.body(A.Rsa{}, D.complete(48, bytes))
    case A.PssAny{}:
      rsa.body(A.PssAny{}, D.complete(48, bytes))
    case A.Pss256{salt}:
      rsa.body(A.Pss256{salt}, D.complete(48, bytes))

def bit_string(algorithm: A.Key, value: Maybe<&1, List<&2, U32>>) -> Maybe<&1, PublicKey>:
  match value:
    case Some{Con{0, bytes}}:
      bits(algorithm, bytes)
    case _:
      None{}

def algorithm.got(value: Maybe<&1, A.Key>, rest: List<&2, U32>) -> Maybe<&1, PublicKey>:
  match value:
    case Some{algorithm}:
      bit_string(algorithm, D.complete(3, rest))
    case _:
      None{}

def algorithm.element(value: Maybe<&1, D.Element>) -> Maybe<&1, PublicKey>:
  match value:
    case Some{D.Element{48, _, rest, encoded}}:
      algorithm.got(A.key(encoded), rest)
    case _:
      None{}

def body(value: Maybe<&1, List<&2, U32>>) -> Maybe<&1, PublicKey>:
  match value:
    case Some{bytes}:
      algorithm.element(D.read(bytes))
    case _:
      None{}

# Exact SPKI SEQUENCE: algorithm followed by an octet-aligned BIT STRING only.
# All nested read inputs come from the admitted outer encoding.
def decode(bytes: List<&2, U32>) -> Maybe<&1, PublicKey>:
  body(D.complete(48, bytes))
