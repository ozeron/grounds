import Base
import ./bytes.bend as B
import ./rsa_integer.bend as R
import ./rsa_encoding.bend as E

# Experimental SHA-256 digest-signature verification, entirely in Bend.
# RSA-PSS uses SHA-256/MGF1-SHA256 and exactly 32 salt bytes.
# RSA key validation/trust, AlgorithmIdentifiers and private operations remain
# the protocol/key owner's responsibility. Synthetic fixtures only for now.

def pss.strip(shorter: Bool, encoded: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match shorter encoded:
    case False{} encoded:
      Some{encoded}
    case True{} Con{0, tail}:
      Some{tail}
    case _ _:
      None{}

def pss.normalized(bits: Nat, digest: List<&2, U32>, value: Maybe<&2, List<&2, U32>>) -> Bool:
  match value:
    case None{}:
      False{}
    case Some{encoded}:
      E.pss_verify_digest(bits, digest, encoded)

def pss.recovered(+bits: Nat, digest: List<&2, U32>, result: Maybe<&2, List<&2, U32>>) -> Bool:
  match result:
    case None{}:
      False{}
    case Some{+encoded}:
      pss.normalized(bits, digest,
        pss.strip(Nat.is_ne(B.length(encoded), E.em_length(bits)), encoded))

def pss.checked(valid: Bool, +modulus: List<&2, U32>, exponent: List<&2, U32>, digest: List<&2, U32>, signature: List<&2, U32>) -> Bool:
  match valid:
    case False{}:
      False{}
    case True{}:
      pss.recovered(Nat.sub(R.bit_length(modulus), 1n), digest,
        R.public_operation(modulus, exponent, signature))

def verify_pss_digest(modulus: List<&2, U32>, exponent: List<&2, U32>, +digest: List<&2, U32>, signature: List<&2, U32>) -> Bool:
  pss.checked(E.valid_digest(digest), modulus, exponent, digest, signature)

def v15.recovered(digest: List<&2, U32>, result: Maybe<&2, List<&2, U32>>) -> Bool:
  match result:
    case None{}:
      False{}
    case Some{encoded}:
      E.v15_verify_digest(digest, encoded)

def v15.checked(valid: Bool, modulus: List<&2, U32>, exponent: List<&2, U32>, digest: List<&2, U32>, signature: List<&2, U32>) -> Bool:
  match valid:
    case False{}:
      False{}
    case True{}:
      v15.recovered(digest, R.public_operation(modulus, exponent, signature))

def verify_v15_digest(modulus: List<&2, U32>, exponent: List<&2, U32>, +digest: List<&2, U32>, signature: List<&2, U32>) -> Bool:
  v15.checked(E.valid_digest(digest), modulus, exponent, digest, signature)
