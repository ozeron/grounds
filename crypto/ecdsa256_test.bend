import Base
import ./ecdsa256.bend as E
import ./ecdsa_sign256.bend as S
import ./ecdsa_der256.bend as D

# Malformed byte values cannot be represented by an OS file, so these closed
# checks exercise the actual U32 API profile rather than only CLI fixtures.
def generator_bytes() -> List<&2, U32>:
  [4, 107, 23, 209, 242, 225, 44, 66, 71, 248, 188, 230, 229, 99, 164, 64, 242, 119, 3, 125, 129, 45, 235, 51, 160, 244, 161, 57, 69, 216, 152, 194, 150, 79, 227, 66, 226, 254, 26, 127, 155, 142, 231, 235, 74, 124, 15, 158, 22, 43, 206, 51, 87, 107, 49, 94, 206, 203, 182, 64, 104, 55, 191, 81, 245]

def rejects_bad_digest_byte() -> {E.verify_digest(generator_bytes(), Con{256, List.replicate(U32, 31n, 0)}, List.replicate(U32, 64n, 1)) == False{} : Bool}:
  {==}

def rejects_bad_signature_byte() -> {E.verify_digest(generator_bytes(), List.replicate(U32, 32n, 0), Con{4294967295, List.replicate(U32, 63n, 1)}) == False{} : Bool}:
  {==}

def rejects_signing_bad_private_byte() -> {Maybe.is_none(&1, List<&2, U32>, S.sign_digest(Con{256, List.replicate(U32, 31n, 1)}, List.replicate(U32, 32n, 0))) == True{} : Bool}:
  {==}

def rejects_signing_bad_digest_byte() -> {Maybe.is_none(&1, List<&2, U32>, S.sign_digest(List.replicate(U32, 32n, 1), Con{256, List.replicate(U32, 31n, 0)})) == True{} : Bool}:
  {==}

def rejects_der_non_byte() -> {Maybe.is_none(&1, List<&2, U32>, D.decode([48, 6, 2, 1, 256, 2, 1, 1])) == True{} : Bool}:
  {==}

def exhausted_nonce_search_fails() -> {Maybe.is_none(&1, List<&2, U32>, S.search.go(0n, [], [], S.SignAgain{S.Nonce{[], []}})) == True{} : Bool}:
  {==}
