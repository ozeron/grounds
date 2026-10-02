import Base
import ./rsa_encoding.bend as E

def rejects_non_byte_digest() -> {Maybe.is_none(&2, List<&2, U32>, E.v15_encode_digest(128n, Con{256, List.replicate(U32, 31n, 0)})) == True{} : Bool}:
  {==}

def rejects_non_byte_salt() -> {Maybe.is_none(&2, List<&2, U32>, E.pss_encode_digest(1023n, List.replicate(U32, 32n, 0), Con{256, List.replicate(U32, 31n, 0)})) == True{} : Bool}:
  {==}

def rejects_non_byte_encoded() -> {E.pss_verify_digest(1023n, List.replicate(U32, 32n, 0), Con{256, List.replicate(U32, 127n, 0)}) == False{} : Bool}:
  {==}

def rejects_non_byte_seed() -> {Maybe.is_none(&2, List<&2, U32>, E.mgf1(1n, [256])) == True{} : Bool}:
  {==}

def rejects_huge_pss_count() -> {Maybe.is_none(&2, List<&2, U32>, E.pss_encode_digest(Nat.add(Nat.mul(4294967295n, 65536n), 65535n), List.replicate(U32, 32n, 0), List.replicate(U32, 32n, 0))) == True{} : Bool}:
  {==}

def rejects_short_pss_count() -> {Maybe.is_none(&2, List<&2, U32>, E.pss_encode_digest(520n, List.replicate(U32, 32n, 0), List.replicate(U32, 32n, 0))) == True{} : Bool}:
  {==}

def rejects_short_v15_padding() -> {Maybe.is_none(&2, List<&2, U32>, E.v15_encode_digest(61n, List.replicate(U32, 32n, 0))) == True{} : Bool}:
  {==}

def rejects_non_byte_pss_encoding_digest() -> {Maybe.is_none(&2, List<&2, U32>, E.pss_encode_digest(1023n, Con{256, List.replicate(U32, 31n, 0)}, List.replicate(U32, 32n, 0))) == True{} : Bool}:
  {==}

def rejects_non_byte_pss_verification_digest() -> {E.pss_verify_digest(1023n, Con{256, List.replicate(U32, 31n, 0)}, List.replicate(U32, 128n, 0)) == False{} : Bool}:
  {==}

def rejects_non_byte_v15_verification_digest() -> {E.v15_verify_digest(Con{256, List.replicate(U32, 31n, 0)}, List.replicate(U32, 128n, 0)) == False{} : Bool}:
  {==}

def rejects_non_byte_v15_encoded() -> {E.v15_verify_digest(List.replicate(U32, 32n, 0), Con{256, List.replicate(U32, 127n, 0)}) == False{} : Bool}:
  {==}
