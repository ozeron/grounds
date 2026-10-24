import Base
import ./ecdsa384.bend as E
import ./ecdsa_der384.bend as D

def rejects_bad_digest_byte() -> {E.verify_digest([], Con{256, List.replicate(U32, 47n, 0)}, List.replicate(U32, 96n, 1)) == False{} : Bool}:
  {==}

def rejects_bad_signature_byte() -> {E.verify_digest([], List.replicate(U32, 48n, 0), Con{4294967295, List.replicate(U32, 95n, 1)}) == False{} : Bool}:
  {==}

def rejects_der_non_byte() -> {Maybe.is_none(&1, List<&2, U32>, D.decode([48, 6, 2, 1, 256, 2, 1, 1])) == True{} : Bool}:
  {==}
