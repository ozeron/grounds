import Base
import ./rsa_signature256.bend as S
import ./bytes.bend as B

def modulus_fixture() -> List<&2, U32>:
  Con{128, B.append(List.replicate(U32, 254n, 0), [1])}

def strips_required_zero() -> {S.pss.strip(True{}, [0, 1]) == Some{[1]} : Maybe<&2, List<&2, U32>>}:
  {==}

def preserves_full_width() -> {S.pss.strip(False{}, [1, 2]) == Some{[1, 2]} : Maybe<&2, List<&2, U32>>}:
  {==}

def rejects_nonzero_width_prefix() -> {Maybe.is_none(&2, List<&2, U32>, S.pss.strip(True{}, [1, 0])) == True{} : Bool}:
  {==}

def rejects_empty_width_prefix() -> {Maybe.is_none(&2, List<&2, U32>, S.pss.strip(True{}, [])) == True{} : Bool}:
  {==}

def rejects_non_byte_pss_digest() -> {S.verify_pss_digest(modulus_fixture(), [3], Con{256, List.replicate(U32, 31n, 0)}, List.replicate(U32, 256n, 0)) == False{} : Bool}:
  {==}

def rejects_non_byte_v15_digest() -> {S.verify_v15_digest(modulus_fixture(), [3], Con{256, List.replicate(U32, 31n, 0)}, List.replicate(U32, 256n, 0)) == False{} : Bool}:
  {==}
