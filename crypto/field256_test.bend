import Base
import ./field256.bend as F

def rejects_short() -> {Maybe.is_none(&1, Array<U32>, F.decode_canonical(F.Field{}, [])) == True{} : Bool}:
  {==}

def rejects_long() -> {Maybe.is_none(&1, Array<U32>, F.decode_canonical(F.Scalar{}, List.replicate(U32, 33n, 0))) == True{} : Bool}:
  {==}

def rejects_field_bad_byte() -> {Maybe.is_none(&1, Array<U32>, F.decode_canonical(F.Field{}, Con{256, List.replicate(U32, 31n, 0)})) == True{} : Bool}:
  {==}

def rejects_scalar_bad_byte() -> {Maybe.is_none(&1, Array<U32>, F.decode_canonical(F.Scalar{}, Con{4294967295, List.replicate(U32, 31n, 0)})) == True{} : Bool}:
  {==}
