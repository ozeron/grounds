import Base
import ./traffic.bend as T

def bad_secret() -> {Maybe.is_none(&1, T.WriteKey, T.new_write(Con{256, List.replicate(U32, 31n, 0)})) == True{} : Bool}:
  {==}

def bad_label_byte() -> {T.expand_label(List.replicate(U32, 32n, 0), [256], [], 32n) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def bad_context_byte() -> {T.expand_label(List.replicate(U32, 32n, 0), [107], [256], 32n) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}
