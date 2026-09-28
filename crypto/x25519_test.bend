import Base
import ./x25519.bend as X

def rejects_short_scalar() -> {X.scalar_mult([], X.base_point()) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def rejects_short_coordinate() -> {X.scalar_mult(List.replicate(U32, 32n, 0), []) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def rejects_out_of_range_scalar() -> {X.scalar_mult(Con{256, List.replicate(U32, 31n, 0)}, X.base_point()) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def rejects_out_of_range_coordinate() -> {X.scalar_mult(List.replicate(U32, 32n, 0), Con{256, List.replicate(U32, 31n, 0)}) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}
