import Base
import ./p256.bend as P

def rejects_empty_peer() -> {Maybe.is_none(&1, P.Point, P.decode([])) == True{} : Bool}:
  {==}

def rejects_infinity_peer() -> {Maybe.is_none(&1, P.Point, P.decode([0])) == True{} : Bool}:
  {==}

def rejects_peer_non_byte() -> {Maybe.is_none(&1, P.Point, P.decode(Con{4, Con{256, List.replicate(U32, 63n, 0)}})) == True{} : Bool}:
  {==}

def rejects_private_non_byte() -> {Maybe.is_none(&1, List<&2, U32>, P.private_scalar(Con{4294967295, List.replicate(U32, 31n, 0)})) == True{} : Bool}:
  {==}
