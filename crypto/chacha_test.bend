import Base
import ./chacha20.bend as C

def quarter_round() -> {C.quarter(C.Quarter{286331153, 16909060, 2609737539, 19088743}) == C.Quarter{3928658676, 3407673550, 1166100270, 1484899515} : C.Quarter}:
  {==}

def block_rejects_bad_byte() -> {C.block(Con{256, List.replicate(U32, 31n, 0)}, List.replicate(U32, 12n, 0), 0) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def crypt_rejects_bad_byte() -> {C.crypt(List.replicate(U32, 32n, 0), List.replicate(U32, 12n, 0), 0, [256]) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}
