import Base
import ./aes128.bend as A

def zero_sbox() -> {A.sbox(0) == 99 : U32}:
  {==}

def rejects_bad_key_byte() -> {A.encrypt(Con{256, List.replicate(U32, 15n, 0)}, List.replicate(U32, 16n, 0)) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def rejects_bad_block_byte() -> {A.encrypt(List.replicate(U32, 16n, 0), Con{4294967295, List.replicate(U32, 15n, 0)}) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}
