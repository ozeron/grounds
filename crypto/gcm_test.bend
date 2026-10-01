import Base
import ./gcm.bend as G

def bit_length_zero() -> {G.length64(0n) == [0, 0, 0, 0, 0, 0, 0, 0] : List<&2, U32>}:
  {==}

def bit_length_one() -> {G.length64(1n) == [0, 0, 0, 0, 0, 0, 0, 8] : List<&2, U32>}:
  {==}

def rejects_bad_key() -> {G.seal(Con{256, List.replicate(U32, 15n, 0)}, List.replicate(U32, 12n, 0), [], []) == None{} : Maybe<&2, G.Sealed>}:
  {==}

def rejects_bad_nonce() -> {G.seal(List.replicate(U32, 16n, 0), Con{256, List.replicate(U32, 11n, 0)}, [], []) == None{} : Maybe<&2, G.Sealed>}:
  {==}

def rejects_bad_aad() -> {G.seal(List.replicate(U32, 16n, 0), List.replicate(U32, 12n, 0), [256], []) == None{} : Maybe<&2, G.Sealed>}:
  {==}

def rejects_bad_plaintext() -> {G.seal(List.replicate(U32, 16n, 0), List.replicate(U32, 12n, 0), [], [4294967295]) == None{} : Maybe<&2, G.Sealed>}:
  {==}

def rejects_bad_ciphertext() -> {G.open(List.replicate(U32, 16n, 0), List.replicate(U32, 12n, 0), [], [256], List.replicate(U32, 16n, 0)) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def rejects_bad_tag() -> {G.open(List.replicate(U32, 16n, 0), List.replicate(U32, 12n, 0), [], [], Con{256, List.replicate(U32, 15n, 0)}) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}
