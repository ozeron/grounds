import Base
import ./aes256.bend as A
import ./gcm.bend as G

def rejects_short_key() -> {A.encrypt([],List.replicate(U32,16n,0)) == None{} : Maybe<&2,List<&2,U32>>}:
  {==}

def rejects_non_byte_key() -> {A.encrypt(Con{256,List.replicate(U32,31n,0)},List.replicate(U32,16n,0)) == None{} : Maybe<&2,List<&2,U32>>}:
  {==}

def rejects_aes192() -> {G.seal(List.replicate(U32,24n,0),List.replicate(U32,12n,0),[],[]) == None{} : Maybe<&2,G.Sealed>}:
  {==}
