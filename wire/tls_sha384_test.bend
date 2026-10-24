import Base
import ./tls_schedule.bend as S
import ./tls_handshake_codec.bend as C
import ../crypto/bytes.bend as B

def hash384_width() -> {S.bytes_hash(List.replicate(U32,48n,0)) == True{} : Bool}:
  {==}

def rejects_hash383() -> {S.bytes_hash(List.replicate(U32,47n,0)) == False{} : Bool}:
  {==}

def encodes_finished384() -> {C.finished(List.replicate(U32,48n,0)) == Some{B.append([20,0,0,48],List.replicate(U32,48n,0))} : Maybe<&2,List<&2,U32>>}:
  {==}

def parses_finished384() -> {C.parse(B.append([20,0,0,48],List.replicate(U32,48n,0))) == Done{C.Finished{List.replicate(U32,48n,0)}} : Result<&2,&2,U32,C.Message>}:
  {==}
