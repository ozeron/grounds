import Base
import ./tls_handshake_stream.bend as S

def empty_clean() -> {S.finish(S.start()) == True{} : Bool}:
  {==}

def partial_header() -> {S.finish(S.Decoder{S.Header{[1], 1n}, 1n}) == False{} : Bool}:
  {==}

def partial_body() -> {S.finish(S.Decoder{S.Body{11, [0, 0, 1, 11], 1n}, 4n}) == False{} : Bool}:
  {==}

def uint24() -> {S.length(0, 0, 3) == 3n : Nat}:
  {==}

def finished_alignment() -> {S.aligned_kind(20) == True{} : Bool}:
  {==}

def certificate_unaligned() -> {S.aligned_kind(11) == False{} : Bool}:
  {==}
