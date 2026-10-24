import Base
import ./sha512.bend as S
import ./sha512_stream.bend as Stream
import ./sha384.bend as T
import ./hmac_sha384.bend as H
import ./hkdf_sha384.bend as K

def sha512_bad_byte() -> {S.digest([256]) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def sha384_bad_byte() -> {T.digest([0, 4294967295]) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def hmac_bad_key() -> {H.digest([256], []) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def hmac_bad_message() -> {H.digest([], [256]) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def hkdf_short_prk() -> {K.expand(1n, [], []) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def stream_large_length() -> {Stream.bit_length(4294967295, 4294967295) == [0, 0, 0, 0, 0, 0, 0, 7, 255, 255, 255, 255, 255, 255, 255, 248] : List<&2, U32>}:
  {==}

def stream_length_carry() -> {Stream.bit_length(536870912, 0) == [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0] : List<&2, U32>}:
  {==}
