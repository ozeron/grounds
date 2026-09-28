import Base
import ./sha256.bend as Sha
import ./hmac.bend as Hmac
import ./hkdf.bend as Hkdf

def accepts_bytes() -> {Sha.valid([0, 127, 255]) == True{} : Bool}:
  {==}

def rejects_large_byte() -> {Sha.valid([0, 256]) == False{} : Bool}:
  {==}

def rotate_right() -> {Sha.rotr(1, 1n) == 2147483648 : U32}:
  {==}

def hmac_rejects_large_byte() -> {Hmac.digest([256], [1]) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def hkdf_rejects_bad_prk() -> {Hkdf.expand(1n, [0], []) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def hkdf_rejects_bad_info() -> {Hkdf.expand(1n, List.replicate(U32, 32n, 0), [256]) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def hkdf_rejects_too_long() -> {Hkdf.expand(8161n, List.replicate(U32, 32n, 0), []) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}
