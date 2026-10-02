import Base
import ./x509_certificate.bend as C
import ./x509_algorithm.bend as A

def nonbyte() -> {C.decode([48, 1, 256]) == None{} : Maybe<&1, C.Certificate>}:
  {==}

def mismatched_algorithms() -> {C.same_algorithm(A.RsaV15256{}, A.RsaPss256{}) == False{} : Bool}:
  {==}

def serial_sign_alias() -> {C.integer([0, 127]) == False{} : Bool}:
  {==}

def serial_negative_alias() -> {C.integer([255, 128]) == False{} : Bool}:
  {==}

def uid_padding() -> {C.bit_string([3, 7]) == False{} : Bool}:
  {==}

def uid_padding_valid() -> {C.bit_string([3, 8]) == True{} : Bool}:
  {==}
