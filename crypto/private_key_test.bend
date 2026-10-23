import Base
import ./private_key.bend as K

def rejects_empty_pkcs8() -> {K.pkcs8([48, 0]) == None{} : Maybe<&1, K.Private>}:
  {==}

def rejects_multiprime_rsa() -> {K.pkcs1([48, 3, 2, 1, 1]) == None{} : Maybe<&1, K.Private>}:
  {==}

def rejects_sec1_without_curve() -> {K.sec1(False{}, [48, 7, 2, 1, 1, 4, 2, 0, 1]) == None{} : Maybe<&1, K.Private>}:
  {==}
