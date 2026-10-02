import Base
import ./x509_public_key.bend as K

def zero_integer() -> {K.positive([0]) == None{} : Maybe<&1, List<&2, U32>>}:
  {==}

def negative_integer() -> {K.positive([128]) == None{} : Maybe<&1, List<&2, U32>>}:
  {==}

def redundant_pad() -> {K.positive([0, 127]) == None{} : Maybe<&1, List<&2, U32>>}:
  {==}

def necessary_pad() -> {K.positive([0, 128]) == Some{[128]} : Maybe<&1, List<&2, U32>>}:
  {==}

def nonbyte() -> {K.decode([48, 1, 256]) == None{} : Maybe<&1, K.PublicKey>}:
  {==}

def empty_spki() -> {K.decode([48, 0]) == None{} : Maybe<&1, K.PublicKey>}:
  {==}
