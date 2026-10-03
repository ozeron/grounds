import Base
import ./x509_eku.bend as K

def empty_list() -> {K.decode([48, 0]) == None{} : Maybe<&1, List<&2, List<&2, U32>>>}:
  {==}

def duplicate_purposes() -> {K.decode([48, 6, 6, 1, 42, 6, 1, 42]) == Some{[[42], [42]]} : Maybe<&1, List<&2, List<&2, U32>>>}:
  {==}

def absent_invalid_query() -> {K.permits(None{}, [], False{}) == False{} : Bool}:
  {==}

def exact_any() -> {K.any([85, 29, 37, 0]) == True{} : Bool}:
  {==}

def any_not_prefix() -> {K.any([85, 29, 37, 0, 0]) == False{} : Bool}:
  {==}

def nonbyte() -> {K.decode([48, 3, 6, 1, 298]) == None{} : Maybe<&1, List<&2, List<&2, U32>>>}:
  {==}
