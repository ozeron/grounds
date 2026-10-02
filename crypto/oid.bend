import Base
import ./der.bend as D

# Canonical base-128 subidentifiers, including the combined first two arcs.
# Keep encoded contents so arbitrarily large arc values never overflow U32.
def scan(bytes: List<&2, U32>, +start: Bool, valid: Bool) -> Bool:
  match bytes:
    case Nil{}:
      Bool.and(start, valid)
    case Con{+byte, rest}:
      scan(rest, U32.is_lt(byte, 128),
        Bool.and(valid, Bool.not(Bool.and(start, U32.is_eq(byte, 128)))))

# Internal: the parent DER decoder already admitted every octet.
def contents(bytes: List<&2, U32>) -> Bool:
  match bytes:
    case Nil{}: False{}
    case Con{+byte, rest}:
      scan(rest, U32.is_lt(byte, 128), U32.is_ne(byte, 128))

def checked(valid: Bool, bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid:
    case True{}: Some{bytes}
    case False{}: None{}

def body(bytes: Maybe<&1, List<&2, U32>>) -> Maybe<&1, List<&2, U32>>:
  match bytes:
    case Some{+bytes}: checked(contents(bytes), bytes)
    case None{}: None{}

def decode(bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  body(D.complete(6, bytes))
