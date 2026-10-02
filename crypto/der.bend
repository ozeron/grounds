import Base
import ./bytes.bend as B

# Bounded TLV framing for certificate schemas, not a complete ASN.1 validator.
# Single-octet tags; minimal definite lengths; at most 65535 input octets.
# Keep the exact consumed encoding so certificate signatures can hash original
# bytes. Schema owners must validate primitive values, nesting and field order.
type Element is Type:
  Element{tag: U32, body: List<&2, U32>, rest: List<&2, U32>, encoded: List<&2, U32>}

def take(left: Nat, +tag: U32, header: List<&2, U32>, bytes: List<&2, U32>, reversed: List<&2, U32>) -> Maybe<&1, Element>:
  match left bytes:
    case 0n rest:
      +body = List.reverse(&2, U32, reversed)
      Some{Element{tag, body, rest, B.append(header, body)}}
    case 1n+p Con{byte, tail}:
      take(p, tag, header, tail, Con{byte, reversed})
    case _ _:
      None{}

def length.checked(valid: Bool, tag: U32, header: List<&2, U32>, count: U32, bytes: List<&2, U32>) -> Maybe<&1, Element>:
  match valid:
    case False{}:
      None{}
    case True{}:
      take(U32.to_nat(count), tag, header, bytes, [])

def length(+tag: U32, bytes: List<&2, U32>) -> Maybe<&1, Element>:
  match bytes:
    case Con{129, Con{+count, rest}}:
      length.checked(U32.is_ge(count, 128), tag, [tag, 129, count], count, rest)
    case Con{130, Con{+high, Con{+low, rest}}}:
      length.checked(U32.is_ne(high, 0), tag, [tag, 130, high, low], U32.add(U32.mul(high, 256), low), rest)
    case Con{+count, rest}:
      length.checked(U32.is_lt(count, 128), tag, [tag, count], count, rest)
    case _:
      None{}

# Internal: bytes already admitted by decode or taken from its valid bodies.
def read.checked(valid: Bool, tag: U32, rest: List<&2, U32>) -> Maybe<&1, Element>:
  match valid:
    case False{}:
      None{}
    case True{}:
      length(tag, rest)

def read(bytes: List<&2, U32>) -> Maybe<&1, Element>:
  match bytes:
    case Con{+tag, rest}:
      read.checked(Bool.and(U32.is_ne(U32.and(tag, 31), 31), U32.is_ne(U32.and(tag, 223), 0)), tag, rest)
    case _:
      None{}

def decode.checked(valid: Bool, bytes: List<&2, U32>) -> Maybe<&1, Element>:
  match valid:
    case False{}:
      None{}
    case True{}:
      read(bytes)

def decode(+bytes: List<&2, U32>) -> Maybe<&1, Element>:
  decode.checked(Bool.and(Nat.is_le(B.length(bytes), 65535n), B.valid(bytes)), bytes)

def complete.checked(valid: Bool, body: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      Some{body}

def complete.got(tag: U32, element: Maybe<&1, Element>) -> Maybe<&1, List<&2, U32>>:
  match element:
    case Some{Element{actual, body, Nil{}, _}}:
      complete.checked(U32.is_eq(tag, actual), body)
    case _:
      None{}

def complete(tag: U32, bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  complete.got(tag, decode(bytes))
