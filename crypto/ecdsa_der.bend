import Base
import ./bytes.bend as B

# Strict DER ECDSA-Sig-Value = SEQUENCE { r INTEGER, s INTEGER }.
# Shared P-256/P-384 DER shape parser. Callers validate scalar range.
# Integers have at most width+1 octets with a necessary sign pad.
# For the admitted widths (32/48), all lengths fit short form. No trailing bytes, negative/nonminimal integers,
# out-of-order tags or long-form length aliases are accepted.
# This is the signature boundary only, not a general certificate/ASN.1 parser.

def pad(left: Nat, bytes: List<&2, U32>) -> List<&2, U32>:
  match left:
    case 0n:
      bytes
    case 1n+p:
      pad(p, Con{0, bytes})

def integer.pad(+width: Nat, valid: Bool, +bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      Some{pad(Nat.sub(width, B.length(bytes)), bytes)}

def integer.minimal(+width: Nat, bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match bytes:
    case Con{0, Con{+next, +tail}}:
      integer.pad(width, Bool.and(U32.is_ge(next, 128), Nat.is_le(B.length(Con{next, tail}), width)), Con{next, tail})
    case Con{+first, +tail}:
      integer.pad(width, Bool.and(U32.is_lt(first, 128), Nat.is_le(B.length(Con{first, tail}), width)), Con{first, tail})
    case Nil{}:
      None{}

def take(left: Nat, bytes: List<&2, U32>, reversed: List<&2, U32>) -> List<&2, U32> & List<&2, U32>:
  match left bytes:
    case 0n bytes:
      (List.reverse(&2, U32, reversed), bytes)
    case 1n+p Con{byte, tail}:
      take(p, tail, Con{byte, reversed})
    case _ _:
      ([], [])

def decode.combine(first: Maybe<&1, List<&2, U32>>, second: Maybe<&1, List<&2, U32>>) -> Maybe<&1, List<&2, U32>>:
  match first second:
    case Some{first} Some{second}:
      Some{B.append(first, second)}
    case _ _:
      None{}

def decode.end(first: Maybe<&1, List<&2, U32>>, second: Maybe<&1, List<&2, U32>>, rest: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match rest:
    case Nil{}:
      decode.combine(first, second)
    case _:
      None{}

def decode.second(+width: Nat, first: Maybe<&1, List<&2, U32>>, pair: List<&2, U32> & List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  (second, rest) = pair
  decode.end(first, integer.minimal(width, second), rest)

def decode.second_length(+width: Nat, valid: Bool, first: Maybe<&1, List<&2, U32>>, count: U32,
                         bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      decode.second(width, first, take(U32.to_nat(count), bytes, []))

def decode.second_tag(+width: Nat, first: Maybe<&1, List<&2, U32>>, rest: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match rest:
    case Con{2, Con{+count, bytes}}:
      decode.second_length(width, Bool.and(U32.is_ge(count, 1), U32.is_le(count, U32.from_nat(Nat.add(width, 1n)))), first, count, bytes)
    case _:
      None{}

def decode.first(+width: Nat, pair: List<&2, U32> & List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  (first, rest) = pair
  decode.second_tag(width, integer.minimal(width, first), rest)

def decode.first_length(+width: Nat, valid: Bool, count: U32, bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      decode.first(width, take(U32.to_nat(count), bytes, []))

def decode.body(+width: Nat, valid: Bool, bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid bytes:
    case True{} Con{2, Con{+count, rest}}:
      decode.first_length(width, Bool.and(U32.is_ge(count, 1), U32.is_le(count, U32.from_nat(Nat.add(width, 1n)))), count, rest)
    case _ _:
      None{}

def decode.profile(+width: Nat, valid: Bool, bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid bytes:
    case True{} Con{48, Con{+count, +body}}:
      decode.body(width, Bool.and(U32.is_le(count, U32.from_nat(Nat.add(Nat.mul(width, 2n), 6n))), Nat.is_eq(B.length(body), U32.to_nat(count))), body)
    case _ _:
      None{}

def decode(+width: Nat, +bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  decode.profile(width, Bool.and(Bool.or(Nat.is_eq(width, 32n), Nat.is_eq(width, 48n)), Bool.and(B.valid(bytes), Nat.is_le(B.length(bytes), Nat.add(Nat.mul(width, 2n), 8n)))), bytes)

