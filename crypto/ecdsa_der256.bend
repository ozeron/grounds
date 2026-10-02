import Base
import ./bytes.bend as B
import ./p256.bend as P

# Strict DER ECDSA-Sig-Value = SEQUENCE { r INTEGER, s INTEGER }.
# P-256 integers need at most 33 octets with a single necessary sign pad.
# All lengths fit short form. No trailing bytes, negative/nonminimal integers,
# zero integers, out-of-order tags or long-form length aliases are accepted.
# This is the signature boundary only, not a general certificate/ASN.1 parser.

def pad(left: Nat, bytes: List<&2, U32>) -> List<&2, U32>:
  match left:
    case 0n:
      bytes
    case 1n+p:
      pad(p, Con{0, bytes})

def integer.nonzero(bytes: List<&2, U32>, scalar: Maybe<&1, List<&2, U32>>) -> Maybe<&1, List<&2, U32>>:
  match scalar:
    case None{}:
      None{}
    case Some{_}:
      Some{bytes}

def integer.range(+bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  integer.nonzero(bytes, P.private_scalar(bytes))

def integer.pad(valid: Bool, +bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      integer.range(pad(Nat.sub(32n, B.length(bytes)), bytes))

def integer.minimal(bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match bytes:
    case Con{0, Con{+next, +tail}}:
      integer.pad(Bool.and(U32.is_ge(next, 128), Nat.is_le(B.length(Con{next, tail}), 32n)), Con{next, tail})
    case Con{+first, +tail}:
      integer.pad(Bool.and(U32.is_lt(first, 128), Nat.is_le(B.length(Con{first, tail}), 32n)), Con{first, tail})
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

def decode.second(first: Maybe<&1, List<&2, U32>>, pair: List<&2, U32> & List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  (second, rest) = pair
  decode.end(first, integer.minimal(second), rest)

def decode.second_length(valid: Bool, first: Maybe<&1, List<&2, U32>>, count: U32,
                         bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      decode.second(first, take(U32.to_nat(count), bytes, []))

def decode.second_tag(first: Maybe<&1, List<&2, U32>>, rest: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match rest:
    case Con{2, Con{+count, bytes}}:
      decode.second_length(Bool.and(U32.is_ge(count, 1), U32.is_le(count, 33)), first, count, bytes)
    case _:
      None{}

def decode.first(pair: List<&2, U32> & List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  (first, rest) = pair
  decode.second_tag(integer.minimal(first), rest)

def decode.first_length(valid: Bool, count: U32, bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      decode.first(take(U32.to_nat(count), bytes, []))

def decode.body(valid: Bool, bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid bytes:
    case True{} Con{2, Con{+count, rest}}:
      decode.first_length(Bool.and(U32.is_ge(count, 1), U32.is_le(count, 33)), count, rest)
    case _ _:
      None{}

def decode.profile(valid: Bool, bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid bytes:
    case True{} Con{48, Con{+count, +body}}:
      decode.body(Bool.and(U32.is_le(count, 70), Nat.is_eq(B.length(body), U32.to_nat(count))), body)
    case _ _:
      None{}

def decode(+bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  decode.profile(Bool.and(B.valid(bytes), Nat.is_le(B.length(bytes), 72n)), bytes)

# Encoding requires validated 32-byte BE scalars from signature generation.
def trim(bytes: List<&2, U32>) -> List<&2, U32>:
  match bytes:
    case Con{0, tail}:
      trim(tail)
    case bytes:
      bytes

def integer.sign(pad: Bool, bytes: List<&2, U32>) -> List<&2, U32>:
  match pad:
    case False{}:
      bytes
    case True{}:
      Con{0, bytes}

def integer.encode(bytes: List<&2, U32>) -> List<&2, U32>:
  match bytes:
    case Con{+first, +tail}:
      integer.sign(U32.is_ge(first, 128), Con{first, tail})
    case Nil{}:
      [0]

def encoded.integer(+bytes: List<&2, U32>) -> List<&2, U32>:
  Con{2, Con{U32.from_nat(B.length(bytes)), bytes}}

def encoded.sequence(+bytes: List<&2, U32>) -> List<&2, U32>:
  Con{48, Con{U32.from_nat(B.length(bytes)), bytes}}

def encode.parts(first: List<&2, U32>, second: List<&2, U32>) -> List<&2, U32>:
  encoded.sequence(B.append(encoded.integer(integer.encode(trim(first))), encoded.integer(integer.encode(trim(second)))))

def encode.split(pair: List<&2, U32> & List<&2, U32>) -> List<&2, U32>:
  (first, second) = pair
  encode.parts(List.reverse(&2, U32, first), second)

def encode(signature: List<&2, U32>) -> List<&2, U32>:
  encode.split(P.split_x(32n, signature, []))
