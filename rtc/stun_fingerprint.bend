import Base
import ./stun.bend as Stun
import ../crypto/bytes.bend as B

# RFC 8489 section 14.7. CRC-32 uses the reflected IEEE polynomial;
# FINGERPRINT covers the original header length and every preceding byte.
def bit(left: Nat, +crc: U32) -> U32:
  match left:
    case 0n:
      crc
    case 1n+p:
      +shifted = U32.shrn(crc, 1n)
      next = Bool.pick(U32, U32.is_eq(U32.and(crc, 1), 1),
        U32.xor(shifted, 3988292384), shifted)
      bit(p, next)

def crc(bytes: List<&2, U32>, +state: U32) -> U32:
  match bytes:
    case Nil{}:
      U32.xor(state, 4294967295)
    case Con{+byte, tail}:
      crc(tail, bit(8n, U32.xor(state, byte)))

def value(bytes: List<&2, U32>) -> U32:
  U32.xor(crc(bytes, 4294967295), 1398035790)

def last(attrs: List<&2, Stun.Attribute>) -> Maybe<&2, U32>:
  match attrs:
    case Nil{}:
      None{}
    case Con{Stun.Attribute{32808, [a, b, c, d]}, Nil{}}:
      Some{U32.or(U32.or(U32.or(U32.shln(a, 24n), U32.shln(b, 16n)),
        U32.shln(c, 8n)), d)}
    case Con{Stun.Attribute{32808, _}, _}:
      None{}
    case Con{_, tail}:
      last(tail)

def compare(t: Stun.Taken, +expected: U32) -> Bool:
  match t:
    case Stun.Took{prefix, _}:
      U32.is_eq(value(prefix), expected)
    case Stun.Short{}:
      False{}

def with_last(found: Maybe<&2, U32>, +raw: List<&2, U32>) -> Bool:
  match found:
    case Some{+expected}:
      compare(Stun.take(raw, Nat.sub(B.length(raw), 8n), []), expected)
    case None{}:
      False{}

def with_packet(parsed: Maybe<&2, Stun.Packet>, raw: List<&2, U32>) -> Bool:
  match parsed:
    case Some{Stun.Packet{_, _, attrs}}:
      with_last(last(attrs), raw)
    case None{}:
      False{}

def verify(+raw: List<&2, U32>) -> Bool:
  with_packet(Stun.parse(raw), raw)
