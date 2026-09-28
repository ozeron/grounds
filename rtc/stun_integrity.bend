import Base
import ./stun.bend as Stun
import ../crypto/hmac_sha1.bend as Hmac
import ../crypto/bytes.bend as B

# RFC 8489 section 14.5 legacy MESSAGE-INTEGRITY. The HMAC covers the
# header (with length adjusted through this attribute) and the attributes
# before MESSAGE-INTEGRITY, excluding its own header and value.
type Found is Data:
  Missing{}
  One{mac: List<&2, U32>}
  Invalid{}

def found.one(ok: Bool, found: Found, value: List<&2, U32>) -> Found:
  match ok found:
    case True{} Missing{}:
      One{value}
    case _ _:
      Invalid{}

def found.kind(kind: U32, +value: List<&2, U32>, found: Found) -> Found:
  match kind:
    case 8:
      found.one(Nat.is_eq(B.length(value), 20n), found, value)
    case 28:
      Invalid{}
    case _:
      found

def find(attrs: List<&2, Stun.Attribute>, found: Found) -> Found:
  match attrs:
    case Nil{}:
      found
    case Con{Stun.Attribute{+kind, value}, tail}:
      find(tail, found.kind(kind, value, found))

type Location is Data:
  NoLocation{}
  At{offset: Nat}

def advance(t: Stun.Taken, +offset: Nat,
            next: List<&2, U32> -> Nat -> Location) -> Location:
  match t:
    case Stun.Took{_, rest}:
      next(rest, offset)
    case Stun.Short{}:
      NoLocation{}

def scan.kind(is_integrity: Bool, rest: List<&2, U32>, +length: Nat,
              +offset: Nat, next: List<&2, U32> -> Nat -> Location) -> Location:
  match is_integrity:
    case True{}:
      At{offset}
    case False{}:
      +pad = Nat.mod(Nat.sub(4n, Nat.mod(length, 4n)), 4n)
      advance(Stun.take(rest, Nat.add(length, pad), []), Nat.add(offset, Nat.add(4n, Nat.add(length, pad))), next)

def scan(fuel: Nat, body: List<&2, U32>, +offset: Nat) -> Location:
  match fuel:
    case 0n:
      NoLocation{}
    case 1n+p:
      match body:
        case Nil{}:
          NoLocation{}
        case Con{+a, Con{+b, Con{+c, Con{+d, rest}}}}:
          scan.kind(U32.is_eq((a * 256 + b : U32), 8), rest,
            U32.to_nat((c * 256 + d : U32)), offset,
            tail => new_offset => scan(p, tail, new_offset))
        case _:
          NoLocation{}

def location.body(+body: List<&2, U32>) -> Location:
  scan(Nat.add(Nat.div(B.length(body), 4n), 1n), body, 0n)

def location.head(t: Stun.Taken) -> Location:
  match t:
    case Stun.Short{}:
      NoLocation{}
    case Stun.Took{_, body}:
      location.body(body)

def location(raw: List<&2, U32>) -> Location:
  location.head(Stun.take(raw, 20n, []))

def adjusted(prefix: List<&2, U32>, +length: Nat) -> List<&2, U32>:
  match prefix:
    case Con{a, Con{b, Con{_, Con{_, rest}}}}:
      Con{a, Con{b, Con{U32.from_nat(Nat.div(length, 256n)),
        Con{U32.from_nat(Nat.mod(length, 256n)), rest}}}}
    case _:
      []

def hmac_input.taken(t: Stun.Taken, +offset: Nat) -> Maybe<&2, List<&2, U32>>:
  match t:
    case Stun.Short{}:
      None{}
    case Stun.Took{prefix, _}:
      Some{adjusted(prefix, Nat.add(offset, 24n))}

def hmac_input(raw: List<&2, U32>, +offset: Nat) -> Maybe<&2, List<&2, U32>>:
  hmac_input.taken(Stun.take(raw, Nat.add(20n, offset), []), offset)

def compare(actual: Maybe<&2, List<&2, U32>>, expected: List<&2, U32>) -> Bool:
  match actual:
    case Some{mac}:
      Stun.same(mac, expected, True{})
    case None{}:
      False{}

def with_input(input: Maybe<&2, List<&2, U32>>, key: List<&2, U32>,
               expected: List<&2, U32>) -> Bool:
  match input:
    case Some{bytes}:
      compare(Hmac.digest(key, bytes), expected)
    case None{}:
      False{}

def with_location(loc: Location, raw: List<&2, U32>, key: List<&2, U32>,
                  expected: List<&2, U32>) -> Bool:
  match loc:
    case At{+offset}:
      with_input(hmac_input(raw, offset), key, expected)
    case NoLocation{}:
      False{}

def with_found(found: Found, +raw: List<&2, U32>, key: List<&2, U32>) -> Bool:
  match found:
    case One{mac}:
      with_location(location(raw), raw, key, mac)
    case _:
      False{}

def with_packet(packet: Maybe<&2, Stun.Packet>, raw: List<&2, U32>,
                key: List<&2, U32>) -> Bool:
  match packet:
    case Some{Stun.Packet{_, _, attrs}}:
      with_found(find(attrs, Missing{}), raw, key)
    case None{}:
      False{}

def verify(+raw: List<&2, U32>, key: List<&2, U32>) -> Bool:
  with_packet(Stun.parse(raw), raw, key)
