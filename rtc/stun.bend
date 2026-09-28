import Base
import ../crypto/bytes.bend as B

# RFC 8489 STUN datagrams. This module parses the common wire envelope and
# attributes; ICE credential checks and transactions are separate work.
type Attribute is Data:
  Attribute{kind: U32, value: List<&2, U32>}

type Packet is Data:
  Packet{kind: U32, transaction: List<&2, U32>, attributes: List<&2, Attribute>}

type Taken is Data:
  Took{front: List<&2, U32>, rest: List<&2, U32>}
  Short{}

def take(xs: List<&2, U32>, left: Nat, reversed: List<&2, U32>) -> Taken:
  match xs:
    case Nil{}:
      match left:
        case 0n:
          Took{List.reverse(&2, U32, reversed), []}
        case 1n+_:
          Short{}
    case Con{+byte, tail}:
      match left:
        case 0n:
          Took{List.reverse(&2, U32, reversed), Con{byte, tail}}
        case 1n+p:
          take(tail, p, Con{byte, reversed})

type Attrs is Data:
  AOk{items: List<&2, Attribute>}
  ABad{}

def attr.padded(t: Taken, +kind: U32, value: List<&2, U32>,
                reversed: List<&2, Attribute>, next: List<&2, U32> -> List<&2, Attribute> -> Attrs) -> Attrs:
  match t:
    case Short{}:
      ABad{}
    case Took{_, rest}:
      next(rest, Con{Attribute{kind, value}, reversed})

def attr.value(t: Taken, +kind: U32, +pad: Nat,
               reversed: List<&2, Attribute>, next: List<&2, U32> -> List<&2, Attribute> -> Attrs) -> Attrs:
  match t:
    case Short{}:
      ABad{}
    case Took{value, rest}:
      attr.padded(take(rest, pad, []), kind, value, reversed, next)

def attrs(fuel: Nat, bytes: List<&2, U32>, reversed: List<&2, Attribute>) -> Attrs:
  match fuel:
    case 0n:
      ABad{}
    case 1n+p:
      match bytes:
        case Nil{}:
          AOk{List.reverse(&2, Attribute, reversed)}
        case Con{+a, Con{+b, Con{+c, Con{+d, rest}}}}:
          +length = (c * 256 + d : U32)
          +pad = Nat.mod(Nat.sub(4n, Nat.mod(U32.to_nat(length), 4n)), 4n)
          attr.value(take(rest, U32.to_nat(length), []), (a * 256 + b : U32), pad,
            reversed, tail => rev => attrs(p, tail, rev))
        case _:
          ABad{}

def parsed(attributes: Attrs, +kind: U32, transaction: List<&2, U32>) -> Maybe<&2, Packet>:
  match attributes:
    case AOk{items}:
      Some{Packet{kind, transaction, items}}
    case ABad{}:
      None{}

def header.ok(ok: Bool, +kind: U32, transaction: List<&2, U32>, +body: List<&2, U32>) -> Maybe<&2, Packet>:
  match ok:
    case True{}:
      parsed(attrs(Nat.add(Nat.div(B.length(body), 4n), 1n), body, []), kind, transaction)
    case False{}:
      None{}

def header.got(+first: U32, +second: U32, +length: Nat,
               transaction: List<&2, U32>, +body: List<&2, U32>) -> Maybe<&2, Packet>:
  header.ok(Bool.and(Bool.and(U32.is_le(first, 63), Nat.is_eq(Nat.mod(length, 4n), 0n)),
    Nat.is_eq(B.length(body), length)), (first * 256 + second : U32), transaction, body)

def header.transaction(t: Taken, +first: U32, +second: U32, +length: Nat) -> Maybe<&2, Packet>:
  match t:
    case Short{}:
      None{}
    case Took{transaction, body}:
      header.got(first, second, length, transaction, body)

def parse.raw(bytes: List<&2, U32>) -> Maybe<&2, Packet>:
  match bytes:
    case Con{+first, Con{+second, Con{+hi, Con{+lo,
         Con{33, Con{18, Con{164, Con{66, tail}}}}}}}}:
      header.transaction(take(tail, 12n, []), first, second, U32.to_nat((hi * 256 + lo : U32)))
    case _:
      None{}

def parse.checked(ok: Bool, bytes: List<&2, U32>) -> Maybe<&2, Packet>:
  match ok:
    case True{}:
      parse.raw(bytes)
    case False{}:
      None{}

def parse(+bytes: List<&2, U32>) -> Maybe<&2, Packet>:
  parse.checked(B.valid(bytes), bytes)

def binding_request.ok(ok: Bool, transaction: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case True{}:
      Some{B.append([0, 1, 0, 0, 33, 18, 164, 66], transaction)}
    case False{}:
      None{}

def binding_request(+transaction: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  binding_request.ok(Bool.and(Nat.is_eq(B.length(transaction), 12n), B.valid(transaction)), transaction)

type IPv4 is Data:
  IPv4{a: U32, b: U32, c: U32, d: U32, port: U32}

def xor_ipv4(attr: Attribute) -> Maybe<&2, IPv4>:
  match attr:
    case Attribute{32, Con{0, Con{1, Con{+p, Con{+q,
         Con{+a, Con{+b, Con{+c, Con{+d, Nil{}}}}}}}}}}:
      Some{IPv4{U32.xor(a, 33), U32.xor(b, 18), U32.xor(c, 164), U32.xor(d, 66),
        U32.xor((p * 256 + q : U32), 8466)}}
    case _:
      None{}

def mapped.go(attrs: List<&2, Attribute>) -> Maybe<&2, IPv4>:
  match attrs:
    case Nil{}:
      None{}
    case Con{Attribute{32, value}, _}:
      xor_ipv4(Attribute{32, value})
    case Con{_, tail}:
      mapped.go(tail)

def mapped_ipv4(packet: Packet) -> Maybe<&2, IPv4>:
  match packet:
    case Packet{_, _, attrs}:
      mapped.go(attrs)

def same(a: List<&2, U32>, b: List<&2, U32>, ok: Bool) -> Bool:
  match a b:
    case Nil{} Nil{}:
      ok
    case Con{+x, at} Con{+y, bt}:
      same(at, bt, Bool.and(ok, U32.is_eq(x, y)))
    case _ _:
      False{}

def binding_success(packet: Packet, transaction: List<&2, U32>) -> Bool:
  match packet:
    case Packet{+kind, got, _}:
      Bool.and(U32.is_eq(kind, 257), same(got, transaction, True{}))
