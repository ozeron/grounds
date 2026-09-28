import Base
import ../wire/bytes.bend as B

# RFC 6455 frames received by a server. The caller retains its input when
# More{} is returned and appends the next read before parsing again.
type Parsed is Data:
  More{}
  Bad{code: U32}
  Frame{fin: Bool, opcode: U32, payload: B.Bytes, rest: B.Bytes}

type Head is Data:
  HMore{}
  HBad{code: U32}
  HReady{fin: Bool, opcode: U32, size: Nat, a: U32, b: U32, c: U32, d: U32, rest: B.Bytes}

def control(+op: U32) -> Bool:
  U32.is_ge(op, 8)

def opcode_ok(+op: U32) -> Bool:
  Bool.or(U32.is_le(op, 2), Bool.or(U32.is_eq(op, 8), Bool.or(U32.is_eq(op, 9), U32.is_eq(op, 10))))

def head.ok2(bad: Bool, fin: Bool, +op: U32, +size: Nat, rest: B.Bytes) -> Head:
  match bad rest:
    case True{} _:
      HBad{1002}
    case False{} B.BCon{a, B.BCon{b, B.BCon{c, B.BCon{d, tail}}}}:
      HReady{fin, op, size, a, b, c, d, tail}
    case False{} _:
      HMore{}

def head.capped(over: Bool, bad: Bool, fin: Bool, +op: U32, +size: Nat,
                rest: B.Bytes) -> Head:
  match over:
    case True{}:
      HBad{1009}
    case False{}:
      head.ok2(bad, fin, op, size, rest)

def head.ok(+first: U32, +second: U32, +size: Nat, rest: B.Bytes) -> Head:
  +op = U32.and(first, 15)
  +fin = U32.is_ge(first, 128)
  head.capped(Nat.is_gt(size, 1048576n),
    Bool.or(Bool.or(Bool.not(U32.is_eq(U32.and(first, 112), 0)), Bool.not(opcode_ok(op))),
      Bool.or(Bool.not(U32.is_ge(second, 128)),
        Bool.and(control(op), Bool.or(Bool.not(fin), Nat.is_gt(size, 125n))))),
    fin, op, size, rest)

def size.finish(short: Bool, +first: U32, +second: U32, +size: Nat, rest: B.Bytes) -> Head:
  match short:
    case True{}:
      HBad{1002}
    case False{}:
      head.ok(first, second, size, rest)

def size.more(bs: B.Bytes, left: Nat, +size: Nat, +first: U32, +second: U32,
              +minimum: Nat) -> Head:
  match bs:
    case B.BNil{}:
      match left:
        case 0n:
          size.finish(Nat.is_lt(size, minimum), first, second, size, B.BNil{})
        case 1n+_:
          HMore{}
    case B.BCon{+byte, tail}:
      match left:
        case 0n:
          size.finish(Nat.is_lt(size, minimum), first, second, size, B.BCon{byte, tail})
        case 1n+p:
          size.more(tail, p, Nat.add(Nat.mul(size, 256n), U32.to_nat(byte)), first, second, minimum)

def head.long.high(high: Bool, +first: U32, +second: U32, bs: B.Bytes) -> Head:
  match high:
    case True{}:
      HBad{1002}
    case False{}:
      size.more(bs, 8n, 0n, first, second, 65536n)

def head.long(bs: B.Bytes, +first: U32, +second: U32) -> Head:
  match bs:
    case B.BNil{}:
      HMore{}
    case B.BCon{+byte, tail}:
      head.long.high(U32.is_ge(byte, 128), first, second, B.BCon{byte, tail})

def head.short(short: U32, +first: U32, +second: U32, tail: B.Bytes) -> Head:
  match short:
    case 126:
      size.more(tail, 2n, 0n, first, second, 126n)
    case 127:
      head.long(tail, first, second)
    case other:
      head.ok(first, second, U32.to_nat(other), tail)

def head(bs: B.Bytes) -> Head:
  match bs:
    case B.BCon{+first, B.BCon{+second, tail}}:
      head.short(U32.and(second, 127), first, second, tail)
    case _:
      HMore{}

def mask.at(+a: U32, +b: U32, +c: U32, +d: U32, +i: U32) -> U32:
  Bool.pick(U32, U32.is_eq(i, 0), a,
    Bool.pick(U32, U32.is_eq(i, 1), b, Bool.pick(U32, U32.is_eq(i, 2), c, d)))

def body(bs: B.Bytes, left: Nat, +a: U32, +b: U32, +c: U32, +d: U32, +i: U32, reversed: B.Bytes,
         fin: Bool, +op: U32) -> Parsed:
  match bs:
    case B.BNil{}:
      match left:
        case 0n:
          Frame{fin, op, B.rev(reversed), B.BNil{}}
        case 1n+_:
          More{}
    case B.BCon{+byte, tail}:
      match left:
        case 0n:
          Frame{fin, op, B.rev(reversed), B.BCon{byte, tail}}
        case 1n+p:
          body(tail, p, a, b, c, d, U32.and((i + 1 : U32), 3),
            B.BCon{U32.xor(byte, mask.at(a, b, c, d, i)), reversed}, fin, op)

def parse.head(h: Head) -> Parsed:
  match h:
    case HMore{}:
      More{}
    case HBad{code}:
      Bad{code}
    case HReady{fin, op, +size, a, b, c, d, rest}:
      body(rest, size, a, b, c, d, 0, B.BNil{}, fin, op)

def parse(bs: B.Bytes) -> Parsed:
  parse.head(head(bs))

def size(bs: B.Bytes, +n: Nat) -> Nat:
  match bs:
    case B.BNil{}:
      n
    case B.BCon{_, tail}:
      size(tail, Nat.add(n, 1n))

def byte(+n: Nat, +factor: Nat) -> U32:
  U32.from_nat(Nat.mod(Nat.div(n, factor), 256n))

def factor32() -> Nat:
  Nat.mul(65536n, 65536n)

def write.large(+op: U32, +n: Nat, payload: B.Bytes) -> B.Bytes:
  B.BCon{(op + 128 : U32), B.BCon{127,
    B.BCon{0, B.BCon{0,
      B.BCon{byte(n, Nat.mul(factor32(), 256n)), B.BCon{byte(n, factor32()),
        B.BCon{byte(n, 16777216n), B.BCon{byte(n, 65536n), B.BCon{byte(n, 256n),
          B.BCon{byte(n, 1n), payload}}}}}}}}}}

def write.medium(under: Bool, +op: U32, +n: Nat, payload: B.Bytes) -> B.Bytes:
  match under:
    case True{}:
      B.BCon{(op + 128 : U32), B.BCon{126,
        B.BCon{byte(n, 256n), B.BCon{byte(n, 1n), payload}}}}
    case False{}:
      write.large(op, n, payload)

def write.sized(short: Bool, +op: U32, +n: Nat, payload: B.Bytes) -> B.Bytes:
  match short:
    case True{}:
      B.BCon{(op + 128 : U32), B.BCon{U32.from_nat(n), payload}}
    case False{}:
      write.medium(Nat.is_lt(n, 65536n), op, n, payload)

# Server frames are always unmasked and final. A connection caps messages
# at one MiB before using this writer.
def write(+op: U32, +payload: B.Bytes) -> B.Bytes:
  write.sized(Nat.is_lt(size(payload, 0n), 126n), op, size(payload, 0n), payload)
