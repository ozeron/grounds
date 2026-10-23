import Base
import ./bytes.bend as B

# One bounded, canonical PEM object. No encrypted-key support or PEM headers.
# Labels are bound to DER schema selection by private_key.bend. Maximum DER
# size is crypto/der.bend's 65535 bytes; text is bounded before conversion.
type Label is Data:
  Pkcs8{}
  Sec1{}
  Pkcs1{}
  Certificate{}

type Error is Data:
  Malformed{}
  Encrypted{}
  TooLarge{}

type Block is Type:
  Block{label: Label, der: List<&2, U32>}

def digit(+c: U32) -> U32:
  Bool.pick(U32, Bool.and(U32.is_ge(c, 65), U32.is_le(c, 90)), U32.sub(c, 65),
    Bool.pick(U32, Bool.and(U32.is_ge(c, 97), U32.is_le(c, 122)), U32.sub(c, 71),
      Bool.pick(U32, Bool.and(U32.is_ge(c, 48), U32.is_le(c, 57)), U32.add(c, 4),
        Bool.pick(U32, U32.is_eq(c, 43), 62, Bool.pick(U32, U32.is_eq(c, 47), 63, 64)))))

def two(a: U32, b: U32) -> U32:
  U32.or(U32.shln(a, 2n), U32.shrn(b, 4n))

def three(b: U32, c: U32) -> U32:
  U32.or(U32.shln(U32.and(b, 15), 4n), U32.shrn(c, 2n))

def four(c: U32, d: U32) -> U32:
  U32.or(U32.shln(U32.and(c, 3), 6n), d)

def base64.end(valid: Bool, reversed: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid:
    case True{}:
      Some{List.reverse(&2, U32, reversed)}
    case False{}:
      None{}

def base64.step(valid: Bool, +a: U32, +b: U32, +c: U32, d: U32, rest: List<&2, U32>, reversed: List<&2, U32>, next: List<&2, U32> -> List<&2, U32> -> Maybe<&1, List<&2, U32>>) -> Maybe<&1, List<&2, U32>>:
  match valid:
    case True{}:
      next(rest, Con{four(c, d), Con{three(b, c), Con{two(a, b), reversed}}})
    case False{}:
      None{}

def base64.go(fuel: Nat, bytes: List<&2, U32>, reversed: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match fuel:
    case 0n:
      None{}
    case 1n+p:
      match bytes:
        case Nil{}:
          Some{List.reverse(&2, U32, reversed)}
        case [a, b, 61, 61]:
          +aa = digit(a)
          +bb = digit(b)
          base64.end(Bool.and(Bool.and(U32.is_lt(aa, 64), U32.is_lt(bb, 64)), U32.is_eq(U32.and(bb, 15), 0)), Con{two(aa, bb), reversed})
        case [a, b, c, 61]:
          +aa = digit(a)
          +bb = digit(b)
          +cc = digit(c)
          base64.end(Bool.and(Bool.and(U32.is_lt(aa, 64), U32.is_lt(bb, 64)), Bool.and(U32.is_lt(cc, 64), U32.is_eq(U32.and(cc, 3), 0))), Con{three(bb, cc), Con{two(aa, bb), reversed}})
        case Con{a, Con{b, Con{c, Con{d, rest}}}}:
          +aa = digit(a)
          +bb = digit(b)
          +cc = digit(c)
          +dd = digit(d)
          base64.step(Bool.and(Bool.and(U32.is_lt(aa, 64), U32.is_lt(bb, 64)), Bool.and(U32.is_lt(cc, 64), U32.is_lt(dd, 64))), aa, bb, cc, dd, rest, reversed, r => acc => base64.go(p, r, acc))
        case _:
          None{}

def base64(+bytes: List<&2, U32>, reversed: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  base64.go(Nat.add(B.length(bytes), 1n), bytes, reversed)

def line(bytes: List<&2, U32>, reversed: String) -> String & List<&2, U32>:
  match bytes:
    case Con{10, rest}:
      (String.reverse(reversed), rest)
    case Con{13, Con{10, rest}}:
      (String.reverse(reversed), rest)
    case Con{byte, rest}:
      line(rest, SCon{Char.from_u32(byte), reversed})
    case Nil{}:
      (String.reverse(reversed), [])

def same_text(a: String, b: String) -> Bool:
  match a b:
    case SNil{} SNil{}:
      True{}
    case SCon{Chr{x}, xs} SCon{Chr{y}, ys}:
      Bool.and(U32.is_eq(x, y), same_text(xs, ys))
    case _ _:
      False{}

def footer(label: Label) -> String:
  match label:
    case Pkcs8{}:
      "-----END PRIVATE KEY-----"
    case Sec1{}:
      "-----END EC PRIVATE KEY-----"
    case Pkcs1{}:
      "-----END RSA PRIVATE KEY-----"
    case Certificate{}:
      "-----END CERTIFICATE-----"

def whitespace.go(bytes: List<&2, U32>, valid: Bool) -> Bool:
  match bytes:
    case Nil{}:
      valid
    case Con{+c, rest}:
      whitespace.go(rest, Bool.and(valid, Bool.or(Bool.or(U32.is_eq(c, 10), U32.is_eq(c, 13)), Bool.or(U32.is_eq(c, 32), U32.is_eq(c, 9)))))

def whitespace(bytes: List<&2, U32>) -> Bool:
  whitespace.go(bytes, True{})

def finish.bounded(valid: Bool, label: Label, der: List<&2, U32>) -> Result<&2, &1, Error, Block>:
  match valid:
    case True{}:
      Done{Block{label, der}}
    case False{}:
      Fail{TooLarge{}}

def finish.decoded(label: Label, value: Maybe<&1, List<&2, U32>>) -> Result<&2, &1, Error, Block>:
  match value:
    case Some{+der}:
      finish.bounded(Nat.is_le(B.length(der), 65535n), label, der)
    case None{}:
      Fail{Malformed{}}

def text.checked(valid: Bool, reversed: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid:
    case True{}:
      Some{reversed}
    case False{}:
      None{}

def text.bytes(text: String, valid: Bool, reversed: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match text:
    case SCon{Chr{+c}, tail}:
      text.bytes(tail, Bool.and(valid, Bool.or(U32.is_lt(digit(c), 64), U32.is_eq(c, 61))), Con{c, reversed})
    case SNil{}:
      text.checked(valid, reversed)

def body.append(label: Label, collected: List<&2, U32>, rest: List<&2, U32>, value: Maybe<&1, List<&2, U32>>, next: List<&2, U32> -> List<&2, U32> -> Result<&2, &1, Error, Block>) -> Result<&2, &1, Error, Block>:
  match value:
    case Some{reversed}:
      next(rest, B.append(reversed, collected))
    case None{}:
      Fail{Malformed{}}

def finish.clean(valid: Bool, label: Label, collected: List<&2, U32>) -> Result<&2, &1, Error, Block>:
  match valid:
    case True{}:
      finish.decoded(label, base64(List.reverse(&2, U32, collected), []))
    case False{}:
      Fail{Malformed{}}

def body.classify(encrypted: Bool, done: Bool, label: Label, collected: List<&2, U32>, text: String, +rest: List<&2, U32>, next: List<&2, U32> -> List<&2, U32> -> Result<&2, &1, Error, Block>) -> Result<&2, &1, Error, Block>:
  match encrypted done:
    case True{} _:
      Fail{Encrypted{}}
    case False{} True{}:
      finish.clean(whitespace(rest), label, collected)
    case False{} False{}:
      body.append(label, collected, rest, text.bytes(text, True{}, []), next)

def body.line(+label: Label, collected: List<&2, U32>, pair: String & List<&2, U32>, next: List<&2, U32> -> List<&2, U32> -> Result<&2, &1, Error, Block>) -> Result<&2, &1, Error, Block>:
  (+text, rest) = pair
  body.classify(same_text(text, "Proc-Type: 4,ENCRYPTED"), same_text(text, footer(label)), label, collected, text, rest, next)

def body.go(fuel: Nat, +label: Label, collected: List<&2, U32>, bytes: List<&2, U32>) -> Result<&2, &1, Error, Block>:
  match fuel bytes:
    case 1n+p Con{byte, rest}:
      body.line(label, collected, line(Con{byte, rest}, ""), r => acc => body.go(p, label, acc, r))
    case _ _:
      Fail{Malformed{}}

def body(label: Label, collected: List<&2, U32>, +bytes: List<&2, U32>) -> Result<&2, &1, Error, Block>:
  body.go(Nat.add(B.length(bytes), 1n), label, collected, bytes)

def header(pair: String & List<&2, U32>, next: List<&2, U32> -> Result<&2, &1, Error, Block>) -> Result<&2, &1, Error, Block>:
  (text, rest) = pair
  match text:
    case "":
      next(rest)
    case "-----BEGIN ENCRYPTED PRIVATE KEY-----":
      Fail{Encrypted{}}
    case "-----BEGIN PRIVATE KEY-----":
      body(Pkcs8{}, [], rest)
    case "-----BEGIN EC PRIVATE KEY-----":
      body(Sec1{}, [], rest)
    case "-----BEGIN RSA PRIVATE KEY-----":
      body(Pkcs1{}, [], rest)
    case "-----BEGIN CERTIFICATE-----":
      body(Certificate{}, [], rest)
    case _:
      Fail{Malformed{}}

def start.go(fuel: Nat, bytes: List<&2, U32>) -> Result<&2, &1, Error, Block>:
  match fuel bytes:
    case 1n+p Con{byte, rest}:
      header(line(Con{byte, rest}, ""), r => start.go(p, r))
    case _ _:
      Fail{Malformed{}}

def start(+bytes: List<&2, U32>) -> Result<&2, &1, Error, Block>:
  start.go(Nat.add(B.length(bytes), 1n), bytes)

def decode.checked(valid: Bool, bytes: List<&2, U32>) -> Result<&2, &1, Error, Block>:
  match valid:
    case True{}:
      start(bytes)
    case False{}:
      Fail{Malformed{}}

def decode.bounded(valid: Bool, +bytes: List<&2, U32>) -> Result<&2, &1, Error, Block>:
  match valid:
    case True{}:
      decode.checked(B.valid(bytes), bytes)
    case False{}:
      Fail{TooLarge{}}

def decode(+bytes: List<&2, U32>) -> Result<&2, &1, Error, Block>:
  decode.bounded(Nat.is_le(B.length(bytes), 100000n), bytes)
