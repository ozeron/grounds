import Base

# Unsigned integers in base 10, as digits and as text. Each digit is a
# constructor, so a law sees it; U32.show and U32.read are opaque to the
# checker. LAWS.bend states what reads back, and PROOF.bend proves it.

type Dig is Data:
  D0{}
  D1{}
  D2{}
  D3{}
  D4{}
  D5{}
  D6{}
  D7{}
  D8{}
  D9{}

# a count, least significant digit first; DNil is 0. A Dec may carry
# leading zeros (DCon{D7, DCon{D0, DNil}} is 07); trim drops them
type Dec is Data:
  DNil{}
  DCon{d: Dig, t: Dec}

# Digits
# ======

def dig.val(x: Dig) -> Nat:
  match x:
    case D0{}:
      0n
    case D1{}:
      1n
    case D2{}:
      2n
    case D3{}:
      3n
    case D4{}:
      4n
    case D5{}:
      5n
    case D6{}:
      6n
    case D7{}:
      7n
    case D8{}:
      8n
    case D9{}:
      9n

def dig.char(x: Dig) -> Char:
  match x:
    case D0{}:
      '0'
    case D1{}:
      '1'
    case D2{}:
      '2'
    case D3{}:
      '3'
    case D4{}:
      '4'
    case D5{}:
      '5'
    case D6{}:
      '6'
    case D7{}:
      '7'
    case D8{}:
      '8'
    case D9{}:
      '9'

# Counting
# ========

def value(d: Dec) -> Nat:
  match d:
    case DNil{}:
      0n
    case DCon{x, t}:
      Nat.add(dig.val(x), Nat.mul(10n, value(t)))

def inc(d: Dec) -> Dec:
  match d:
    case DNil{}:
      DCon{D1{}, DNil{}}
    case DCon{D0{}, t}:
      DCon{D1{}, t}
    case DCon{D1{}, t}:
      DCon{D2{}, t}
    case DCon{D2{}, t}:
      DCon{D3{}, t}
    case DCon{D3{}, t}:
      DCon{D4{}, t}
    case DCon{D4{}, t}:
      DCon{D5{}, t}
    case DCon{D5{}, t}:
      DCon{D6{}, t}
    case DCon{D6{}, t}:
      DCon{D7{}, t}
    case DCon{D7{}, t}:
      DCon{D8{}, t}
    case DCon{D8{}, t}:
      DCon{D9{}, t}
    case DCon{D9{}, t}:
      DCon{D0{}, inc(t)}

# Doubling
# --------
# 2x + c for one digit x and a carry c in, split into the digit kept and
# the carry out; the carry out is x >= 5 whatever c is

def dbl.dig(x: Dig, c: Bool) -> Dig:
  match x c:
    case D0{} False{}:
      D0{}
    case D0{} True{}:
      D1{}
    case D1{} False{}:
      D2{}
    case D1{} True{}:
      D3{}
    case D2{} False{}:
      D4{}
    case D2{} True{}:
      D5{}
    case D3{} False{}:
      D6{}
    case D3{} True{}:
      D7{}
    case D4{} False{}:
      D8{}
    case D4{} True{}:
      D9{}
    case D5{} False{}:
      D0{}
    case D5{} True{}:
      D1{}
    case D6{} False{}:
      D2{}
    case D6{} True{}:
      D3{}
    case D7{} False{}:
      D4{}
    case D7{} True{}:
      D5{}
    case D8{} False{}:
      D6{}
    case D8{} True{}:
      D7{}
    case D9{} False{}:
      D8{}
    case D9{} True{}:
      D9{}

def dbl.carry(x: Dig) -> Bool:
  match x:
    case D0{}:
      False{}
    case D1{}:
      False{}
    case D2{}:
      False{}
    case D3{}:
      False{}
    case D4{}:
      False{}
    case D5{}:
      True{}
    case D6{}:
      True{}
    case D7{}:
      True{}
    case D8{}:
      True{}
    case D9{}:
      True{}

# 2d + c
def dbl(d: Dec, c: Bool) -> Dec:
  match d:
    case DNil{}:
      match c:
        case True{}:
          DCon{D1{}, DNil{}}
        case False{}:
          DNil{}
    case DCon{+x, t}:
      DCon{dbl.dig(x, c), dbl(t, dbl.carry(x))}

# the bits, low bit first, doubled in from the top down
def of_word(n: Nat, w: Word(n)) -> Dec:
  match n:
    case 0n:
      DNil{}
    case 1n+p:
      match w:
        case WCon{b, t}:
          dbl(of_word(p, t), b)

# U32 and Dec
# ===========

# the digits of x, with no leading zeros; 0 is DNil
def of_u32(x: U32) -> Dec:
  match x:
    case U32{w}:
      of_word(32n, w)

# u survives the trip through U32: it is at most 2^32 - 1. A law cannot
# compare against that literal, which it would expand, but it can take a
# word apart bit by bit
def fits(+u: Nat) -> Bool:
  Nat.is_eq(U32.to_nat(U32.from_nat(u)), u)

def to_u32.keep(ok: Bool, +v: Nat) -> Maybe<&2, Nat>:
  match ok:
    case True{}:
      Some{v}
    case False{}:
      None{}

def to_u32.step(x: Dig, m: Maybe<&2, Nat>) -> Maybe<&2, Nat>:
  match m:
    case Some{v}:
      +u = Nat.add(dig.val(x), Nat.mul(10n, v))
      to_u32.keep(fits(u), u)
    case None{}:
      None{}

# the value, from the top digit down, given up once past 2^32 - 1: a Nat
# past 2^48 - 1 aborts the runtime, and a Dec may have any number of digits
def to_u32.go(d: Dec) -> Maybe<&2, Nat>:
  match d:
    case DNil{}:
      Some{0n}
    case DCon{x, t}:
      to_u32.step(x, to_u32.go(t))

def to_u32.fin(m: Maybe<&2, Nat>) -> Maybe<&2, U32>:
  match m:
    case Some{v}:
      Some{U32.from_nat(v)}
    case None{}:
      None{}

# None past 2^32 - 1
def to_u32(d: Dec) -> Maybe<&2, U32>:
  to_u32.fin(to_u32.go(d))

# Leading zeros
# =============

def trim.top(x: Dig) -> Dec:
  match x:
    case D0{}:
      DNil{}
    case y:
      DCon{y, DNil{}}

# x put under an already trimmed t: the rest decides first, so x is kept
# whenever t has digits
def trim.con(x: Dig, t: Dec) -> Dec:
  match t:
    case DNil{}:
      trim.top(x)
    case DCon{y, u}:
      DCon{x, DCon{y, u}}

def trim(d: Dec) -> Dec:
  match d:
    case DNil{}:
      DNil{}
    case DCon{x, t}:
      trim.con(x, trim(t))

# Text
# ====

# the digits, most significant first, before out
def show.go(d: Dec, out: String) -> String:
  match d:
    case DNil{}:
      out
    case DCon{x, t}:
      show.go(t, SCon{dig.char(x), out})

# the digits as written, leading zeros too; DNil is "0"
def show(d: Dec) -> String:
  match d:
    case DNil{}:
      "0"
    case DCon{x, t}:
      show.go(DCon{x, t}, "")

# the digits of s pushed onto acc, most significant first
def parse.go(s: String, acc: Dec) -> Maybe<&2, Dec>:
  match s:
    case SNil{}:
      Some{acc}
    case SCon{c, t}:
      match c:
        case '0':
          parse.go(t, DCon{D0{}, acc})
        case '1':
          parse.go(t, DCon{D1{}, acc})
        case '2':
          parse.go(t, DCon{D2{}, acc})
        case '3':
          parse.go(t, DCon{D3{}, acc})
        case '4':
          parse.go(t, DCon{D4{}, acc})
        case '5':
          parse.go(t, DCon{D5{}, acc})
        case '6':
          parse.go(t, DCon{D6{}, acc})
        case '7':
          parse.go(t, DCon{D7{}, acc})
        case '8':
          parse.go(t, DCon{D8{}, acc})
        case '9':
          parse.go(t, DCon{D9{}, acc})
        case _:
          None{}

def parse.fin(m: Maybe<&2, Dec>) -> Maybe<&2, Dec>:
  match m:
    case Some{DNil{}}:
      None{}
    case Some{DCon{x, t}}:
      Some{trim(DCon{x, t})}
    case None{}:
      None{}

# one or more ASCII digits and nothing else, leading zeros dropped
def parse(s: String) -> Maybe<&2, Dec>:
  parse.fin(parse.go(s, DNil{}))

# U32 as text
# ===========

def show_u32(x: U32) -> String:
  show(of_u32(x))

def read_u32.go(m: Maybe<&2, Dec>) -> Maybe<&2, U32>:
  match m:
    case Some{d}:
      to_u32(d)
    case None{}:
      None{}

# one or more digits, leading zeros allowed, 0 to 2^32 - 1
def read_u32(s: String) -> Maybe<&2, U32>:
  read_u32.go(parse(s))
