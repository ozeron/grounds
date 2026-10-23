import Base
import ../decimal.bend as D

# Leading zeros and text: trimming keeps the value and commutes with
# doubling, so of_u32 writes none; parse reads what show wrote, digit by
# digit, and drops the leading zeros.

# Leading zeros
# -------------

law con_value:
  for +x: D.Dig
  for +t: D.Dec
  {D.value(D.trim.con(x, t)) == Nat.add(D.dig.val(x), Nat.mul(10n, D.value(t))) : Nat}

def con_value(x, t):
  match x t:
    case D.D0{} D.DNil{}:
      {==}
    case D.D1{} D.DNil{}:
      {==}
    case D.D2{} D.DNil{}:
      {==}
    case D.D3{} D.DNil{}:
      {==}
    case D.D4{} D.DNil{}:
      {==}
    case D.D5{} D.DNil{}:
      {==}
    case D.D6{} D.DNil{}:
      {==}
    case D.D7{} D.DNil{}:
      {==}
    case D.D8{} D.DNil{}:
      {==}
    case D.D9{} D.DNil{}:
      {==}
    case _ D.DCon{y, u}:
      {==}

law trim_value:
  for +d: D.Dec
  {D.value(D.trim(d)) == D.value(d) : Nat}

def trim_value(d):
  match d:
    case D.DNil{}:
      {==}
    case D.DCon{x, t}:
      %Equal.sym(Nat, D.value(D.trim.con(x, D.trim(t))), Nat.add(D.dig.val(x), Nat.mul(10n, D.value(D.trim(t)))), con_value(x, D.trim(t))) : {_ == Nat.add(D.dig.val(x), Nat.mul(10n, D.value(t))) : Nat}
      Equal.cong(Nat, Nat, v => Nat.add(D.dig.val(x), Nat.mul(10n, v)), D.value(D.trim(t)), D.value(t), trim_value(t))

# a digit doubled onto a trimmed rest is the double of the digit put on it
law con_dbl:
  for +x: D.Dig
  for +c: Bool
  for +t: D.Dec
  {D.trim.con(D.dbl.dig(x, c), D.dbl(t, D.dbl.carry(x))) == D.dbl(D.trim.con(x, t), c) : D.Dec}

def con_dbl(x, c, t):
  match x c t:
    case D.D0{} False{} D.DNil{}:
      {==}
    case D.D0{} True{} D.DNil{}:
      {==}
    case D.D1{} False{} D.DNil{}:
      {==}
    case D.D1{} True{} D.DNil{}:
      {==}
    case D.D2{} False{} D.DNil{}:
      {==}
    case D.D2{} True{} D.DNil{}:
      {==}
    case D.D3{} False{} D.DNil{}:
      {==}
    case D.D3{} True{} D.DNil{}:
      {==}
    case D.D4{} False{} D.DNil{}:
      {==}
    case D.D4{} True{} D.DNil{}:
      {==}
    case D.D5{} False{} D.DNil{}:
      {==}
    case D.D5{} True{} D.DNil{}:
      {==}
    case D.D6{} False{} D.DNil{}:
      {==}
    case D.D6{} True{} D.DNil{}:
      {==}
    case D.D7{} False{} D.DNil{}:
      {==}
    case D.D7{} True{} D.DNil{}:
      {==}
    case D.D8{} False{} D.DNil{}:
      {==}
    case D.D8{} True{} D.DNil{}:
      {==}
    case D.D9{} False{} D.DNil{}:
      {==}
    case D.D9{} True{} D.DNil{}:
      {==}
    case _ _ D.DCon{y, u}:
      {==}

law trim_dbl:
  for +d: D.Dec
  for +c: Bool
  {D.trim(D.dbl(d, c)) == D.dbl(D.trim(d), c) : D.Dec}

def trim_dbl(d, c):
  match d:
    case D.DNil{}:
      match c:
        case True{}:
          {==}
        case False{}:
          {==}
    case D.DCon{x, t}:
      %Equal.sym(D.Dec, D.trim(D.dbl(t, D.dbl.carry(x))), D.dbl(D.trim(t), D.dbl.carry(x)), trim_dbl(t, D.dbl.carry(x))) : {D.trim.con(D.dbl.dig(x, c), _) == D.dbl(D.trim.con(x, D.trim(t)), c) : D.Dec}
      con_dbl(x, c, D.trim(t))

law of_word_trim:
  for +n: Nat
  for +w: Word(n)
  {D.trim(D.of_word(n, w)) == D.of_word(n, w) : D.Dec}

def of_word_trim(n, w):
  match n:
    case 0n:
      match w:
        case WNil{}:
          {==}
    case 1n+p:
      match w:
        case WCon{b, t}:
          %Equal.sym(D.Dec, D.trim(D.dbl(D.of_word(p, t), b)), D.dbl(D.trim(D.of_word(p, t)), b), trim_dbl(D.of_word(p, t), b)) : {_ == D.dbl(D.of_word(p, t), b) : D.Dec}
          Equal.cong(D.Dec, D.Dec, y => D.dbl(y, b), D.trim(D.of_word(p, t)), D.of_word(p, t), of_word_trim(p, t))

# Text
# ----

# d then acc, low digits first: what parsing the digits of d onto acc leaves
def cat(d: D.Dec, acc: D.Dec) -> D.Dec:
  match d:
    case D.DNil{}:
      acc
    case D.DCon{x, t}:
      D.DCon{x, cat(t, acc)}

law cat_nil:
  for +d: D.Dec
  {cat(d, D.DNil{}) == d : D.Dec}

def cat_nil(d):
  match d:
    case D.DNil{}:
      {==}
    case D.DCon{x, t}:
      Equal.cong(D.Dec, D.Dec, y => D.DCon{x, y}, cat(t, D.DNil{}), t, cat_nil(t))

law parse_char:
  for +x: D.Dig
  for +out: String
  for +acc: D.Dec
  {D.parse.go(SCon{D.dig.char(x), out}, acc) == D.parse.go(out, D.DCon{x, acc}) : Maybe<&2, D.Dec>}

def parse_char(x, out, acc):
  match x:
    case D.D0{}:
      {==}
    case D.D1{}:
      {==}
    case D.D2{}:
      {==}
    case D.D3{}:
      {==}
    case D.D4{}:
      {==}
    case D.D5{}:
      {==}
    case D.D6{}:
      {==}
    case D.D7{}:
      {==}
    case D.D8{}:
      {==}
    case D.D9{}:
      {==}

law parse_show_go:
  for +d: D.Dec
  for +out: String
  for +acc: D.Dec
  {D.parse.go(D.show.go(d, out), acc) == D.parse.go(out, cat(d, acc)) : Maybe<&2, D.Dec>}

def parse_show_go(d, out, acc):
  match d:
    case D.DNil{}:
      {==}
    case D.DCon{x, t}:
      Equal.trans(Maybe<&2, D.Dec>, D.parse.go(D.show.go(t, SCon{D.dig.char(x), out}), acc), D.parse.go(SCon{D.dig.char(x), out}, cat(t, acc)), D.parse.go(out, D.DCon{x, cat(t, acc)}),
        parse_show_go(t, SCon{D.dig.char(x), out}, acc),
        parse_char(x, out, cat(t, acc)))

law parse_show:
  for +d: D.Dec
  {D.parse(D.show(d)) == Some{D.trim(d)} : Maybe<&2, D.Dec>}

def parse_show(d):
  match d:
    case D.DNil{}:
      {==}
    case D.DCon{x, t}:
      %Equal.sym(Maybe<&2, D.Dec>, D.parse.go(D.show.go(D.DCon{x, t}, ""), D.DNil{}), D.parse.go("", cat(D.DCon{x, t}, D.DNil{})), parse_show_go(D.DCon{x, t}, "", D.DNil{})) : {D.parse.fin(_) == Some{D.trim(D.DCon{x, t})} : Maybe<&2, D.Dec>}
      %Equal.sym(D.Dec, cat(t, D.DNil{}), t, cat_nil(t)) : {Some{D.trim(D.DCon{x, _})} == Some{D.trim(D.DCon{x, t})} : Maybe<&2, D.Dec>}
      {==}
