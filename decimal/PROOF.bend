import Base
import ./LAWS.bend as Laws
import ./decimal.bend as D
import ./proof/nat.bend as N
import ./proof/count.bend as Count
import ./proof/text.bend as Text

def Laws.u32_text_round_trip(x):
  match x:
    case U32{w}:
      %Equal.sym(Maybe<&2, D.Dec>, D.parse(D.show(D.of_word(32n, w))), Some{D.trim(D.of_word(32n, w))}, Text.parse_show(D.of_word(32n, w))) : {D.read_u32.go(_) == Some{U32{w}} : Maybe<&2, U32>}
      %Equal.sym(D.Dec, D.trim(D.of_word(32n, w)), D.of_word(32n, w), Text.of_word_trim(32n, w)) : {D.to_u32(_) == Some{U32{w}} : Maybe<&2, U32>}
      Count.u32_round_trip(U32{w})

def Laws.u32_round_trip(x):
  Count.u32_round_trip(x)

def Laws.of_u32_value(x):
  Count.of_u32_value(x)

def Laws.of_u32_trimmed(x):
  match x:
    case U32{w}:
      Text.of_word_trim(32n, w)

def Laws.parse_show(d):
  Text.parse_show(d)

def Laws.trim_value(d):
  Text.trim_value(d)

def Laws.inc_value(d):
  match d:
    case D.DNil{}:
      {==}
    case D.DCon{D.D0{}, t}:
      {==}
    case D.DCon{D.D1{}, t}:
      {==}
    case D.DCon{D.D2{}, t}:
      {==}
    case D.DCon{D.D3{}, t}:
      {==}
    case D.DCon{D.D4{}, t}:
      {==}
    case D.DCon{D.D5{}, t}:
      {==}
    case D.DCon{D.D6{}, t}:
      {==}
    case D.DCon{D.D7{}, t}:
      {==}
    case D.DCon{D.D8{}, t}:
      {==}
    case D.DCon{D.D9{}, t}:
      %Equal.sym(Nat, D.value(D.inc(t)), 1n+D.value(t), Laws.inc_value(t)) : {Nat.mul(10n, _) == 1n+Nat.add(9n, Nat.mul(10n, D.value(t))) : Nat}
      N.mul_succ(10n, D.value(t))

def main() -> IO(Unit):
  IO.print("grounds-decimal: all laws hold")
