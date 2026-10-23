import Base
import ./LAWS.bend as Laws
import ./decimal.bend as D
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
  Count.inc_value(d)

def main() -> IO(Unit):
  IO.print("grounds-decimal: all laws hold")
