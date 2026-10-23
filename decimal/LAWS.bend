import Base
import ./decimal.bend as D

# Laws grounds-decimal must keep. `bend PROOF.bend` fails while any is open or false.

# reading what show_u32 wrote gives back the number, for every U32
law u32_text_round_trip:
  for +x: U32
  {D.read_u32(D.show_u32(x)) == Some{x} : Maybe<&2, U32>}

# to_u32 reads back what of_u32 wrote
law u32_round_trip:
  for +x: U32
  {D.to_u32(D.of_u32(x)) == Some{x} : Maybe<&2, U32>}

# of_u32 counts exactly x
law of_u32_value:
  for +x: U32
  {D.value(D.of_u32(x)) == U32.to_nat(x) : Nat}

# of_u32 writes no leading zeros
law of_u32_trimmed:
  for +x: U32
  {D.trim(D.of_u32(x)) == D.of_u32(x) : D.Dec}

# parse reads what show wrote, leading zeros dropped
law parse_show:
  for +d: D.Dec
  {D.parse(D.show(d)) == Some{D.trim(d)} : Maybe<&2, D.Dec>}

# dropping leading zeros keeps the value
law trim_value:
  for +d: D.Dec
  {D.value(D.trim(d)) == D.value(d) : Nat}

law inc_value:
  for +d: D.Dec
  {D.value(D.inc(d)) == 1n+D.value(d) : Nat}
