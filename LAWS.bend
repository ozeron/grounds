import Base
import ./bjson.bend as J
import ./fast.bend as F

# Laws bjson must keep. `bend PROOF.bend` fails while any is open or false.

# parsing what the printer wrote gives back the same value, for every value
law round_trip:
  for j: J.Json
  {J.parse(J.stringify(j)) == Done{j} : Result<&2, &2, J.Error, J.Json>}

# the one-pass reformatter, which bjson runs, reads printed JSON back to
# the same text
law fast_round_trip:
  for j: J.Json
  {F.reformat(J.stringify(j)) == F.Ok{J.stringify(j)} : F.Out}

# the same for the indented text bjson prints by default
law pretty_round_trip:
  for j: J.Json
  {J.parse(J.pretty(j, "  ")) == Done{j} : Result<&2, &2, J.Error, J.Json>}

# so the printer never writes invalid JSON
law always_parses:
  for j: J.Json
  {J.is_ok(J.parse(J.stringify(j))) == True{} : Bool}

# every literal survives a print and a parse
law bool_round_trip:
  for b: Bool
  {J.parse(J.stringify(J.JBool{b})) == Done{J.JBool{b}} : Result<&2, &2, J.Error, J.Json>}

law null_round_trip:
  {J.parse(J.stringify(J.JNull{})) == Done{J.JNull{}} : Result<&2, &2, J.Error, J.Json>}

# compact and pretty print a literal the same way
law pretty_literal:
  for b: Bool
  for unit: String
  {J.pretty(J.JBool{b}, unit) == J.stringify(J.JBool{b}) : String}

# lookups on empty containers find nothing
law get_empty:
  for k: String
  {J.get(J.JObj{[]}, k) == None{} : Maybe<&2, J.Json>}

law at_empty:
  for n: Nat
  {J.at(J.JArr{[]}, n) == None{} : Maybe<&2, J.Json>}

# lookups on the wrong kind of value find nothing
law get_not_object:
  for xs: List<&2, J.Json>
  for k: String
  {J.get(J.JArr{xs}, k) == None{} : Maybe<&2, J.Json>}

law at_not_array:
  for fs: List<&2, J.Field>
  for n: Nat
  {J.at(J.JObj{fs}, n) == None{} : Maybe<&2, J.Json>}

# a bool is only ever read as a bool
law as_bool_exact:
  for b: Bool
  {J.as_bool(J.JBool{b}) == Some{b} : Maybe<&2, Bool>}

law as_str_exact:
  for s: String
  {J.as_str(J.JStr{s}) == Some{s} : Maybe<&2, String>}

# whitespace is skipped wholesale: nothing after it starts with ws
law skip_ws_space:
  for s: String
  {J.skip_ws(SCon{' ', s}) == J.skip_ws(s) : String}
