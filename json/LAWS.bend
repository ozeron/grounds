import Base
import ./json.bend as J
import ./fast.bend as F

# Laws grounds-json must keep. `bend PROOF.bend` fails while any is open or false.

# parsing what the printer wrote gives back the same value, for every value
law round_trip:
  for j: J.Json
  {J.parse(J.encode(j)) == Done{j} : Result<&2, &2, J.Error, J.Json>}

# the one-pass reformatter, which grounds-json runs, reads printed JSON back to
# the same text
law fast_round_trip:
  for j: J.Json
  {F.reformat(J.encode(j)) == F.Ok{J.encode(j)} : F.Out}

# the same for the indented text grounds-json prints by default
law pretty_round_trip:
  for j: J.Json
  {J.parse(J.pretty(j, "  ")) == Done{j} : Result<&2, &2, J.Error, J.Json>}

# so the printer never writes invalid JSON
law always_parses:
  for j: J.Json
  {J.is_ok(J.parse(J.encode(j))) == True{} : Bool}

# every literal survives a print and a parse
law bool_round_trip:
  for b: Bool
  {J.parse(J.encode(J.JBool{b})) == Done{J.JBool{b}} : Result<&2, &2, J.Error, J.Json>}

law null_round_trip:
  {J.parse(J.encode(J.JNull{})) == Done{J.JNull{}} : Result<&2, &2, J.Error, J.Json>}

# compact and pretty print a literal the same way
law pretty_literal:
  for b: Bool
  for unit: String
  {J.pretty(J.JBool{b}, unit) == J.encode(J.JBool{b}) : String}

# Reads (docs/API.md, level A)

# a read failed because the value had another kind
def mistyped(-A: Data, r: Result<&2, &2, J.Access, A>) -> Bool:
  match r:
    case Fail{J.Expected{_, _, _}}:
      True{}
    case _:
      False{}

def kcode(k: J.JKind) -> U32:
  match k:
    case J.KNull{}:
      0
    case J.KBool{}:
      1
    case J.KNumber{}:
      2
    case J.KString{}:
      3
    case J.KArray{}:
      4
    case J.KObject{}:
      5

def kind_is(a: J.JKind, b: J.JKind) -> Bool:
  U32.is_eq(kcode(a), kcode(b))

# get finds a key, and the last of duplicate keys wins
law get_last:
  for +k: String
  for +v: J.Json
  for +fs: List<&2, J.Field>
  {J.get(J.JObj{List.append(&2, J.Field, fs, [J.Field{k, v}])}, k) == Done{v} : Result<&2, &2, J.Access, J.Json>}

law get_missing:
  for k: String
  {J.get(J.JObj{[]}, k) == Fail{J.Missing{[J.Name{k}]}} : Result<&2, &2, J.Access, J.Json>}

law index_first:
  for x: J.Json
  for xs: List<&2, J.Json>
  {J.index(J.JArr{Con{x, xs}}, 0) == Done{x} : Result<&2, &2, J.Access, J.Json>}

law index_second:
  for x: J.Json
  for y: J.Json
  for ys: List<&2, J.Json>
  {J.index(J.JArr{Con{x, Con{y, ys}}}, 1) == Done{y} : Result<&2, &2, J.Access, J.Json>}

law index_empty:
  for i: U32
  {J.index(J.JArr{[]}, i) == Fail{J.Missing{[J.Index{i}]}} : Result<&2, &2, J.Access, J.Json>}

# each read gives back what was stored
law string_exact:
  for s: String
  {J.string(J.JStr{s}) == Done{s} : Result<&2, &2, J.Access, String>}

law bool_exact:
  for b: Bool
  {J.bool(J.JBool{b}) == Done{b} : Result<&2, &2, J.Access, Bool>}

law number_exact:
  for n: J.Number
  {J.number(J.JNum{n}) == Done{n} : Result<&2, &2, J.Access, J.Number>}

law array_exact:
  for xs: List<&2, J.Json>
  {J.array(J.JArr{xs}) == Done{xs} : Result<&2, &2, J.Access, List<&2, J.Json>>}

law object_exact:
  for fs: List<&2, J.Field>
  {J.object(J.JObj{fs}) == Done{fs} : Result<&2, &2, J.Access, List<&2, J.Field>>}

# each read fails as mistyped exactly on the other kinds
law string_kind:
  for j: J.Json
  {mistyped(String, J.string(j)) == Bool.not(kind_is(J.kind(j), J.KString{})) : Bool}

law bool_kind:
  for j: J.Json
  {mistyped(Bool, J.bool(j)) == Bool.not(kind_is(J.kind(j), J.KBool{})) : Bool}

law number_kind:
  for j: J.Json
  {mistyped(J.Number, J.number(j)) == Bool.not(kind_is(J.kind(j), J.KNumber{})) : Bool}

law array_kind:
  for j: J.Json
  {mistyped(List<&2, J.Json>, J.array(j)) == Bool.not(kind_is(J.kind(j), J.KArray{})) : Bool}

law object_kind:
  for j: J.Json
  {mistyped(List<&2, J.Field>, J.object(j)) == Bool.not(kind_is(J.kind(j), J.KObject{})) : Bool}

law u32_kind:
  for j: J.Json
  {mistyped(U32, J.u32(j)) == Bool.not(kind_is(J.kind(j), J.KNumber{})) : Bool}

law f32_kind:
  for j: J.Json
  {mistyped(F32, J.f32(j)) == Bool.not(kind_is(J.kind(j), J.KNumber{})) : Bool}

law index_kind:
  for j: J.Json
  for +i: U32
  {mistyped(J.Json, J.index(j, i)) == Bool.not(kind_is(J.kind(j), J.KArray{})) : Bool}

law get_kind:
  for j: J.Json
  for +k: String
  {mistyped(J.Json, J.get(j, k)) == Bool.not(kind_is(J.kind(j), J.KObject{})) : Bool}

# whitespace is skipped wholesale: nothing after it starts with ws
law skip_ws_space:
  for s: String
  {J.skip_ws(SCon{' ', s}) == J.skip_ws(s) : String}
