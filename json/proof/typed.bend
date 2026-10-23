import Base
import ../json.bend as J
import ./access.bend as Access
import ./u32.bend as Unsigned

def R(-A: Data) -> Data:
  Result<&2, &2, J.Access, A>

law string_copy_round_trip:
  for +s: String
  {J.string_at(J.JStr{s}, []) == Done{s} : R(String)}

def string_copy_round_trip(s):
  Equal.cong(String, R(String), x => Done{x}, J.copy_text(s, ""), s, Access.copy_text_go(s, ""))

def u32_copy_at(+x: U32, +path: List<&2, J.Step>) -> {J.read_at.fin(U32, J.u32(J.copy_leaf(J.num_u32(x))), path) == Done{x} : R(U32)}:
  %Equal.sym(J.Json, J.copy_leaf(J.num_u32(x)), J.num_u32(x), Access.copy_num_u32(x)) : {J.read_at.fin(U32, J.u32(_), path) == Done{x} : R(U32)}
  %Equal.sym(R(U32), J.u32(J.num_u32(x)), Done{x}, Unsigned.u32_round_trip(x)) : {J.read_at.fin(U32, _, path) == Done{x} : R(U32)}
  {==}

law u32_copy_round_trip:
  for +x: U32
  {J.u32_at(J.num_u32(x), []) == Done{x} : R(U32)}

def u32_copy_round_trip(x):
  u32_copy_at(x, [])

law bool_copy_round_trip:
  for +b: Bool
  {J.bool_at(J.JBool{b}, []) == Done{b} : R(Bool)}

def bool_copy_round_trip(b):
  Equal.cong(Bool, R(Bool), x => Done{x}, J.copy_bool(b), b, Access.copy_bool_id(b))

# Template hypotheses are reusable without storing affine functions in Data.
def optional_some_field(~A: Data, ~enc: A -> J.Json, ~dec: J.Json -> R(A), ~item_law: @+x: A -> {J.optional(~A, ~dec, enc(x)) == Done{Some{x}} : R(Maybe<&2, A>)}, +k: String, +x: A) -> {J.optional_at(~A, ~dec, J.obj([J.field_opt(A, k, Some{x}, enc)]), [J.Name{k}]) == Done{Some{x}} : R(Maybe<&2, A>)}:
  %Equal.sym(Bool, J.same(k, k, True{}), True{}, Access.same_refl(k, True{})) : {J.walk_with(~Maybe<&2, A>, ~(v => done => J.optional_at.fin(A, J.optional(~A, ~dec, v), List.reverse(&2, J.Step, done))), ~(st => done => J.optional_missing(A, st, done)), 4294967294n, [], 1n, J.last_key.pick(_, 1n, 0n), J.JNull{}, [J.Field{k, enc(x)}], [], [J.Name{k}]) == Done{Some{x}} : R(Maybe<&2, A>)}
  %Equal.sym(R(Maybe<&2, A>), J.optional(~A, ~dec, enc(x)), Done{Some{x}}, item_law(x)) : {J.optional_at.fin(A, _, [J.Name{k}]) == Done{Some{x}} : R(Maybe<&2, A>)}
  {==}

def optional_none_round_trip(~A: Data, ~enc: A -> J.Json, ~dec: J.Json -> R(A), +k: String) -> {J.optional_at(~A, ~dec, J.obj([J.field_opt(A, k, None{}, enc)]), [J.Name{k}]) == Done{None{}} : R(Maybe<&2, A>)}:
  {==}

def both3_done(-A: Data, -B: Data, -C: Data, -Z: Data, +a: A, +b: B, +c: C, f: A -> B -> C -> Z) -> {J.both3(A, B, C, Z, Done{a}, Done{b}, Done{c}, f) == Done{f(a, b, c)} : R(Z)}:
  {==}

def both4_done(-A: Data, -B: Data, -C: Data, -D: Data, -Z: Data, +a: A, +b: B, +c: C, +d: D, f: A -> B -> C -> D -> Z) -> {J.both4(A, B, C, D, Z, Done{a}, Done{b}, Done{c}, Done{d}, f) == Done{f(a, b, c, d)} : R(Z)}:
  {==}

def both5_done(-A: Data, -B: Data, -C: Data, -D: Data, -E: Data, -Z: Data, +a: A, +b: B, +c: C, +d: D, +e: E, f: A -> B -> C -> D -> E -> Z) -> {J.both5(A, B, C, D, E, Z, Done{a}, Done{b}, Done{c}, Done{d}, Done{e}, f) == Done{f(a, b, c, d, e)} : R(Z)}:
  {==}

def both6_done(-A: Data, -B: Data, -C: Data, -D: Data, -E: Data, -F: Data, -Z: Data, +a: A, +b: B, +c: C, +d: D, +e: E, +v: F, f: A -> B -> C -> D -> E -> F -> Z) -> {J.both6(A, B, C, D, E, F, Z, Done{a}, Done{b}, Done{c}, Done{d}, Done{e}, Done{v}, f) == Done{f(a, b, c, d, e, v)} : R(Z)}:
  {==}

def list_round_trip.go(~A: Data, ~enc: A -> J.Json, ~dec: J.Json -> R(A), ~item_law: @+x: A -> {dec(enc(x)) == Done{x} : R(A)}, +xs: List<&2, A>, +i: U32, +acc: List<&2, A>) -> {J.list_read.go(~A, ~dec, J.map_list(~A, ~J.Json, ~enc, xs), i, Done{acc}) == Done{List.reverse(&2, A, List.reverse.go(&2, A, xs, acc))} : R(List<&2, A>)}:
  match xs:
    case Nil{}:
      {==}
    case Con{h, t}:
      %Equal.sym(R(A), dec(enc(h)), Done{h}, item_law(h)) : {J.list_read.go(~A, ~dec, J.map_list(~A, ~J.Json, ~enc, t), (i + 1 : U32), J.list_read.push(A, _, acc, i)) == Done{List.reverse(&2, A, List.reverse.go(&2, A, Con{h, t}, acc))} : R(List<&2, A>)}
      list_round_trip.go(~A, ~enc, ~dec, ~item_law, t, (i + 1 : U32), Con{h, acc})

def append_nil(-A: Data, +xs: List<&2, A>) -> {List.append(&2, A, xs, []) == xs : List<&2, A>}:
  match xs:
    case Nil{}:
      {==}
    case Con{h, t}:
      Equal.cong(List<&2, A>, List<&2, A>, x => Con{h, x}, List.append(&2, A, t, []), t, append_nil(A, t))

def reverse_twice.go(-A: Data, +xs: List<&2, A>, +acc: List<&2, A>, +out: List<&2, A>) -> {List.reverse.go(&2, A, List.reverse.go(&2, A, xs, acc), out) == List.reverse.go(&2, A, acc, List.append(&2, A, xs, out)) : List<&2, A>}:
  match xs:
    case Nil{}:
      {==}
    case Con{h, t}:
      reverse_twice.go(A, t, Con{h, acc}, out)

def reverse_twice(-A: Data, +xs: List<&2, A>) -> {List.reverse(&2, A, List.reverse(&2, A, xs)) == xs : List<&2, A>}:
  Equal.trans(List<&2, A>, List.reverse(&2, A, List.reverse(&2, A, xs)), List.append(&2, A, xs, []), xs, reverse_twice.go(A, xs, [], []), append_nil(A, xs))

# Standard item round-trip hypothesis, for every value of the item type.
def list_round_trip(~A: Data, ~enc: A -> J.Json, ~dec: J.Json -> R(A), ~item_law: @+x: A -> {dec(enc(x)) == Done{x} : R(A)}, +xs: List<&2, A>, +path: List<&2, J.Step>) -> {J.list_read(~A, ~dec, J.list_json(~A, ~enc, xs), path) == Done{xs} : R(List<&2, A>)}:
  %Equal.sym(R(List<&2, A>), J.list_read.go(~A, ~dec, J.map_list(~A, ~J.Json, ~enc, xs), 0, Done{[]}), Done{List.reverse(&2, A, List.reverse(&2, A, xs))}, list_round_trip.go(~A, ~enc, ~dec, ~item_law, xs, 0, [])) : {J.list_read.fin(A, _, path) == Done{xs} : R(List<&2, A>)}
  Equal.cong(List<&2, A>, R(List<&2, A>), x => Done{x}, List.reverse(&2, A, List.reverse(&2, A, xs)), xs, reverse_twice(A, xs))

def list_at_round_trip(~A: Data, ~enc: A -> J.Json, ~dec: J.Json -> R(A), ~item_law: @+x: A -> {dec(enc(x)) == Done{x} : R(A)}, +xs: List<&2, A>) -> {J.list_at(~A, ~dec, J.list_json(~A, ~enc, xs), []) == Done{xs} : R(List<&2, A>)}:
  list_round_trip(~A, ~enc, ~dec, ~item_law, xs, [])

# A field-level list law, including its path.
def list_field_round_trip(~A: Data, ~enc: A -> J.Json, ~dec: J.Json -> R(A), ~item_law: @+x: A -> {dec(enc(x)) == Done{x} : R(A)}, +k: String, +xs: List<&2, A>) -> {J.list_at(~A, ~dec, J.obj([J.field_list(~A, ~enc, k, xs)]), [J.Name{k}]) == Done{xs} : R(List<&2, A>)}:
  %Equal.sym(Bool, J.same(k, k, True{}), True{}, Access.same_refl(k, True{})) : {J.walk_with(~List<&2, A>, ~(v => done => J.list_read(~A, ~dec, v, List.reverse(&2, J.Step, done))), ~(st => done => Fail{J.Missing{List.reverse(&2, J.Step, done)}}), 4294967294n, [], 1n, J.last_key.pick(_, 1n, 0n), J.JNull{}, [J.Field{k, J.list_json(~A, ~enc, xs)}], [], [J.Name{k}]) == Done{xs} : R(List<&2, A>)}
  list_round_trip(~A, ~enc, ~dec, ~item_law, xs, [J.Name{k}])

# Five successful field reads reduce to one successful constructor call.
def both5_reads(-A: Data, -B: Data, -C: Data, -D: Data, -E: Data, -Z: Data, +a: A, +b: B, +c: C, +d: D, +e: E, +r1: R(A), +r2: R(B), +r3: R(C), +r4: R(D), +r5: R(E), f: A -> B -> C -> D -> E -> Z, h1: {r1 == Done{a} : R(A)}, h2: {r2 == Done{b} : R(B)}, h3: {r3 == Done{c} : R(C)}, h4: {r4 == Done{d} : R(D)}, h5: {r5 == Done{e} : R(E)}) -> {J.both5(A, B, C, D, E, Z, r1, r2, r3, r4, r5, f) == Done{f(a, b, c, d, e)} : R(Z)}:
  %Equal.sym(R(A), r1, Done{a}, h1) : {J.both5(A, B, C, D, E, Z, _, r2, r3, r4, r5, f) == Done{f(a, b, c, d, e)} : R(Z)}
  %Equal.sym(R(B), r2, Done{b}, h2) : {J.both5(A, B, C, D, E, Z, Done{a}, _, r3, r4, r5, f) == Done{f(a, b, c, d, e)} : R(Z)}
  %Equal.sym(R(C), r3, Done{c}, h3) : {J.both5(A, B, C, D, E, Z, Done{a}, Done{b}, _, r4, r5, f) == Done{f(a, b, c, d, e)} : R(Z)}
  %Equal.sym(R(D), r4, Done{d}, h4) : {J.both5(A, B, C, D, E, Z, Done{a}, Done{b}, Done{c}, _, r5, f) == Done{f(a, b, c, d, e)} : R(Z)}
  %Equal.sym(R(E), r5, Done{e}, h5) : {J.both5(A, B, C, D, E, Z, Done{a}, Done{b}, Done{c}, Done{d}, _, f) == Done{f(a, b, c, d, e)} : R(Z)}
  {==}

law string_optional_present:
  for +s: String
  {J.optional(~String, ~J.string, J.copy_leaf(J.JStr{s})) == Done{Some{s}} : R(Maybe<&2, String>)}

def string_optional_present(s):
  Equal.cong(String, R(Maybe<&2, String>), x => Done{Some{x}}, J.copy_text(s, ""), s, Access.copy_text_go(s, ""))

def null_is_empty(b: Bool) -> Type:
  match b:
    case True{}:
      Empty
    case False{}:
      Unit

def impossible_null(h: {True{} == False{} : Bool}) -> Empty:
  %Equal.sym(Bool, True{}, False{}, h) : null_is_empty(_)
  Unit{}

# Non-null is necessary: null is reserved for None, even for custom codecs.
def optional_present(~A: Data, ~dec: J.Json -> R(A), +j: J.Json, +x: A, h: {dec(j) == Done{x} : R(A)}, nonnull: {J.is_null(j) == False{} : Bool}) -> {J.optional(~A, ~dec, j) == Done{Some{x}} : R(Maybe<&2, A>)}:
  match j:
    case J.JNull{}:
      Empty.absurd({J.optional(~A, ~dec, J.JNull{}) == Done{Some{x}} : R(Maybe<&2, A>)}, impossible_null(nonnull))
    case J.JBool{b}:
      Equal.cong(R(A), R(Maybe<&2, A>), r => J.map(A, Maybe<&2, A>, r, v => Some{v}), dec(J.JBool{b}), Done{x}, h)
    case J.JNum{n}:
      Equal.cong(R(A), R(Maybe<&2, A>), r => J.map(A, Maybe<&2, A>, r, v => Some{v}), dec(J.JNum{n}), Done{x}, h)
    case J.JStr{s}:
      Equal.cong(R(A), R(Maybe<&2, A>), r => J.map(A, Maybe<&2, A>, r, v => Some{v}), dec(J.JStr{s}), Done{x}, h)
    case J.JArr{xs}:
      Equal.cong(R(A), R(Maybe<&2, A>), r => J.map(A, Maybe<&2, A>, r, v => Some{v}), dec(J.JArr{xs}), Done{x}, h)
    case J.JObj{fs}:
      Equal.cong(R(A), R(Maybe<&2, A>), r => J.map(A, Maybe<&2, A>, r, v => Some{v}), dec(J.JObj{fs}), Done{x}, h)

def optional_some_round_trip(~A: Data, ~enc: A -> J.Json, ~dec: J.Json -> R(A), ~item_law: @+x: A -> {dec(enc(x)) == Done{x} : R(A)}, ~nonnull: @+x: A -> {J.is_null(enc(x)) == False{} : Bool}, +k: String, +x: A) -> {J.optional_at(~A, ~dec, J.obj([J.field_opt(A, k, Some{x}, enc)]), [J.Name{k}]) == Done{Some{x}} : R(Maybe<&2, A>)}:
  optional_some_field(~A, ~enc, ~dec, ~(x => optional_present(~A, ~dec, enc(x), x, item_law(x), nonnull(x))), k, x)

def optional_null(~A: Data, ~dec: J.Json -> R(A)) -> {J.optional_at(~A, ~dec, J.JNull{}, []) == Done{None{}} : R(Maybe<&2, A>)}:
  {==}

def default_some(-A: Data, +x: A, fallback: A) -> {J.default(A, Done{Some{x}}, fallback) == Done{x} : R(A)}:
  {==}

def default_none(-A: Data, +fallback: A) -> {J.default(A, Done{None{}}, fallback) == Done{fallback} : R(A)}:
  {==}

# Applies by conversion to field_str, field_u32 and field_bool.
def scalar_field_round_trip(~A: Data, ~enc: A -> J.Json, ~dec: J.Json -> R(A), ~item_law: @+x: A -> {dec(J.copy_leaf(enc(x))) == Done{x} : R(A)}, +k: String, +x: A) -> {J.read_at(A, J.obj([[J.Field{k, enc(x)}]]), [J.Name{k}], dec) == Done{x} : R(A)}:
  %Equal.sym(Bool, J.same(k, k, True{}), True{}, Access.same_refl(k, True{})) : {J.read_at.leaf(A, J.walk_with(~J.Leaf, ~(j => done => Done{J.Leaf{J.copy_leaf(j), done}}), ~(st => done => Fail{J.Missing{List.reverse(&2, J.Step, done)}}), 4294967294n, [], 1n, J.last_key.pick(_, 1n, 0n), J.JNull{}, [J.Field{k, enc(x)}], [], [J.Name{k}]), dec) == Done{x} : R(A)}
  %Equal.sym(R(A), dec(J.copy_leaf(enc(x))), Done{x}, item_law(x)) : {J.read_at.fin(A, _, [J.Name{k}]) == Done{x} : R(A)}
  {==}

def u32_leaf_round_trip(+x: U32) -> {J.u32(J.copy_leaf(J.num_u32(x))) == Done{x} : R(U32)}:
  Equal.trans(R(U32), J.u32(J.copy_leaf(J.num_u32(x))), J.u32(J.num_u32(x)), Done{x}, Equal.cong(J.Json, R(U32), j => J.u32(j), J.copy_leaf(J.num_u32(x)), J.num_u32(x), Access.copy_num_u32(x)), Unsigned.u32_round_trip(x))

def string_field_round_trip(+k: String, +s: String) -> {J.string_at(J.obj([J.field_str(k, s)]), [J.Name{k}]) == Done{s} : R(String)}:
  scalar_field_round_trip(~String, ~(x => J.JStr{x}), ~J.string, ~string_copy_round_trip, k, s)

def u32_field_round_trip(+k: String, +x: U32) -> {J.u32_at(J.obj([J.field_u32(k, x)]), [J.Name{k}]) == Done{x} : R(U32)}:
  scalar_field_round_trip(~U32, ~J.num_u32, ~J.u32, ~u32_leaf_round_trip, k, x)

def bool_field_round_trip(+k: String, +b: Bool) -> {J.bool_at(J.obj([J.field_bool(k, b)]), [J.Name{k}]) == Done{b} : R(Bool)}:
  scalar_field_round_trip(~Bool, ~(x => J.JBool{x}), ~J.bool, ~bool_copy_round_trip, k, b)
