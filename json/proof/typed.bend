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

# Any successful decoder lifts through a path prefix.
def decode_round_trip(~A: Data, ~enc: A -> J.Json, ~dec: J.Json -> R(A), ~item_law: @+x: A -> {dec(enc(x)) == Done{x} : R(A)}, +x: A, +path: List<&2, J.Step>) -> {J.decode_at.fin(A, dec(enc(x)), path) == Done{x} : R(A)}:
  %Equal.sym(R(A), dec(enc(x)), Done{x}, item_law(x)) : {J.decode_at.fin(A, _, path) == Done{x} : R(A)}
  {==}

def decode_at_round_trip(~A: Data, ~enc: A -> J.Json, ~dec: J.Json -> R(A), ~item_law: @+x: A -> {dec(enc(x)) == Done{x} : R(A)}, +x: A) -> {J.decode_at(~A, ~dec, enc(x), []) == Done{x} : R(A)}:
  decode_round_trip(~A, ~enc, ~dec, ~item_law, x, [])

def decode_field_round_trip(~A: Data, ~enc: A -> J.Json, ~dec: J.Json -> R(A), ~item_law: @+x: A -> {dec(enc(x)) == Done{x} : R(A)}, +k: String, +x: A) -> {J.decode_at(~A, ~dec, J.obj([J.field_obj(A, k, x, enc)]), [J.Name{k}]) == Done{x} : R(A)}:
  %Equal.sym(Bool, J.same(k, k, True{}), True{}, Access.same_refl(k, True{})) : {J.walk_with(~A, ~(v => done => J.decode_at.fin(A, dec(v), List.reverse(&2, J.Step, done))), ~(st => done => Fail{J.Missing{List.reverse(&2, J.Step, done)}}), 4294967294n, [], 1n, J.last_key.pick(_, 1n, 0n), J.JNull{}, [J.Field{k, enc(x)}], [], [J.Name{k}]) == Done{x} : R(A)}
  decode_round_trip(~A, ~enc, ~dec, ~item_law, x, [J.Name{k}])

def both7_done(-A: Data, -B: Data, -C: Data, -D: Data, -E: Data, -F: Data, -G: Data, -Z: Data, +a: A, +b: B, +c: C, +d: D, +e: E, +v: F, +g: G, f: A -> B -> C -> D -> E -> F -> G -> Z) -> {J.both7(A, B, C, D, E, F, G, Z, Done{a}, Done{b}, Done{c}, Done{d}, Done{e}, Done{v}, Done{g}, f) == Done{f(a, b, c, d, e, v, g)} : R(Z)}:
  {==}

def both7_reads(-A: Data, -B: Data, -C: Data, -D: Data, -E: Data, -F: Data, -G: Data, -Z: Data, +a: A, +b: B, +c: C, +d: D, +e: E, +v: F, +g: G, +r1: R(A), +r2: R(B), +r3: R(C), +r4: R(D), +r5: R(E), +r6: R(F), +r7: R(G), f: A -> B -> C -> D -> E -> F -> G -> Z, h1: {r1 == Done{a} : R(A)}, h2: {r2 == Done{b} : R(B)}, h3: {r3 == Done{c} : R(C)}, h4: {r4 == Done{d} : R(D)}, h5: {r5 == Done{e} : R(E)}, h6: {r6 == Done{v} : R(F)}, h7: {r7 == Done{g} : R(G)}) -> {J.both7(A, B, C, D, E, F, G, Z, r1, r2, r3, r4, r5, r6, r7, f) == Done{f(a, b, c, d, e, v, g)} : R(Z)}:
  %Equal.sym(R(A), r1, Done{a}, h1) : {J.both7(A, B, C, D, E, F, G, Z, _, r2, r3, r4, r5, r6, r7, f) == Done{f(a, b, c, d, e, v, g)} : R(Z)}
  %Equal.sym(R(B), r2, Done{b}, h2) : {J.both7(A, B, C, D, E, F, G, Z, Done{a}, _, r3, r4, r5, r6, r7, f) == Done{f(a, b, c, d, e, v, g)} : R(Z)}
  %Equal.sym(R(C), r3, Done{c}, h3) : {J.both7(A, B, C, D, E, F, G, Z, Done{a}, Done{b}, _, r4, r5, r6, r7, f) == Done{f(a, b, c, d, e, v, g)} : R(Z)}
  %Equal.sym(R(D), r4, Done{d}, h4) : {J.both7(A, B, C, D, E, F, G, Z, Done{a}, Done{b}, Done{c}, _, r5, r6, r7, f) == Done{f(a, b, c, d, e, v, g)} : R(Z)}
  %Equal.sym(R(E), r5, Done{e}, h5) : {J.both7(A, B, C, D, E, F, G, Z, Done{a}, Done{b}, Done{c}, Done{d}, _, r6, r7, f) == Done{f(a, b, c, d, e, v, g)} : R(Z)}
  %Equal.sym(R(F), r6, Done{v}, h6) : {J.both7(A, B, C, D, E, F, G, Z, Done{a}, Done{b}, Done{c}, Done{d}, Done{e}, _, r7, f) == Done{f(a, b, c, d, e, v, g)} : R(Z)}
  %Equal.sym(R(G), r7, Done{g}, h7) : {J.both7(A, B, C, D, E, F, G, Z, Done{a}, Done{b}, Done{c}, Done{d}, Done{e}, Done{v}, _, f) == Done{f(a, b, c, d, e, v, g)} : R(Z)}
  {==}

def both_reads(-A: Data, -B: Data, -Z: Data, +a: A, +b: B, +r1: R(A), +r2: R(B), f: A -> B -> Z, h1: {r1 == Done{a} : R(A)}, h2: {r2 == Done{b} : R(B)}) -> {J.both(A, B, Z, r1, r2, f) == Done{f(a, b)} : R(Z)}:
  %Equal.sym(R(A), r1, Done{a}, h1) : {J.both(A, B, Z, _, r2, f) == Done{f(a, b)} : R(Z)}
  %Equal.sym(R(B), r2, Done{b}, h2) : {J.both(A, B, Z, Done{a}, _, f) == Done{f(a, b)} : R(Z)}
  {==}

def copy_sign_id(+s: J.Sign) -> {J.copy_sign(s) == s : J.Sign}:
  match s:
    case J.NoSign{}:
      {==}
    case J.Plus{}:
      {==}
    case J.Minus{}:
      {==}

def copy_frac_id(+f: J.Frac) -> {J.copy_frac(f) == f : J.Frac}:
  match f:
    case J.FNone{}:
      {==}
    case J.FSome{d, ds}:
      %Equal.sym(J.Digit, J.copy_digit(d), d, Access.copy_digit_id(d)) : {J.FSome{_, J.copy_digits(ds, [])} == J.FSome{d, ds} : J.Frac}
      %Equal.sym(List<&2, J.Digit>, J.copy_digits(ds, []), ds, Access.copy_digits_go(ds, [])) : {J.FSome{d, _} == J.FSome{d, ds} : J.Frac}
      {==}

def copy_exp_id(+e: J.Exp) -> {J.copy_exp(e) == e : J.Exp}:
  match e:
    case J.ENone{}:
      {==}
    case J.ESome{u, s, d, ds}:
      %Equal.sym(Bool, J.copy_bool(u), u, Access.copy_bool_id(u)) : {J.ESome{_, J.copy_sign(s), J.copy_digit(d), J.copy_digits(ds, [])} == J.ESome{u, s, d, ds} : J.Exp}
      %Equal.sym(J.Sign, J.copy_sign(s), s, copy_sign_id(s)) : {J.ESome{u, _, J.copy_digit(d), J.copy_digits(ds, [])} == J.ESome{u, s, d, ds} : J.Exp}
      %Equal.sym(J.Digit, J.copy_digit(d), d, Access.copy_digit_id(d)) : {J.ESome{u, s, _, J.copy_digits(ds, [])} == J.ESome{u, s, d, ds} : J.Exp}
      %Equal.sym(List<&2, J.Digit>, J.copy_digits(ds, []), ds, Access.copy_digits_go(ds, [])) : {J.ESome{u, s, d, _} == J.ESome{u, s, d, ds} : J.Exp}
      {==}

# A structural budget, never an expanded numerical bound. Each recursive copy
# must have fuel; the two branches of a member require their own witnesses.
def CopyFits(fuel: Nat, mode: J.CopyMode, j: J.Json, xs: List<&2, J.Json>, fs: List<&2, J.Field>) -> Type:
  match fuel mode j xs fs:
    case 0n _ _ _ _:
      Empty
    case 1n+k J.CopyValue{} J.JArr{ys} _ _:
      CopyFits(k, J.CopyArray{}, J.JNull{}, ys, [])
    case 1n+k J.CopyValue{} J.JObj{ys} _ _:
      CopyFits(k, J.CopyObject{}, J.JNull{}, [], ys)
    case 1n+k J.CopyValue{} _ _ _:
      Unit
    case 1n+k J.CopyArray{} _ Nil{} _:
      Unit
    case 1n+k J.CopyArray{} _ Con{h, t} _:
      CopyFits(k, J.CopyValue{}, h, [], []) & CopyFits(k, J.CopyArray{}, J.JNull{}, t, [])
    case 1n+k J.CopyObject{} _ _ Nil{}:
      Unit
    case 1n+k J.CopyObject{} _ _ Con{J.Field{_, v}, t}:
      CopyFits(k, J.CopyValue{}, v, [], []) & CopyFits(k, J.CopyObject{}, J.JNull{}, [], t)

def copy_target(mode: J.CopyMode, j: J.Json, xs: List<&2, J.Json>, fs: List<&2, J.Field>) -> J.Json:
  match mode:
    case J.CopyValue{}:
      j
    case J.CopyArray{}:
      J.JArr{xs}
    case J.CopyObject{}:
      J.JObj{fs}

def copy_number_id(+n: J.Number) -> {J.copy_leaf(J.JNum{n}) == J.JNum{n} : J.Json}:
  match n:
    case J.Number{neg, i, f, e}:
      %Equal.sym(Bool, J.copy_bool(neg), neg, Access.copy_bool_id(neg)) : {J.JNum{J.Number{_, J.copy_int(i), J.copy_frac(f), J.copy_exp(e)}} == J.JNum{J.Number{neg, i, f, e}} : J.Json}
      %Equal.sym(J.Int, J.copy_int(i), i, Access.copy_int_id(i)) : {J.JNum{J.Number{neg, _, J.copy_frac(f), J.copy_exp(e)}} == J.JNum{J.Number{neg, i, f, e}} : J.Json}
      %Equal.sym(J.Frac, J.copy_frac(f), f, copy_frac_id(f)) : {J.JNum{J.Number{neg, i, _, J.copy_exp(e)}} == J.JNum{J.Number{neg, i, f, e}} : J.Json}
      %Equal.sym(J.Exp, J.copy_exp(e), e, copy_exp_id(e)) : {J.JNum{J.Number{neg, i, f, _}} == J.JNum{J.Number{neg, i, f, e}} : J.Json}
      {==}

def copy_json.go_id(+fuel: Nat, +mode: J.CopyMode, +j: J.Json, +xs: List<&2, J.Json>, +fs: List<&2, J.Field>, fits: CopyFits(fuel, mode, j, xs, fs)) -> {J.copy_json.go(fuel, mode, j, xs, fs) == Done{copy_target(mode, j, xs, fs)} : R(J.Json)}:
  match fuel mode j xs fs:
    case 0n _ _ _ _:
      Empty.absurd({J.copy_json.go(0n, mode, j, xs, fs) == Done{copy_target(mode, j, xs, fs)} : R(J.Json)}, fits)
    case 1n+k J.CopyValue{} J.JArr{ys} _ _:
      copy_json.go_id(k, J.CopyArray{}, J.JNull{}, ys, [], fits)
    case 1n+k J.CopyValue{} J.JObj{ys} _ _:
      copy_json.go_id(k, J.CopyObject{}, J.JNull{}, [], ys, fits)
    case 1n+k J.CopyValue{} J.JNull{} _ _:
      {==}
    case 1n+k J.CopyValue{} J.JBool{b} _ _:
      Equal.cong(Bool, R(J.Json), x => Done{J.JBool{x}}, J.copy_bool(b), b, Access.copy_bool_id(b))
    case 1n+k J.CopyValue{} J.JNum{n} _ _:
      Equal.cong(J.Json, R(J.Json), x => Done{x}, J.copy_leaf(J.JNum{n}), J.JNum{n}, copy_number_id(n))
    case 1n+k J.CopyValue{} J.JStr{s} _ _:
      Equal.cong(String, R(J.Json), x => Done{J.JStr{x}}, J.copy_text(s, ""), s, Access.copy_text_go(s, ""))
    case 1n+k J.CopyArray{} _ Nil{} _:
      {==}
    case 1n+k J.CopyArray{} _ Con{h, t} _:
      (head_fits, tail_fits) = fits
      %Equal.sym(R(J.Json), J.copy_json.go(k, J.CopyValue{}, h, [], []), Done{h}, copy_json.go_id(k, J.CopyValue{}, h, [], [], head_fits)) : {J.copy_json.arr(_, J.copy_json.go(k, J.CopyArray{}, J.JNull{}, t, [])) == Done{J.JArr{Con{h, t}}} : R(J.Json)}
      %Equal.sym(R(J.Json), J.copy_json.go(k, J.CopyArray{}, J.JNull{}, t, []), Done{J.JArr{t}}, copy_json.go_id(k, J.CopyArray{}, J.JNull{}, t, [], tail_fits)) : {J.copy_json.arr(Done{h}, _) == Done{J.JArr{Con{h, t}}} : R(J.Json)}
      {==}
    case 1n+k J.CopyObject{} _ _ Nil{}:
      {==}
    case 1n+k J.CopyObject{} _ _ Con{J.Field{key, v}, t}:
      (head_fits, tail_fits) = fits
      %Equal.sym(String, J.copy_text(key, ""), key, Access.copy_text_go(key, "")) : {J.copy_json.obj(_, J.copy_json.go(k, J.CopyValue{}, v, [], []), J.copy_json.go(k, J.CopyObject{}, J.JNull{}, [], t)) == Done{J.JObj{Con{J.Field{key, v}, t}}} : R(J.Json)}
      %Equal.sym(R(J.Json), J.copy_json.go(k, J.CopyValue{}, v, [], []), Done{v}, copy_json.go_id(k, J.CopyValue{}, v, [], [], head_fits)) : {J.copy_json.obj(key, _, J.copy_json.go(k, J.CopyObject{}, J.JNull{}, [], t)) == Done{J.JObj{Con{J.Field{key, v}, t}}} : R(J.Json)}
      %Equal.sym(R(J.Json), J.copy_json.go(k, J.CopyObject{}, J.JNull{}, [], t), Done{J.JObj{t}}, copy_json.go_id(k, J.CopyObject{}, J.JNull{}, [], t, tail_fits)) : {J.copy_json.obj(key, Done{v}, _) == Done{J.JObj{Con{J.Field{key, v}, t}}} : R(J.Json)}
      {==}

def copy_json_id(+j: J.Json, fits: CopyFits(4294967295n, J.CopyValue{}, j, [], [])) -> {J.copy_json(j) == Done{j} : R(J.Json)}:
  copy_json.go_id(4294967295n, J.CopyValue{}, j, [], [], fits)

# A single successful decoder equality also lifts; no global hypothesis needed.
def decode_field_value(~A: Data, ~dec: J.Json -> R(A), +k: String, +j: J.Json, +x: A, h: {dec(j) == Done{x} : R(A)}) -> {J.decode_at(~A, ~dec, J.JObj{[J.Field{k, j}]}, [J.Name{k}]) == Done{x} : R(A)}:
  %Equal.sym(Bool, J.same(k, k, True{}), True{}, Access.same_refl(k, True{})) : {J.walk_with(~A, ~(v => done => J.decode_at.fin(A, dec(v), List.reverse(&2, J.Step, done))), ~(st => done => Fail{J.Missing{List.reverse(&2, J.Step, done)}}), 4294967294n, [], 1n, J.last_key.pick(_, 1n, 0n), J.JNull{}, [J.Field{k, j}], [], [J.Name{k}]) == Done{x} : R(A)}
  %Equal.sym(R(A), dec(j), Done{x}, h) : {J.decode_at.fin(A, _, [J.Name{k}]) == Done{x} : R(A)}
  {==}

def array_copy_round_trip(+xs: List<&2, J.Json>, fits: CopyFits(4294967295n, J.CopyValue{}, J.JArr{xs}, [], [])) -> {J.copy_json.array(J.copy_json(J.JArr{xs})) == Done{xs} : R(List<&2, J.Json>)}:
  %Equal.sym(R(J.Json), J.copy_json(J.JArr{xs}), Done{J.JArr{xs}}, copy_json_id(J.JArr{xs}, fits)) : {J.copy_json.array(_) == Done{xs} : R(List<&2, J.Json>)}
  {==}

def object_copy_round_trip(+fs: List<&2, J.Field>, fits: CopyFits(4294967295n, J.CopyValue{}, J.JObj{fs}, [], [])) -> {J.copy_json.object(J.copy_json(J.JObj{fs})) == Done{fs} : R(List<&2, J.Field>)}:
  %Equal.sym(R(J.Json), J.copy_json(J.JObj{fs}), Done{J.JObj{fs}}, copy_json_id(J.JObj{fs}, fits)) : {J.copy_json.object(_) == Done{fs} : R(List<&2, J.Field>)}
  {==}

def array_at_round_trip(+k: String, +xs: List<&2, J.Json>, fits: CopyFits(4294967295n, J.CopyValue{}, J.JArr{xs}, [], [])) -> {J.array_at(J.JObj{[J.Field{k, J.JArr{xs}}]}, [J.Name{k}]) == Done{xs} : R(List<&2, J.Json>)}:
  decode_field_value(~List<&2, J.Json>, ~J.array_copy, k, J.JArr{xs}, xs, array_copy_round_trip(xs, fits))

def object_at_round_trip(+k: String, +fs: List<&2, J.Field>, fits: CopyFits(4294967295n, J.CopyValue{}, J.JObj{fs}, [], [])) -> {J.object_at(J.JObj{[J.Field{k, J.JObj{fs}}]}, [J.Name{k}]) == Done{fs} : R(List<&2, J.Field>)}:
  decode_field_value(~List<&2, J.Field>, ~J.object_copy, k, J.JObj{fs}, fs, object_copy_round_trip(fs, fits))
