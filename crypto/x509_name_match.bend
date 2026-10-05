import Base
import ./x509_name.bend as N
import ./x509_name_prepare.bend as P
import ./unicode32_prepare.bend as U
import ./unicode32_nfkc_compose.bend as C
import ./unicode32_nfkc_buffer.bend as B
import ./x509_name_schema.bend as S
import ./x509_identity.bend as I

# Complete DER admission precedes stored attribute preparation. An unsupported
# equality profile or failed preparation is None, never an equal empty value.
# Arrays remain affine through sorting/comparison; no full scalar list is made.
type Key is Type:
  Key{oid: List<&2, U32>, values: Array<U32>, length: U32}

def Keys() -> Type:
  List<&1, Key>

type Prepared is Type:
  Prepared{rdns: List<&1, Keys()>}

def order(+a: U32, +b: U32) -> U32:
  Bool.pick(U32, U32.is_eq(a, b), 0, Bool.pick(U32, U32.is_lt(a, b), 1, 2))

def oid.order(a: List<&2, U32>, b: List<&2, U32>, +relation: U32) -> U32:
  match a b:
    case Nil{} Nil{}: relation
    case Nil{} Con{_, _}: Bool.pick(U32, U32.is_eq(relation, 0), 1, relation)
    case Con{_, _} Nil{}: Bool.pick(U32, U32.is_eq(relation, 0), 2, relation)
    case Con{x, xs} Con{y, ys}:
      oid.order(xs, ys, Bool.pick(U32, U32.is_eq(relation, 0), order(x, y), relation))

type Words is Type:
  Words{a: Array<U32>, b: Array<U32>, relation: U32}

def word.right(a: Array<U32>, x: U32, result: Array<U32> & U32) -> Words:
  (b, y) = result
  Words{a, b, order(U32.shrn(x, 8n), U32.shrn(y, 8n))}

def word.left(at: U32, b: Array<U32>, result: Array<U32> & U32) -> Words:
  (a, x) = result
  word.right(a, x, Array.get(U32, b, at))

def words.checked(equal: Bool, +at: U32, state: Words, next: U32 -> Words -> Words) -> Words:
  match equal state:
    case False{} state: state
    case True{} Words{a, b, _}:
      next(U32.inc(at), word.left(at, b, Array.get(U32, a, at)))

def words(left: Nat, at: U32, state: Words) -> Words:
  match left state:
    case 0n state: state
    case 1n+p Words{a, b, +relation}:
      words.checked(U32.is_eq(relation, 0), at, Words{a, b, relation}, i => s => words(p, i, s))

def key.finished(oa: List<&2, U32>, ob: List<&2, U32>, na: U32, nb: U32, state: Words) -> Key & Key & U32:
  match state:
    case Words{a, b, relation}: (Key{oa, a, na}, Key{ob, b, nb}, relation)

# OID, scalar count, then scalar content form a total order for equality keys.
# Only equality uses this order; original signed DER and RDN order are intact.
def key.compare(a: Key, b: Key) -> Key & Key & U32:
  match a b:
    case Key{+oa, a, +na} Key{+ob, b, +nb}:
      +relation = oid.order(oa, ob, 0)
      key.finished(oa, ob, na, nb, words(U32.to_nat(na), 0,
        Words{a, b, Bool.pick(U32, U32.is_eq(relation, 0), order(na, nb), relation)}))

def merge.compared(xs: Keys(), ys: Keys(), reversed: Keys(), result: Key & Key & U32,
  next: Keys() -> Keys() -> Keys() -> Maybe<&1, Keys()>) -> Maybe<&1, Keys()>:
  (x, y, relation) = result
  match relation:
    case 2: next(Con{x, xs}, ys, Con{y, reversed})
    case _: next(xs, Con{y, ys}, Con{x, reversed})

# The budget is the original total key count. Each comparison emits one key.
# Exhaustion with both runs nonempty fails closed; no key is discarded.
def merge(left: Nat, xs: Keys(), ys: Keys(), reversed: Keys()) -> Maybe<&1, Keys()>:
  match left xs ys:
    case _ Nil{} ys: Some{List.reverse.go(&1, Key, reversed, ys)}
    case _ xs Nil{}: Some{List.reverse.go(&1, Key, reversed, xs)}
    case 0n _ _: None{}
    case 1n+p Con{x, xs} Con{y, ys}:
      merge.compared(xs, ys, reversed, key.compare(x, y), a => b => rev => merge(p, a, b, rev))

def split(left: Nat, keys: Keys(), reversed: Keys()) -> Keys() & Keys():
  match left keys:
    case 0n keys: (List.reverse(&1, Key, reversed), keys)
    case 1n+p Con{key, rest}: split(p, rest, Con{key, reversed})
    case _ Nil{}: (List.reverse(&1, Key, reversed), [])

def sort.second(size: Nat, first: Keys(), other: Maybe<&1, Keys()>) -> Maybe<&1, Keys()>:
  match other:
    case None{}: None{}
    case Some{other}: merge(size, first, other, [])

def sort.first(size: Nat, second: Unit -> Maybe<&1, Keys()>, first: Maybe<&1, Keys()>) -> Maybe<&1, Keys()>:
  match first:
    case None{}: None{}
    case Some{first}: sort.second(size, first, second(Unit{}))

def sort.split(size: Nat, parts: Keys() & Keys(), first: Keys() -> Maybe<&1, Keys()>,
  second: Keys() -> Maybe<&1, Keys()>) -> Maybe<&1, Keys()>:
  (a, b) = parts
  sort.first(size, u => second(b), first(a))

def sort.checked(small: Bool, +size: Nat, keys: Keys(),
  first: Nat -> Keys() -> Maybe<&1, Keys()>, second: Nat -> Keys() -> Maybe<&1, Keys()>) -> Maybe<&1, Keys()>:
  match small:
    case True{}: Some{keys}
    case False{}:
      +half = Nat.div(size, 2n)
      sort.split(size, split(half, keys, []), a => first(half, a), b => second(Nat.sub(size, half), b))

def sort.exhausted(small: Bool, keys: Keys()) -> Maybe<&1, Keys()>:
  match small:
    case True{}: Some{keys}
    case False{}: None{}

# DER Names have at most 65535 octets, hence fewer than 65536 attributes.
# Sixteen balanced splits reach singleton runs; exhaustion rejects explicitly.
# Each branch owns its keys and a separate continuation, retaining affine arrays.
def sort.walk(depth: Nat, +size: Nat, keys: Keys()) -> Maybe<&1, Keys()>:
  match depth:
    case 0n: sort.exhausted(Nat.is_le(size, 1n), keys)
    case 1n+ +p:
      sort.checked(Nat.is_le(size, 1n), size, keys,
        n => a => sort.walk(p, n, a), n => b => sort.walk(p, n, b))

def sort(size: Nat, keys: Keys()) -> Maybe<&1, Keys()>:
  sort.walk(16n, size, keys)

# RFC 5280 7.3 (updated by RFC 9549): stored domainComponent IA5 octets
# compare exactly except ASCII case. Do not apply DirectoryString whitespace,
# deletion or Unicode folding. DNS/IDNA label validation has a separate owner.
def domain.words(bytes: List<&2, U32>, buffer: B.Buffer) -> C.Normalized:
  match bytes buffer:
    case Nil{} B.Buffer{values, length, _, _, _, _, _}: C.Normalized{values, length}
    case Con{byte, rest} buffer:
      domain.words(rest, B.put(U32.shln(I.lower(byte), 8n), buffer))

def domain.admitted(tables: U.Tables, bytes: List<&2, U32>, status: Maybe<&1, Bool>) -> U.Tables & Maybe<&1, C.Normalized>:
  match status:
    case Some{True{}}: (tables, Some{domain.words(bytes, B.new())})
    case _: (tables, None{})

def attribute.prepare(is_domain: Bool, tables: U.Tables, oid: List<&2, U32>, +tag: U32, +bytes: List<&2, U32>) -> U.Tables & Maybe<&1, C.Normalized>:
  match is_domain:
    case True{}: domain.admitted(tables, bytes, S.value(S.Rule{3, 0, 65535}, tag, bytes))
    case False{}: P.prepare(tables, oid, tag, bytes)

def attributes.prepared(oid: List<&2, U32>, result: U.Tables & Maybe<&1, C.Normalized>,
  next: U.Tables -> Key -> U.Tables & Maybe<&1, Keys()>) -> U.Tables & Maybe<&1, Keys()>:
  (tables, value) = result
  match value:
    case None{}: (tables, None{})
    case Some{C.Normalized{values, length}}:
      next(tables, Key{oid, values, length})

def attributes(attrs: List<&2, N.Attribute>, tables: U.Tables, reversed: Keys(), count: Nat) -> U.Tables & Maybe<&1, Keys()>:
  match attrs:
    case Nil{}: (tables, sort(count, reversed))
    case Con{N.Attribute{+oid, tag, bytes, _}, rest}:
      attributes.prepared(oid,
        attribute.prepare(S.rule.same(oid, [9,146,38,137,147,242,44,100,1,25], True{}), tables, oid, tag, bytes),
        t => key => attributes(rest, t, Con{key, reversed}, Nat.add(count, 1n)))

def rdns.prepared(result: U.Tables & Maybe<&1, Keys()>,
  next: U.Tables -> Keys() -> U.Tables & Maybe<&1, Prepared>) -> U.Tables & Maybe<&1, Prepared>:
  (tables, keys) = result
  match keys:
    case None{}: (tables, None{})
    case Some{keys}: next(tables, keys)

def rdns(input: List<&2, List<&2, N.Attribute>>, tables: U.Tables, reversed: List<&1, Keys()>) -> U.Tables & Maybe<&1, Prepared>:
  match input:
    case Nil{}: (tables, Some{Prepared{List.reverse(&1, Keys(), reversed)}})
    case Con{attrs, rest}: rdns.prepared(attributes(attrs, tables, [], 0n), t => keys => rdns(rest, t, Con{keys, reversed}))

def decoded(tables: U.Tables, value: Maybe<&1, N.Name>) -> U.Tables & Maybe<&1, Prepared>:
  match value:
    case None{}: (tables, None{})
    case Some{N.Name{input, _}}: rdns(input, tables, [])

def prepare(tables: U.Tables, bytes: List<&2, U32>) -> U.Tables & Maybe<&1, Prepared>:
  decoded(tables, N.decode(bytes))

def keys.compared(result: Key & Key & U32, next: Unit -> Bool) -> Bool:
  (_, _, relation) = result
  match relation:
    case 0: next(Unit{})
    case _: False{}

def keys.equal(xs: Keys(), ys: Keys()) -> Bool:
  match xs ys:
    case Nil{} Nil{}: True{}
    case Con{x, xs} Con{y, ys}: keys.compared(key.compare(x, y), u => keys.equal(xs, ys))
    case _ _: False{}

def names.checked(equal: Bool, next: Unit -> Bool) -> Bool:
  match equal:
    case True{}: next(Unit{})
    case False{}: False{}

def names.equal(xs: List<&1, Keys()>, ys: List<&1, Keys()>) -> Bool:
  match xs ys:
    case Nil{} Nil{}: True{}
    case Con{x, xs} Con{y, ys}: names.checked(keys.equal(x, y), u => names.equal(xs, ys))
    case _ _: False{}

def compare.prepared(tables: U.Tables, first: Prepared, other: Maybe<&1, Prepared>) -> U.Tables & Maybe<&1, Bool>:
  match first other:
    case Prepared{a} Some{Prepared{b}}: (tables, Some{names.equal(a, b)})
    case _ _: (tables, None{})

def compare.right(first: Prepared, result: U.Tables & Maybe<&1, Prepared>) -> U.Tables & Maybe<&1, Bool>:
  (tables, other) = result
  compare.prepared(tables, first, other)

def compare.left(bytes: List<&2, U32>, result: U.Tables & Maybe<&1, Prepared>) -> U.Tables & Maybe<&1, Bool>:
  (tables, value) = result
  match value:
    case None{}: (tables, None{})
    case Some{left}: compare.right(left, prepare(tables, bytes))

def compare(tables: U.Tables, a: List<&2, U32>, b: List<&2, U32>) -> U.Tables & Maybe<&1, Bool>:
  compare.left(b, prepare(tables, a))
