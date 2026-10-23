# grounds-json typed API

Levels A (primitive reads), B (paths), D (typed composition) and E (user codecs) are available. D uses fixed-arity products and compile-time decoder templates; runtime `Decoder<A>` objects and derive macros remain deferred.

## Primitive reads and paths

`parse(String)` and `parse_bytes(List<&2, U32>)` return `Result<&2, &2, Error, Json>`. `encode(Json)` prints compact JSON; `pretty(Json, String)` prints indented JSON. `message(Error)` formats parse errors.

The following reads return `Result<&2, &2, Access, A>`:

```python
J.get(j, key)       # Json; the last duplicate key wins
J.index(j, i)       # Json; i is U32
J.string(j)        # String
J.u32(j)           # U32; whole and in range, including 1e2 and 100.0
J.bool(j)          # Bool
J.f32(j)           # F32; OutOfRange rather than infinity or NaN
J.number(j)        # Number; exact digits, sign, fraction and exponent
J.array(j)         # List<&2, Json>
J.object(j)        # List<&2, Field>, including duplicate keys
J.is_null(j)       # Bool, not a Result

J.at(j, [J.Name{"users"}, J.Index{3}])  # Result<Access, Json>
J.string_at(j, path)
J.u32_at(j, path)
J.bool_at(j, path)
J.f32_at(j, path)
J.number_at(j, path)
J.array_at(j, path)  # List<&2, Json>; all items, in order
J.object_at(j, path) # List<&2, Field>; all fields, in order, duplicates included
```

`Path` means `List<&2, Step>`, where `Step` is `Name{key: String}` or `Index{i: U32}`. `Access` is `Missing{path}`, `Expected{path, want, got}`, or `OutOfRange{path}`. `J.message_access(e)` formats errors such as `$.users[3].age: expected number, found bool`; unusual keys are quoted as in `$["a.b"]`.

A missing parent reports the first step that could not be found. A wrong parent kind reports that parent's path. A wrong leaf kind reports the full leaf path. Duplicate keys retain the existing last-key-wins behavior.

## Level D: typed composition

Below, `R(A)` abbreviates `Result<&2, &2, J.Access, A>` and every type parameter is `Data`.

```python
J.map(A, B, r: R(A), f: A -> B) -> R(B)
J.both(A, B, Z, r1: R(A), r2: R(B), f: A -> B -> Z) -> R(Z)
J.both3(A, B, C, Z, r1, r2, r3, f: A -> B -> C -> Z) -> R(Z)
J.both4(A, B, C, D, Z, r1, r2, r3, r4, f) -> R(Z)
J.both5(A, B, C, D, E, Z, r1, r2, r3, r4, r5, f) -> R(Z)
J.both6(A, B, C, D, E, F, Z, r1, r2, r3, r4, r5, r6, f) -> R(Z)
J.both7(A, B, C, D, E, F, G, Z, r1, r2, r3, r4, r5, r6, r7, f) -> R(Z)
```

All products return the first failing argument, in argument order. This specifies which error is returned; it does not promise lazy evaluation of the reads. An applicative `ap` cannot use the existing Result: Bend 2.0.38 gives functions kind `Type`, while its reusable Result payload must be `Data`.

### Optional values and defaults

```python
J.optional_at(~A, ~item: Json -> R(A), j: Json, path: Path) -> R(Maybe<&2, A>)
J.string_opt_at(j, path) -> R(Maybe<&2, String>)
J.u32_opt_at(j, path) -> R(Maybe<&2, U32>)
J.bool_opt_at(j, path) -> R(Maybe<&2, Bool>)
J.f32_opt_at(j, path) -> R(Maybe<&2, F32>)
J.number_opt_at(j, path) -> R(Maybe<&2, Number>)
J.default(A, r: R(Maybe<&2, A>), fallback: A) -> R(A)
```

A missing **final object key**, or `null` at a resolved path, gives `Done{None{}}`. A present value is decoded as `Some`; wrong kinds and numeric range errors still fail. A missing intermediate key or any missing array index remains `Missing`. A null intermediate parent is a kind error. An empty path observes the root: root null is None.

`default` replaces only a successful None. It preserves Some and every error. `optional_at` accepts custom object or list decoders too, and prefixes their relative error paths. For round trips, a Some encoder must never emit null: null is reserved for None.

### Nested records

```python
J.decode_at(~A, ~dec: Json -> R(A), j: Json, path: Path) -> R(A)
J.field_obj(A, k: String, v: A, enc: A -> Json) -> List<&2, Field>

J.decode_at(~Address, ~(x => Address.from_json(x)), j,
  [J.Name{"user"}, J.Name{"address"}])
J.field_obj(Address, "address", address, Address.to_json)
```

`decode_at` walks to the sub-document, runs its decoder and prefixes the decoder's relative errors with the resolved path. An Address decoder reading `city` therefore reports `$.user.address.city: missing`. Missing parents and wrong parent kinds keep the walker's existing errors. Empty paths decode the root. The decoder determines which JSON kinds it accepts; `decode_at` itself does not require an object.

Each record owns its encoder, decoder and round-trip theorem. `decode_field_round_trip` lifts an arbitrary codec's round-trip hypothesis through `field_obj` and `decode_at`; `list_field_round_trip` does the same for lists. These combine: a nested record can contain a list of records whose fields are themselves nested.

### Lists of user types

```python
J.list_at(~A, ~item: Json -> R(A), j: Json, path: Path) -> R(List<&2, A>)

J.list_at(~String, ~(x => J.string_at(x, [])), j, [J.Name{"tags"}])
```

The `~` arguments are templates, substituted at compile time. Bend closures are affine, so a runtime function cannot be reused for every element. Templates must be closed expressions: use top-level names or literal lambdas, without captured runtime variables.

Items decode in order; the first failure wins. An item decoder's relative path is prefixed with the array path and its index. Nested list decoders compose these prefixes. `examples/users.bend` decodes a list of two-field Person objects, while reading another field from the same document. Tests include `$.users[3].age`, nested indices, missing item fields, wrong array kinds and empty arrays.

### Keeping types cold

The scalar `_at` reads rebuild their leaves. `list_at` walks the source read-only and builds a fresh decoded list, without copying source Json containers into an intermediate tree. Its item decoder must also return rebuilt data. Use typed path reads to rebuild returned data; a raw `J.string` returns the source String. Reusable named record decoders work in the nested User recipe. Other callbacks can retain the source across suspended calls, so compile their consumers with the cold gate. Use `+x => ...` when the item expression reads x several times. `examples/users.bend` demonstrates the complete object callback.

`scripts/cold.py` checks both typed recipes, their separate law example and `examples/containers.bend`, including consumers of returned strings and nested Json values from decoders that read the source document again. Error prefixing uses tail-recursive path concatenation: a suspended append can heat the source document even on successful reads. Keep reads in defs, because main owns its arguments.

`array_at` and `object_at` now return actual members, with a full cold copy of every nested value, key and number representation. Their old empty-container result was a bug. Scalar reads still use the existing kind-only container copies and keep their error messages. Low-level `at` retains its API.

The copier uses separate source cursors because reconstructing source tails as `JArr{tail}` or `JObj{tail}` makes Bend's compiler share the source. Its structural recursion budget is 4,294,967,295, independently of the path walk's budget. Each descent or sibling step spends one unit; sibling branches each receive the remaining budget. Exhaustion fails as `OutOfRange` at the selected container, and never returns a truncated tree. Container identity and member laws require a `CopyFits` witness for this budget; they are **not unrestricted laws for arbitrarily large trees**. The unrestricted cold copier and unconditional container laws remain unresolved. Typed `list_at` lifting laws have no such copy-budget hypothesis.

## Encoders

Encoder helpers return **field chunks** (`List<&2, Field>`). `obj` joins a list of chunks, so an optional field can contribute zero fields without special caller branches.

```python
J.obj(fields: List<&2, List<&2, Field>>) -> Json
J.field_str(k: String, s: String) -> List<&2, Field>
J.field_u32(k: String, x: U32) -> List<&2, Field>
J.field_bool(k: String, b: Bool) -> List<&2, Field>
J.field_obj(A, k: String, v: A, enc: A -> Json) -> List<&2, Field>
J.field_opt(A, k: String, m: Maybe<&2, A>, enc: A -> Json) -> List<&2, Field>
J.field_list(~A, ~enc: A -> Json, k: String, xs: List<&2, A>) -> List<&2, Field>
J.list_json(~A, ~enc: A -> Json, xs: List<&2, A>) -> Json
```

`field_opt` omits None and encodes Some. `field_u32` uses the proven `num_u32`, which builds decimal digits without opaque text conversion. Raw constructors and `num`, `num_f32` remain available.

## Level E: a complete recipe

`examples/user.bend` imports only Base and the runtime JSON module. It contains the type, encoder, decoder, parse-result adapter and a runnable main:

```python
type Pet is Data:
  Pet{name: String}

def Pet.to_json(p: Pet) -> J.Json:
  match p:
    case Pet{n}:
      J.obj([J.field_str("name", n)])

def Pet.from_json(j: J.Json) -> Result<&2, &2, J.Access, Pet>:
  J.map(String, Pet, J.string_at(j, [J.Name{"name"}]), n => Pet{n})

type Address is Data:
  Address{city: String, zip: U32}

def Address.to_json(a: Address) -> J.Json:
  match a:
    case Address{c, z}:
      J.obj([J.field_str("city", c), J.field_u32("zip", z)])

def Address.from_json(+j: J.Json) -> Result<&2, &2, J.Access, Address>:
  J.both(String, U32, Address, J.string_at(j, [J.Name{"city"}]), J.u32_at(j, [J.Name{"zip"}]), c => z => Address{c, z})

type User is Data:
  User{name: String, age: U32, admin: Bool, email: Maybe<&2, String>, tags: List<&2, String>, address: Address, pets: List<&2, Pet>}

def User.to_json(u: User) -> J.Json:
  match u:
    case User{n, a, b, e, t, address, pets}:
      J.obj([J.field_str("name", n), J.field_u32("age", a), J.field_bool("admin", b), J.field_opt(String, "email", e, s => J.JStr{s}), J.field_list(~String, ~(s => J.JStr{s}), "tags", t), J.field_obj(Address, "address", address, Address.to_json), J.field_list(~Pet, ~Pet.to_json, "pets", pets)])

def User.from_json(+j: J.Json) -> Result<&2, &2, J.Access, User>:
  J.both7(String, U32, Bool, Maybe<&2, String>, List<&2, String>, Address, List<&2, Pet>, User,
    J.string_at(j, [J.Name{"name"}]), J.u32_at(j, [J.Name{"age"}]), J.bool_at(j, [J.Name{"admin"}]),
    J.string_opt_at(j, [J.Name{"email"}]), J.list_at(~String, ~(x => J.string_at(x, [])), j, [J.Name{"tags"}]),
    J.decode_at(~Address, ~(x => Address.from_json(x)), j, [J.Name{"address"}]), J.list_at(~Pet, ~Pet.from_json, j, [J.Name{"pets"}]),
    n => a => b => e => t => address => pets => User{n, a, b, e, t, address, pets})
```

Unknown object fields are ignored. Name, age, admin, tags, address and pets are required. Email is optional; tags and pets may be empty. To default a missing list, combine `optional_at` with a list decoder and `default`. The runnable example exercises a parsed nested User, value encoding and a list of Users, with absent and present email.

## Proven laws

`proof/typed.bend` contains shared proofs, imported by `PROOF.bend`:

- `string_copy_round_trip`, `u32_copy_round_trip`, `bool_copy_round_trip`, and `u32_copy_at` connect copied reads to their stored values.
- `scalar_field_round_trip`, with `string_field_round_trip`, `u32_field_round_trip` and `bool_field_round_trip`, proves the scalar encoder/read pairs for arbitrary keys.
- `optional_some_round_trip` proves a Some field round trip from the item's round-trip hypothesis and a non-null encoder hypothesis. `optional_none_round_trip` proves omission decodes as None; `optional_null` proves null decodes as None. `default_some` and `default_none` prove defaults.
- `list_round_trip`, `list_at_round_trip` and `list_field_round_trip` prove list round trips from `for x: dec(enc(x)) == Done{x}`. No list length or sample-value restriction is used.
- `both3_done` through `both7_done` prove successful product reduction. `both_reads`, `both5_reads` and `both7_reads` compose individual field equalities into a constructor equality. Error priority is covered at every argument position in `typed_test.bend`.

- `decode_round_trip`, `decode_at_round_trip` and `decode_field_round_trip` lift `for x: dec(enc(x)) == Done{x}` through decoder error prefixing, root decoding and object fields. `decode_field_value` lifts a single successful decoder equality.
- `copy_json.go_id` proves deep-copy identity under a structural `CopyFits` witness for any fuel. `copy_json_id`, `array_copy_round_trip`, `object_copy_round_trip`, `array_at_round_trip` and `object_at_round_trip` specialize it to the public copy budget and container reads. Nested values, order, duplicate keys and exact number representations are preserved within that budget. The predicate and proof peel `1n+k` structurally; they never expand or compare huge closed Nats.

`examples/user_laws.bend` imports the proof tree separately. Definition lengths, including the `def` line and excluding law declarations and blank lines:

| Law | Lines | Composition |
|---|---:|---|
| `pet_round_trip` | 4 | shared string copy law |
| `address_round_trip` | 4 | shared string and U32 copy laws |
| `user_round_trip` | 10 | `both7_reads`, scalar/optional laws, `decode_field_round_trip` with Address's theorem, `list_field_round_trip` with Pet's theorem |
| `user_text_round_trip` | 3 | JSON's text theorem and User's value theorem |
| `users_round_trip` | 2 | generic list theorem and User's theorem |

User's proof does not inspect Address or Pet. Its two branches handle omitted versus present email, which changes literal-key lookup in the encoded object. The general typed container laws take each type's existing round-trip proof as their hypothesis; they do not re-prove its fields. All are checked by `json:check`, and the runtime recipe imports no proofs.

## Deferred

Runtime Decoder objects, automatic deriving, a cursor API, string queries, JSON Pointer and signed integer conversions remain outside this change. Existing reads, `map`, `both`, errors and messages retain their APIs.
