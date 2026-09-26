# grounds-json public API v1

Level A is built (see the README's tables); B and E are next. v1 = **A + B + E**: safe accessors, typed paths, and hand-written decoders. Generic `Decoder<A>` combinators (D) wait until we see what composes well in Bend.

The example throughout:

```json
{"user": {"name": "Alex", "age": 31, "tags": ["quant", "coffee"]}}
```

## What we have now

| Area | Now | Problem |
|---|---|---|
| Parse | `parse(String)`, `parse_bytes(List<U32>)` (provisional) | fine; `parse_bytes` still marked provisional |
| Print | `stringify(j)`, `pretty(j, unit)` | `stringify` is a JS word; the proposal says `encode` |
| Access | `get(j, key)`, `at(j, n: Nat)` → `Maybe` | no error to report; `at` takes a `Nat`, everything else takes a `U32` |
| Typed reads | `as_bool`, `as_str`, `as_u32`, `as_f32`, `as_list`, `as_fields` → `Maybe` | no signed read: `as_u32` cannot read `-1` |
| Build | `num(text)`, `num_u32`, `num_f32`, the constructors `JNull`… `JObj` | fine |
| Errors | `Error{reason, offset, line, column}`, `message(e)` | parse errors only; no access errors |
| Bug | `get` compares keys with `String.eq` inside `Bool.pick` | shares Strings, so a program that calls `get` gets reference-counted Strings; it also scans every field after a match |
| Docs | README lists `J.decode` | it moved to `utf8` (`U.decode`) |

## Level A: primitives

Each returns `Result<&2, &2, Access, A>`: `Done{a}` or `Fail{why}`.

```python
J.get(j, "user")        # the value of a key; the last one wins on duplicates
J.index(j, 0)           # the item at an index (U32)
J.string(j)             # String
J.u32(j)                # U32: a whole number in range
J.f32(j)                # F32: may round, e.g. past 2^24
J.bool(j)
J.array(j)              # List<Json>
J.object(j)             # List<Field>, in order, duplicates kept
J.number(j)             # Number: exact digits, for anything u32/f32 cannot hold
J.is_null(j)            # Bool
```

`Access` says what went wrong and where:

```python
type Access is Data:
  Missing{path: Path}                            # no such key, or index past the end
  Expected{path: Path, want: JKind, got: JKind}  # e.g. want KString, got KNumber
  OutOfRange{path: Path}                         # a number u32 or f32 cannot hold

type JKind is Data:        # `Kind` is a Bend keyword
  KNull{}  KBool{}  KNumber{}  KString{}  KArray{}  KObject{}
```

`J.message_access(a)` → `"$.user.tags[0]: expected string, found number"`.

Level A reports the step it tried for `Missing` (`$.name`, `$[3]`) and the empty path `$` otherwise; level B fills in the full path.

## Level B: paths

```python
type Step is Data:
  Name{key: String}   # `Key` is taken by Base's keyboard events
  Index{i: U32}

# Path is List<&2, Step>
J.at(j, [J.Name{"user"}, J.Name{"name"}])              # Result<Access, Json>
J.string_at(j, [J.Name{"user"}, J.Name{"name"}])       # Done{"Alex"}
J.u32_at(j, [J.Name{"user"}, J.Name{"age"}])           # Done{31}
J.string_at(j, [J.Name{"user"}, J.Name{"tags"}, J.Index{0}])  # Done{"quant"}
J.bool_at, J.f32_at, J.number_at, J.array_at, J.object_at
```

This is the main win in Bend. Bend can't `match` on a function's result without a helper def, so chaining level A calls takes one small def per step. A path call does the whole lookup in one expression.

## Level E: your own decoders

No combinators. Write one def per type, built from level B:

```python
type User is Data:
  User{name: String, age: U32}

def User.from.go(name: Result<&2, &2, J.Access, String>, age: Result<&2, &2, J.Access, U32>) -> Result<&2, &2, J.Access, User>:
  match name age:
    case Done{n} Done{a}:
      Done{User{n, a}}
    case Fail{e} _:
      Fail{e}
    case _ Fail{e}:
      Fail{e}

def User.from_json(+j: J.Json) -> Result<&2, &2, J.Access, User>:
  User.from.go(J.string_at(j, [J.Name{"name"}]), J.u32_at(j, [J.Name{"age"}]))
```

The `.go` helper is the price of Bend's match rule. The README would show this pattern as the recommended decoder recipe.

Open question: add `J.both(r1, r2) -> Result<Access, A & B>` so a two-field decoder needs no helper? It is one def and saves the most boilerplate. Past two fields it nests, so it doesn't replace the helper.

## Names

| Now | v1 | Why |
|---|---|---|
| `stringify` | `encode` | pairs with `parse`; keep `stringify` one release as an alias? |
| `pretty` | `pretty` | |
| `get` | `get` | now `Result` |
| `at(j, n: Nat)` | `index(j, i: U32)` | `at` becomes the path lookup |
| `as_str` / `as_bool` / … | `string` / `bool` / `u32` / `f32` / `array` / `object` / `number` | now `Result`; done |
| `as_list`, `as_fields` | `array`, `object` | JSON's own words |
| `parse_bytes` | `parse_bytes` | no longer provisional |
| `num`, `num_u32`, `num_f32`, `num_text` | keep | building numbers |
| `message(e)` | keep, plus `message_access(a)` | |

Clean break or aliases: we have no users yet, so I'd make a clean break and skip the aliases.

## Laws (proven, in LAWS.bend)

- `get(JObj{[Field{k, v}]}, k) == Done{v}`, and later fields win.
- `index(JArr{xs}, i)` is the i-th item, or `Missing` past the end.
- `at(j, [])` is `Done{j}`; `at(j, s <> p)` is one step, then `at` on the rest.
- `string_at(j, p)` is `at(j, p)` then `string`; the same for every typed `_at`.
- Each typed read answers `Done` exactly on its own kind: `string(JStr{s}) == Done{s}`, and `Expected` otherwise.
- The existing round trips stay as they are.

## Not in v1

- Generic `Decoder<A>` (D): after v1 shows what composes in Bend.
- Cursor (C): Bend has no method chaining, so paths give the same thing with less API.
- String query `"user.name"` (F): escaping and syntax errors; maybe a later `query`.
- JSON Pointer `"/user/tags/0"` (G): a later add-on, since it's a standard and easy to build on paths.
- Signed integers: Base has only U32, F32 and Nat. `number` returns the exact digits, and an `i32` read would follow if Base or the hub gets a signed type (the hub has `bend-i64`).

## Work

1. [x] Fix `get` so it shares no String; `cold.py` checks `examples/access.bend`. It reads every field, since the last duplicate wins.
2. [x] Add `Access`, `JKind`, `Step` and level A, with their laws. [ ] Level B.
3. [x] Rename per the table; update `test.bend`, the proofs and the README.
4. Write the `User.from_json` recipe as a tested example (`examples/user.bend`).
5. README: an API table for each level and the decoder recipe.

About two days. The proofs mostly stay: they are about `parse` and the printer, not the accessors.
