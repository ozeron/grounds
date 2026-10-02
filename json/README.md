# grounds-json

The `json` package of [grounds](../README.md): a JSON parser and printer for [Bend 2](https://github.com/bendlang/bend), per [RFC 8259](docs/rfc8259.txt).

Proven for every value `j` (`LAWS.bend`, checked by `bend PROOF.bend`):

- `parse(encode(j)) == Done{j}`
- `reformat(encode(j)) == Ok{encode(j)}`: the one-pass loop `grounds-json` runs reads printed JSON back unchanged
- `parse(pretty(j, "  ")) == Done{j}`: indented output reads back too (`proof/layout.bend`, for any indent of spaces and tabs)

```sh
mise install                          # installs the pinned bend (run anywhere in the repo)
moon run json:check                   # every test, law and conformance case; or ./check.sh here
bend main.bend -- file.json           # pretty-print, or report line:col of the error
scripts/build.sh                      # native CLI with PGO: ./grounds-json [--compact] file.json
```

`--max-bytes N` (provisional) refuses a file over N bytes before reading it.

## API

Import it with `import ./json.bend as J`.

| Function | Does |
|---|---|
| `J.parse(s)` | `Done{json}` or `Fail{J.Error{reason, offset, line, column}}` |
| `J.parse_bytes(bs)` | `parse` on raw bytes (`List<U32>`, 0..255); bytes that are not UTF-8 fail as `InvalidUtf8` |
| `J.encode(j)` | compact text |
| `J.pretty(j, "  ")` | indented text; the argument is one level of indent |
| `J.message(e)` | `"3:5: unexpected \",\""` |

Reads (level A of [docs/API.md](docs/API.md)) give `Done{value}` or `Fail{access}`:

| Function | Does |
|---|---|
| `J.get(j, key)` | the value of a key; the last one wins on duplicates |
| `J.index(j, i)` | the item at index `i` (`U32`) |
| `J.string(j)`, `J.bool(j)` | the string, the bool |
| `J.u32(j)` | a whole number from 0 to 2^32 − 1, however it is written (`1e2`, `100.0`, `-0`); anything else is `OutOfRange` |
| `J.f32(j)` | the nearest F32; past 2^24 not every whole number has one, and past about 3.4e38 it is `OutOfRange`, never infinity |
| `J.number(j)` | the number exactly as written, for what `u32` and `f32` cannot hold |
| `J.array(j)`, `J.object(j)` | the items, the fields, in order |
| `J.is_null(j)` | `Bool` |
| `J.message_access(a)` | `"$.user.tags[0]: expected string, found number"`; a key that is not a plain name is quoted: `$["a.b"]` |

`Access` is `Missing{path}` (no such key, or an index past the end), `Expected{path, want, got}` (another kind of value) or `OutOfRange{path}`. A path is a list of `Name{key}` and `Index{i}` steps; kinds are `KNull`, `KBool`, `KNumber`, `KString`, `KArray`, `KObject`. `LAWS.bend` proves each read: it gives back what was stored, fails as `Expected` exactly on other kinds, and `get` finds a key with the last duplicate winning. `u32` reads the same value across forms (`.0`, `e0`, `-0`, and `e1` against an added `0`), and `f32` never answers infinity or NaN.

Build values with `JNull`, `JBool`, `JNum{Number}`, `JStr`, `JArr{List<Json>}`, `JObj{List<Field>}`, and numbers with `J.num(text)`, `num_u32(x)`, `num_f32(x)` (`num` and `num_f32` give `None` for text that is not a JSON number, e.g. `inf`); `J.num_text(n)` is a number's text.

A `Number` holds the sign, digits, fraction and exponent as written. An invalid number cannot be built.

Paths (level B) read a nested value in one call, and their errors carry the full path:

| Function | Does |
|---|---|
| `J.at(j, [J.Name{"user"}, J.Index{0}])` | the value at a path |
| `J.string_at`, `bool_at`, `u32_at`, `f32_at`, `number_at` | a typed read at a path; it copies what it returns, so one document can be read many times |
| `J.array_at`, `J.object_at` | the items, the fields at a path |
| `J.both(A, B, C, r1, r2, f)` | two reads joined by `f`; the first error wins |
| `J.map(A, B, r, f)` | `f` on a read's value |

A decoder is one expression (`examples/user.bend`):

```python
def User.from_json(+j: J.Json) -> Result<&2, &2, J.Access, User>:
  J.both(String, U32, User, J.string_at(j, [J.Name{"name"}]), J.u32_at(j, [J.Name{"age"}]), n => a => User{n, a})
```

Read one document many times only with the typed `_at` reads: `at`, `array_at` and `object_at` return part of it, which shares it. Call reads from a def, not from `main` itself: a read there owns its argument, which heats a type the decoder reads twice.

## Behavior to know

- Numbers keep their exact digits, so big and precise numbers round-trip exactly. Convert with `as_u32` or `as_f32`.
- Objects keep every member in order, duplicates included. `get` returns the last one.
- A lone surrogate like `"\uDEAD"` is an error.
- Where JSONTestSuite leaves the answer to the parser (its `i_` cases), numbers of any size, deep nesting and a leading BOM parse; lone surrogate escapes and non-UTF-8 input fail. `scripts/gen_suite.py` holds the rules.
- A leading byte order mark is skipped.
- Input that is not UTF-8 is an error, reported where the bad bytes start. `grounds-json` checks this before parsing.
- Offsets and columns count Unicode code points, not bytes.
- Parsing has no nesting limit: it uses an explicit stack, and 100k levels work.
- Printing uses an explicit stack too: 100k levels print and pretty-print.

## Performance

`bench/run.sh` times a full round trip (read, parse, print compact) on the [nativejson-benchmark](https://github.com/miloyip/nativejson-benchmark) files, and fails if canada takes over 1.5x Go. Apple Silicon, mean of 10+ runs, startup included.

| tool | canada 2.3 MB | citm_catalog 1.7 MB | twitter 0.6 MB |
|---|---|---|---|
| `grounds-json --compact` | 37 ms | 17 ms | 8.2 ms |
| Go `encoding/json` | 28 ms | 15 ms | 8.1 ms |
| Bun | 20 ms | 16 ms | 15 ms |
| Node | 31 ms | 22 ms | 20 ms |
| jq | 42 ms | 29 ms | 18 ms |
| Python `json` | 59 ms | 22 ms | 19 ms |

`bench/big.sh` does the same on a 100 MB file (the three files, repeated):

| tool | time | peak memory |
|---|---|---|
| `grounds-json --compact` | 1.4 s | 2.9 GB |
| `grounds-json` (pretty) | 2.1 s | 4.6 GB |
| `spec-grounds-json --compact` (proven path) | 2.0 s | 3.0 GB |
| Go `encoding/json` | 1.0 s | 0.7 GB |
| jq | 1.7 s | 1.0 GB |

Memory is the cost of Bend strings: a cons cell per char, for the input and the output both, about 29 bytes per input byte. Use `--max-bytes` to cap it.

`grounds-json` runs everything through `fast.bend`: one pass that checks the input and writes the output, compact or indented, without building a `Json` value. It answers exactly what the proven `J.parse`, `J.encode` and `J.pretty` answer, errors included: `suite.bend` checks this on every JSONTestSuite case, and `scripts/integration.py` fuzzes `grounds-json` against `spec_cli.bend`, the same CLI on the proven parser.

Neither `grounds-json` nor the proven library may share a String: one shared String makes the runtime count references on every String in the program, which halves the speed. `scripts/cold.py` fails the check if `main.bend` or `spec_cli.bend` does. So the proven parser's errors count the chars left instead of keeping the input, and its round trip, UTF-8 decoding included, takes 55 ms on canada and 13 ms on twitter.

The cold-type gate reads Bend 2.0.27's `CID_HOT_T`, or the hot column of
Bend 2.0.34's `CID_T`. It rejects unknown tables, inconsistent constructor IDs
and unrecognized accessors. `python3 scripts/cold_test.py` checks both formats
and failure behavior without compiling Bend. This format support does not
change the repository's compiler pin or establish constant-time execution.

## Files

| File | Holds |
|---|---|
| `json.bend` | the library |
| `../utf8`, `../io` | UTF-8 decoding and file reads, shared with other grounds packages |
| `test.bend` | unit tests; each is a proof that checks at compile time |
| `LAWS.bend`, `PROOF.bend` | laws the library keeps, and their proofs |
| `proof/` | the round-trip proofs: `print` (printer = spec), `strings`, `numbers`, `parse` (the loop); `fast_text`, `fast`, `fast_run` for `fast.bend` (the tail of `fast_run` is generated by `scripts/gen_fast_proof.py`); `layout`, generated by `scripts/gen_layout_proof.py`, for indented text |
| `suite.bend` | [JSONTestSuite](https://github.com/nst/JSONTestSuite) cases, generated by `scripts/gen_suite.py`; run by `suite_run.bend` |
| `stress.bend` | 100k-sized inputs |
| `reads_check.bend` | reads on numbers too large for `test.bend`, whose cases the checker evaluates at compile time |
| `scripts/integration.py` | builds the CLI and fuzzes it against Python's `json`; `SEED=` and `N=` set the run |
| `main.bend` | the CLI, on `fast.bend` |
| `fast.bend` | the one-pass reformatter; generated by `scripts/gen_fast.py` from `scripts/fast_head.bend.in` |
| `spec_cli.bend` | the same CLI on the proven parser, for tests |
| `scripts/cold.py` | fails if a program makes any type reference counted |
| `scripts/cold_test.py` | cold-type metadata and CLI regression checks, without invoking Bend |
| `docs/TODO.md` | the RFC as a checklist |
| `vendor/` | serde_json and Zig std.json, for reference |

## Bend notes

These rules shaped the code:

- No mutual recursion. The parser is one loop over an explicit stack of open containers.
- Every loop must provably end. The parser's step count is bounded by the input length.
- `Bool.pick` evaluates both branches. Keep recursive calls out of it, or they run anyway.
- Deep non-tail recursion overflows the runtime stack, even when guarded by a constructor. Everything that walks input or output is tail-recursive. The printer walks an explicit stack, with fuel to pass the termination check.
- A proof cannot see through a `match` on char literals when the char is unknown. So string chars go through one classifier, `class`, that the printer and the lexer share.
- A value is shared when it is owned (returned, stored, or passed to a def that does either) and then used again. One shared value makes its type reference counted in the whole program, and every constructor of it slower. A `+x` whose earlier uses only read `x` is fine. `Bool.pick(a, b)` owns both, so it shares whatever they have in common.
- A loop compiles to a tight C loop only if it calls nothing that compiles to a segment (IO, or a call into a slower def).
