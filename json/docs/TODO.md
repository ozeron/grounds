# grounds-json TODO

Built from [RFC 8259](rfc8259.txt) (JSON, STD 90). Section numbers point into it.

## Value model (§3)
- [x] `Json` type: null, bool, number, string, array, object
- [x] Number repr: a typed `Number` with the exact digits; convert with `as_u32` / `as_f32` (§6)
- [x] Object repr: ordered `List<Field>`, duplicates kept (§4)

## Parser
### Whitespace and top level (§2)
- [x] Skip `ws` = space, tab, LF, CR — nothing else
- [x] `JSON-text = ws value ws`; any scalar is valid at the top
- [x] Reject trailing non-ws after the value
- [x] Skip a leading BOM (§8.1, MAY)

### Literals (§3)
- [x] `true`, `false`, `null`, lowercase only
- [x] Reject any other bare word (`True`, `NaN`, `undefined`)

### Objects (§4)
- [x] `{}` and `{ "k": v, ... }`
- [x] Keys must be strings
- [x] Reject trailing comma, missing colon, missing comma
- [x] Duplicate keys: keep all in order; `get` returns the last

### Arrays (§5)
- [x] `[]` and `[v, ...]` with mixed element types
- [x] Reject trailing comma and missing comma

### Numbers (§6)
- [x] Optional `-`; no leading `+`
- [x] Int: `0` or `1-9` then digits; reject leading zeros (`01`)
- [x] Fraction: `.` plus 1+ digits (reject `1.`, `.5`)
- [x] Exponent: `e`/`E`, optional `+`/`-`, 1+ digits (reject `1e`)
- [x] Reject `Infinity`, `NaN`, hex
- [x] Limits (§9): none; the text is kept as is, so any size round-trips

### Strings (§7)
- [x] Delimited by `"`
- [x] Reject raw control chars U+0000–U+001F
- [x] Escapes: `\" \\ \/ \b \f \n \r \t`
- [x] `\uXXXX`, hex digits in either case
- [x] Combine surrogate pairs (`𝄞` → U+1D11E)
- [x] Lone surrogates like `\uDEAD` (§8.2): error
- [x] Reject any other escape (`\x`, `\'`, `\0`)

### Encoding (§8.1)
- [x] Reject input that is not UTF-8 (overlong forms, surrogates, past U+10FFFF, cut-off sequences) as `InvalidUtf8`, at the code point where the bad bytes start
- [x] `parse_bytes` decodes bytes itself; `grounds-json` reads text through the runtime and re-reads the bytes only if the text has a U+FFFD

### Errors and limits (§9)
- [x] Error type with reason
- [x] Position: offset, line and column, in code points
- [x] Max nesting depth: none for parsing (explicit stack, 100k levels tested); printing handles about 5,000
- [x] Max string length / input size: none; 100k-char strings tested

## Serializer (§10)
- [x] Emit only valid JSON
- [x] Escape `"`, `\` and U+0000–U+001F; use short escapes where they exist
- [x] Never emit NaN/Infinity: `num_f32` returns `None` for them
- [x] Never emit a BOM
- [x] Compact output
- [x] Pretty output with configurable indent

## Equality (§8.3)
- [x] Keys are compared after unescaping, code point by code point

## API
- [x] `parse(String) -> Result<Error, Json>`
- [x] `encode(Json) -> String`, `pretty(Json, indent) -> String`
- [x] Accessors: `get(key)`, `at(index)`, `as_str`, `as_f32`, `as_u32`, `as_bool`, `as_list`, `as_fields`, `is_null`
- [x] `message(Error)` for people
- [x] CLI: `main.bend`, builds to a native binary

## Laws (`LAWS.bend` / `PROOF.bend`)
- [x] Literals round-trip; pretty equals compact on literals
- [x] Lookups on empty or wrong-kind values give `None`
- [x] Typed reads return what was stored
- [x] Parser and printer terminate on every input (checked by Bend)
- [x] Prove `parse(encode(j)) == Done{j}` for every `j` (`proof/`)
- [x] Prove `encode` output always parses

## Tests
- [x] JSONTestSuite: all 318 cases pass, i_ ones included, with the answers decided in `scripts/gen_suite.py`: any number parses, lone surrogate escapes and non-UTF-8 input fail
- [x] Unit tests per grammar rule (`test.bend`)
- [x] Stress: 100k escapes, items, digits and nesting levels (`stress.bend`)
- [x] 1 MB round trip through the native CLI matches Python's `json`
- [x] Integration: the native CLI fuzzed against Python's `json` (`scripts/integration.py`)

## Next: prove the fast path equals the proven parser on every input

Goal: `F.reformat(s)` ends where `J.parse_state(s)` does, for every `s`: `Ok{encode(v)}` on `Fin{v}`, `Err{r, left}` on `Bad{r, left}`. Then prove `parse` accepts exactly the RFC 8259 grammar, numbers first. Mutation-test each proof.

Started on branch `m5-fast-left` (not green):
- [x] Fast-path errors count the chars left (`Err{reason, left}`), as J's do, so the two compare without U32 arithmetic
- [x] `J.parse_state(s)`: the loop's end state; `suite.bend` compares the fast path against it
- [ ] Fix: `main.bend` is reference counted again (`scripts/cold.py`); not the new `J.size` calls in the error rows, still to find
- [ ] Update `proof/fast.bend`, `proof/fast_run.bend` and `scripts/gen_fast_proof.py` from `at`/`ea` to `bk`

The blocker for an any-input proof: both loops match char literals (`'['`, `'0'`), which a proof cannot evaluate for an unknown char. Plan:
- [ ] One set of classifiers for both loops: `class` (strings, as now), `nclass` (numbers), and a new `tok` for structure, white space, literals and escape letters
- [ ] The fast loop makes exactly J's classifier calls at each char, so a proof splits on their results and both sides follow
- [ ] The fast loop outputs canonical chars (`digit_char(d)`), never an echo of a classified char, so no proof needs `tok(c) == K` to give `c == '['`
- [ ] Benchmark first: `TOK=1 python3 scripts/gen_fast.py` makes a prototype dispatching on a per-char tag; keep canada within 1.5x Go
- [ ] Generate the simulation proof (like `scripts/gen_layout_proof.py`); `fast_round_trip` then follows from it and `round_trip`

## CI
- [x] One Linux job: `check.sh`, the bench gate, a nightly fuzz that saves failing inputs for `examples/regress/`; verified with `act`
- [ ] macOS: building the fast loop takes about 9 GB, over a macOS runner's 7 GB; cut the build's memory first

## Next: stream the input in chunks (measured, `bench/spike/`)

The fast loop pauses at each chunk's end and resumes on the next; the CLI writes each chunk's output. Measured (PGO, Apple Silicon), against today's grounds-json and Go:

| | chunked | grounds-json now | Go |
|---|---|---|---|
| canada | 34.9 ms | 38.7 ms | 27.3 ms |
| citm_catalog | 15.7 ms | 18.4 ms | 14.2 ms |
| twitter | 7.9 ms | 8.7 ms | 7.6 ms |
| 100 MB | 1.24 s, 39 MB | 1.32 s, 2.9 GB | 1.0 s, 0.7 GB |

Base's `Array` is a tree (each read rebuilds a path), so a packed byte buffer would be slower than lists: chunking, not packing, is what cuts memory.

- [ ] `grounds-io`: a C effect that reads up to n bytes and backs off to a UTF-8 boundary (`lseek` back the cut-off tail), so no char is split across chunks
- [ ] `fast.bend`: the end-of-input row returns the paused state; `reformat(s)` finishes it; update `fast_round_trip` by that one step
- [ ] CLI: the chunk driver (`bench/spike/chunkfmt.bend`); bad UTF-8 checked per chunk
- [ ] Keep it cold: pass a chunk twice as the fuel and input, never rebuild it from shared parts

## Upstream: report to Bend

- [ ] Base's `Nat.min`, `Nat.max` and `Nat.mul` (large first argument) recurse one step at a time, while `Nat.add`, `Nat.sub` and `Nat.cmp` run natively. `Nat.min(4294967295n, x)` overflows the machine stack. `json.bend` works around it (`nat_min` via `Nat.is_le`; `Nat.mul(10n, acc)` with the small factor first); other Bend code will hit it.
- [ ] The checker evaluates Nats one by one, so a `test.bend` case on a large number (e.g. `u32("1e999999999999999999")`) runs for minutes; such cases live in `reads_check.bend`, run natively.
