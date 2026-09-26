# bjson TODO

Built from [RFC 8259](rfc8259.txt) (JSON, STD 90). Section numbers point into it.

## Value model (§3)
- [x] `Json` type: null, bool, number, string, array, object
- [x] Number repr: keep the source text; convert with `as_u32` / `as_f32` (§6)
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
- [x] Input is a Bend `String` (code points); `File.read` decodes UTF-8 before bjson sees it

### Errors and limits (§9)
- [x] Error type with reason
- [x] Position: offset, line and column, in code points
- [x] Max nesting depth: none needed; the stack is explicit, 100k levels tested
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
- [x] `stringify(Json) -> String`, `pretty(Json, indent) -> String`
- [x] Accessors: `get(key)`, `at(index)`, `as_str`, `as_f32`, `as_u32`, `as_bool`, `as_list`, `as_fields`, `is_null`
- [x] `message(Error)` for people
- [x] CLI: `main.bend`, builds to a native binary

## Laws (`LAWS.bend` / `PROOF.bend`)
- [x] Literals round-trip; pretty equals compact on literals
- [x] Lookups on empty or wrong-kind values give `None`
- [x] Typed reads return what was stored
- [x] Parser and printer terminate on every input (checked by Bend)
- [ ] Prove `parse(stringify(j)) == Done{j}` for every `j` (tested, not proven; needs lemmas about the parser loop)
- [ ] Prove `stringify` output always parses

## Tests
- [x] JSONTestSuite: all 271 y_/n_ cases pass; 25 cases skipped because their bytes are not valid UTF-8
- [x] Unit tests per grammar rule (`test.bend`)
- [x] Stress: 100k escapes, items, digits and nesting levels (`stress.bend`)
- [x] 1 MB round trip through the native CLI matches Python's `json`
