# bjson TODO

Built from [RFC 8259](rfc8259.txt) (JSON, STD 90). Section numbers point into it.

## Value model (§3)
- [x] `Json` type: null, bool, number, string, array, object
- [ ] Decide number repr: F32 only, or keep the source text / split int vs float (§6)
- [ ] Decide object repr: ordered `List<Field>` (current) vs `Map` (§4)

## Parser
### Whitespace and top level (§2)
- [x] Skip `ws` = space, tab, LF, CR — nothing else
- [x] `JSON-text = ws value ws`; any scalar is valid at the top
- [x] Reject trailing non-ws after the value
- [ ] Optionally skip a leading UTF-8 BOM (§8.1, MAY)

### Literals (§3)
- [x] `true`, `false`, `null`, lowercase only
- [x] Reject any other bare word (`True`, `NaN`, `undefined`)

### Objects (§4)
- [ ] `{}` and `{ "k": v, ... }`
- [ ] Keys must be strings
- [ ] Reject trailing comma, missing colon, missing comma
- [ ] Pick a duplicate-key policy: keep last, keep all, or error (SHOULD be unique)

### Arrays (§5)
- [ ] `[]` and `[v, ...]` with mixed element types
- [ ] Reject trailing comma and missing comma

### Numbers (§6)
- [ ] Optional `-`; no leading `+`
- [ ] Int: `0` or `1-9` then digits; reject leading zeros (`01`)
- [ ] Fraction: `.` plus 1+ digits (reject `1.`, `.5`)
- [ ] Exponent: `e`/`E`, optional `+`/`-`, 1+ digits (reject `1e`)
- [ ] Reject `Infinity`, `NaN`, hex
- [ ] Document range/precision limits (§9 allows them); ints in ±(2^53-1) should round-trip

### Strings (§7)
- [ ] Delimited by `"`
- [ ] Reject raw control chars U+0000–U+001F
- [ ] Escapes: `\" \\ \/ \b \f \n \r \t`
- [ ] `\uXXXX`, hex digits in either case
- [ ] Combine surrogate pairs (`𝄞` → U+1D11E)
- [ ] Pick a policy for lone surrogates like `\uDEAD` (§8.2): error or replace
- [ ] Reject any other escape (`\x`, `\'`, `\0`)

### Encoding (§8.1)
- [ ] Input is UTF-8; decide what to do with invalid UTF-8

### Errors and limits (§9)
- [x] Error type with reason
- [ ] Add position (offset or line:col) to errors
- [ ] Max nesting depth (needs a `Nat` fuel arg for termination anyway)
- [ ] Max string length / input size, if any

## Serializer (§10)
- [ ] Emit only valid JSON
- [ ] Escape `"`, `\` and U+0000–U+001F; use short escapes where they exist
- [ ] Never emit NaN/Infinity: error or `null`
- [ ] Never emit a BOM
- [ ] Compact output
- [ ] Pretty output with configurable indent

## Equality (§8.3)
- [ ] Compare keys after unescaping, code point by code point

## API
- [x] `parse(String) -> Result<Error, Json>`
- [ ] `stringify(Json) -> String`, `pretty(Json, indent) -> String`
- [ ] Accessors: `get(key)`, `at(index)`, `as_str`, `as_num`, `as_bool`, `is_null`

## Laws (`LAWS.bend` / `PROOF.bend`)
- [ ] `parse(stringify(j)) == Done{j}` — round-trip
- [ ] `stringify` output always parses
- [ ] `stringify` is deterministic for ordered objects
- [ ] Parser terminates on every input (checked by Bend already)

## Tests
- [ ] Port cases from `vendor/zig-std-json/JSONTestSuite_test.zig` (y_/n_/i_ cases)
- [ ] Unit tests per grammar rule above
