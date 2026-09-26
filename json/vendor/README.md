# vendor

Reference implementations, read-only. Not built or imported.

| Dir | Source | Commit | License |
|---|---|---|---|
| `serde_json/` | github.com/serde-rs/json (v1.0.151) | `afdf6fc6` | MIT / Apache-2.0 |
| `zig-std-json/` | codeberg.org/ziglang/zig `lib/std/json` + `json.zig` | `880d7add` | MIT |

Where to look:
- Rust parser: `serde_json/src/read.rs` (bytes, escapes, surrogates), `de.rs` (grammar)
- Rust value + printer: `serde_json/src/value/`, `ser.rs` (escaping, pretty)
- Zig tokenizer: `zig-std-json/Scanner.zig` — streaming state machine, no recursion
- Zig printer: `zig-std-json/Stringify.zig`
- Zig dynamic value: `zig-std-json/dynamic.zig`
- Conformance cases: `zig-std-json/JSONTestSuite_test.zig`
