# Bend cookie HMAC boundary

The explicit `cookie_bend.sign` / `cookie_bend.verify` calls retain the existing cookie
signature format and IO result shapes. Legacy `sign` / `verify` remain
OpenSSL-backed on native and unavailable on JS. The new path calls the pure
`cookie_crypto` module and shared Bend HMAC-SHA256; it imports no crypto effect.

The authenticated message is the exact UTF-8 value, including embedded dots,
NUL and non-normalized Unicode. The suffix is a dot followed by the complete
32-byte HMAC in hex. Verification consumes exactly 64 trailing characters,
requires the separator, admits ASCII upper/lowercase hex and checks the full
MAC. Rejection occurs before returning the value. Empty values are valid.
Malformed framing/hex, changed values and wrong keys return `None`.

Invalid Unicode scalars are rejected before encoding. Callers must bound
header/value lengths before cryptographic work. This module does not establish
cookie expiration, session ownership, key rotation, purpose separation or
secure transport; those belong in the signaling/application owner.

The source XOR/OR reduction visits every MAC byte rather than returning at
the first mismatch. Generated JS retains that reduction. Pinned generated C,
both generated JS programs and pinned native undefined symbols contain no
legacy cookie effect, OpenSSL, host HMAC or dynamic crypto-loader dependency.
This evidence covers the emitted cookie programs, not arbitrary future callers.

Runtime review remains open. String/byte-list sharing, temporary HMAC pads and
hash states have no explicit secure-erasure owner. Native optimization,
allocation/scheduling and Bun optimizing-JIT behavior require review before
live-secret use. Source loops and correctness tests alone do not resolve
those findings. All current keys and authenticated values are synthetic.

The independent checker pins two full RFC 4231 SHA-256 vectors and compares
2,675 cases against Python HMAC: empty/Unicode/NUL/dotted values, block/key
boundaries, deterministic random cases, 4,096-byte values, wrong keys,
changed values, every alternative lowercase hex digit at every tag position,
non-hex tags and malformed envelopes. Final native/Bun reports for pinned
Bend 2.0.27 and scoped 2.0.34 are under
`/Users/ozeron/.codex/artifacts/grounds/2026-10-03/http-bend-cookies/`.
These establish tested-input interoperability; they do not complete package,
secure-signaling or full-stack acceptance.

The UTF-8 fixture rejects invalid encodings before invoking the signer; direct
Bend invalid-scalar constructor coverage is still required for that branch.
