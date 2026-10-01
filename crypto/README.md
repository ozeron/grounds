# grounds-crypto

Pure Bend cryptographic primitives. This package implements SHA-1, SHA-256, HMAC-SHA1, HMAC-SHA256, HKDF-SHA-256, ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD, AES-128 encryption, AES-128-GCM, and X25519. They are **experimental**: cookie signing and TLS still use OpenSSL while the Bend implementation is verified and its generated code is reviewed for timing behavior. Plain SHA-1 is used only for the WebSocket handshake challenge; HMAC-SHA1 is for the legacy STUN MESSAGE-INTEGRITY attribute.

| Module | Public calls | Source |
|---|---|---|
| `sha1.bend` | `digest(bytes)` | RFC 3174 / WebSocket RFC 6455 challenge |
| `sha256.bend` | `digest(bytes)`, `digest_hex(bytes)` | FIPS 180-4 / RFC 6234 |
| `hmac_sha1.bend` | `digest(key, bytes)` | RFC 2104 / RFC 2202 / STUN RFC 8489 |
| `hmac.bend` | `digest(key, bytes)`, `digest_hex(key, bytes)` | RFC 2104 / RFC 4231 |
| `hkdf.bend` | `extract(salt, ikm)`, `expand(length, prk, info)` | RFC 5869 |
| `chacha20.bend` | `block(key, nonce, counter)`, `crypt(key, nonce, counter, bytes)` | RFC 8439 |
| `poly1305.bend` | `mac(one_time_key, bytes)` | RFC 8439 |
| `aead.bend` | `seal(key, nonce, aad, plaintext)`, `open(key, nonce, aad, ciphertext, tag)` | RFC 8439 |
| `aes128.bend` | `encrypt(key, block)` | FIPS 197 AES-128 encryption |
| `gcm.bend` | `seal(key, nonce, aad, plaintext)`, `open(key, nonce, aad, ciphertext, tag)` | SP 800-38D, 96-bit nonce / 128-bit tag profile |
| `traffic.bend` | `expand_label`, `new_write`, `new_read`, `new_aes128_write`, `new_aes128_read`, `seal`, `open`, `rekey_write`, `rekey_read`, `close_write`, `close_read` | RFC 9846 TLS 1.3 traffic-key/nonce lifecycle for ChaCha20-Poly1305 and AES-128-GCM with SHA-256 |
| `x25519.bend` | `scalar_mult(scalar, u)`, `public_key(scalar)`, `shared(scalar, peer_public)` | RFC 7748 |
| `field25519.bend` | Internal `add`, `sub`, `mul`, `square`, `decode`, `encode` | GF(2^255-19) arithmetic used by X25519 |
| `bytes.bend` | `length`, `valid`, `append`, `hex` | Tail-recursive byte-list helpers |

Byte input and output use `List<U32>` with values 0–255. The public calls return `None{}` for an out-of-range byte; `expand` also rejects a PRK other than 32 bytes or a requested length over 8160 bytes. SHA-1 and HMAC-SHA1 return 20 bytes; SHA-256 and HMAC-SHA256 return 32 bytes. The hex helpers are for diagnostics and tests; protocols should use raw bytes.

ChaCha20 requires a 32-byte key and 12-byte nonce. `block` returns 64 keystream bytes; `crypt` XORs a message with successive blocks and rejects a request that would wrap the 32-bit counter. It does **not** authenticate ciphertext. Poly1305 requires a fresh 32-byte one-time key per message. AEAD derives that key from ChaCha20 block zero, encrypts from counter one, authenticates the associated data and ciphertext, and returns plaintext only after checking all 16 tag bytes. The caller must ensure a unique nonce for every message under a key; these calls do not manage nonce allocation.

AES-128 `encrypt` requires exactly 16 valid key bytes and 16 block bytes.
The S-box computes inversion in GF(2^8) followed by the FIPS affine transform;
it does not index a table with a secret byte. Key expansion supplies ten rounds
with column-major state, SubBytes/ShiftRows, MixColumns and AddRoundKey. GCM
uses only block encryption; AES decryption and 192/256-bit keys are not supplied.
The internal prepared-key helpers assume validated key/block input and are
not validating entry points.

AES-128-GCM requires a 16-byte key, 12-byte nonce and full 16-byte tag.
`seal` returns its own `Sealed{ciphertext, tag}`; `open` returns plaintext only
after scanning the entire supplied tag. GHASH uses eight 16-bit limbs and fixed
128-bit multiplication. It processes AAD and ciphertext separately, pads each
final partial block and authenticates their big-endian 64-bit bit lengths,
without allocating a combined MAC-input message. Counter encryption starts at
two, with `nonce || 1` reserved for the tag mask. The plaintext/ciphertext
limit is 2^36−32 bytes, following SP 800-38D section 5.2.1.1; a larger length
is rejected before encryption, preventing counter reuse. AAD is limited by
Bend's representable byte-list length (Nat maximum 2^48−1), which is smaller
than the published general AEAD bound. Nonce uniqueness and per-key record
usage limits remain the protocol owner's responsibility. TLS callers use
the AES-128 traffic factories below, which enforce bounded TLS records and
the sending epoch's usage cap.

Native and Bun checks compare all 256 S-box bytes with FIPS 197 Table 4,
the published cipher example, all 284 AESAVS AES-128 ECB encryption KATs,
40 independent OpenSSL cases and malformed key/block lengths. GCM checks
select 150 NIST CAVP cases across every 96-bit-IV/full-tag PT/AAD length group,
including 32 authentication failures. Independent OpenSSL AES plus Python
bigint GHASH agrees on round trips through 64 KiB, every tag-byte mutation,
AAD/ciphertext/key/nonce tampering, 166 field products and 16 compiled
length/counter boundaries up to the largest Nat. Closed Bend checks reject
out-of-range bytes. The JSON vector fixtures carry source URLs, archive hashes
and selection details and participate in Moon's crypto task hash. These are
informal correctness checks, not NIST validation or timing certification.
[FIPS 197](https://csrc.nist.gov/pubs/fips/197/final) and
[SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) were reviewed on
2026-10-01. SP 800-38D remains the final published specification with a revision
planned. RFC 5116 section 5.1 publishes a one-byte-larger plaintext bound;
this implementation uses the NIST bound above. The RFC errata snapshot lists
verified 4008 (decrypt input wording) and 4268 (nonce-persistence example),
both consistent with this interface. Reported 5219 proposes the NIST plaintext
bound; it remains reported, so this limit is grounded in the NIST specification.

Run `moon run crypto:check --force`. The check proves that SHA-256 state output is always 32 bytes, compiles the native adapters, tests invalid-byte handling, compares SHA-256 against four published vectors and boundary/binary cases, compares HMAC against RFC 4231 and Python, and checks three RFC 5869 extract/expand vectors plus output-length boundaries. The million-`a` SHA-256 vector exercises a multi-block message.

`traffic.bend` owns TLS_CHACHA20_POLY1305_SHA256 and TLS_AES_128_GCM_SHA256 keys, IVs and
64-bit record counters. `new_write` / `new_read` validate a 32-byte traffic
secret and return distinct affine owners. `seal` / `open` consume that owner
and return its successor alongside `Done` or `Fail`; callers must retain only
the successor. The nonce is the derived 12-byte IV XOR the left-padded,
big-endian sequence. Sequence zero is used first, the last 64-bit value is
used once, and a further operation fails without wrapping. Invalid seal input,
failed authentication and attempted counter wrap retire the owner; closed
owners cannot reopen or update. Explicit close consumes the live epoch.

`new_write` / `new_read` retain the original ChaCha20-Poly1305 behavior;
`new_aes128_write` / `new_aes128_read` explicitly select AES-128-GCM. AES epochs
derive a 16-byte key and 12-byte IV and retain their algorithm through updates.
No authentication fallback chooses another cipher suite. AES sending epochs
allow at most 2^24 records, conservatively below RFC 9846 section 5.5's
approximately 2^24.5 full-record bound. An attempted extra seal returns
`UsageLimit` and retires the owner. Its raw input bounds are five AAD bytes
and 16385 inner plaintext bytes, preserving the full-record usage assumptions.
Oversized seal input returns `Invalid` and retires; receive input errors retire
as authentication failures. Receiving epochs enforce the size/sequence bounds
and authenticate each record but do not apply the sending usage cap.
Send old-key KeyUpdate before exhausting the allowance; the final permitted
record can carry that message, followed by an explicit key update/reset.

`rekey_write` / `rekey_read` derive a new secret with `traffic upd`, then a new
key and IV, and reset the record sequence. Sending updates are limited to
2^48−1; exceeding that limit returns `UpdateLimit` while preserving the
current epoch, and receive updates have no such cap. The TLS handshake owner
must enforce handshake phase, emit/process KeyUpdate under the old key before
changing keys, and update proactively while it can still send that message.
Record framing, content types, padding, TLS record-size limits, stream
fragmentation and the complete handshake are not implemented by this module.
Initial traffic secrets must be unique for each connection/direction/epoch;
constructors and internal helpers are visible in Bend, so deliberately
reconstructing an owner can bypass this interface's lifecycle discipline.
Retiring an epoch releases its references logically; it does not prove physical
erasure of every runtime copy or timing-safe execution.

The traffic evaluator passes 70 scenarios on native and Bun: three RFC 8448
KDF vectors, independent Python HKDF and OpenSSL-ChaCha20/bigint-Poly1305
records, sequential records, 32/64-bit carries, exhaustion, four key updates,
the sending update cap/carry, replay/reordering, wrong-key/AAD/ciphertext/tag,
invalid inputs and retirement. The compiler also rejects affine owner copies
and direction confusion. Counter/generation injection exists only in the
synthetic CLI to reach impractical boundaries. The 16-byte RFC key vector
tests HKDF label serialization. Separate AES-GCM owner checks pass 72
independent lifecycle scenarios per target, including sequential records,
all tag positions, usage-cap boundaries, uncapped receiving counters,
64-bit carry/exhaustion, five epochs, sending update-generation limits,
algorithm confusion, malformed inputs and permanent retirement.
[RFC 9846](https://www.rfc-editor.org/info/rfc9846/) (July 2026) supersedes
RFC 8446; sections 4.7.3, 5.3/5.5 and 7.1–7.3 and
[its errata](https://www.rfc-editor.org/errata/rfc9846) were reviewed on
2026-10-01. The errata page lists five reported records and no verified records;
none changes these implemented operations. RFC 9846's TLS label is distinct
from DTLS 1.3's label; this owner must not be reused for DTLS unchanged.

SHA-256 and HMAC-SHA256 now use `bytes.bend` for length, validation and append traversal. The RTC authentication checks independently compare SHA-256 STUN MACs and maximum-length STUN packet signing on native and Bun; these paths exposed and now avoid Base's non-tail list recursion on JS. The crypto check itself retains the native SHA-256/HMAC/HKDF vectors; RTC supplies this additional compiled JS evidence.

SHA-1 is checked against published vectors and Python's `hashlib` on native and Bun JS, including a 64 KiB message on both targets and the million-`a` vector on native. Its sole protocol use here is `Sec-WebSocket-Accept`.

HMAC-SHA1 is checked against all seven RFC 2202 vectors and eight Python `hmac` differential cases on native and Bun JS, including a 64 KiB message. The `rtc` package uses it to verify the RFC 5769 STUN MESSAGE-INTEGRITY vectors. This does not establish timing-safe execution or authenticate the current unauthenticated Binding discovery client.

The check also proves the RFC 8439 quarter-round example, compares the ChaCha20 block and stream functions with RFC 8439 vectors, and checks additional block and stream cases against OpenSSL on native and, when Bun is installed, JS targets. It checks malformed key/nonce lengths and counter limits.

Poly1305 passes nine RFC 8439 vectors and 250 cases against an independent bigint reference, including extreme clamped-key/block patterns and both sides of final prime selection. AEAD matches the RFC ciphertext and tag, plus 12 differential records against OpenSSL ChaCha20 and the independent Poly1305 reference, including a 64 KiB seal/open on both native and Bun JS. The check rejects changed key, nonce, associated data, ciphertext and tag bytes, and bad key, nonce and tag lengths. Bend proofs cover invalid-byte rejection and basic MAC input layout. `bytes.bend` avoids JS stack overflow from Bend Base's non-tail list length and append operations on the tested 64 KiB record.

Poly1305 now uses thirteen base-2^10 limbs. Coefficient k is bounded by
(61−4k)·1023²; every product sum and its incoming carry remains below 2^26.
This avoids the old base-2^13 product coefficients above signed 32-bit range.
Five fixed normalization passes produce 10-bit digits: after the first fold,
the second pass has final carry at most one; if that carry propagates to the
top, limbs 2–12 become zero and the third pass cannot propagate beyond limb
one. Canonical selection uses 0/1023 masks and XOR 1023 for their complement,
with no unsigned negative subtraction. Source/range calculations and generated
C/JS/arm64 assembly are retained under
`/Users/ozeron/.codex/artifacts/grounds/2026-10-01/aes-gcm/`.
The numeric-range finding is mitigated at these sites. Reference counting,
allocator/scheduler behavior, optimized machine code, Bun JIT and key erasure
remain open review gates before live-secret use.

X25519 accepts 32-byte scalars and public coordinates, clamps scalars, masks the high coordinate bit, reduces noncanonical coordinates, and uses the RFC Montgomery ladder. `scalar_mult` returns the raw result; `shared` rejects an all-zero secret after scanning all output bytes. The field check compares 319 pairs across addition, subtraction, and multiplication against Python big integers on native and Bun, including every byte carry/borrow boundary and all 19 noncanonical coordinates with their high-bit aliases. X25519 checks the RFC function, Alice/Bob, and one-iteration vectors, four OpenSSL key exchanges, malformed lengths, all those coordinate aliases, and four constant/alternating scalar patterns on both targets; native also passes the RFC 1,000 iteration chain. Bend checks prove malformed input is rejected before ladder evaluation.

`field25519.decode` assumes exactly 32 valid bytes; use the validating X25519 calls for external input.

This is correctness evidence for tested inputs, not a proof of constant-time execution or production security. The current compiled CLI has reference-counted constructors (`json/scripts/cold.py` reports hot types), so byte representation and throughput need more work. X25519 in particular needs a generated-code timing audit before handling live secrets. The next gates are that audit, throughput work, traffic-owner integration/erasure, mandatory TLS algorithms/signatures, and integration with cookie signing before replacing its OpenSSL effect.

Initial static review on 2026-10-01 retained generated C for X25519, AEAD and
HMAC-SHA1, generated X25519 JavaScript and default Apple Clang 21 `-O3` arm64
assembly in `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/foundations/`.
`generated-review.json` pins source/generated digests and exact evidence lines.
The inspected native field and Poly1305 selection helpers use U32 bit masks;
their selected value does not choose a branch or array index in those helpers.
This is support for those operations, not approval of the full runtime or crypto.

The X25519 numeric-range finding is now mitigated at its inspected sites:
`cswap` and field canonicalization use 0/255 byte masks, and the inverse
selection mask is XOR 255. Canonical subtraction biases each byte by 256,
keeping the difference in 0–511 and the borrow in 0/1 without unsigned negative
wraparound. This relies on canonical byte digits and ladder bits in 0/1; field
carry/reduction and scalar-bit extraction establish those bounds. Regenerated
C/JavaScript and default Clang arm64 assembly are retained in
`/Users/ozeron/.codex/artifacts/grounds/2026-10-01/x25519-ranges/` with review
metadata. This removes the previous wide-mask/wrapped-subtraction forms at those
sites; it does not establish whole-runtime or Bun JIT timing safety, and no
measured timing leak is claimed. [RFC 7748 sections 5 and 5.1](https://www.rfc-editor.org/rfc/rfc7748.html#section-5)
and [its errata](https://www.rfc-editor.org/errata/rfc7748) were reviewed on
2026-10-01; verified errata 7625 clarifies the XOR ladder update, which remains
unchanged, and 5028 clarifies the decoded coordinate after top-bit masking.
`control-memory-review.json` maps all generated field/X25519 core functions:
accepted-input ladder/inversion counts and field array indices follow public
counters; secret bits affect masks/arithmetic. Field products plus their bounded
carry stay below 2^21. Shared-secret zero rejection scans the entire result
before its final observable accept/reject decision. Native U32 buffers use direct
word copies without per-digit term tag/refcount dispatch. These static findings
still leave complete optimized native code, allocator/scheduler, JavaScript
array/object storage, garbage collection and JIT lowering to review.
Clang `-O3 -fstack-usage` reports 784 static function frames in the generated
X25519 CLI, with a largest frame of 2176 bytes in `io_exec`; the `.su` file and
`stack-usage-evidence.json` are retained. This is a per-function estimate, not
an aggregate call-depth bound or evidence about the larger signaling fixture.
The inspected native free path recycles cells without a dedicated
complete payload scrub; clearing a new host RNG buffer does not erase every
Bend key/field copy. Secret ownership/erasure, full generated control/memory
dependency review, Bun JIT behavior and generated-runtime ABI/stack review remain
required before live-secret use. The large local signaling fixture still needs
its separately documented Apple Clang stack-probe workaround.
