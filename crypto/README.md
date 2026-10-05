# grounds-crypto

Pure Bend cryptographic primitives. This package implements SHA-1, SHA-256, HMAC-SHA1, HMAC-SHA256, HKDF-SHA-256, ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD, AES-128 encryption, AES-128-GCM, X25519, P-256 ECDH, P-256/SHA-256 ECDSA and RSA-PSS/v1.5 SHA-256 digest verification. They are **experimental**: legacy cookie signing and live TLS still use OpenSSL while the Bend implementation is verified and its generated code is reviewed for timing behavior. The HTTP core now exposes explicit Bend cookie HMAC wrappers for synthetic-key verification on native and Bun. Plain SHA-1 is used only for the WebSocket handshake challenge; HMAC-SHA1 is for the legacy STUN MESSAGE-INTEGRITY attribute.

| Module | Public calls | Source |
|---|---|---|
| `sha1.bend` | `digest(bytes)` | RFC 3174 / WebSocket RFC 6455 challenge |
| `sha256.bend` | `digest(bytes)`, `digest_hex(bytes)` | FIPS 180-4 / RFC 6234 |
| `sha256_stream.bend` | `start`, `update`, `finish`, `finish_hex` | RFC 6234 byte-aligned incremental SHA-256 |
| `sha256_file.bend` | `digest_hex(path)` | Bounded OS reads; Bend streaming SHA-256 |
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
| `p256.bend` | `public_key(private)`, `shared(private, peer_public)`, `decode(peer_public)` | SP 800-186 P-256 / SEC 1 v2.0 ECDH |
| `ecdsa_scheme256.bend` | `sign_digest(private, digest)`, `verify_digest(peer, digest, signature)` | RFC 6979 / SEC 1 v2.0; strict DER signature boundary |
| `rsa_encoding.bend` | `mgf1`, `pss_encode_digest`, `pss_verify_digest`, `v15_encode_digest`, `v15_verify_digest` | RFC 8017 SHA-256 encoding |
| `rsa_integer.bend` | `public_operation(modulus, exponent, signature)` | Experimental Bend RSAVP1, 2048–4096-bit RSA public keys |
| `rsa_signature256.bend` | `verify_pss_digest(modulus, exponent, digest, signature)`, `verify_v15_digest(modulus, exponent, digest, signature)` | Experimental full SHA-256 digest-signature verification; 774 focused cases pass on native and Bun |
| `field256.bend` | Internal P-256 prime/order `add`, `sub`, `mul`, `square`, `invert`, `decode_canonical` | SP 800-186 section 3.2.1.3 arithmetic foundation |
| `bytes.bend` | `length`, `valid`, `append`, `hex` | Tail-recursive byte-list helpers |
| `der.bend` | `decode(bytes)`, `complete(tag, bytes)` | Bounded DER TLV framing for future certificate schemas; preserves exact consumed bytes |
| `x509_algorithm.bend` | `key(bytes)`, `signature(bytes)`, `compatible(key, signature)` | Public SHA-256 RSA/P-256 certificate algorithm admission; preserves PSS key restrictions |
| `oid.bend` | `decode(bytes)` | Canonical primitive DER OID admission; retains encoded contents without narrowing arc values |
| `x509_public_key.bend` | `decode(bytes)` | Complete RSA/PSS or uncompressed P-256 SPKI structural/public-parameter admission; retains algorithm restrictions |
| `x509_certificate.bend` | `decode(bytes)` | Bounded certificate field framing; retains exact signed bytes and binds supported inner/outer algorithms |
| `x509_validity.bend` | `decode_time(bytes)`, `decode(bytes)`, `valid_at(bytes, now)` | Strict civil UTC calendar/interval admission and inclusive validity bounds; caller supplies trusted time |
| `x509_extensions.bend` | `decode(bytes)`, `optional(bytes)` | Exact extension envelopes, canonical OIDs/critical flags and collision-safe duplicate rejection; opaque payloads |
| `x509_constraints.bend` | `basic(bytes)`, `usage(bytes)`, `path_allows(limit,count)`, `policy(basic,usage)` | Basic-constraints/key-usage payload admission and local consistency; arbitrary-size path limits retained |
| `x509_eku.bend` | `decode(bytes)`, `permits(eku,purpose,allow_any)`, `tls13(usage,eku,server,allow_any)` | Canonical EKU payloads and explicit purpose permission; TLS 1.3 requires digitalSignature when KU is present |
| `x509_identity.bend` | `dns(pattern,reference)`, `ip(presented,reference)` | Typed ASCII DNS/IP comparison; complete leftmost wildcard only, exact IP octets |
| `x509_hostname.bend` | `frame(bytes)`, `san(bytes,kind,reference)`, `extensions(bytes,kind,reference)`, `certificate(bytes,kind,reference)` | Actual SAN-field DNS/IP identity matching without CN fallback; framing preserves other forms for pending schema/profile processing |
| `x509_san.bend` | `inspect(bytes)`, `permits(result,critical)`, `subject(subject,extensions)`, `certificate(bytes)` | Selected DNS/IP SAN admission and empty-subject critical-SAN binding; other name forms remain deferred |
| `unicode32_profile.bend` | `tables()`, `flags(state,code)`, `map_code(code)` | Full Unicode 3.2 RFC 4518 literal mapping/prohibition/combining-mark properties; preserves table ownership; case folding/NFKC are separate modules; complete preparation remains pending |
| `unicode32_prepare.bend` | `tables(normalization_bytes,profile_bytes)`, `prepare(state,codes,casefold)` | Complete RFC 4518 stored/non-substring scalar preparation after caller transcoding; packed output, optional B.2 case folding; not yet integrated into Name comparison |
| `unicode32_nfkc.bend` | `normalize(state,codes)` | Exact Unicode 3.2 NFKC with authenticated asset tables, packed scalar output and stable canonical ordering; full preparation/Name comparison remain pending |
| `unicode32_fold.bend` | `tables()`, `code(state,code)`, `map_code(state,code)`, `string(state,codes,mapping)` | Exact Unicode 3.2 RFC 3454 B.2 case folding and RFC 4518 literal mapping before folding; NFKC is separate; full preparation remains pending |
| `x509_name_schema.bend` | `inspect(bytes,allow_empty)`, `pair(issuer,subject)` | Shared RDN/attribute/string syntax checks without retaining a Name collection |
| `x509_name.bend` | `decode(bytes)`, `inspect(bytes,allow_empty)`, `pair(issuer,subject)` | RDN/attribute framing, DER SET ordering and selected typed attribute syntax; preserve original attributes and defer unknown types/Teletex |
| `x509_name_certificate.bend` | `certificate(bytes)` | Inspect actual issuer/subject fields; an issuer must be nonempty |
| `x509_extension_policy.bend` | `decode(bytes)`, `optional(bytes)`, `certificate(bytes)`, `tls13_extensions(bytes,server,allow_any)`, `tls13_certificate(bytes,server,allow_any)` | Process basic constraints/KU/EKU and selected DNS/IP SAN, enforce empty-subject SAN binding, reject unsupported critical extensions, retain pending purpose/identity entries; TLS helpers check purpose permission only |
| `x509_signature.bend` | `verify_signature(issuer_spki, certificate)` | Mathematical issuer-signature verification using admitted key restrictions and original signed bytes; no trust decision |

Byte input and output use `List<U32>` with values 0–255. The public calls return `None{}` for an out-of-range byte; `expand` also rejects a PRK other than 32 bytes or a requested length over 8160 bytes. SHA-1 and HMAC-SHA1 return 20 bytes; SHA-256 and HMAC-SHA256 return 32 bytes. The hex helpers are for diagnostics and tests; protocols should use raw bytes.

`der.bend` supplies single-octet-tag framing with minimal definite lengths and
a 65,535-byte input bound. `decode` returns the tag, body, unconsumed rest and
exact consumed encoding; `complete` additionally requires the selected tag and
no trailing bytes. Eight closed checks and 1,552 native/Bun oracle cases pass.
Complete certificate schemas, primitive-value rules, trust and handshake
integration remain required. Selected algorithm/SPKI admission is supplied by
the separate modules below. See [DER_REVIEW.md](DER_REVIEW.md).

`x509_algorithm.bend` parses complete certificate AlgorithmIdentifiers for
SHA-256 RSA PSS/v1.5 signatures and P-256 ECDSA. RSA and PSS-only key identities
remain distinct; present PSS parameters bind hash/MGF/trailer and a retained
minimum salt. Native and Bun each pass 4,563 cases; seven algorithm closed
checks pass. This does not decode SPKI bits, verify a certificate or implement
TLS wire SignatureScheme admission. See [X509_ALGORITHM_REVIEW.md](X509_ALGORITHM_REVIEW.md)
for supported encodings, compiler memory evidence and pending integration.

`x509_public_key.decode` admits one exact SPKI SEQUENCE with an octet-aligned
BIT STRING. RSA INTEGERs normalize only necessary sign padding and retain the
RSA/PSS key identity; modulus/exponent admission matches the existing public
RSA primitive. P-256 uses the existing canonical on-curve point decoder.
Six closed checks and 11,547 independent cases per native/Bun target pass,
including published NIST points and frozen OpenSSL public keys. RSA factor
structure, certificate constraints/trust/hostname and TLS scheme
binding remain required as applicable. See [X509_PUBLIC_KEY_REVIEW.md](X509_PUBLIC_KEY_REVIEW.md).

RSA encoding is an experimental component, documented in
[RSA_REVIEW.md](RSA_REVIEW.md). PSS uses a 32-byte digest, MGF1-SHA-256 and a
caller-supplied 32-byte salt; `emBits` ranges from 521 through 4096. This is an
encoding bound, not a permitted TLS key-size policy. PKCS#1 v1.5 uses the exact
SHA-256 DER DigestInfo including NULL parameters, with encoded lengths 62–512
bytes. MGF1 accepts valid seeds and output lengths through 512 bytes. Encoding
returns `None{}` on invalid input; verification returns `False{}`. RSA
private exponentiation, salt generation and private-key
lifecycle are not implemented here. `rsa_integer.public_operation` separately
admits canonical unsigned big-endian odd moduli of 2048–4096 bits, canonical
odd exponents greater than one and below the modulus, and exactly `k` valid
signature bytes representing an integer below the modulus. It returns `k`
big-endian bytes or `None{}`. This assumes a valid RSA key and does not certify
factor structure. `rsa_signature256` connects that primitive to both encoding
verifiers and returns `False{}` for malformed parameters or failed verification.
PSS requires SHA-256/MGF1-SHA-256 and exactly 32 salt bytes. It requires a zero
leading byte before shortening a recovered `k`-byte value to `emLen` when the
modulus bit length is congruent to one modulo eight; other encodings retain
their complete width. Native and Bun each pass 774 full-signature cases and
725 public-arithmetic cases with the current in-place Montgomery limb shift.
The shift reuses its owned array and clears the vacated high cell. Measured
array creation decreases; a reduction in peak RAM or execution time has not
been established. Complete package/repository gates remain pending.
Certificate key/algorithm binding and signature math are now connected by
`x509_signature`; semantic key policy, trust and handshake integration remain
required.
See [RSA_REVIEW.md](RSA_REVIEW.md) for evidence and limits.

The Bun RSA signature checker announces each existing four-case subprocess
batch as a separate resource phase. All 774 published, peer, admission and
per-byte tampering cases remain in order, with identical inputs/oracles;
196 declared phases include the final partial batches. The complete focused
pinned run passes with a longest phase of 8.325 seconds, 82.5 MiB aggregate
peak and 527.811 seconds overall. Every phase retains the 120-second deadline,
1 GiB limits and pressure refusal. This fixes package phase granularity, not
cryptographic behavior or timing safety; full changed-package/root acceptance
must still run on the final source.


`x509_certificate.decode` preserves original TBSCertificate bytes and all
mandatory/optional field encodings while binding the inner/outer supported
SHA-256 signature profiles. Six closed checks and 31,428 independent cases per
native/Bun target pass. Calendar/interval checks are supplied by the separate
validity module; Name/extension semantics, trust/hostname and TLS integration remain
required. Native evidence uses unmodified Bend 2.0.27 source under Bun 1.3.13;
packaged native generation still exceeds the local cutoff. See
[X509_CERTIFICATE_REVIEW.md](X509_CERTIFICATE_REVIEW.md) for fields, constraints,
compiler provenance, measured resources and reproducible commands.

`x509_signature.verify_signature` admits the explicit issuer SPKI and complete
certificate, binds key/profile restrictions, hashes the original signed TBS
encoding and verifies SHA-256 RSA PSS/v1.5 or strict-DER P-256 ECDSA in Bend.
All 4,825 whole-verifier cases pass on native and Bun; signature math can succeed
for invalid time contents, a wrong SAN or an unknown critical extension.
Time checks are supplied separately; Name/extensions, constraints,
chain/trust/hostname and TLS scheme/handshake
validation remain required. The focused generated targets use official Bend
2.0.34 within existing memory cutoffs; the repository remains pinned to 2.0.27
and full package/compiler compatibility gates remain pending. See
[X509_SIGNATURE_REVIEW.md](X509_SIGNATURE_REVIEW.md).

`x509_validity` separately admits complete certificate times and ordered
validity intervals, then checks inclusive bounds against caller-supplied civil
UTC seconds since year 1. It rejects malformed digits/DER, invalid calendars,
offsets/fractions and unsupported leap-second encodings. Native and Bun each
pass 31,545 cases; the signed invalid-time-content fixture now fails this time
owner. Trusted host-clock integration, Name/extensions, constraints/trust/
hostname and handshake ownership remain required. See
[X509_VALIDITY_REVIEW.md](X509_VALIDITY_REVIEW.md).

`oid` and `x509_extensions` admit canonical OIDs and exact nonempty extension
envelopes, preserving opaque payloads/order and rejecting explicit default
critical flags and duplicate identities. Native and baseline-JIT Bun each pass
67,731 cases, including long OIDs and exact hash collisions. The Bun evidence
explicitly disables DFG optimization within the unchanged memory cutoff;
default optimizing-JIT resource acceptance remains pending. Remaining known payloads,
critical-extension policy, Name semantics and trust/hostname still need owners.
See [X509_EXTENSIONS_REVIEW.md](X509_EXTENSIONS_REVIEW.md).

`rsa_integer_bench.py` measures a precompiled public-power evaluator with frozen
public operands, including full-width sparse/dense exponents. It checks every
result against an independent bigint oracle and records startup/file-I/O time;
it does not compile an evaluator or certify alternate exponents as valid keys.
Run it through the resource guard. [RSA_REVIEW.md](RSA_REVIEW.md) records the
native/Bun samples and generated-code allocation findings; integrated
verification work budgets and native/JIT/erasure review remain required.

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

Run `moon run crypto:check --force` through the sequential
[build guard](../tools/README.md), using its documented local recovery settings.
The current user-authorized limits are 1024 MiB per process and aggregate,
with a 120-second deadline per job or declared phase and macOS pressure refusal.
Compiler and evaluator jobs share these limits. These are sampled
cutoffs, not hard OS memory quotas; full gates remain pending under these limits.
Native adapters use `tools/bend_native.sh` to release the Bend frontend before
clang starts, then compiles large CPU C in sequential translation units with one
runtime owner. JavaScript generation and all correctness checks remain Bend-based.
The check proves that SHA-256 state output is always 32 bytes, compiles the native adapters, tests invalid-byte handling, compares SHA-256 against four published vectors and boundary/binary cases, compares HMAC against RFC 4231 and Python, and checks three RFC 5869 extract/expand vectors plus output-length boundaries. The million-`a` SHA-256 vector exercises a multi-block message.
SHA-256, HMAC-SHA-256 and HKDF run the same matrix on native and Bun, including
the million-byte hash and the maximum 8,160-byte HKDF expansion.

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
The package gate builds separate read/write evaluator fixtures to keep compiler
memory within its process cutoff. Each fixture retains its affine owner for the
entire scenario, including all records, updates, failures and retirement. The
Python test launcher only selects and executes the matching Bend fixture;
cryptography and lifecycle transitions remain in Bend. Shared formatting and
synthetic boundary injection live in `traffic_fixture_support.bend`. The
combined `traffic_cli.bend` remains available, with its original interface.
`traffic_type_check.py` accepts valid read/write owner retirement and rejects
copies of either affine owner and read/write direction confusion. Temporary
fixtures use a module-local import, so compiler import restrictions cannot
replace the intended ownership diagnostic.
[RFC 9846](https://www.rfc-editor.org/info/rfc9846/) (July 2026) supersedes
RFC 8446; sections 4.7.3, 5.3/5.5 and 7.1–7.3 and
[its errata](https://www.rfc-editor.org/errata/rfc9846) were reviewed on
2026-10-01. The errata page lists five reported records and no verified records;
none changes these implemented operations. RFC 9846's TLS label is distinct
from DTLS 1.3's label; this owner must not be reused for DTLS unchanged.

SHA-256 and HMAC-SHA256 now use `bytes.bend` for length, validation and append traversal. The RTC authentication checks independently compare SHA-256 STUN MACs and maximum-length STUN packet signing on native and Bun; these paths exposed and now avoid Base's non-tail list recursion on JS. The crypto check itself retains the native SHA-256/HMAC/HKDF vectors; RTC supplies this additional compiled JS evidence.

The file-hash CLI streams 4 KiB reads through an affine SHA-256 owner instead
of retaining a whole-file list. The owner keeps fewer than 64 pending bytes,
an exact two-word byte count, and the existing Bend compression state. It
rejects non-byte input, inconsistent buffering and lengths at or above 2^64
bits, and pads exactly once at finalization. File handling retains at most two
read chunks, closes on EOF/error/rejected state, and handles short reads until
EOF. Existing whole-list hash and HMAC APIs remain available. This is hash
ownership and tested-input correctness, not secret erasure or timing safety.

Native and optimizing-JIT Bun fixtures pass the published million-byte vector,
all original SHA-256/HMAC/HKDF cases, 275 chunk partitions, 30 length encodings,
12 state guards, two FIFO streams, and 200 successful plus 200 overflowed hashes
under a 64-descriptor limit. Two valid type probes pass; stream copying and
repeated finalization fail. Both pinned Bend 2.0.27 and isolated 2.0.34 are
verified. [RFC 6234 sections 4.1 and 6.2](https://www.rfc-editor.org/rfc/rfc6234.html#section-4.1)
were refreshed on 2026-10-03; both official errata queries returned Internal
Error, so no new verified correction is inferred. Full package/root acceptance
remains recorded separately in STACK_PROGRESS.md.

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

`field256.bend` supplies arithmetic for the P-256 coordinate prime and scalar
order. It uses canonical little-endian byte limbs in owned 64-cell U32 arrays;
its arithmetic helpers require canonical operands. `decode_canonical` validates
exactly 32 bytes and rejects values at or above the selected modulus; `decode`
reduces 32-byte aliases, while `decode_wide` reduces validated 64-byte inputs.
The reducing helpers require their stated byte/length preconditions. Protocol
point/private-key parsers must use strict decoding and enforce their additional
range, byte-order and curve-point requirements.

The prime, scalar order and Montgomery R-squared constants use eight public
32-bit words each. Their byte accessors retain the same little-endian values
and return zero outside indices 0–31. Two four-word groups keep pattern checks
small. Group/word selection and bounded byte shifts
use public indices, reducing the compiler's pattern-checking workload without
changing the arithmetic schedule. The field test CLI factors argument parsing
and uses decreasing public fuel for at most 1048576 operations per process;
the validating arithmetic APIs have no such batch limit.

Multiplication uses two byte-limb Montgomery products to return the ordinary
representation. Inner product-plus-carry sums stay at or below 65535; explicit
high carry is retained before the canceled low byte is shifted away. Conditional
modulus subtraction uses 0/255 masks. Wide reduction retains a fixed 512-bit
binary baseline. Inversion raises a nonzero element to the public modulus minus
two; zero is rejected after a full 32-byte scan. Source loop counts and indices
are public; this does not approve optimized runtime/JIT timing or secret erasure.

Native and Bun each pass 4178 independent Python bigint cases across both
moduli: all 256 binary carry/borrow boundaries, canonical and noncanonical
operands, random values, 512-bit reduction, Montgomery versus the retained
binary implementation, inverse/zero behavior, strict decoding and malformed
lengths. Four closed Bend checks reject bad lengths and U32 values outside the
byte range. Constants are grounded in [NIST SP 800-186 section 3.2.1.3](https://csrc.nist.gov/pubs/sp/800/186/final).
This arithmetic foundation supports the P-256 module below. Complete signature
integration and TLS/DTLS certificate/handshake validation remain required.


`p256.bend` accepts exactly 32 big-endian private-scalar bytes in 1..n−1.
Public points use only the 65-byte uncompressed SEC1 encoding `04 || x || y`,
with two canonical 32-byte big-endian coordinates. It rejects wrong lengths,
non-byte U32 values, coordinate aliases, off-curve points and infinity;
compressed/hybrid encodings are not supported. P-256 has cofactor one, so a
validated non-infinity curve point belongs to the prime-order subgroup.
`public_key` returns the uncompressed point; `shared` returns exactly the
32-byte big-endian affine x coordinate, including leading zero bytes. Rejection
returns `None`. Secret/key ownership, ephemeral generation, KDF/domain binding
and protocol lifecycle remain integration responsibilities.

Internally, ordinary projective coordinates represent x=X/Z and y=Y/Z in
canonical Montgomery byte limbs. Point addition ports the 43 straight-line
[RCB add-2015-rcb-3 formulas](https://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective-3.html#addition-add-2015-rcb-3),
including doubling, inverse pairs and infinity. Raw point helpers require valid
curve representatives. Scalar multiplication always performs 256 doublings,
256 additions and 256 byte-mask selections; only public bit positions choose
list/array indices. It selects with 0/255 masks. Affine normalization rejects
zero Z and uses the field's public-exponent inverse. There is no source-level
secret-bit exceptional-case branch in the group schedule; generated runtime,
allocation/scheduling, native optimizations and Bun JIT timing/erasure remain
unresolved. This is synthetic correctness evidence, not production approval.

The native/Bun evaluator covers 609 cases: all 25 published NIST P-256 ECDH
vectors with both local public keys and shared coordinates; independent affine
addition and rescaled projective representatives including infinity, doubling
and inverses; scalar zero/order/byte-transition/alternating/dense/random cases;
strict private/public malformed, range and tampering rejections; and eight
bidirectional OpenSSL exchanges with both public keys. The independent Python
oracle uses textbook affine slopes/inversions, not the RCB implementation.
Four closed Bend checks reject malformed or non-byte input. Projective and raw
scalar adapters are synthetic arithmetic fixtures; they do not expand the
validating protocol API. The JSON fixture pins the NIST archive URL/hash and is
included in Moon's crypto input hash. Encoding and validation follow
[Standards for Efficient Cryptography 1 (SEC 1) v2.0](https://www.secg.org/sec1-v2.pdf),
sections 2.3.3–2.3.4, 3.2.2 and 3.3.1.

`ecdsa_scheme256.bend` supplies P-256/SHA-256 ECDSA over an already-computed
32-byte SHA-256 digest. Signing accepts a canonical nonzero 32-byte big-endian
private scalar and returns a strict DER signature or `None`; verification accepts
a validated uncompressed 65-byte SEC1 public key and returns `Bool`. Both signature
scalars must lie in 1..n-1. DER rejects trailing bytes, negative/zero/nonminimal
integers, non-byte input, wrong tags and long-form length aliases. The internal
`ecdsa256` verifier and `ecdsa_sign256` signer use r_BE32 || s_BE32. Digest integers
may exceed n and are reduced in scalar arithmetic; private, signature and nonce
scalars must be canonical rather than reduced into range.

The signer follows RFC 6979 section 3.2 HMAC-SHA256 initialization and rejection,
including rejection of zero r and zero s. It tries at most 128 candidates and
fails closed on exhaustion. Nonce candidates are compared to n, never reduced
modulo n. Public signature DER encoding is a separate narrow module; certificate
semantic validation, trust, hostname and TLS handshake ownership remain pending.
Signing is deterministic for a given private scalar/digest; this API supplies
neither private-key generation nor a nonce/key storage owner.

The crypto gate retains every previous check and adds six closed byte/exhaustion
checks, the NIST P-256/SHA-256 SigGen/SigVer rows, RFC 6979 sample/test signatures,
an independent affine/HMAC oracle, deterministic repeats, digest/key/signature
mutations, raw/DER range and length failures, infinity rejection, nonce rejection
transitions and bidirectional OpenSSL DER interop on native and Bun. The separate
DER matrix has 1,388 canonical, sign-pad, all-bit, range, tag, length and trailing
cases. These remain correctness gates, not NIST validation or timing approval.
Each entire operation executes in one Bend evaluator; the Python fixture routes
batches sequentially among public DER, raw signing, raw verification, DER and
synthetic rejection evaluators. It does not implement crypto or DER conversion.
Short rejection-fixture opcodes reduce compiler literal-pattern expansion. No
protocol consumes the synthetic known-nonce, artificial-point or retry hooks.

See [ECDSA review](ECDSA_REVIEW.md) for the current evidence and unresolved
generated-runtime/erasure findings. ECDSA is experimental and must use synthetic
keys until those findings are resolved; it is not connected to a live TLS/DTLS path.

The X25519 evaluator consumes exact `public`, `mult` and `shared` operation
names with a character-by-character classifier instead of expanded long String
patterns. The public CLI interface, file-read/error ordering and cryptographic
functions remain unchanged. Its existing native/Bun vector, differential,
noncanonical-input and malformed-crypto matrix also checks 124 operation-name
and arity rejections per target; native retains the RFC 1,000-iteration vector.
The guarded focused build/check peaks at 144.8 MiB on 2026-10-02. This reduces
evaluator compiler workload; it does not change or certify X25519 arithmetic.

`x509_constraints.bend` decodes the basic-constraints and key-usage extension
payloads according to [RFC 5280 sections 4.2.1.3 and 4.2.1.9](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.9)
and Appendix B. Basic constraints require an omitted default FALSE or canonical
TRUE, permit a nonnegative canonical path-length INTEGER only with TRUE, and
retain every INTEGER byte. Limits above U32 are compared without truncation or
wrap; `path_allows` accepts a U32 count of non-self-issued intermediate CAs.
The path owner must compute that count correctly. The existing 65,535-byte DER
input bound applies. Key usage admits nonempty combinations of the nine named
bits, requires zero padding and omitted trailing zero bits, and returns the
wire-order mask (digitalSignature=128, keyCertSign=4, decipherOnly=32768).

The public `policy` accepts optional encoded payloads. An absent extension is
`None`; a malformed present `Some{bytes}` fails closed. It checks that
keyCertSign implies cA, and that a present key-usage payload permits certificate
signing when a path-length constraint is present. The selected local policy
also rejects encipherOnly/decipherOnly without keyAgreement, whose meaning the
RFC leaves undefined. Pure decoder results and the internal admitted-value
helpers do not authorize certificate use. The module does not recognize all
critical extensions, check their criticality, enforce issuer/algorithm/purpose
profiles, construct a chain, select trust, compare Names, check hostname,
handle revocation or compose a trusted clock. These remain required integration
work. Both official verified-errata query forms returned Internal Error on
2026-10-03; no new correction is inferred.

On 2026-10-03, 7,657 independent integer/bit-set cases pass on native and
optimizing-JIT Bun for both pinned Bend 2.0.27 and isolated official 2.0.34.
The identical corpus covers Appendix C payloads, all 511 nonempty bit sets,
1,533 cross-field combinations, malformed-present versus absent payloads,
canonical/malformed lengths and padding, huge INTEGERs, depth comparison and
the exact DER input-size boundary. Eight closed check declarations pass the
frontend; no kernel `--verdict` claim follows. The four runtime runs together
peak at 78.1 MiB aggregate / 49.6 MiB individual under the unchanged guard.
Sources, generated targets, commands and reports are retained under
`/Users/ozeron/.codex/artifacts/grounds/2026-10-03/constraints/`.

`x509_extension_policy` connects complete extension-envelope admission to the
constraint payload decoders. Its current exact-OID registry recognizes basic
constraints (2.5.29.19), key usage (2.5.29.15) and EKU (2.5.29.37). Recognized payloads must decode
and pass consistency checks regardless of criticality. Unsupported critical
entries fail closed; other noncritical entries survive in original order with
their exact OID and payload bytes. Duplicate OIDs and malformed envelopes fail
before dispatch. `certificate` uses the certificate's actual extension field;
an absent field is distinct from a malformed or empty present sequence.
The result retains recognized payloads and criticality flags as well as the
deferred entries, so later owners can process identity/purpose restrictions.
The unchanged `Admission` constructor retains validated EKU and selected SAN
among its deferred entries, including their critical flags. Deferred means pending use-specific
processing; it does not mean every entry is unknown or noncritical.
This follows [RFC 5280 section 4.2](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2).
Both official verified-errata forms returned Internal Error on 2026-10-03.

This is a partial extension-processing result, never certificate authorization.
Other SAN name forms, key identifiers, Name constraints, policies and the other required
handlers remain to be implemented; unsupported critical forms are rejected
until their handlers exist. Deferred noncritical entries are not a permission
to omit a recognized handler in the eventual full validator. Issuer criticality,
key/algorithm/purpose profiles, Name matching, hostname, trust, revocation,
trusted time and chain validation remain required. None of the TLS paths uses
this partial result to authorize a peer.

The earlier BC/KU-only revision on isolated official Bend 2.0.34 passed
19,515 independent cases, including both criticality forms of every recognized
payload regression, order/duplicate/malformed cases, unsupported critical and
deferred noncritical fields, exact input bounds and complete certificate field
extraction. Four existing signed-invalid certificates still pass Bend signature
math and now fail this policy due to their unsupported critical extension.
Changing only the unsupported critical flags admits their extension metadata;
those four modified certificates fail Bend signature verification, keeping the
extension-processing and signature obligations separate.
Pinned Bend 2.0.27 passes the frontend and five closed declarations, but both
native emission and separate JS emission reach the unchanged 320 MiB individual
cutoff. A smaller 64 MiB compiler RAM hint does not resolve native emission;
no cutoff is raised. No pinned runtime or kernel-verdict pass is claimed.
Its historical artifacts live under
`/Users/ozeron/.codex/artifacts/grounds/2026-10-03/extension-policy/`.

`x509_eku` requires a complete, nonempty DER sequence of canonical OIDs within
the 65,535-byte bound. It preserves arbitrary-size arcs, unknown purposes,
original order and repeated purpose OIDs; the ASN.1 sequence is not a set.
`permits` validates the complete payload before matching the exact requested
OID, so an early match cannot hide a malformed later item. An absent extension
does not restrict a valid purpose query. `allow_any` is an explicit application
policy: false requires the specific purpose; true also accepts
anyExtendedKeyUsage (2.5.29.37.0). These rules follow
[RFC 5280 section 4.2.1.12](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.12).

The TLS helpers intersect serverAuth/clientAuth permission with digitalSignature
when KU is present. The policy helpers first apply complete extension/payload
admission and BC/KU consistency; standalone `x509_eku.tls13` handles only KU
encoding and KU/EKU purpose permission. This implements the KU requirement of
[RFC 9846 section 4.5.1.2](https://datatracker.ietf.org/doc/html/rfc9846#section-4.5.1.2),
the July 2026 TLS 1.3 revision replacing RFC 8446. It does not check compatible
signature schemes, Names, issuer profiles, trusted time, chain/trust, revocation
or hostname. Neither helper authorizes a peer. The official RFC 5280 and RFC
9846 errata endpoints returned Internal Error on 2026-10-03; a successful fresh
verified-errata review remains outstanding.

The current EKU revision passes 14,565 identical independent cases on native
and optimizing-JIT Bun with both pinned Bend 2.0.27 and isolated official
2.0.34. Whole-extension/certificate policy passes 24,610 identical cases on
both modern targets. Nine synthetic signed certificates reproduce 18 OpenSSL
3.6.4 SSL-purpose results and also pass Bend signature math. The fixture with
only keyEncipherment illustrates why the TLS 1.3 helper is stricter than
OpenSSL's general SSL-server purpose check. Frozen references explicitly bypass
time and trust the local fixture; they do not prove trust, time or hostname.
Unknown and repeated purposes, critical EKU, specific versus any purpose,
every nonempty KU mask, malformed later items, absent extensions and exact
input bounds are covered. Six EKU and five existing policy declarations pass
both frontends; no kernel-verdict claim follows. Pinned whole-policy native
and JS generation reach the unchanged 320 MiB individual compiler cutoff;
no pinned whole-policy runtime pass is claimed. Current
sources, targets and resource reports live under
`/Users/ozeron/.codex/artifacts/grounds/2026-10-03/eku/`.

`x509_identity` compares ASCII DNS labels case-insensitively, enforcing LDH
syntax, 63-byte labels and a 253-byte domain bound. A wildcard is accepted only
as the complete leftmost label followed by a nonempty domain; it matches one
nonempty reference label. Partial/multiple wildcards do not match. A presented
invalid pattern can be ignored while another DNS-ID matches. IP comparison
requires exactly 4 or 16 valid octets on each side and exact equality, with no
IPv4/IPv6-mapped alias or subnet matching. These are the DNS/IP comparison
rules for HTTPS/WSS from
[RFC 9525 sections 6.2–6.4](https://www.rfc-editor.org/rfc/rfc9525.html#section-6).

Reference construction is mandatory before calling these helpers: DNS-ID and
IP-ID are distinct types (`kind` 0 and 1 respectively), and callers must select
the type from the trusted original authority rather than a resolved address or
presented certificate. Inputs use ASCII LDH/A-label DNS bytes without a terminal
root dot, or raw network-order IP bytes. U-label conversion, complete IDNA
validation, textual-IP parsing, URI/SRV identity profiles and public-suffix
policy remain required owners. Comparing matching ASCII A-label strings does
not prove they passed IDNA validation.

`x509_hostname` reads the actual SAN OID through strict extension-envelope and
certificate-field decoding. An absent SAN, duplicate extension, wrong OID or
malformed complete framing cannot match; subject CN is never a fallback.
The complete nonempty sequence is framed before searching. Framing checks
GeneralName choice tags, nonempty IA5 octets, exact IP sizes and canonical
registered OID contents, retaining raw entries in order. Constructed otherName,
X.400, directoryName and EDI contents are retained without schema admission;
mailbox/URI/DNS profiles and the other semantic validators are also pending.
This follows the field layout in
[RFC 5280 section 4.2.1.6](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.6).
The matcher checks DNS/IP identity permission only. It neither admits the SAN
extension semantically nor authorizes a peer. `x509_san` separately checks the
selected DNS/IP payload policy; `x509_extension_policy` retains admitted SAN
entries for subsequent identity processing. Signature, purpose, trusted time,
Name/chain/trust, revocation and critical-extension checks remain mandatory.
The official RFC 9525 errata endpoint and verified-errata query returned
Internal Error on 2026-10-03; a fresh verified review is outstanding.

The current matcher passes 5,900 identical independent cases on native and
optimizing-JIT Bun with both pinned Bend 2.0.27 and isolated official 2.0.34.
The combined corpus adds 2,447 SAN/framing/certificate cases to those 5,900
core cases, passing 8,347 identical cases per modern target. It includes 150
no-CN/no-partial-wildcard OpenSSL 3.6.4 queries against 15 signed
synthetic certificates. The corpus covers every octet at selected DNS/IP
positions, label/domain limits, type separation, invalid reference/pattern
handling, complete malformed/truncated/mutated SAN framing, exact DER bounds,
entry order, actual extension OIDs/duplicates and certificate versions.
Six core and three framing declarations pass both frontends; no kernel verdict
is claimed. The pinned whole-hostname CLI frontend reaches its existing
individual compiler cutoff before generation; no pinned whole-hostname runtime
pass follows. Artifacts are under
`/Users/ozeron/.codex/artifacts/grounds/2026-10-03/hostname/`.

`x509_san.inspect` requires complete nonempty GeneralNames framing and checks
every DNS pattern against the selected ASCII LDH/A-label and complete left-label
wildcard policy. This checks A-label spelling, not IDNA decoding/validation.
IP names require exactly 4 or 16 octets. Malformed later DNS/IP
names reject the payload even if an earlier name matches. The result is
`Some{True}` when all names are supported, `Some{False}` when other framed forms
remain deferred, and `None` for malformed supported data or framing. A critical
SAN requires every form to be supported. Noncritical deferred forms retain their
exact bytes; they still need their schema/profile owners. Mailbox/URI syntax,
OtherName, Name, X.400 and EDI processing remain outstanding.

The certificate extension policy now rejects an empty subject unless a supported
critical SAN is present. This follows
[RFC 5280 sections 4.1.2.6 and 4.2.1.6](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.6).
The direct [RFC 5280 errata listing](https://www.rfc-editor.org/errata/rfc5280)
became available on 2026-10-03: its six verified corrections (3579, 5802, 5938,
6414, 7658 and 7661) do not change this empty-subject/SAN rule. This supersedes
the unavailable query refresh noted above; RFC 9525's refresh remains unavailable.
It preserves the `Admission` constructor and critical SAN payload for the later
identity owner. `x509_name` separately validates selected Name schemas. None of
these functions supplies signature, issuer, time, Name constraints, trust,
revocation or complete peer authorization.

Official Bend 2.0.34 native and optimizing-JIT Bun pass 1,841 standalone SAN
cases and 28,044 whole-policy cases per target. Six synthetic signed certificates
record independent OpenSSL strict-profile results: valid critical DNS/IP with an
empty subject, invalid absent/noncritical SAN with an empty subject, and a named
subject. OpenSSL also admits the critical URI fixture; the selected Bend owner
rejects that deferred form. Bend signature math accepts all six original signed
certificates and rejects all six signature-bit changes per target, independently
of SAN policy. Commands, hashes, results and compiler limits are in
`/Users/ozeron/.codex/artifacts/grounds/2026-10-03/san/`. The pinned
2.0.27 proof frontend passes; whole CLI generation reaches its individual
compiler cutoff, so no pinned SAN runtime result is claimed. Full package/compiler
acceptance and the remaining GeneralName/profile handlers stay required.

`x509_name.decode` retains RDN sequence order and every attribute's canonical
OID contents, value tag/body and exact original attribute encoding. Each RDN
must be a nonempty SET of two-field AttributeTypeAndValue sequences; members
must follow the complete unsigned DER-encoding order, including length bytes,
with identical encodings permitted. RDNs themselves are never sorted. This
uses the existing single-octet-tag / 65,535-octet DER envelope boundary.

Known attribute rules cover RFC 5280's common name, country, organization,
organizational unit, locality, state, title, serial number, DN qualifier, name,
surname, given name, initials, generation qualifier and pseudonym, plus
domainComponent and legacy emailAddress. Selected DirectoryString tags support
strict UTF-8, PrintableString, UCS-2 BMPString and four-octet UniversalString;
surrogates, overlong/cut UTF-8 and out-of-range scalars fail. SIZE bounds count
characters rather than UTF-8 octets. PrintableString and IA5-only attributes
require their declared tag/alphabet; country is exactly two PrintableString
characters. Country registration, domain/mailbox profiles, IDNA, prohibited
character mapping and normalized comparison are separate unfinished checks.
The attribute syntax follows
[RFC 5280 sections 4.1.2.4/4.1.2.6 and Appendix A.1](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.4);
SET ordering follows [X.690 section 11.6](https://www.itu.int/rec/T-REC-X.690-202102-I/en).

Unknown attribute values retain their framed bytes with `supported=False`.
Nonempty Teletex DirectoryStrings are likewise deferred: their character
interpretation and SIZE bounds require a T.61 owner; octet length is not a
substitute. An empty Name is structurally permitted for subjects, while
`inspect(...,False)` and the certificate adapter reject an empty issuer.
`pair` runs both actual Names through one shared schema traversal.
The extension/TLS-purpose owner now applies this shared schema to both actual
Names. It rejects malformed Names and an empty issuer, and rejects an empty
subject for a CA or a certificate whose key usage includes cRLSign, even when
a valid critical SAN is present. Its five-field `Admission` remains partial
policy processing. Structurally valid unknown attributes and Teletex remain
deferred and require their owners before complete authorization.

This is not normalized Name equality or chain authorization. RFC 4518 string
preparation, RFC 9549 IDNA2008/domain constraints, GeneralName directoryName
integration, issuer/subject binding across a chain, trust, revocation and
trusted-time composition remain required.

`x509_name_text.decode(tag,bytes)` supplies the scalar transcoding step for
[RFC 4518 section 2.1](https://www.rfc-editor.org/rfc/rfc4518.html#section-2.1).
It accepts primitive UTF8String (12), PrintableString (19), IA5String (22),
UniversalString (28) and BMPString (30) values, returning `Some{codes}` in
original scalar order. It applies the shared Name schema's strict syntax,
rejects non-octet inputs and values exceeding 65,535 bytes, and treats BMPString
as UCS-2: paired UTF-16 surrogates are invalid too. BOMs, controls, case, spaces,
noncharacters and unassigned scalars are preserved here; the Unicode 3.2
preparation owner performs its separate mapping and prohibition steps.

Malformed values, Teletex and other tags return `None`. The decoder supplies
no implicit Latin-1 mapping for Teletex. Attribute SIZE/type validation still
belongs to the surrounding Name schema; scalar decoding does not authorize an
attribute or certificate. The `x509_name_prepare` owner connects supported
attributes to Unicode preparation; comparing RDN multisets in Name sequence
order remains required work.

Pinned Bend 2.0.27 passes twelve checked constructor examples, including a
direct out-of-octet input. Native and optimizing-JIT Bun each pass the same
9,321 independent Python codec/UCS-2 checks: every single octet, every BMP and
UniversalString surrogate, malformed UTF-8, truncation/bit changes, scalar
boundaries, seeded cross-encoding order and exact octet-bound tail walks.
Native checks peak at 35.5 MiB in 2.116s; Bun at 112.7 MiB in 5.891s.
These new five check phases supplement every existing package case.

`x509_name_prepare.prepare(tables,oid,tag,bytes)` composes canonical OID/octets,
the shared Name attribute's original tag/alphabet/scalar SIZE check, strict
transcoding and Unicode 3.2 stored caseIgnoreMatch preparation. Mapping,
B.2 folding, NFKC, prohibition and insignificant-space handling use the existing
authenticated affine tables. Invalid inputs and prohibited prepared values
return `None`; the table owner returns on both success and failure for the next
attribute. SIZE admission precedes deletion/expansion, so mapping cannot rescue
an empty or oversized original value. This applies
[RFC 5280 section 7.1](https://www.rfc-editor.org/rfc/rfc5280.html#section-7.1)
and [RFC 4518](https://www.rfc-editor.org/rfc/rfc4518.html), retaining the existing
verified space/mapping corrections. The official errata search and inline
renderings were checked on 2026-10-04; direct erratum links still failed to fetch.
RFC 5280 erratum 7658 corrects its insignificant-space hyperlink, and RFC 4518
erratum 9048 is editorial; neither changes this composition.

DirectoryString and selected PrintableString attributes are supported. Teletex
has no configured transcoding policy; IA5 domain/mailbox matching and unknown
equality rules remain separate. `admission` reports `Some{False}` for those
unsupported profiles, `None` for malformed selected inputs, and `Some{True}`
for admitted selected syntax. Successful preparation supplies packed scalars,
not Name equality, issuer binding or certificate authorization.

Pinned Bend 2.0.27 passes twelve checked admission examples, including direct
non-octet OID/value inputs. Native and optimizing-JIT Bun each pass the complete
same 18,996 independent composed cases and fourteen corrupt-table rejections:
3.570s/125.6 MiB and 42.647s/188.8 MiB aggregate. The corpus preserves every
transcoder case and adds published B.2 cross-encoding inputs, original
OID/type/SIZE limits, unassigned/prohibited scalars, space/mark/order sequences
and full-byte-bound deletion/expansion. Mixed accepted/rejected records reuse
one table owner across two fixture files. Five additional mandatory native/
frontend or Bun-available phases retain every original check; full package
and repository acceptance remain distinct gates.

Official Bend 2.0.34 native and optimizing-JIT Bun each pass 11,195 independent
Name checks, preserving the original 8,507 cases and adding all 128 canonical
single-octet standard attribute arcs across seven value tags and three lengths.
Both targets also pass 28,319 integrated extension/TLS-purpose cases, including
all prior policy cases, actual issuer/subject schema failures, signed Name
controls and empty CA/CRL-subject permutations. The seven signed admission gaps
recorded by the previous baseline are now rejected. The 13 public signed
fixtures use `policy_expected` for this adopted partial policy; the field rename
changes no DER, signatures or expectations. Their prior independent OpenSSL
digest and frozen Bend signature-math evidence remains applicable: all originals
are valid signatures, while all signature-bit changes fail on both targets.

A diagnostic copy of the exact official tagged compiler localizes significant
memory growth to U32 literal-pattern expansion, notably `printable` and OID
classification. Equivalent range predicates and tail-recursive exact OID
comparison preserve the rules while reducing the scoped modern Name build peak
from 289.9 to 192.2 MiB. The integrated modern proof frontend/native/JS build
passes at 313.3 MiB aggregate / 309.4 MiB individual in 24.677 s. The complete
four-corpus runtime job peaks at 109.7 / 75.6 MiB in 48.588 s. These are scoped
2.0.34 artifact results; the primary pin remains 2.0.27. Diagnostic compiler
instrumentation is not installed or used for acceptance, and live heap retention
or exact allocation counts are not established.

Pinned 2.0.27 now passes the seven Name literal checks' proof frontend, but its
Name CLI emission still hits the individual cutoff (324.7 MiB aggregate /
320.7 MiB individual); its complete policy proof frontend also stops at the
individual cutoff. No pinned runtime or kernel-verdict pass follows. Fresh
forced crypto and root repository gates fail under the unchanged aggregate
limit before package completion, at 390.9 and 391.0 MiB. All heavy jobs remain
sequential and pressure stays normal. Exact commands, input/program hashes,
compiler traces, complete corpus reports and limitations are under
`/Users/ozeron/.codex/artifacts/grounds/2026-10-03/compiler-name/`.

`unicode32_profile` supplies the Unicode 3.2 property foundation required by
[RFC 5280 section 7.1](https://www.rfc-editor.org/rfc/rfc5280.html#section-7.1)
and [RFC 4518](https://www.rfc-editor.org/rfc/rfc4518.html). Its 396 unassigned
ranges come from RFC 3454 Table A.1; its 112 combining-mark ranges come from
RFC 4518's expressly definitive Appendix A. Sorted ranges are compiled as
constants and searched in Bend, using retained affine arrays. Runtime C/JS do
not perform Unicode classification or preparation. `flags(state,code)` returns
the retained tables and an integer mask: 1 literal deletion, 2 map to SPACE,
4 prohibited after normalization, 8 combining mark. The prohibitions include
unassigned, private-use, noncharacter, surrogate, C.8 display/deprecated codes,
U+FFFD and values outside Unicode. `map_code` distinguishes `Removed`,
`Mapped{code}` and `Invalid`, so invalid scalar input cannot become a legitimate
deletion. Non-scalar input is invalid; otherwise this helper applies only the
literal mapping, retaining prohibited characters until the proper later stage.

The variation-selector deletion range applies verified
[erratum 860](https://www.rfc-editor.org/errata/eid860): FE00-FE0F. The definitive
mark appendix differs from Unicode 3.2 categories at three values: U+05BD is
omitted; U+094E/U+094F are included. The independent Python oracle uses its
frozen 3.2 UCD/stringprep properties with these explicit normative exceptions.
No unverified correction replaces the definitive appendix. Official search
results expose verified entries 860/1757/1758/7213; direct live listing/query
refreshes failed. The substring-space corrections remain relevant to the future
complete preparation owner.

Pinned Bend 2.0.27 and scoped official 2.0.34 native and optimizing-JIT Bun
all pass the identical 2,244,608 property/mapping checks per target: every
1,114,112 Unicode code point, including surrogates and all planes, plus 8,192
out-of-repertoire U32 values. Invalid scalar status is checked independently
of property flags. Corpus SHA-256 is
`a2f70f2d299fa869b928c4bded9524df7ab371d0cf467c048e9bb06dd30b88ca`.
Eight literal checks pass both proof frontends; no separate kernel verdict is
claimed. Modern build peak is 98.0 MiB; pinned build is 122.4 MiB. Modern native
and Bun corpora finish in 0.834 s / 2.053 s at 32.1 / 88.4 MiB aggregate.
The two pinned corpora finish in 8.536 s at 102.4 MiB aggregate / 75.8 MiB
individual. All retain the existing sequential guards and JIT/DFG settings.

The offline `unicode32_generate.py --source-dir <snapshots> --output-dir <dir>`
reproduces `unicode32_ranges.bend` and `unicode32_ranges.json` from SHA-pinned
RFC 3454/4518 text. Regeneration matches both committed artifacts exactly.
The sources, complete Unicode 3.2 data/normalization-test snapshots, commands,
program hashes and four corpus reports are frozen under
`/Users/ozeron/.codex/artifacts/grounds/2026-10-03/unicode32/`.
The first capped normalization download and an incorrect end-marker assertion
are archived as rejected preparation; the accepted 2,025,975-byte snapshot
contains its actual END OF FILE marker. No Bend normalization result follows
from that download.

Case folding and NFKC are implemented separately below. Combining-mark-aware
insignificant-space handling, complete transcoding/preparation and normalized
RDN/Name equality/subtree matching remain required. This property module is
not yet composed into Name or certificate authorization. Fresh forced crypto
and root gates still stop before package completion at unchanged aggregate
cutoffs, 387.8 / 397.9 MiB; neither is package/repository acceptance.

`unicode32_fold` implements all 1,371 published
[RFC 3454 B.2 mappings](https://www.rfc-editor.org/rfc/rfc3454.html#appendix-B.2)
with retained affine tables and a bounded sorted-key lookup. `code` folds one
valid scalar, preserving its identity when absent from B.2; `map_code` first
applies RFC 4518 literal deletion/SPACE mapping. `string` performs either mode
on a scalar list, preserves expansion order, and returns `Invalid` for any
non-scalar input. Legitimate deletion is `Folded{[]}`. The shared
`unicode32_lookup` operates on trusted generated sorted key/value rows. No
host Unicode or case conversion executes in the production path.

The SHA-pinned offline `unicode32_fold_generate.py --source <rfc3454.txt>`
reproduces the Bend constants, provenance manifest and published-vector JSON.
Nat constants avoid thousands of elaborated word literals, and literal chunks
have at most 128 integers: the first monolithic generated JS
expression exceeds Bun's loader stack limit before evaluation. The chunked
constants preserve every mapping and pass native/Bun. The independent checker
reads the published vectors and combines them with the existing frozen 3.2
literal-property oracle; it does not reconstruct the production descriptor
lookup. Host Python `stringprep.map_table_b2` is unsuitable as a complete
Unicode 3.2 oracle: its current-Unicode lowercase operation changes Cherokee
U+13A0 and unassigned-in-3.2 U+1C90. The literal B.2 identity results are tested.

Native and optimizing-JIT Bun on pinned 2.0.27 and scoped official 2.0.34
are checked over every Unicode code point plus 8,192 out-of-repertoire U32
values in both folding modes. Eight whole-list cases cover empty input,
expansion order, mapping/deletion, historical version behavior and invalid
interior scalars. A separate 65,535-scalar list of U+33C6 checks every one of the 262,140
output scalars in the fourfold expansion on both native targets and modern
Bun. Pinned Bun completes the full scalar/short-list corpus but the expansion
test hits the unchanged 96 MiB individual guard, even in a separate process;
its large-list resource acceptance remains open. A smaller heap hint and an
owned tail-loop reversal do not resolve that pinned-runtime limit. Neither
the long input nor guard cutoff is reduced to claim a pass. Exact reports and resource evidence
are under `/Users/ozeron/.codex/artifacts/grounds/2026-10-03/unicode-normalize/`.
This folding stage is not NFKC, prohibition/SPACE preparation, Name equality,
chain verification or authorization. Complete stored-value preparation and
this folding module's pinned-runtime large-list resource issue remain open.
The separate packed normalization module follows.


`unicode32_nfkc.normalize(state,codes)` implements exact Unicode 3.2 NFKC:
recursive compatibility decomposition, algorithmic Hangul, stable canonical
ordering and blocked canonical composition. It retains the affine tables and
returns `Maybe<Normalized>`; invalid scalars or more than 262,140 input scalars
return `None`. Empty input is a valid zero-length result. The bound admits the
fourfold B.2 expansion of every scalar in a 65,535-byte enclosing Name value.
`Normalized{values,length}` owns packed U32 cells `(scalar << 8) | CCC`; only
`length` cells are output, and consumers recover scalars with `>> 8`. This API
retains unassigned/private-use/noncharacter values for the later prohibition
stage. Literal mapping, folding, post-normalization prohibition and SPACE
handling are composed by the stored-value preparation owner below.

`unicode32_nfkc_tables.decode(bytes)` checks byte validity, exact length and
Bend SHA-256 before creating tables from the pinned 87,660-byte asset. Runtime
C/JS only read bytes; all table interpretation, lookup and normalization run
in Bend. The asset has 5,143 recursively expanded decomposition rows, 327
nonzero combining classes and 917 canonical composition pairs. The binary
avoids thousands of compiler word literals. Expansion uses a growing packed
array; ordering keys/scratch arrays are allocated only when needed. Stable
four-pass radix sorting by starter segment and CCC avoids quadratic insertion
for an adversarial long combining sequence. Composition overwrites that buffer.

The offline `unicode32_nfkc_generate.py --unicode-data <UnicodeData-3.2.0.txt>
--exclusions <CompositionExclusions-3.2.0.txt> --normalization-test
<NormalizationTest-3.2.0.txt> --output-dir <existing-directory>` requires three
SHA-pinned official sources. The manifest records format, sizes, hashes and
historical mappings. Regeneration of the binary, metadata Bend/JSON and
complete deterministic gzip corpus must match the committed files exactly.
The binary SHA-256 is
`c5253e66db1ca6f2e156702d0e74adf49af620d95862c259d397dd5b821e6541`.
Unicode 3.2 predates [Corrigendum 4](https://www.unicode.org/versions/corrigendum4.html):
U+2F868/U+2F874/U+2F91F/U+2F95F/U+2F9BF retain their original mappings to
U+2136A/U+5F33/U+43AB/U+7AAE/U+4D57. The generator reads the original data;
the oracle uses frozen `unicodedata.ucd_3_2_0.normalize`, whose old-version
results differ from the newer decomposition-property strings for these codes.

`unicode32_nfkc_check.py` checks all 16,992 official rows in all five columns:
84,960 NFKC results, plus 1,050 independent fixed/random sequence cases and
seven truncated/extended/modified-asset rejections. `unicode32_nfkc_matrix_check.py`
compares all 1,114,112 Unicode code points and 8,192 out-of-repertoire U32
values against the frozen 3.2 oracle. Separate stress processes check every
output of three exactly 65,535-byte UTF-8 inputs: 18-fold Arabic compatibility
expansion (393,210 outputs), reversed-class ordering and equal-class stability
(each 32,767 outputs). A fourth checks the 262,140/262,141 scalar admission
boundary. Fourteen literal assertions check through both version frontends;
no separate kernel verdict is claimed.

Focused native/Bun checks and program/source/resource identities are recorded
under `/Users/ozeron/.codex/artifacts/grounds/2026-10-03/unicode-normalization-owner/`.
Pinned Bun matrix/stress use `BUN_JSC_forceRAMSize=33554432` (32 MiB GC
hint), which those mandatory steps set explicitly. This does not disable JIT/DFG
or change the unchanged 128 MiB aggregate / 96 MiB process guard. With the
64 MiB hint, the expansion process is stopped by that guard. This normalization
pass does not resolve the previous folding module's large-list issue, complete
StringPrep/Name comparison or establish package/repository acceptance.

Final focused suites pass on pinned Bend 2.0.27 and scoped official 2.0.34
native/Bun. The scalar corpus hash is
`2ad5780fe9ae1af30aa613d2c1ea0e07dfa85f016632c0b22e14a395960bb2a2`;
the official/differential corpus hash is
`14af0910376aade482a7c95fd254106efb03db48bdc9a53ce3ed19e484625d19`.
Fresh forced crypto and root gates still stop during compilation at aggregate
memory cutoffs of 392.5 / 391.2 MiB. Scoped success does not change the SDK pin
or complete either gate. The next owner must compose mapping/folding into
packed decomposition without materializing the known failing large folded
list, then apply prohibition and the definitive-Appendix-A SPACE rules.


`unicode32_prepare` composes stored/non-substring DirectoryString scalar
preparation after caller-owned transcoding, as specified by
[RFC 4518](https://www.rfc-editor.org/rfc/inline-errata/rfc4518.html).
`tables(normalization_bytes,profile_bytes)` validates the exact pinned NFKC
asset and the separate 21,284-byte B.2/property asset with Bend SHA-256 before
loading affine arrays. C/JS supply file bytes only. The new asset is generated
from the SHA-pinned published B.2 vectors and the definitive property-range
manifest; those existing artifacts remain independently regenerable from
pinned RFC text. `unicode32_prepare_generate.py --source-dir <crypto>
--output-dir <existing-directory>` reproduces binary and Bend/JSON metadata.
The preparation asset SHA-256 is
`ad6aa93b373aa4b8a3c46a0ce5098ac93b934704fc85dde1d1b19916c3aa387c`.

`prepare(state,codes,casefold)` retains every table owner and returns a packed
`Maybe<Normalized>`, using the same scalar/CCC representation as NFKC.
It rejects invalid scalars or more than 65,535 input scalars. The caller must
already enforce the enclosing DER byte bound and transcode the string tag;
a 65,535-byte encoded value can have at most 65,535 decoded scalars. For case
ignore matching use `True`; exact matching uses `False` and still performs
literal mapping, NFKC, prohibition and stored SPACE handling. Each original
scalar is mapped/folded to at most four scalars and decomposed into packed
storage. A preflight pass counts the exact decomposed length before allocating
the full buffer. A one-scalar cache retains at most 72 packed values, reusing
folding/decomposition for repeated input without changing whole-input ordering
or composition. No full folded linked list is materialized. Normalization,
post-normalization prohibition and the definitive Appendix A mark properties
are shared with the existing modules. Private-use scalars are rejected before
allocation: all 137,468 survive literal mapping, B.2 and NFKC unchanged, have
CCC zero and never occur in composition pairs. A frozen-UCD/table audit proves
this stable subset; other prohibition still follows normalization, allowing
U+0341 to normalize to an admissible value. RFC 4518 adds no bidi rejection.

`unicode32_space` delays classification of a SPACE until it has inspected the
next scalar's definitive mark flag. This preserves SPACE followed by a mark,
including marks with CCC zero, and treats U+05BD as the normative appendix
requires rather than inferring from its Unicode category. Regular leading/
trailing spaces are replaced by one margin SPACE, nonempty internal runs by
two SPACEs; empty/all-space prepared input produces exactly two SPACEs.
A first pass checks every normalized value, compacts internal SPACE runs to
one temporary marked token in the owned array and counts the exact result.
Mark lookup is needed only immediately after SPACE. A backward pass expands
marked runs to two SPACEs in the same array and adds the margins, growing only
if the existing capacity is insufficient. The public result contains no
temporary bit. No second full-sized output array is allocated.
A prohibited interior value rejects the whole value before emission. Deleted input remains
distinct from invalid input. The returned scalar sequence is for equality
matching, not display, serialization or certificate authorization.

The RFC Editor inline-errata rendering was refreshed for this change. Verified
1757/1758 correct substring inner-space rules/examples, and 7213 removes an
unnecessary comma. Verified 9048 corrects an Appendix B typo without changing
preparation rules; substring/numeric/telephone profiles are outside this
stored-value API. Existing FE00-FE0F mapping applies verified erratum 860.
Transcoding integration, Teletex interpretation, Name/RDN equality, subtree/
constraints and chain/trust/hostname/time composition remain required.

The independent checker uses published B.2 mappings, frozen Unicode 3.2
normalization and property rules, with explicit normative appendix exceptions.
Each exact/folded corpus has 97,731 cases: 22 literal cases, every one of the
84,960 official normalization input sequences, 1,371 published fold
neighborhoods, 2,048 deterministic random sequences and 9,330 exhaustive
short SPACE/mark/deletion neighborhoods. It also mutates/truncates/extends
both assets in 14 rejection cases. Long stress fixtures check every output
for exactly 65,535-byte compatibility expansion, reordered/equal-class marks,
CCC-zero protected SPACEs, empty-after-space handling and fourfold folding.
A separate 65,535-scalar U+33C6 case expands to 262,142 prepared scalars;
its UTF-8 encoding is 196,605 bytes and tests the looser scalar admission
bound, not an enclosing DER byte-valid Name. Boundary checks include actual
`prepare` rejection at 65,536 scalars. Large Python oracle allocations happen
in a child that exits before the evaluator starts, keeping guarded host/test
allocations sequential. Each corpus invocation processes two 128-record
fixture files with one authenticated table owner; each byte-reading action
returns before the next file. `--start`/`--limit` isolate diagnosis, and their
reports explicitly mark partial coverage. Complete final evidence is recorded under
`/Users/ozeron/.codex/artifacts/grounds/2026-10-03/unicode-stored-preparation/`.

The composed Bun corpus checks use an explicit 8 MiB GC hint
(`BUN_JSC_forceRAMSize=8388608`); the maximum-input stress checks use a
4 MiB hint (`4194304`). JIT and DFG remain enabled. Guards remain
384/320 MiB for compilers and 128/96 MiB for evaluators in those historical
runs. The current user-authorized aggregate/process limit is 1 GiB; the latest
package results are recorded in `STACK_PROGRESS.md`. Earlier growing-buffer,
separate-output and fold-only cache attempts still crossed the process guard.
The pinned phase probe localizes its failure to mapping; counted allocation
plus the bounded decomposition cache clears that stage. In-place SPACE
handling also avoids a second large output allocation. Diverse exact-mode
fixtures still crossed the guard at 16/8 MiB before stable private-use rejection;
those failed runs remain recorded. Final pinned maximum expansion also crosses
the guard at the 8 MiB hint; the explicit 4 MiB stress hint clears it.
No input or memory/time
cutoff is relaxed. Final-source hashes and exact commands distinguish this
verification from the exploratory reports. Package/repository acceptance and
complete Name/certificate authorization remain separate required gates.

Final complete preparation checks pass for both matching modes on pinned
2.0.27 and scoped 2.0.34, each on native and Bun, alongside full property
regressions and nine folded stress cases per target. The fresh forced crypto
check still stops during compilation at 387.9 MiB aggregate (33.820 s);
the fresh root check stops in crypto at 386.4 MiB (26.907 s). Neither of those
preparation-era gates completes. The accepted report manifest distinguishes the final sealed
programs and 4 MiB Bun stress runs from earlier failed attempts.

`check_phases.json` enumerates 354 phases for all 217 existing frontend,
native build/oracle and Bun emission/oracle commands in their original order.
The Bun P-256 and ECDSA oracles announce their existing 39 sixteen-case and
100 four-case batches individually; all 609 and 384 cases remain required.
Their optional `--phase-prefix` argument changes resource reporting only.
`check.sh` retains
the same arguments, environment overrides, complete corpora, long/iterated
native checks and shared temporary outputs. Use `tools/build_guard.py --phases
crypto/check_phases.json` around the Moon command for one aggregate 1 GiB
process-tree guard, a 120-second deadline per declared phase and ten-second
startup/transition/cleanup bounds. Missing or failed phases reject the run.
The 228 Bun phases record individual explicit skips only when Bun is absent;
a skip cannot prove Bun acceptance. The manifest and announcement helper are
Moon cache inputs. Current commands, limits, failures and passing scope remain
in the evidence ledger.
