# Certificate public-key admission

`x509_public_key.decode(bytes)` parses a complete SubjectPublicKeyInfo in Bend
and returns public `Rsa{algorithm, modulus, exponent}` or `P256{encoded}` metadata,
or `None`. This is structural and public-parameter admission, not certificate
validation. Helper functions expect the outer decoder's admitted octets;
protocol callers use `decode`.

The outer SEQUENCE must contain exactly an admitted AlgorithmIdentifier and
one primitive BIT STRING. The latter must be octet-aligned: its initial unused
bits count is zero. All input octets are checked and the total input is bounded
at 65,535 bytes. Nested lengths retain the DER framing module's minimal definite
encoding rules; wrong tags, truncation, reordering and extra fields fail closed.

RSA and PSS-only keys contain a complete RSAPublicKey SEQUENCE with exactly two
positive INTEGERs. Empty, zero, negative and redundantly padded encodings are
rejected. A necessary leading sign-suppression zero is removed, producing
canonical unsigned big-endian modulus/exponent bytes. Public restrictions match
`rsa_integer.public_operation`: odd 2048–4096-bit modulus, canonical odd exponent
greater than one and smaller than the modulus. The decoder reuses that module's
bit-length, canonicality and comparison helpers; it performs no exponentiation.
This admission does not certify RSA factor structure or private-key possession.
Synthetic arithmetic boundary cases are not asserted to be valid RSA key pairs.

The `algorithm` field retains unrestricted RSA, PSS-only with absent parameters,
or PSS-only with the admitted SHA-256/MGF1-SHA-256/trailer/minimum-salt restriction.
Stripping an INTEGER sign pad cannot strip those algorithm restrictions.
P-256 requires the named-curve identifier and an uncompressed 65-byte SEC1 point.
`p256.decode` checks canonical field coordinates, the curve equation and
non-infinity; the existing cofactor-one reasoning applies. The encoded point is
retained after validation. Compressed points are unsupported; hybrid encodings,
other prefixes, off-curve points and coordinate aliases are rejected. Metadata
is copiable public `Data`; no private key, nonce or secret array is retained.

Encoding rules were reviewed on 2026-10-02 against
[RFC 5280 §4.1.2.7](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.7),
[RFC 4055 §1.2](https://www.rfc-editor.org/rfc/rfc4055#section-1.2) and
[RFC 5480 §2](https://www.rfc-editor.org/rfc/rfc5480#section-2).
The six current verified RFC 5280 errata were inspected: 5802/6414 affect future
EKU handling, 5938 future identity/path validation, 7661 cross-certificate wording,
3579 policy type naming and 7658 a name-comparison link. None changes the SPKI
structure here. Held items remain distinct from verified corrections. Current
RFC 5280 updates and RFC 8813 EC key-usage rules must be applied when implementing
the pending certificate constraints/identity/path owner.

Six closed checks cover INTEGER normalization and invalid SPKI octets/shape.
Native and normal-JIT Bun each pass all 11,547 cases: key size/parity/exponent
boundaries, INTEGER encodings, preserved PSS metadata, every unused-bits count,
all point-prefix octets, canonical-coordinate/curve failures, 50 public points
from the existing 25 published NIST P-256 ECDH vectors, valid negated points,
all truncations and individual bit mutations of four SPKI fixtures, seeded
mutations, field/length failures and exact total-input boundaries. Four frozen
public OpenSSL SPKIs are compared to values independently extracted from their
retained OpenSSL public-key displays. The oracle uses Python integers and a
curve equation, with the previously verified independent algorithm oracle.
Every implementation result comes from one whole Bend evaluator. No private
NIST fixture field is consumed by this checker and no private peer key is kept.

Standalone closed/native-C/clang/JS compilation passes in 15.631s, peak 288.0 MiB,
using the invocation-local compiler JIT workaround documented in
[X509_ALGORITHM_REVIEW.md](X509_ALGORITHM_REVIEW.md). Native/Bun matrix times are
3.617/24.194s; peaks 36.8/98.3 MiB aggregate. All jobs are sequential and nice 10,
with 120-second deadlines, sampled 384/320 MiB compiler and 128/96 MiB evaluator
cutoffs and normal macOS pressure observations. Large inputs run alone. Cutoffs
can overshoot and are not OS memory quotas. Generated Bun evaluation keeps
normal JIT. Bend 2.0.27, Bun 1.3.13, Python 3.12.8, Apple clang 21 and OpenSSL
3.6.4 are used. Evidence, retained C/JS, reports, hashes, standards snapshots
and the corrected first syntax failure are under
`/Users/ozeron/.codex/artifacts/grounds/2026-10-02/x509-public-key/`.

Certificate field framing is now supplied by
[X509_CERTIFICATE_REVIEW.md](X509_CERTIFICATE_REVIEW.md). Certificate
signature verification, key usage, constraints, time, hostname,
trust/path validation, TLS SignatureScheme admission and handshake integration
remain required. Existing crypto arithmetic and its unresolved private-owner,
timing/runtime/erasure findings are unchanged. Full crypto/repository/browser
gates remain stopped after the memory complaint; no stack acceptance box closes
from this public-key milestone.
