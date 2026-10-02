# Certificate AlgorithmIdentifier admission

`x509_algorithm.bend` supplies public algorithm metadata for the future Bend
certificate verifier. `key(bytes)` and `signature(bytes)` parse one complete
AlgorithmIdentifier and return `None` for unsupported or malformed input.
`compatible(key, signature)` checks the selected certificate signature profile.
The byte admission boundary is `der.complete`: valid octets, at most 65,535
bytes, one exact SEQUENCE and no trailing data. OIDs match exact encoded octets;
unknown identifiers cannot alias supported ones.

| Identifier | Supported parameters / result |
|---|---|
| `rsaEncryption` key | Mandatory NULL; `Rsa` |
| `id-RSASSA-PSS` key, absent parameters | `PssAny`; remains PSS-only |
| `id-RSASSA-PSS` key, present parameters | SHA-256, MGF1-SHA-256, trailer 1, minimum salt 0–32; `Pss256` retains that minimum |
| `id-ecPublicKey` key | Mandatory named-curve OID `secp256r1`; `P256` |
| `id-RSASSA-PSS` signature | Mandatory parameters: SHA-256, MGF1-SHA-256, exact salt 32, trailer 1 |
| `sha256WithRSAEncryption` signature | NULL or absent parameters |
| `ecdsa-with-SHA256` signature | Absent parameters only |

SHA-256 hash identifiers accept NULL or absent parameters. PSS fields must be
ordered and unique. Missing hash/MGF fields select SHA-1 and are unsupported;
they never select SHA-256. Missing salt defaults to 20, which is admitted as a
key minimum but fails the selected signature profile. Explicit trailer 1 is
recognized as required by RFC 4055. Salt INTEGER encodings must be minimal,
nonnegative and within the selected range. Explicit defaults are recognized for
profile compatibility; this is not general canonical ASN.1 schema validation.

Unrestricted RSA allows both selected RSA signatures. PSS keys allow PSS only;
their present restrictions must permit the signature's salt. P-256 allows the
selected ECDSA signature only. Metadata is public, copiable `Data`; it contains
no private key or nonce material.

Rules were reviewed on 2026-10-02 against
[RFC 4055 §§1.2, 2, 3.1–3.3, 5](https://www.rfc-editor.org/rfc/rfc4055),
[RFC 5756](https://www.rfc-editor.org/rfc/rfc5756),
[RFC 5480 §2.1](https://www.rfc-editor.org/rfc/rfc5480) and
[RFC 5758 §3.2](https://www.rfc-editor.org/rfc/rfc5758).
Verified errata 4055/1468, 4055/1676, 5480/6670 and 5480/8026 were reviewed;
they correct field/MGF naming, key-usage naming and a different curve's spelling.
Held errata are retained separately. Future EC key-usage checks must also apply
[RFC 8813](https://www.rfc-editor.org/rfc/rfc8813).

Seven algorithm closed checks pass in the primary checkout. Native and normal
Bun evaluators each pass all 4,563 independent oracle cases: PSS parameter
combinations/defaults, field order/duplicates, NULL/absent distinctions, every
truncation/bit mutation of supported fixtures, PKCS OID suffixes, cross-algorithm
bindings, DER boundaries and four public OpenSSL certificate algorithm fixtures.
The Python driver only routes files to precompiled Bend evaluators; all
implementation parsing/classification runs in Bend. The oracle separately uses
byte slicing and a field map, with manually asserted RFC fixture expectations.
Synthetic private peer keys were deleted when fixtures were prepared.

The default-JIT compiler crossed the unchanged 320 MiB process cutoff for the
key adapter. Invocation-local `BUN_JSC_useJIT=false` lets that same source compile
at 242.1 MiB; the sequential closed/C/clang/JS build peaks at 249.5 MiB.
This is a measured workaround for these standalone inputs, not a general
compiler-memory fix. `check.sh` applies it only to the new Bend compiler calls;
generated Bun evaluation keeps its normal JIT. Native/Bun matrix peaks are
55.4/121.0 MiB aggregate; Bun's largest process is 75.5 MiB. Jobs run nice 10,
with 120-second deadlines and sampled 384/320 MiB compile or 128/96 MiB evaluator
cutoffs. Sampling can overshoot; no setting is a hard OS allocation quota.
Large DER diagnostics run individually and all cases remain. macOS pressure
observations are normal. Bend 2.0.27, Bun 1.3.13, Python 3.12.8, Apple clang 21
and OpenSSL 3.6.4 are pinned in the evidence.

Evidence: `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/x509-admission/`,
including native/Bun reports, retained C/JS, build/primary/resource logs,
input hashes and `evidence.json`. Original peer/standards preparation and failed
draft builds remain in the adjacent `x509-algorithm/` artifact.

This does not decode SPKI key bits or validate certificates, signatures, inner/
outer signature consistency, key usage, constraints, chains, trust, times or
hostnames. TLS wire SignatureScheme admission is separate: RSA key OIDs distinguish
`rsa_pss_rsae_sha256` from `rsa_pss_pss_sha256`; PKCS#1 v1.5 certificate signatures
do not authorize TLS 1.3 CertificateVerify
([RFC 9846 §4.3.3](https://datatracker.ietf.org/doc/html/rfc9846#section-4.3.3)).
SHA-1, other hash/curve profiles,
private-key operations and handshake integration remain required as applicable.
Full crypto/repository/browser gates remain stopped after the memory complaint.
