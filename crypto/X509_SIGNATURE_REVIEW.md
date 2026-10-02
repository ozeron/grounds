# Certificate issuer-signature verification

`x509_signature.verify_signature(issuer_spki, certificate)` returns `Bool` from
one complete issuer SPKI and certificate. Bend admits the key and certificate,
checks key/algorithm compatibility, hashes the original encoded TBSCertificate
with SHA-256, and verifies the mathematical signature. The issuer key is an
explicit argument; the certificate's subject key is never substituted for it.
The decoded-record helpers assume records produced by the admission modules.
External byte inputs should use `verify_signature`.

The supported profiles are SHA-256 RSA PKCS#1 v1.5, RSA PSS with SHA-256,
MGF1-SHA-256, salt length 32 and trailer 1, and P-256/SHA-256 ECDSA. RSA public
parameter/width limits and PSS key restrictions come from the existing modules.
ECDSA signature bytes pass strict DER and scalar-range admission before the
public verification primitive. No signing facade or private-key owner is
imported. File I/O is the fixture CLI's only host effect; host bigint/curve and
OpenSSL operations are independent test references.

This is a mathematical signature result. Time validation is supplied separately
by [x509_validity](X509_VALIDITY_REVIEW.md); composition with a trusted clock is
still required. Issuer selection, Name/extension semantics, constraints,
chain/trust/hostname validation, TLS wire signature
schemes and handshakes remain required. A signed fixture with invalid time
contents deliberately verifies. Fresh fixtures also carry a wrong SAN and an
unknown critical extension. Those certificates must fail the future trust
owner even though their signature math succeeds. Certificate RSA v1.5 admission
does not permit it in TLS 1.3 CertificateVerify; RSA/PSS key identity must also
remain distinct when admitting TLS's rsae and pss wire schemes.

Rules were checked on 2026-10-02 against
[RFC 5280 §4.1.1.3](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.1.3),
[RFC 8017 §§8.1.2 and 8.2.2](https://www.rfc-editor.org/rfc/rfc8017.html#section-8.1.2)
and [RFC 5758 §3.2](https://www.rfc-editor.org/rfc/rfc5758.html#section-3.2).
The original DER TBS bytes are hashed without reconstruction. Existing
[algorithm](X509_ALGORITHM_REVIEW.md), [SPKI](X509_PUBLIC_KEY_REVIEW.md),
[RSA](RSA_REVIEW.md) and [ECDSA](ECDSA_REVIEW.md) reviews retain the current
verified-errata/vector evidence. This integration changes no arithmetic or
algorithm-admission rule. Current RFC 5280 updates and verified errata still
need application to the remaining semantic/path owners.

Native and normal-JIT Bun each passed all 4,825 whole-verifier cases and three
CLI error checks. The independent Python oracle slices certificate bytes,
admits key/profile metadata, and uses textbook public bigint/affine math.
Coverage includes four frozen OpenSSL self-signatures and four fresh public
issuer/subject fixtures across all three schemes, every certificate truncation,
every signature-byte mutation, each TBS field's edge bytes, wrong/malformed
issuer keys, signature width/DER/range, all signature unused-bits values,
inner/outer profile binding, NULL/absent equivalences, PSS-only/minimum-salt
restrictions and exact input boundaries. Cases stream in batches of eight;
inputs above 4,096 bytes run alone. Temporary synthetic peer private keys were
removed before public export. `whole_certificate_results_pending_at_capture`
records historical fixture capture, not the current verification status.

The saved native/Bun whole matrices took 7.314/96.892s and peaked at
29.1/96.8 MiB aggregate; Bun's largest process peaked at 70.3 MiB. A fresh
primary-source native repeat using the retained executable passed all cases
in 6.769s, peak 29.0 MiB. All 24 input hashes match between these runs.
The unchanged published RSA checker also passed all 774 cases on both targets
in 2.616/24.045s. An artifact-only ECDSA adapter through this module's strict-DER
public verifier passed 32 NIST/RFC 6979 verification vectors on each target
in 1.373/28.350s. Its coverage does not establish private signing or the entire
ECDSA matrix. Existing 31 closed checks across algorithm/SPKI/certificate/RSA/
ECDSA files passed compiler checking; `--verdict` kernel validation was not run.

The whole CLI's retained C and JS were generated with the official, unmodified
Bend 2.0.34 macOS arm64 release. Generation and clang `-O3` passed at 241.5 MiB
aggregate / 239.5 MiB individual. All 74 extracted archive files match the
retained release archive, SHA-256
`a60c820c0ced758d8ace839507ff6c508a204ce4ef0f45e1089ed7bc73e8c267`.
Earlier Bend 2.0.27 C/JS generation cutoffs and unsuccessful isolated compiler
GC/OID experiments remain retained; those patches were not adopted. The
repository compiler pin remains 2.0.27: a global upgrade needs broader API and
runtime checks. The scoped result does not establish full 2.0.34 compatibility.
The [official changelog](https://github.com/bendlang/bend/blob/v2.0.34/CHANGELOG.md)
records the 2.0.32 change to include the invoked program in `IO.args()`.
The fixture CLI requires `verify` in the first or second position to support
both conventions; it does not guess filenames by argument count.

All retained jobs were sequential, nice 10, with 120-second deadlines and
normal macOS pressure samples. Compiler cutoffs were 384/320 MiB aggregate/
individual, and evaluators/provenance 128/96 MiB. Compiler environment was
`BEND_NO_TELEMETRY=1 BUN_OPTIONS=--smol BUN_JSC_forceRAMSize=134217728
BUN_JSC_useJIT=false`; generated Bun used normal JIT and
`BUN_OPTIONS=--smol BUN_JSC_forceRAMSize=67108864`. Sampled cutoffs can overshoot
and are not OS allocation quotas; Bun settings are GC hints. No heavy build
was restarted during the adoption after the latest memory complaint.

Artifacts, failed attempts, exact commands, public peer preparation, generated
targets and reports are retained under
`/Users/ozeron/.codex/artifacts/grounds/2026-10-02/x509-signature/`, with the older
failed experiments under `../x509-certificate/`. `build.sh` and
`build-published.sh` resolve the scoped compiler. The checker command is
`python3 crypto/x509_signature_check.py --report <report> -- <native|bun js>`;
run it inside `tools/build_guard.py` with the cutoffs above.
`compiler-provenance.json` and `validated-inputs.json` bind exact sources,
generated outputs and retained prior checks. Versions: Bend 2.0.34, Bun 1.3.13,
Python 3.12.8, Apple clang 21 and OpenSSL 3.6.4 for the public peer fixtures.

`check.sh` adds both whole-verifier targets and preserves all prior commands.
Its default 2.0.27 compiler still encounters documented generation cutoffs.
Full forced crypto, repository and browser gates remain pending and stopped
after the memory complaint. No full-stack acceptance box closes, and no timing,
erasure, private-operation or live-secret approval follows from these results.
