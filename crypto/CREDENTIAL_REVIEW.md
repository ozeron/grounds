# M2 server credential admission (2026-10-23)

All committed private keys and certificates are **synthetic public test fixtures**.
These APIs inherit the live-secret limitations in `RUNTIME_REVIEW.md` and
`RSA_PRIVATE_REVIEW.md`. Successful parsing is neither certificate trust nor
approval for a live signing key.

## APIs and ownership

- `pem.decode(bytes) -> Result<Error, Block>` admits one PEM object with an exact
  supported label, canonical Base64 (including zero padding bits), LF or CRLF,
  and no object after its footer. It bounds text at 100000 octets and decoded
  DER at 65535 octets. Blank lines before the header and ASCII whitespace after
  the footer are accepted; whitespace inside Base64 lines is rejected.
  `Encrypted` is returned for `ENCRYPTED PRIVATE KEY` and traditional
  `Proc-Type: 4,ENCRYPTED`; there is no decrypt/password interface.
- `private_key.sec1(inherited_curve, der)`, `.pkcs8(der)`, `.pkcs1(der)` return
  `Maybe<Private>`. `.pem(bytes)` retains PEM's distinct encrypted-key error.
  `Private` is affine (`Type`), with `P256{scalar, public}` and
  `Rsa{rsa_private.Private}` variants.
- `credential.from_key(leaf_der, imported_private)` and `.import_pem(leaf_der, pem)` return
  an affine `Credential{leaf, key}` only when the derived public key exactly
  matches the certificate's validated SPKI. `from_key` expects a key returned
  by the private-key importer; direct construction of internal representations
  does not establish validation. The encoded leaf is retained for
  the Certificate message. A PSS-only RSA SPKI is rejected because the selected
  CertificateVerify profile accepts `rsa_pss_rsae_sha256`, not
  `rsa_pss_pss_sha256`.

Format references: RFC 7468 (PEM textual encodings), RFC 4648 (Base64),
RFC 5915 (SEC1 ECPrivateKey), RFC 5208 (PrivateKeyInfo), and RFC 8017
(RSAPrivateKey). Canonical padding handling follows the existing repository
`http/core/base64.bend` behavior, implemented locally over byte lists to avoid
a crypto dependency on the HTTP package. No external implementation is called.

The importer uses `der.bend` for bounded definite-length framing and validates
exact schemas and field order. PKCS#8 accepts RFC 5208 version zero without
attributes or trailing fields. SEC1 accepts version one and exactly 32 scalar
bytes, with `1 <= scalar < order`; standalone SEC1 requires namedCurve
secp256r1. PKCS#8 supplies that named curve and any inner curve must agree.
An optional SEC1 public point must equal Bend's derived public point. Compressed
points and other curves are outside this profile.

PKCS#1 accepts version zero and exactly eight minimally encoded positive
integers after the version. Multi-prime RSA is rejected. `rsa_private.validate`
owns factor/modulus sizes, public exponent bounds and CRT consistency checks;
see its review for the explicit trusted-key-generation/primality boundary.

Certificate decoding reuses `x509_certificate` and `x509_public_key`, preserving
algorithm restrictions and the selected SHA-256 certificate schema. Import
checks key correspondence only. Chain signatures, trust, validity, extensions,
server purpose and reference identity remain the composed X.509 decision's
responsibility, to be applied by the M3 handshake owner.

Every error consumes the affine key/stage owner. The fields contain duplicable
byte lists and the compiler may duplicate representations. Affine ownership
prevents accidental reuse of the owner; it does not prove unique underlying
storage, GC retirement, locked memory, physical erasure, or constant-time
parsing/private operations. A caller must drop the original PEM/DER byte lists
and any explicit copies after import, retain the credential only for its
configured server lifetime, and drop it on replacement or shutdown.

## Independent evidence

`private_key_fixture.py` uses Python cryptography 50.0.2 to construct synthetic
P-256 and RSA credentials, serialize each supported format, reload every
positive DER and PEM, derive independent public keys and assert RSA CRT
relations. It independently attempts every malformed input too and freezes
the actual cryptography loader verdict; `--verify` rechecks the frozen corpus
without replacing keys. `private_key_vectors.json` freezes these inputs and oracle outputs;
ordinary checks require only Python stdlib and the Bend executable.

`pem_check.py` independently generates canonical Base64 and malformed padding,
alphabet, object framing, encryption and size-boundary cases. The private-key
corpus includes truncation, trailing fields, versions, scalar range, named curve,
embedded-public disagreement and every RSA private component mutation.
`credential_check.py` includes matching keys, wrong leaves, PSS-only SPKI,
malformed certificate encodings and explicit encrypted-key errors. Diagnostic
CLIs print public parameters or verdicts only. `private_key_type_check.py`
checks valid consumption and compiler rejection of private/credential owner
copying and repeated use.

Generated native and Bun verification counts and guarded reports are recorded
by the M2 ledger under `~/.codex/artifacts/grounds/2026-10-23/m2/credentials/`.


Focused checks on Bend 2.0.38 pass **579/579 per target**: PEM 436,
private-key import 123 (76 EC / 47 RSA), and credential binding 20. Native and
Bun include all cases without skips. The frozen Python cryptography recheck
passes 123/123 (20 matching public keys and 103 independently rejected inputs).
Four PEM, three private-key and one credential frontend declarations pass;
all six ownership probes pass (two valid consumption, four rejected copies or
repeated uses).

Every frontend, generated-code build, native/Bun evaluator check and final
independent frozen-oracle check ran through `tools/build_guard.py` at unchanged
4096 MiB aggregate/process limits and a 120-second phase cap. Maximum measured
peak was 599.4 MiB. Compiler-only `BUN_JSC_useJIT=false`, `BUN_OPTIONS=--smol`
and `BUN_JSC_forceRAMSize=134217728` bound frontend allocation; generated Bun
programs ran with their ordinary JIT configuration. Five failed frontend calls
remain in the report directory: computed-match syntax, helper fill/decreasing
recursion, and binder-match order. The two repeated compiler issues received
Astra low consultations before further attempts. The final source uses
input-length-derived decreasing fuel, helpers ordered before callers, and fresh
helper parameters for subsequent matches. Those compiler corrections do not
change the admitted corpus or resource limits.
