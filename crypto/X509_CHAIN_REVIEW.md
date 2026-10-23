# Composed server-certificate authentication

`x509_chain.verify(tables, presented, anchors, identity, ServerAuth{}, now)`
returns `(tables, Verification)`. `presented` is leaf-first DER followed by an
unordered intermediate pool; `anchors` is a separate explicit list of DER
CA certificates. `identity` is `Dns{ASCII bytes}` or `Ip{4 or 16 octets}`.
The affine Unicode state comes from `unicode32_prepare.tables`, which
authenticates the bundled assets; it is returned for reuse. No effect, network
lookup, host crypto, implicit trust store or implicit clock occurs in this API.
Trusted `now` is integral civil UTC seconds since 0001-01-01; add
62,135,596,800 to nonnegative Unix seconds. Both validity endpoints are inclusive.

The result is `Success`, or `Untrusted`, `WrongIssuer`, `BadSignature`, `Expired`,
`NotYetValid`, `CaBasicConstraints`, `PathLength`, `KeyUsage`, `Eku`,
`UnsupportedCriticalExtension`, `UnsupportedNameConstraints`, `UnsupportedName`,
`IdentityMismatch`, `DepthLimit`, `Cycle`, `Duplicate`, `SearchLimit`, `InputLimit`
or `Malformed` (all nullary constructors). Malformed also covers failed selected
algorithm/SPKI/extension admission and invalid reference/clock input. A diagnostic
describes the deterministic failed search, not every possible path's errors.

Issuer linkage uses the existing `x509_name_match.compare` unchanged. Its
OID-bound prepared attributes, multiplicity-preserving sorted RDN multisets,
ordered Name sequences, encoding/case/space handling and unsupported-name
failure already meet M1 item 1; the existing 33,037-case matrices remain in the
package gate. Signatures use the parent's SPKI and the child's original signed
TBS encoding through `x509_signature.verify_signature`. The admitted profiles
remain P-256 ECDSA/SHA-256, RSA PKCS#1 v1.5/SHA-256 and RSA-PSS with SHA-256,
MGF1-SHA-256 and 32-byte salt, preserving RSA/PSS key restrictions. This is not
TLS CertificateVerify wire-scheme admission.

`x509_ca_path` implements RFC 5280 6.1.4(k)-(n) bottom-up: the count below each
ancestor contains non-self-issued intermediate CAs only. Each pathLen must
cover that count, which is equivalent to the top-down decrements and minima.
The leaf is excluded; prepared issuer/subject equality exempts a self-issued
rollover from pathLen but never from physical depth, signature, time or policy
checks. Existing arbitrary-size INTEGER comparison prevents truncation/wrap.
Intermediates and certificate-form anchors must be v3, CA=true and have an
explicit KU with keyCertSign. Requiring KU even when absent, and applying CA,
time, EKU and extension policy to anchors, are deliberate stricter profile
choices. Anchor self-signatures are not a trust premise. Non-self-signed CA
anchors can terminate a path; direct leaf pinning is not provided.

The leaf needs digitalSignature if KU exists and serverAuth if EKU exists;
anyExtendedKeyUsage alone is insufficient. All selected CAs also restrict EKU
to serverAuth when present. Identity uses SAN only, with exact IP octets or
the existing ASCII DNS/full-leftmost-label wildcard rules; no CN fallback,
IDNA conversion or DNS resolution. Every selected certificate, including its
anchor, receives the same caller clock with no skew allowance.

Search is deterministic depth-first: anchors in caller order, then peer
intermediates in presentation order. A failed signature, expired CA or dead
end can backtrack to a later issuer; only a complete path succeeds. Trust is
conferred solely by choosing a supplied anchor. A peer root alone is untrusted;
an anchor need not appear in the peer list. Exact-DER duplicates within either
input list reject; the normal overlap between the two lists is allowed.
Repeated DER in a selected path rejects as a cycle; an untrusted self-root
reports `Untrusted`. The first failure beyond issuer/trust linkage is retained
unless a complete path succeeds or the global work budget exhausts.

Limits are 16 peer certificates, 16 anchors, 65,535 bytes per certificate,
eight certificates per path including leaf and anchor, and 512 candidate
examinations across all branches. Each examination spends fuel before Name
comparison, including mismatches and backtracking. Structural Nat fuel proves
termination; the separately returned budget bounds aggregate work. Exhaustion
fails closed. Byte/Name normalization work is also bounded by the inherited
admission limits; these are not a latency or allocation-performance guarantee.
All input certificates must pass exact certificate framing, even unused ones;
semantic/time/critical policy is checked on the selected path.

Supported critical semantics are BC, KU, EKU and fully supported DNS/IP SAN.
Other critical extensions and unsupported critical SAN forms reject explicitly.
Name constraints are deliberately unsupported: either criticality rejects with
`UnsupportedNameConstraints`, including on anchors. Other well-framed unknown
noncritical extensions are opaque and ignored. Certificate-policy processing,
revocation/CRL/OCSP, AIA fetching, alternate identity forms, unsupported Name
attributes/Teletex and algorithms outside the selected profile are not provided.
This bounded server profile does not claim general-purpose RFC 5280 coverage.

The local synthetic fixture generator uses Python cryptography only as an
oracle/issuer and exports public DER. It keeps no private keys on disk. Normal
checks require only stdlib Python, OpenSSL 3 for the independent oracle, and the
whole native/Bun Bend evaluator. The frozen 193 complete-chain cases include
55 accepted paths, all three signature profiles, DNS/IPv4/IPv6, cross-encoded
issuer Names, wrong-Name valid signatures, exact-TBS tampering, trust and
boundary time failures, CA/KU/EKU/pathLen, self-issued rollover, unsupported
critical/Name/NC semantics, backtracking, duplicates, cycles, exact depth eight
versus nine, global search/input limits, truncation and trailing DER.
Fourteen CA and twelve composition declarations are checked by the frontend;
there is no kernel `--verdict` claim.

OpenSSL's primary results are asserted separately from Bend's selected profile.
Recorded differences include its exclusive notAfter boundary, CN fallback,
keyEncipherment server permission, optional CA KU, unsupported-name/SAN/NC
support, duplicates, trailing DER, and larger input/depth limits. Python
datetime fixes the inclusive boundary seconds. For three same-Name/same-SKI
cross-certificate presentations OpenSSL does not discover the good branch;
the oracle additionally verifies the complete successful alternate path.
Differences are explicit evidence, never counted as identical verdicts.

Standards retrieved on 2026-10-23: RFC 5280 (especially 4.2, 6.1.3,
6.1.4(k)-(o) and 7.1), RFC 6818 anchor clarification, RFC 9549 Name updates,
RFC 9525 SAN identity, and the current RFC 5280 updates 8398/8399, 9598, 9608,
9618, 9925 and 10007. The six Verified errata (5802, 5938, 6414, 7661, 3579,
7658) were read; reported/held records are not normative replacements.
Email and policy updates remain outside the admitted critical profile;
unsigned-certificate algorithms reject; revocation updates do not establish
revocation support. No external implementation code was ported or linked.
Source snapshots, hashes, commands, source bindings, failed attempts and reports
are under `~/.codex/artifacts/grounds/2026-10-23/m1/`.

Acceptance on 2026-10-23, implementation commit `46770d4`: native and Bun each
pass all 193 frozen cases (55 accepted, 138 rejected), both focused and within
each fresh gate. The forced crypto gate passes 1,673/1,673 phases; the forced
root gate passes 1,869/1,869, with no skipped or unexecuted phases. Both use
pinned Bend 2.0.38, unchanged 4 GiB aggregate/process guards and 120-second
per-phase deadlines. All 1,569 pre-existing crypto phases retain their order
and optionality; 104 phases were added. `closeout-evidence-audit.json` binds
all per-target batch reports and unchanged gate sources. Exact commands,
resource results and report paths are in the dated STACK_PROGRESS ledger.

M1's exit criteria are met. This does not close the TLS handshake,
private-key/runtime review, HTTPS/WSS or broader RTC gates; M2 has not been
started here.
