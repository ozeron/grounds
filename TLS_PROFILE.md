# Bend HTTPS implementation profile

Decision date: 2026-10-05. Status: selected build target, not implemented TLS
acceptance. This document refines STACK_PLAN.md M2/M3 without removing M0-M4
exit requirements. RTC expansion is deferred by user decision.

## Standards baseline

Use [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.txt), which supersedes
RFC 8446, for TLS 1.3. Section 9 requires AES-128-GCM/SHA-256, P-256 key
exchange, RSA SHA-256 certificate signatures, RSA-PSS/SHA-256 and P-256 ECDSA.
It recommends X25519 and additional suites. Sections 9.2/9.3 include
certificate-signature negotiation and extensibility rules; unknown offered
parameters are not automatically fatal. CertificateVerify must not use RSA
PKCS#1 v1.5. Implement retry-cookie handling, transcript replacement for
HelloRetryRequest, and correct record/key transitions.

The official RFC 9846 errata listing retrieved today contains five Reported
entries (9040, 9042, 9043, 9161, 9157), no Verified entries. Do not silently
promote reported changes to normative requirements. The legacy-version items
concern older-version negotiation; this new path selects only TLS 1.3. Revisit
message-specific errata when implementing each owner.

Use [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525.html) for DNS/IP service
identity: SAN identity matching is separate from full path validation, and
Common Name is not a hostname fallback. The existing certificate composition
work remains required. [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html)
is supplemental deployment guidance, not evidence that this implementation is
ready for deployment.

Source snapshots and SHA-256 manifest:
`/Users/ozeron/.codex/artifacts/grounds/2026-10-05/https-baseline/sources/`.
The browser retrieval tool could not fetch RFC 9846; direct official HTTPS
retrieval succeeded. No generated summary substitutes for that retained text.

## Selected parameters and implementation owners

| Surface | Decision | Existing Bend owner / required composition |
|---|---|---|
| Protocol | TLS 1.3 only in the new transport; no downgrade to legacy effects | New handshake/negotiation owner |
| AEAD/hash | AES-128-GCM/SHA-256 and ChaCha20-Poly1305/SHA-256 | `crypto/gcm.bend`, `aead.bend`, `traffic.bend`, `wire/tls_record.bend` |
| Key agreement | P-256 and X25519, with fresh per-connection private material | `crypto/p256.bend`, `x25519.bend`; connect host RNG and private-key ownership |
| Handshake signatures | P-256 ECDSA/SHA-256 and RSA-PSS-RSAE/SHA-256 | `ecdsa_scheme256.bend`, `rsa_signature256.bend`; RSA private signing and full ownership are unfinished |
| Certificate signatures | P-256 ECDSA/SHA-256, RSA PKCS#1 v1.5/SHA-256 and admitted RSA-PSS/SHA-256 | `x509_algorithm.bend`, `x509_public_key.bend`, `x509_signature.bend`; preserve key/parameter restrictions |
| Transcript/KDF | SHA-256 incremental transcript and TLS HKDF labels | `wire/tls_transcript.bend`, `wire/tls_schedule.bend`, `sha256_stream.bend`, `hkdf.bend`, `traffic.expand_label`; component checks pass, live handshake composition remains |
| Application | HTTP/1.1; WebSocket over that connection; ALPN `http/1.1` only | HTTP client/server plus new TLS transport adapter; never advertise h2/h3 |
| Trust | Caller-supplied explicit anchors and expected DNS/IP identity | M1 composed validation, not a signature-only result or automatic trust of supplied peer roots |
| Server credentials | Synthetic P-256 certificate first; RSA signing remains part of profile acceptance | Fixture import plus explicit key ownership; no host signing delegation |

AES-256/SHA-384 is not selected: the current SHA-256 implementation path is the
bounded target. Record this omission in capability documentation; do not claim
unrestricted TLS algorithm support. ECDSA-first is implementation order only,
not permission to omit required RSA verification/signing from final evidence.

## Connection behavior to build

1. **Negotiation and framing.** Validate complete lengths before allocation;
   collect fragmented handshake messages across records and split coalesced
   messages. Decode supported_versions, supported_groups, key_share, both
   signature lists, SNI, ALPN and retry cookies. Apply context-specific unknown,
   duplicate and unsolicited extension handling. Never advertise an algorithm
   absent from the actual implementation. Support HelloRetryRequest and reject
   illegal repeated retries. Specify finite connection/message/chain bounds in
   the codec API and test exact boundaries before exposing it to sockets.
2. **Authenticated transcript.** Retain exact handshake encodings. Bind the
   chosen parameters, certificate chain, CertificateVerify and Finished to the
   correct transcript and role. Establish independent read/write handshake and
   application epochs; no application delivery before authentication succeeds.
   Record state transitions and secret retirement without logging secret bytes.
3. **Certificate decision.** Compose Name/RDN equality, issuer linkage, exact-DER
   signature verification, trust anchors, CA/path/usage/critical-extension/name
   constraints, time and SAN checks. A caller receives one success/failure
   decision. Unsupported authorization semantics reject explicitly. OS effects
   may supply time/file bytes, never certificate parsing or authorization.
4. **Lifetime.** Handle KeyUpdate, close_notify, fatal alerts, cancellation,
   timeout, peer EOF/truncation and partial writes. Keep record keys and sequence
   numbers connection-owned. NewSessionTicket can be parsed and discarded;
   do not store or offer resumable sessions. Keep compatibility CCS processing
   separate from transcript authentication and legal only in its specified window.
5. **Deliberate exclusions.** No PSK resumption, 0-RTT, client-certificate
   authentication, post-handshake authentication, session-ticket issuance,
   certificate fetching, HTTP/2, QUIC or DTLS in this goal. Do not advertise
   these features. An optional client CertificateRequest needs protocol-correct
   empty-certificate handling; a peer requiring client authentication fails
   explicitly. Well-formed unused offers must still follow extensibility rules.

## Evidence matrix

Each cell needs native and Bun evidence on the accepted current compiler.
Independent peers are test references; OpenSSL may be used by a peer or oracle,
never by the new Grounds TLS/crypto execution path.

| Gate | Required positive evidence | Required negative/lifecycle evidence |
|---|---|---|
| Handshake client | Independent server, each suite/group and both handshake signature schemes; retry path | Wrong chain/hostname/time/signature/Finished, unsupported choice, malformed framing, retry misuse |
| Handshake server | Independent client and browser, both local signing schemes and selected suite/group combinations | No common choice, invalid share, malformed extension/state order, altered Finished |
| Certificate composition | Trusted root/intermediate/leaf paths, DNS and IP identities, cross-encoding issuer names | Untrusted/wrong issuer, CA/path/usage/constraints/critical policy, expiry and exact boundary cases |
| Records/lifetime | Fragmented/coalesced flights, streaming, KeyUpdate, close, reconnect | Modified ciphertext, stale epochs, counters/usage limits, EOF and resource cleanup |
| HTTP/browser | Request/response, streaming, signed cookies and WSS with normal certificate verification | Origin/auth denials, bad certificate, disconnect/reconnect and cleanup |

Runtime timing/secret-dependent behavior and erasure findings in
`crypto/ECDSA_REVIEW.md` and related reviews remain completion blockers.
Logical affine ownership does not prove physical erasure. Synthetic-key runs
may establish interoperability while those findings are open; they cannot
establish live-secret safety or complete M2/M4.

The final no-delegation test must make legacy TLS/crypto effects fail if the new
path invokes them, alongside an import/effect audit. Retain compatibility-path
regressions separately. A passing browser ICE test or encrypted-record fixture
cannot stand in for any live TLS/HTTPS cell above.


## Current component and runtime review checkpoint (2026-10-05)

Transcripts, no-PSK SHA-256 schedule/Finished and handshake-record reassembly now
have independent native/Bun component evidence and a fresh eleven-phase wire
pass (commit 44249af; details in STACK_PROGRESS.md). These components still need
negotiation, body codecs, role/order enforcement, certificate authentication and
record-epoch integration before any live TLS claim.

A static inspection of the current pinned P-256 diagnostic JavaScript preserves
five exact generated functions and input hashes in
`/Users/ozeron/.codex/artifacts/grounds/2026-10-05/p256-phases/generated-runtime-review.json`.
Its scalar loop follows public counters and its inspected selector uses bitwise
masks. This is narrow positive source evidence; it does not cover all arithmetic,
optimized machine code, Bun JIT behavior or timing distributions. The generated
path retains tagged heap records, trampoline state and array-to-list slice
copies. Physical lifetime/erasure remains unverified.

The new schedule's affine wrappers contain ordinary duplicable byte lists.
Consuming a Finished key or a stage owner prevents the tested logical reuse; it
does not erase every underlying heap/runtime copy. Existing ECDSA retry findings
and native/runtime review remain open. Before M2 closes, bind the full signing,
key-agreement, KDF and AEAD generated paths to reviewed compiler/runtime versions,
resolve secret-dependent timing findings, and implement/test an explicit secret
storage and retirement contract. No timing or erasure approval follows from this
checkpoint; synthetic fixture keys remain the only authorized test material.
