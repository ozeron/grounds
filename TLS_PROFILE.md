# Bend HTTPS implementation profile

Binding M2 build decision and M3b composition: 2026-10-23. This finite profile
governs synthetic-key TLS acceptance. STACK_PLAN.md remains the acceptance contract.
Only synthetic credentials may be used: see crypto/RUNTIME_REVIEW.md.

## Standards baseline

[RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.txt), published July 2026,
**obsoletes RFC 8446**. The repository citation is correct; TLS 1.3 bis is
published. Use RFC 9846 normatively and RFC 8448 for published traces.
CertificateVerify is RFC 8446 §4.4.3 / RFC 9846 §4.5.2; Finished respectively
§4.4.4 / §4.5.3, KeyUpdate §4.6.3 / §4.7.3. Record usage remains §5.5.
RFC 9525 governs SAN-only service identity; RFC 9325 is deployment guidance.

Official texts and complete errata searches were retrieved on 2026-10-23;
exact bytes, hashes and verified-entry inventory are retained under
`~/.codex/artifacts/grounds/2026-10-23/m2/sources/`.
RFC 9846 now has **one Verified erratum, 9040**, verified 2026-10-12.
It corrects Appendix E.2 legacy-version selection without supported_versions.
Our TLS-1.3-only path requires a supported_versions offer containing 1.3 and
otherwise sends protocol_version; it never adds TLS 1.2 fallback.
9042, 9043, 9161 and 9157 remain Reported, not normative corrections.
This supersedes the October 5 snapshot with no Verified entries.

All 16 Verified RFC 8446 entries were checked against this profile:

| Errata | Disposition |
|---|---|
| 5483 | Send X25519 public output, never private scalar or base-point input. |
| 5868 | ECDSA DER is exactly two INTEGERs (RFC 4492 form). |
| 6123 | Certificate-based server authentication is required here. |
| 6142, 7250, 8799 | No ticket/PSK use; silently discard authenticated NewSessionTicket with bounded framing. |
| 6146 | Negotiate the selected version; no downgrade path. |
| 7303 | M3 sends close_notify at warning level and ignores subsequent data. |
| 8423 | ClientHello extension-vector lower bound is seven bytes; required-extension semantics are separate. |
| 8795 | Legal main-handshake CertificateRequest differs from forbidden post-handshake auth. |
| 8803 | Security-considerations correction; no assumption of peer authentication before verification. |
| 5976, 6122, 6141, 7774 | Registry/editorial corrections; no algorithm/wire change. |
| 6139 | Send SNI for DNS identities; raw IP literals are not HostName values. |

## Frozen parameters

| Surface | Binding decision |
|---|---|
| Version | TLS 1.3 (0x0304) only. Standard legacy fields and compatibility-CCS windows still apply. |
| Suites | TLS_AES_128_GCM_SHA256 (0x1301), TLS_CHACHA20_POLY1305_SHA256 (0x1303). |
| Groups | x25519 (0x001d), secp256r1 (0x0017), fresh connection/replacement shares. Uncompressed SEC1 P-256 only. |
| CertificateVerify | ecdsa_secp256r1_sha256 (0x0403), rsa_pss_rsae_sha256 (0x0804), advertised in signature_algorithms. PSS hash/MGF SHA-256, salt exactly 32 bytes. |
| Certificate signatures | The above plus rsa_pss_pss_sha256 (0x0809) and rsa_pkcs1_sha256 (0x0401), **only inside certificates** and signature_algorithms_cert. Preserve PSS-only SPKI restrictions. Neither additional scheme is admitted for CertificateVerify. |
| Local credentials | P-256 SEC1/PKCS#8; two-prime RSA PKCS#1/PKCS#8 with rsaEncryption identity. No encrypted PEM, multiprime RSA, compressed points, explicit EC parameters or other curves. RSA n: 2048–4096 bits, p/q: 1024–2048 bits, canonical odd e: 3..2^32−1. Trusted prime generation is a prerequisite, not supplied by import. |
| Peer certificates | M1 explicit-anchor x509_chain.verify, supported P-256/RSA/PSS-only issuers, SAN-only DNS/IP and caller UTC time. A PSS-only leaf cannot authenticate RSAE CertificateVerify. Existing M1 rejections remain in force. |
| ALPN | http/1.1 only; never advertise h2/h3. Offered ALPN with no common protocol fails no_application_protocol; absent ALPN permits the HTTP/1.1 default. Reject unsolicited/wrong server selections. |
| SNI | Client sends one DNS HostName for a DNS identity; server validates and exposes it on the accepted connection. The current caller supplies its credential before accept; dynamic selection callbacks are deferred. Reject empty/duplicate host_name, NUL and IP literals. Verify DNS/IP identity independently. |

The M4a HTTP Bend server has the following target/credential support boundary
(both suites above). This is a server-adapter latency restriction, not a change
to the crypto correctness profile or peer certificate verification.

| Bend HTTPS server target | P-256 ECDSA credential | RSA credential |
|---|---|---|
| Native | Supported, live-gated | Supported, live-gated |
| Bun | Supported, live-gated | Unsupported; rejected at startup before listen |

Bun RSA repeated-handshake maxima measured in round 3 were **969.9 ms AES /
730.7 ms ChaCha**, compared with native **about 46 ms**, against the unchanged
**1000 ms** handshake deadline. Bun RSA live positive/negative phases are
excluded from M4a acceptance by user decision; RSA crypto unit/differential
suites remain unchanged on both targets. The cancelled optimization patch is
preserved, unapplied, for possible later work at
`~/.codex/artifacts/grounds/2026-10-23/m4a/round4/cancelled-rsa-wip.patch`.

AES-256/SHA-384, X448, EdDSA and FFDHE are outside the profile. Unknown
well-formed offers follow context-specific RFC extensibility rules; never
advertise or select an absent algorithm.

PSK/external PSK, resumption and 0-RTT are unsupported and unadvertised.
Do not send pre_shared_key, psk_key_exchange_modes or early_data, or issue
tickets. Require a certificate/ECDHE path; ignore unused offers where the RFC
permits, while enforcing extension framing/order. Reject unsolicited PSK
selection. Silently discard authenticated NewSessionTicket; never cache/resume
it. Reject unsolicited early application data and out-of-state EndOfEarlyData.

Client certificates and post-handshake authentication are unsupported and
unadvertised. The server never requests client authentication. A client handles
a legal main-handshake CertificateRequest with an empty Certificate and no
CertificateVerify; a server requiring authentication may reject it.
Post-handshake CertificateRequest without post_handshake_auth fails
unexpected_message. Client-role signature helpers exist for domain-separation
tests, not permission to advertise client authentication.

## Operation-to-implementation matrix

“Existing” means a component exists, not a composed socket handshake. Tests
below apply to native and Bun; exact results are recorded in STACK_PROGRESS.
M3a/M3b supply both socket roles below; HTTP integration remains M4.

| Operation | Status / Bend owner | Evidence / remaining obligation |
|---|---|---|
| Host randomness | Existing: wire.wire_random_bytes, OS-only random effects | random_check.py/random_host_check.c: bounds, errors, octets, zero draws. |
| Ephemeral generation/retirement | Existing: wire/tls_key_share.bend generate/from_random/shared/retire | tls_key_share_check.py and affine checks; 32 bytes/X25519 draw; P-256 rejects 0 or >=n, 32 bytes/attempt, max 16 attempts. |
| X25519 ECDH/validation | Existing: crypto/x25519.bend shared | RFC 7748/x25519_check.py; full-scan all-zero rejection. |
| P-256 ECDH/validation | Existing: crypto/p256.bend | NIST/SEC1/p256_check.py; canonical on-curve non-infinity peer, cofactor one; scalar 1..n−1. |
| PEM/private import/leaf binding | Existing: crypto/pem.bend, private_key.bend, credential.bend | private_key_check.py: independent synthetic DER/PEM, malformed/encrypted/mismatch cases. |
| RSA-PSS private signature | Existing: crypto/rsa_private.bend validate/sign_digest | rsa_private_check.py: RFC 8017/Python cryptography oracle and existing Bend verifier; CRT/base blinding/public fault check. Synthetic-only runtime. |
| ECDSA private signature | Existing: crypto/ecdsa_scheme256.bend/ecdsa_sign256.bend | RFC 6979/NIST/ecdsa_check.py, nonce rejection; retry timing explicitly dispositioned. |
| CertificateVerify role/content/signature | Existing: wire/tls_certificate_verify.bend | tls_certificate_verify_check.py: RFC 8448 content/transcript where applicable, independent signature checks, role/hash mutations. verify binds selected scheme to authenticated SPKI. |
| Transcript/HRR rewrite | Existing: wire/tls_transcript.bend/crypto/sha256_stream.bend | RFC 8448 1-RTT/retry, exact encodings/snapshots, message_hash replacement, affine checks. |
| No-PSK HKDF schedule | Existing: wire/tls_schedule.bend | RFC 8448/independent Python HKDF, directional handshake/application owners. M3 supplies validated shared input and ordered snapshots. |
| Finished | Existing: wire/tls_schedule.bend finished/verify_finished | 798 independent schedule outputs, mutations, single-use Finished key, full-width comparison. M3 gates delivery on verification. |
| Certificate authentication | Existing: crypto/x509_chain.bend verify | M1: 193 complete-chain cases/target, 55 accepted/138 rejected, independent full-chain oracle. |
| Protected record encrypt/decrypt | Existing: wire/tls_record.bend/crypto/traffic.bend | RFC 8448 AES records, independent AES/ChaCha fixtures, tag-before-release, malformed-input retirement. |
| Sequence/usage/KeyUpdate derivation | Existing: crypto/traffic.bend | 70 ChaCha + 72 AES lifecycle scenarios/target; counter exhaustion, 2^24 AES sending cap, 2^48−1 sending updates; receiving has no sending caps. |
| Handshake reassembly | Existing: wire/tls_handshake_stream.bend | 939 independent cases/target, fragmented/coalesced RFC flights, 1 MiB bound, consumed errors. |
| Extension framing | Existing: wire/tls_extensions.bend | 1,756 ordinary + 10 stress cases/target. Context, required fields and body semantics remain M3. |
| Hello field framing | Existing: wire/tls_hello.bend parse/is_retry | tls_hello_check.py: 2,986 ordinary + seven stress cases/target, now integrated into the native/Bun wire and root manifests. |
| Hello negotiation/HRR | Client: wire/tls_client.bend; server: tls_server_handshake.bend + bend_tls_server.bend | Both suites/groups/CV schemes; client fresh P-256 replacement/cookie-only retry; server policy preferences, stateful exact-echo random cookie, immutable CH2 checks, message_hash rewrite, one retry. Legacy offers without supported_versions reject70. |
| EE/Certificate/CV/Finished codecs/order | wire/tls_handshake_codec.bend + tls_client.bend + tls_server_flight.bend | Bounded codecs and exact transcripts; client x509_chain.verify then CV/Finished; server credential.import_pem and context-bound ECDSA/RSA-PSS CV then client Finished verification. No server CR/tickets. |
| Application epochs/KeyUpdate ordering | wire/bend_tls_client.bend + bend_tls_server.bend + traffic/schedule/record owners | Authentication gates both connection owners; old-key KU before rekey; update_requested response; reserve old-key record before sending cap; enforce epoch record boundaries. |
| TCP/alerts/close/deadlines/cancellation | Both connection APIs; asynchronous cancellation remains missing | Exact bounded record reads, actual 3-byte TCP writes/coalescing, partial writes, fatal cleanup/alerts, warning close_notify, EOF/truncation, absolute monotonic deadlines and retained-process descriptor checks. |
| Unsupported post-handshake disposal | wire/tls_handshake_codec.bend + role-aware bend_tls_client.bend receive loop | Client parses/discards authenticated NST; server sends none and rejects client NST10. No resumption/0-RTT/client auth; unsolicited PHA rejected10. |
| No-delegation live evidence | bend_tls_no_delegation_build.py + bend_tls_no_openssl_check.py + complete interop corpus | Both roles built with legacy TLS and cookie effects replaced by aborts; native/Bun positive controls prove traps. Emitted C/JS effects/imports/calls, native symbols/libraries/loader literals audited. Invalid loader/host-CA paths are additional evidence only. |
| HTTP/HTTPS/WSS/browser | M4a server adapter; M4b native client, WSS and verified Chrome HTTPS/WSS locally accepted. Comparative native performance is recorded; fresh full root acceptance remains pending on host memory pressure. | Separate bend_server.bend and bend_client.bend/bend_pool.bend entry graphs; explicit client PEM anchors, URL-bound DNS/IP verification and trusted clock sample; affine WSS transport with Origin/auth/cookie_bend checks. Legacy entries retain their APIs/cold graphs and OpenSSL default. Native HTTP streaming/pool/SSE and independent Python/Go WSS, emitted C/native audits and abort controls: dated STACK_PROGRESS receipts. |

## Client connection behavior built in M3a

`wire/bend_tls_client.bend` is an affine connected-socket API: connect, send,
recv, key_update, deadline and close. Errors close the socket and return no
successor. The caller supplies DER anchors, DNS or raw IP identity, authenticated
Unicode assets, a wall-clock effect in civil UTC seconds since 0001-01-01 and
an absolute IO.now millisecond deadline. DNS identities supply SNI; raw IPs do
not. No ambient CA store or implicit wall clock enters certificate admission.

Order is CH → optional HRR/CH2 → SH → EE → optional CR → Certificate → CV →
server Finished → optional empty client Certificate → client Finished. Only
then can application operations obtain a connection. Legal compatibility CCS
never enters the transcript. Each encoded handshake is at most 1 MiB, with
512 KiB/16-entry chain bounds and 65,535 bytes per certificate. Receive/handshake
loops also have finite work budgets; deadlines are never implicitly renewed.

M3a evidence covers the client only. The exact RFC8448 replay deliberately
retains the frozen certificate and extension policies: published CH/SH keys and
hash match; exact EE rejects unoffered record_size_limit110. A separately
labelled modified-EE branch reaches and rejects the published RSA1024 cert42.
Neither branch claims complete RFC trace authentication. See wire/README.md
for the public API and dated STACK_PROGRESS.md reports for final gate counts.

| Client evidence | Native and Bun coverage |
|---|---|
| Codec / Hello | Every-byte truncation, lengths, extension contexts/duplicates, serializer round trips, maximum message/chain cases, RFC message fixtures. |
| Authentication and algorithms | OpenSSL 3 s_server: each of 2 suites × 2 groups × 2 CV schemes; every successful connection negotiates http/1.1; P-256 forces HRR. |
| Connection lifecycle | Main CR empty Certificate, DNS/IP, tickets, fragmented/coalesced records, both KeyUpdate directions, requested response and close_notify. |
| Rejection behavior | Wrong identity/trust/time; altered CV/Finished/tag; unsupported choices/schemes; malformed/context/duplicate/unsolicited messages; double HRR/order; truncation/EOF/deadline; early application/PHA; invalid KU and KU record boundaries. Matching local and peer-visible alerts where transport/deadline permits writing. |
| Owner / host boundary | Frontend copy/reuse rejection, cap-reservation/SNI diagnostics, emitted program/import/symbol audit and invalid compatibility-library/host-CA paths. |

## Server connection behavior built in M3b

`wire/bend_tls_server.bend` provides `from_pem`, `accept`, `send`, `recv`,
`key_update`, `deadline` and `close`. The PEM helper consumes leaf-first
certificate blocks and an unencrypted private key through M2 credential import.
The affine config owns this credential, DER intermediates, ordered suite/group
preferences, ALPN policy and an absolute monotonic deadline. A fresh owner is
required for each accept. SNI is validated and returned to the caller; the
credential is supplied before the handshake. Application ownership is delivered
only after verifying client Finished. No client certificate is requested.

Flow: CH → optional HRR/CH2 → SH → EE → Certificate → server CV → server
Finished → client Finished. HRR uses message_hash and a connection-local random
32-byte cookie with exact echo checking. This is stateful, not a stateless MAC.
CH2 keeps immutable fields/extensions, supplies exactly one requested share and
removes early_data; permitted padding and PSK age/binder/removal changes are
checked. PSK/modes/early_data framing is checked but no PSK or early data is
accepted. The server always authenticates with a certificate and sends no NST.
Absent ALPN sends no ALPN; an offered list without enabled http/1.1 fails 120.
CCS is accepted only after CH1 and before client Finished. Both roles retain
bounded work/record/message/chain limits and never renew deadlines implicitly.

RSA CV rejection-samples fresh full-width blinding candidates against the
public modulus before its one private signing attempt (maximum 32 draws), then
draws a fresh 32-byte salt. No reduction bias or private-operation rescue/retry.
ECDSA retains M2 deterministic signing. Neither changes the live-secret boundary.

| Server evidence | Native and Bun coverage |
|---|---|
| Negotiation / retry | 43 encoded CH cases and 16 HRR-invariant cases; eight affine frontend probes. Missing/unsupported version 70, no common suite/group/signature 40, malformed/duplicate framing 50, missing extensions 109, invalid shares/CH2/cookie 47, incompatible ALPN 120. |
| Independent authentication | OpenSSL3 s_client and Go crypto/tls client: every 2 suites × 2 groups × 2 server CV schemes, explicit synthetic CA/hostname verification and http/1.1. Python ssl: both server credential types with normal CA/hostname verification. HRR observed in both group directions. |
| Second server peer / self-peer | Go crypto/tls server against M3a client and Bend-to-Bend: all eight combinations each. Go server ChaCha rows disable AES hardware preference using GODEBUG=cpu.all=off; actual suite/group/ALPN are asserted. |
| Negative / lifecycle | 78 live server scenarios per target, including altered client Finished 51, bad record tag 20, forbidden message/CCS/boundary 10, malformed KU 47, peer alerts, actual 3-byte TCP writes/coalescing, 40,000-byte echo, both KU directions, close, EOF/truncation 50, deadline 80 and repeated failure/deadline descriptor/socket cleanup. Deadline expiry closes without promising an alert write. |
| No delegation | Both role executables use unchanged Bend/OS byte/RNG sources with legacy TLS/cookie effects removed and replaced by abort/throw stubs. All independent interop runs use these builds; deliberate native/Bun probes hit each trap. Generated C/JS and native symbol/library/loader audit is a permanent phase. |

## Key lifecycle and runtime boundary

Each connection draws fresh ephemeral material from the host RNG effect;
M3's Hello randoms are separate 32-byte draws. P-256 uses rejection sampling,
never modulo reduction or deterministic RNG fallback. ECDSA uses RFC 6979,
including verified erratum 3812's s=0 rejection. RSA-PSS needs 32 fresh salt
bytes plus k uniform blinding candidate bytes per attempt; rejected candidates
consume the owner and emit no signature. Sign helpers accept explicit entropy;
M3 must obtain it via wire_random_bytes.

Record counters are directional/epoch-owned, start at zero and never wrap.
ChaCha reaches its sequence limit before its full-record usage bound. AES sends
at most 2^24 records/epoch, below §5.5's 2^24.5; reserve an old-key record for
KeyUpdate before exhaustion. Sending updates stop at 2^48−1; receiving owners
do not enforce sending caps. Invalid seal/authentication/exhaustion errors
retire traffic owners; Finished and signing errors consume their stages.
UpdateLimit is a recoverable refusal retaining the old traffic epoch: M3 must
close it explicitly if the connection decision is fatal.

See [crypto/RUNTIME_REVIEW.md](crypto/RUNTIME_REVIEW.md) for the exact secret
storage/retirement contract and every disposition. Affine wrappers prevent
ordinary logical copies/reuse, not physical wiping of inner lists, allocator,
GC/JIT, stack/register or OS copies; visible constructors can bypass discipline.
M2 may close for synthetic-key component interoperability when every finding
has a disposition. **Live-secret use stays blocked**, and M3/M4 stay open.
Passing vectors and timing samples cannot establish constant-time execution.

## M3b focused acceptance and root boundary

The final source-bound focused run (`m3b/wire-04`) passes **230/230 phases**,
zero skipped or unexecuted, with the unchanged 4 GiB aggregate/process and
120-second phase limits. Native and Bun each pass 43 negotiation +16 retry
cases, 158 live scenarios (93 ordinary negatives) and 18 repeated cleanup
attempts. The eight suite/group/server-signature combinations pass for all five
peer/role pairings: OpenSSL server, OpenSSL client, Go server, Go client and
Bend-to-Bend. Python additionally verifies both credential types normally
against the synthetic CA/localhost identity. Both role programs run with legacy
TLS/cookie effects unavailable; trap controls and C/JS/import/symbol audits pass.

**Fresh full root acceptance is pending because of shared-host memory pressure.**
All partial and scheduling-blocked attempts remain inspectable under
`~/.codex/artifacts/grounds/2026-10-23/m3b/`. The M3 checklist remains open until
that gate completes; M4 is not started. Synthetic-key scope and every existing
live-secret runtime/erasure blocker remain in force.
