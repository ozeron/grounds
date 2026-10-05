# Full Bend stack completion contract

Active goal (2026-10-05): complete native/Bun Bend HTTPS/WSS first. Defer new
RTC work until HTTPS acceptance, preserving existing RTC code and checks.
The broader roadmap remains the complete native, browser-interoperable Grounds
stack across wire, crypto, TLS/DTLS, HTTP signaling and RTC. Completing the
active HTTP goal does not complete that broader contract. Current capability and test evidence belong in
[STACK_PROGRESS.md](STACK_PROGRESS.md); this file defines the remaining work,
execution order and final acceptance gates.

## Boundaries

- Grounds packet formats, cryptography, handshakes and protocol state machines
  run in Bend. C/JS provide OS and device effects only. Existing OpenSSL-backed
  paths may remain for API compatibility, but cannot satisfy the new Bend path.
- Browser built-in networking/WebRTC and independent implementations are peers
  and test references, not implementations of the Grounds protocol logic.
- Preserve existing APIs and meaningful checks. Leave unrelated changes and
  `bounty/` untouched; never stage `bounty/`.
- Make bounded, reviewable milestone commits with package documentation and
  ledger updates. No push, deploy, publish or external messages without a new
  explicit user request. Use local synthetic credentials and media fixtures.
- Run heavy work sequentially under the memory/pressure guard. The user's
  2026-10-05 RAM instruction sets the current aggregate/process limit to
  4 GiB (4096 MiB), replacing the previous 1 GiB limit. Retain the
  pressure check and current 120-second per-job timeout.
- After two failed attempts on the same bug, consult an Astra subagent at low
  reasoning effort before another attempt, as requested on 2026-10-03.
- Check current RFCs and verified errata before implementation. Document supported
  protocol versions, cipher suites, codecs, optional features and limitations;
  do not label an unsupported feature as passing or omit a required gate.

## Acceptance checklist

All boxes require current, inspectable implementation and verification evidence.

### Wire

- [ ] Supply TCP/UDP byte transport for the stack on native and Bun, including
  IPv4/IPv6 addressing, bulk host RNG bytes and monotonic deadlines.
- [ ] Verify byte preservation, empty and oversized datagrams, partial/fragmented
  stream I/O, timeouts, cancellation and socket/resource cleanup.
- [ ] Measure byte-storage and transport throughput against a recorded baseline;
  choose and document representations from actual measurements.

### Crypto

- [ ] Implement in Bend all hashes, HMAC/KDF, AEAD, key agreement and signatures
  needed by the selected interoperable TLS, DTLS, SRTP and application paths.
- [ ] Pass published vectors and independent differential tests on native and
  Bun, including invalid inputs, tampering and nonce/counter/key-lifecycle cases.
- [ ] Review generated-code timing behavior and secret-dependent control/memory
  operations. Record evidence and resolve findings before live-secret use;
  passing vectors or timing samples alone do not prove constant-time execution.
- [ ] Integrate Bend cryptography into cookie signing and the new secure stack;
  verify these paths do not silently invoke OpenSSL cryptography.

### TLS and DTLS

- [ ] Implement Bend TLS 1.3 handshake, records, key schedule, certificate parsing,
  signature/chain/trust/hostname verification and orderly/error shutdown.
- [ ] Verify native and Bun client/server interop with independent implementations,
  including bad signatures, untrusted/expired certificates, hostname mismatches,
  malformed records, fragmentation and authentication failure.
- [ ] Implement the browser-compatible DTLS version(s) and extensions needed for
  RTC, including retransmissions, flight fragmentation/reassembly, replay defense,
  fingerprint binding, key export and interoperable SRTP negotiation.
- [ ] Prove the new end-to-end paths use Bend TLS/DTLS and Bend cryptography;
  OpenSSL TLS effects and WebRTC library delegation cannot satisfy these gates.

### HTTP and signaling

- [ ] Preserve HTTP/1.1 and WebSocket behavior while integrating Bend TLS and
  Bend cookie/HMAC signing.
- [ ] Build authenticated signaling with Origin policy, session/credential binding,
  SDP/candidate exchange, ICE restart/lifecycle handling and bounded cleanup.
- [ ] Verify signaling and HTTPS/WSS in a real browser, including denied origins,
  failed authentication, reconnects and malformed signaling messages.

### RTC

- [ ] Complete ICE transactions, pacing/retransmission, candidate gathering and
  pair/checklist state, triggered checks, role conflicts, nomination, consent,
  RFC 8863 PAC failure timing,
  restart and failure/cleanup behavior. Preserve the completed STUN milestone.
- [ ] Add IPv6 and TURN authentication/allocation/permissions/channel/refresh
  behavior; demonstrate a relay path as well as direct connectivity.
- [ ] Integrate fingerprint-bound DTLS, SCTP and WebRTC data channels; verify
  messages in both directions, ordering/reliability modes, fragmentation,
  flow control and close/error behavior with a real browser.
- [ ] Implement RTP/RTCP and SRTP/SRTCP, packetization, replay/authentication checks,
  feedback and media timing, with the codec support needed for real audio/video
  exchange. Verify browser decode/playback and the native receive path using
  reproducible media fixtures; a data-channel echo does not satisfy media interop.
- [ ] Demonstrate direct and relayed browser sessions covering signaling, ICE,
  DTLS, data and media together, including representative loss/reordering,
  reconnect/restart, tampering and resource cleanup. Use actual rendered/decoded
  output and captured/logged protocol evidence, not just connection-state flags.

## Current priority and scope decision (2026-10-05)

The next end-to-end milestone is authenticated HTTP/1.1 over Bend TLS 1.3,
followed by browser HTTPS/WSS. Sequence new work around that dependency path.
The existing nineteen full-stack requirements above remain the overall contract;
none is completed or removed by this planning update. These broader gates are
not all exit requirements for the active HTTPS goal; M0-M4 define its exit.

User decision: defer RTC expansion until HTTPS works. Preserve existing RTC
code/checks; do not build new DTLS, SCTP, TURN or media features for this goal.
Do not delete media or relay requirements: they remain follow-on roadmap work.
Fix RTC regressions caused by shared changes, but do not require new direct/relay
data-and-media acceptance to complete the active HTTPS goal.

## Build decomposition

Each work item is a bounded implementation/review unit, not a claim of completion.
Record its source revision, compiler/runtime, exact command, complete versus
partial coverage, report paths and remaining failures in STACK_PROGRESS.md.

### M0 — Reproducible current baseline

- [ ] Inspect and finish or isolate the existing uncommitted RSA check-phase
  changes without discarding user work. Preserve the full corpus and explicit
  phase accounting; splitting phases must not conceal missing cases.
- [ ] Obtain a complete fresh crypto gate on the selected supported compiler.
  The isolated 2.0.34 354-phase pass predates current additions and cannot stand
  in for current-tree acceptance. Resolve primary 2.0.27 failures or qualify a
  compiler migration through actual consumers before changing the pin.
- [ ] Resolve HTTP consumer compatibility while preserving meaningful equality
  proofs; verify wire, HTTP and crypto together. Distinguish missing phases,
  compiler errors, resource cutoffs and protocol assertion failures.
- [ ] Make the complete root gate executable under sequential declared phases,
  existing memory limits and per-phase deadlines. Do not extend a whole-job
  deadline or accept a cached/partial run as complete acceptance.

Exit: a reproducible supported toolchain and fresh baseline report identifying
all passes and remaining blockers. A failed baseline is useful evidence, but M0
is not complete while required checks fail or remain unexecuted.

### M1 — Composed certificate authentication

- [ ] Build OID-bound attribute equality on x509_name_text/x509_name_prepare;
  compare RDNs as multiplicity-preserving multisets and Names in sequence order.
  Cover cross-encoding equality, order, duplicates and unsupported attributes.
- [ ] Bind child issuer to parent subject and exact signed certificate bytes;
  compose signature verification, CA/basic constraints, path length and key usage.
- [ ] Compose explicit trust anchors, bounded path processing, supported critical
  extensions/name constraints and cycle/depth rejection. Unsupported critical
  semantics must reject explicitly rather than be treated as validated.
- [ ] Compose TLS purpose, DNS/IP identity and trusted wall-clock validity into
  one auditable verification result with explicit failure reasons. Monotonic
  deadlines are not a substitute for certificate-validity wall-clock input.
- [ ] Differential-test complete accepted/rejected chains using local synthetic
  fixtures, including wrong issuer, trust, time, hostname and signature cases.

Exit: one caller-facing certificate authentication operation on native and Bun,
with independent full-chain evidence; parser and Unicode counts alone cannot pass.

### M2 — TLS profile and private-key/runtime readiness

Selected target and protocol-to-source/evidence matrix: [TLS_PROFILE.md](TLS_PROFILE.md).
The profile is a build decision; M2 stays open until implementation and review pass.

- [ ] Freeze a bounded TLS 1.3 interoperability profile: version, cipher suites,
  groups, signature schemes, certificate forms, ALPN and unsupported extensions.
  Check current standards and errata before implementing; explicitly document
  omissions such as resumption/0-RTT rather than silently accepting them.
- [ ] Map each selected handshake operation to existing Bend primitives; implement
  only missing operations required by that profile. Private RSA signing is a
  dependency only if the selected local signing profile requires it.
- [ ] Complete private-key ownership, RNG consumption, nonce/counter limits,
  failure cleanup and key-update lifecycle for the selected path.
- [ ] Review generated native/Bun code and runtime behavior for secret-dependent
  branches/memory access, duplication and erasure. Resolve findings before
  live-secret use; synthetic interoperability is not timing-safety evidence.

Exit: profile-to-implementation matrix, independent vectors/differential tests,
and an explicit disposition for each runtime/key-lifecycle finding.

### M3 — Live Bend TLS client and server

- [ ] Build bounded handshake message parsing/serialization and transcript state,
  negotiation, key exchange, TLS HKDF schedule and authenticated Finished checks.
- [ ] Integrate M1 certificate authentication and selected CertificateVerify
  signing/verification, binding the signatures to the correct transcript/context.
- [ ] Connect existing record/traffic owners to TCP with fragmented/coalesced I/O,
  strict handshake state transitions, alerts, orderly shutdown and deadlines.
- [ ] Exercise Bend client against an independent server and independent client
  against Bend server on native and Bun. Test malformed negotiation/messages,
  altered signatures/Finished/records, fragmentation and cleanup after failure.
- [ ] Prove the new path performs no OpenSSL cryptography or TLS operations:
  audit imports/effect boundaries and run with the compatibility TLS/crypto
  effects unavailable or instrumented to fail if invoked by the new path.

Exit: authenticated application bytes in both roles on both targets, independent
interop and negative-case reports, plus inspectable no-delegation evidence.

### M4 — HTTPS/WSS integration and HTTP migration acceptance

- [ ] Add explicit Bend transport selection to HTTP client/server without breaking
  existing APIs; keep legacy compatibility paths clearly distinguishable.
- [ ] Integrate Bend cookie signing/verification and runtime key ownership into
  the new path; preserve authentication and cookie behavior with regression tests.
- [ ] Verify real HTTP request/response and WebSocket traffic through Bend TLS,
  including streaming, reconnect, denied origins/authentication and cleanup.
- [ ] Run real-browser HTTPS/WSS with locally trusted synthetic certificate
  fixtures and normal verification enabled; do not bypass certificate checks.
- [ ] Run full fresh repository acceptance and audit the HTTP milestone against
  actual source/artifacts. Record supported profile, performance baseline,
  limitations and remaining full-stack requirements.

Exit: an independently verified HTTP/HTTPS/WSS path whose protocol and crypto
logic run in Bend on native and Bun. This completes the HTTP migration milestone,
not the full nineteen-gate RTC/media contract unless the user revises its scope.

## Execution order and continuation

1. Establish M0 acceptance and preserve the current dirty work.
2. Finish M1 certificate composition and M2 profile/key/runtime readiness.
   Use the profile to prevent unrelated algorithm or certificate feature expansion.
3. Implement M3 as one live client/server TLS path, then integrate M4 HTTPS/WSS.
4. Complete the active HTTPS goal after M0-M4 evidence is accepted. Report RTC
   as deferred, not complete; existing RTC regressions remain protected.
5. If the original full-stack goal is retained, complete gathering/IPv6/TURN,
   DTLS/SCTP data channels, then SRTP/RTP/RTCP/codecs and direct/relay media
   acceptance. Audit all nineteen original gates before full-goal completion.

Adjust the order when dependency evidence warrants it, while retaining every
acceptance requirement. After each bounded change, run focused tests, inspect
failures, correct the cause and update the progress ledger. Record the exact next
action, commands, target/version, fresh versus cached results, artifacts and open
limitations so another turn can continue without reconstructing the work.

After two failed attempts on the same bug, consult an Astra subagent at low
reasoning before another attempt. Preserve both failures and give the reviewer
the exact source, resource reports and current hypothesis. Keep heavy jobs
sequential under the current 4 GiB aggregate/individual sampled cutoffs,
system-pressure checks and 120-second phase deadlines; never raise them to
force a passing result.

Use `PYTHONDONTWRITEBYTECODE=1 moon run <package>:check --force` for changed
packages and `PYTHONDONTWRITEBYTECODE=1 moon run :check` at milestones. The active HTTPS final
gate is `PYTHONDONTWRITEBYTECODE=1 moon run :check --force` under the sequential
resource/phase guard, plus fresh independent native/Bun TLS client/server and
real-browser HTTPS/WSS runs. The later full-stack final gate additionally needs
fresh integrated direct/relay data-and-media runs. Optional unrelated checks may be
reported as skipped; a missing target, browser or required acceptance test leaves
the full goal incomplete.

For an external/input blocker, record the exact failure, attempts and required
unlock, then continue independent work. Follow the runtime's repeated-blocker
rules before marking blocked. Never mark the full goal complete from a local
slice, protocol vector, mocked peer, cached report, exhausted budget or elapsed
time.
