# Full Bend stack completion contract

Build the complete native, browser-interoperable Grounds stack across wire,
crypto, TLS/DTLS, HTTP signaling and RTC. Completion of a milestone does not
complete this contract. Current capability and test evidence belong in
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
  2026-10-03 RAM instruction sets the current aggregate/process limit to
  1 GiB (1024 MiB), replacing the previous 128/384 MiB limits. Retain the
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

## Execution order and continuation

1. Complete ICE transaction retries and retained-socket operation, then candidate
   pairs, triggered checks, role conflicts and nomination. Establish a real-browser
   ICE evaluator and local authenticated signaling as soon as useful.
2. Complete required crypto and generated-code review, byte/RNG foundations, and
   interoperable Bend TLS/DTLS. Integrate the secure HTTP/signaling path.
3. Complete IPv6/TURN and browser DTLS/data channels. Keep direct and relay
   integration tests reproducible with local fixtures.
4. Complete media protocols and codec support, then exercise browser/native audio
   and video through the integrated stack under normal and adverse conditions.
5. Audit every checklist item against current source, fresh tests and artifacts;
   remove abandoned scaffolding, finish docs, run the full fresh repository gate
   and commit the verified final state.

Adjust the order when dependency evidence warrants it, while retaining every
acceptance requirement. After each bounded change, run focused tests, inspect
failures, correct the cause and update the progress ledger. Record the exact next
action, commands, target/version, fresh versus cached results, artifacts and open
limitations so another turn can continue without reconstructing the work.

Use `PYTHONDONTWRITEBYTECODE=1 moon run <package>:check --force` for changed
packages and `PYTHONDONTWRITEBYTECODE=1 moon run :check` at milestones. The final
gate is `PYTHONDONTWRITEBYTECODE=1 moon run :check --force` plus fresh real-browser
integrated direct/relay data-and-media runs. Optional unrelated checks may be
reported as skipped; a missing target, browser or required acceptance test leaves
the full goal incomplete.

For an external/input blocker, record the exact failure, attempts and required
unlock, then continue independent work. Follow the runtime's repeated-blocker
rules before marking blocked. Never mark the full goal complete from a local
slice, protocol vector, mocked peer, cached report, exhausted budget or elapsed
time.
