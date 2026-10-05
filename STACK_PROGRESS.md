# Full Bend stack progress

Target: a native, browser-interoperable network stack with crypto, TLS/DTLS and RTC protocols authored in Bend. C/JS should only implement OS and device effects. `bounty/` is unrelated and must never be staged.

The full completion checklist and continuation order are in [STACK_PLAN.md](STACK_PLAN.md). Completed RTC milestones do not complete the five-layer stack.

| Layer | Current state | Next proof of progress |
|---|---|---|
| `wire` | Byte TCP and IPv4 UDP effects, explicit local-IP binding and OS bound-address/ephemeral-port discovery; OpenSSL TLS effects. UDP handles all octets, zero datagrams, timeout and oversize errors, with same-port/two-IP isolation and failed-bind descriptor checks. Actual SIGTERM/SIGINT stop parked native/Bun loops and release the listener; Bun uses an OS-only C11 atomic signal bridge because its synchronous runtime cannot dispatch JS signal callbacks. Bounded bulk host RNG bytes now pass native/Bun guard/error tests and supply signaling credentials. Public-pattern byte/RNG and retained UDP measurements are recorded; Bend Base supplies monotonic `IO.now`. | Verify IPv6/cancellation and packed storage/long-session allocation, retaining measured baselines; complete crypto/runtime review before secure transport. |
| `crypto` | Bend SHA-1 for WebSocket challenge, HMAC-SHA1 for legacy STUN integrity, SHA-256, HMAC-SHA256, HKDF-SHA-256, ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD, AES-128 encryption, AES-128-GCM and X25519; P-256 prime/order arithmetic, uncompressed-point ECDH, experimental P-256/SHA-256 raw/DER ECDSA, SHA-256 RSA PSS/v1.5 encoding, variable-size public modular exponentiation/RSAVP1 and full digest-signature verification (725 arithmetic and 774 signature cases pass on native and Bun; in-place limb shift reduces array creation), bounded DER, SHA-256 certificate AlgorithmIdentifier admission, RSA/P-256 SPKI public-key decoding, certificate field framing preserving exact signed bytes, mathematical issuer-signature verification (4,825 native/Bun cases) and strict civil-time/validity checks (31,545 cases per target using scoped official Bend 2.0.34), canonical OID/extension envelope admission (67,731 native/baseline-JIT Bun cases), BC/KU payload consistency and EKU/TLS-purpose permission (14,565 independent EKU cases on pinned/modern native/Bun; 28,044 whole-policy cases per modern target; selected DNS/IP SAN and empty-subject critical-SAN binding add 1,841 standalone cases per modern target), plus DNS/IP identity matching and actual SAN-field queries (5,900 core cases per pinned/modern native/Bun target; 2,447 further framing/certificate cases per modern target), plus typed Name/RDN/attribute schema and actual issuer/subject queries (11,195 independent cases per modern native/Bun target), now composed into extension/TLS-purpose admission with nonempty issuer and CA/CRL-subject requirements (28,319 whole-policy cases per modern target), plus composed Unicode 3.2 stored-value preparation (97,731 exact and folded cases per pinned/modern native/Bun target, with folded full-input stress), and exact Unicode 3.2 NFKC with authenticated packed tables (84,960 official sequence checks, 1,050 differential cases and 1,122,304 scalar checks per pinned/modern native/Bun target, with full-byte-bound expansion/ordering stress), plus TLS HKDF labels and distinct affine ChaCha/AES-GCM traffic owners with 64-bit nonces/key updates and AES sending usage limits. Poly1305 products now stay below 2^26; Legacy cookie signing and live TLS retain OpenSSL; explicit Bend HTTP cookie signing/verification passes synthetic-key native/Bun checks. | Strict UTF8/Printable/IA5/Universal/BMP transcoding passes 9,321 cases per pinned native/Bun target; composed supported-attribute stored preparation passes 18,996 per target. OID-bound Name/RDN comparison now passes all 33,037 independent cases on native/Bun; compose exact-DER issuer binding and resolve the standalone folding module's pinned Bun large-list limit and Teletex interpretation and known extension/critical policies, constraints/trust/hostname, trusted-clock composition and TLS schemes; finish current ECDSA/package/compiler compatibility verification and runtime/erasure review, implement private RSA owners, then cookie and full handshake integration. |
| `tls` | Bend protected TLS 1.3 ChaCha20-Poly1305 and AES-128-GCM records and traffic/key lifecycle pass synthetic native/Bun differential tests; AES also reproduces RFC 8448 encrypted records. Bend streaming transcript ownership, retry rewriting and snapshot/size/invalid-input checks now pass native/Bun and complete wire package acceptance. Typed no-PSK SHA-256 handshake/application derivation and one-use Finished keys now pass 798 independent outputs per native/Bun target and the fresh nine-phase wire gate. Bounded handshake-record reassembly passes 939 independent scenarios per native/Bun target and the fresh eleven-phase wire gate. Live TLS client/server still use OpenSSL C effects; JS TLS effects return `ENOSYS`. | Complete mandatory TLS algorithms, handshake/transcripts, certificates/signatures/trust/hostname checks and real client/server interop; DTLS 1.2 for RTC. |
| `http` | Bend HTTP/1.1 client/server, routing, JSON, cookies, auth, CORS, multipart, SSE, and server WebSocket handshake/framing/session. Native echo interops with a third-party Python client and Bun's WebSocket API. The HTTP server accepts immutable runtime handler context. The bounded signaling fixture now binds a Bend HMAC-SHA256 cookie to an exact purpose/session/issuing deadline before upgrade/UDP allocation. Its pure admission policy passes native/Bun tests; Bun live signing, denials, restart/reconnect and actual expiry/UDP cleanup pass. Fresh HTTP server package acceptance passes all thirteen resource phases under 1 GiB with no skips. Earlier unsigned-cookie native/Chrome interop remains historical evidence. | Native signed-cookie signaling/ICE now passes the full headless-shell browser scenario and independent packet checks. Complete RTC/root gates and full Chrome startup acceptance; resolve key lifecycle/runtime review and integrate Bend TLS for browser HTTPS/WSS. |
| `rtc` | Bend STUN parsing, IPv4 XOR-MAPPED-ADDRESS, SHA-1/SHA-256/dual integrity, FINGERPRINT, authenticated incoming/outgoing ICE Binding exchanges, retained-socket retransmissions and explicit error/integrity outcomes. IPv4 candidate/pair priorities, bounded checklist formation, stable transport references and guarded state transitions, role-driven priority reordering, a paced shared-socket transaction engine with response-only interruption, protected incoming replies and server-side role decisions, FIFO triggered queues, ordinary round-robin/foundation scheduling and generation/sent-role attempt ownership. A bounded session now binds signaled credentials, registered receiving/sending bases, observed peer-reflexive candidates, deferred incoming work, retained attempts and endpoint integrity policies. Authenticated non-symmetric responses fail only their original current pair; interrupted old listeners retire independently. The live owner fixture explicitly binds unicast IPv4 bases and queries actual local ports before candidate formation. An additive valid-list owner resolves authenticated mappings, learns locally peer-reflexive candidates from retained signed-request priority, allocates IP-keyed foundations, reranks by role and keeps late paths separate from replacement flights. A nomination-evidence owner associates current successful checks with their valid paths and retains qualified incoming intent through materialization, exact triggered flights and response-only listeners; already-Succeeded counterparts resolve their actual generating record. A generation lifecycle owner now applies regular controlling/controlled nomination, selects completed stream paths, removes nominated component checks while retaining response listeners, continues authenticated Binding service, and defers failure through PAC. An outer transport owner derives selected physical consent routes, serves authenticated consent-only Binding requests, shares actual-send pacing and recent transaction identity admission, gates logical application routes, and preserves sealed consent loss. Full/full credential restart rebuilds ICE state while retaining only selected old consent/server contexts until replacement selection. Bounded SDP/signaling now binds connection-owned credentials and the actual retained UDP base; real Chrome verifies direct selected pairs, fresh consent, restart and cleanup on native and Bun. Separate unauthenticated discovery remains available. | Complete crypto/runtime foundations and secure signaling, then gathering, IPv6/TURN, DTLS/SCTP and SRTP/media. |

## Evidence ledger

- 2026-10-05 (user-authorized 4 GiB limit; verification retry):
  User explicitly requests "let's go please set 4gb limit", superseding the
  preceding 1 GiB restriction. `tools/build_guard.py` defaults now enforce
  4096 MiB aggregate and per process. STACK_PLAN.md and current command guidance
  reflect 4 GiB; historical report limits remain intact. The 120-second job/phase
  deadlines, sequential lock, pressure refusal and all required cases remain.
  The older goal objective text's 1 GiB clause is superseded by this direct user
  instruction; the exposed goal-status API cannot edit its objective or resume
  its blocked status, so the authoritative current bound is this user decision
  and STACK_PLAN.md. Authorized work resumes without changing completion scope.

  A controlled small-process configuration check verifies both actual default
  limits are 4,294,967,296 bytes and timeout 120 seconds. Only that unit check
  substitutes a normal pressure observation; all real build commands use the
  unmodified OS observer. Three existing pressure-regression tests pass in
  3.501s, covering pre-launch refusal, owned-child cleanup during warning/critical
  pressure and pressure-read failure. Evidence is under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-05/guard-4g/`.

  The preserved Hello verification is retried with explicit 4096 MiB limits in
  `2026-10-05/hello-4g-v1/`. Its first frontend attempt is refused before launch
  (exit 125, zero owned peak) because macOS remains at warning pressure. That
  actual report confirms the new limit is used; it does not claim a frontend
  pass. No background wait or compiler job remains running. Increasing the job
  budget does not override the separate system-pressure safeguard. Next: when
  pressure is normal, use a fresh report directory to run Hello focused tests,
  integrate its package phases after they pass, and finish current crypto/root
  acceptance under the authorized 4 GiB guards. All M0-M4 requirements remain;
  RTC is deferred and bounty untouched.

- 2026-10-05 (issuer verification pressure wait ended; CA path draft prepared):
  This full-stack continuation revalidated issuer attempts v10/v11 as terminal
  exit 125, system-memory-pressure-before-launch, zero owned memory. The older
  issuer runtime handle 48487 and P-256 guard PID 2587 are terminal; their earlier
  live observations below are historical. No complete issuer Bun acceptance is
  claimed. The original full-stack goal remains active and retains all 19 gates.

  A single lightweight pressure queue, PID 32696/session 86637, sampled pressure
  every five seconds for up to 600 seconds, requiring sixty seconds of normal
  samples before entering the unchanged shared build queue/guard. It expires
  exit 125 with every recorded sample warning; no compiler/evaluator is launched.
  A final process inspection confirms no build_guard or stable_queue remains.
  Its sample history is `2026-10-04/name-comparison/issuer-bun-all-v12-phased-pressure-wait.json`.
  The 1024 MiB aggregate/individual caps and 120-second phase limits are unchanged.
  These are explicit limits in this full-stack thread's isolated runner, not
  the shared repository defaults: another session's c6c3820 changes those defaults
  to 4096 MiB. This thread's retained commands continue to pass explicit 1024 MiB
  caps; its observed pressure stop and pending verification are unchanged.

  Independent light work prepares isolated `x509_ca_path.bend`, its CLI, fourteen
  closed frontend declarations and checker. The draft implements RFC 5280
  6.1.4(k)-(n) CA/keyCertSign admission and decreasing path limits, using prepared
  issuer/subject Name equality for self-issued status. Every intermediate spends
  a bounded slot; only non-self-issued intermediates decrement pathLen before
  applying their own limit. Arbitrary-size admitted INTEGERs clamp without
  truncation; extension admission remains in the result for later policies.
  It selects v3 intermediates and rejects v1/v2 without out-of-band CA authority.

  The independent Python fixture/oracle preparation completes 3,660 cases in
  0.307s, with all key-usage bit combinations, state/limit bounds, rollover,
  large integers, prepared Names, malformed/absent payloads, retained opaque
  noncritical extensions and every certificate truncation. Encoded corpus SHA
  is `479bdd5ff4f9843e7d21529f3ab9e988368978c9a906b5a19509e935b7f7b54e`.
  Astra LOW reviews the source read-only; two repeated affine U32/Bool uses are
  corrected. This is oracle/source-review evidence only: no CA Bend frontend,
  native/Bun runtime or full-path acceptance is claimed, and no draft is promoted.

  Exact sources, hashes and review scope are retained under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-04/name-comparison/`, including
  `ca-path-draft-v1-binding.json` and `ca-path-oracle-v1.json`. Static AST equality
  confirms issuer expected/cases/encoding functions are unchanged by final phase
  reporting (`issuer-final-oracle-binding-v12.json`). Next on genuine normal
  pressure: a new complete 33-phase issuer Bun attempt and final native checker;
  then guarded CA frontend/build/native/Bun checks before integration. Signature,
  anchor trust, time, revocation, name/policy constraints, TLS purpose and identity
  still require full composition. Crypto/root gates and HTTPS/RTC remain open.

- 2026-10-05 (blocked audit: persistent external memory pressure):
  The previous turn made draft/oracle progress. This turn re-polled session 2842
  and PID 33122, confirming the exact Hello queue was still waiting and macOS
  pressure still warning (flag 2). This is the third consecutive goal turn with
  the same external pressure condition: the complete crypto gate stopped, Hello
  draft verification remained prohibited, and the current guard prerequisites
  remain unsatisfied. Required compiled/full-package evidence cannot advance
  without an external return to stable normal pressure. More unverified code
  would not resolve the current acceptance dependency.

  Before stopping the queue, verified its exact command, absence of children,
  absence of any frontend resource report, and current warning pressure. Sent
  SIGTERM only to that idle owned Python queue; session 2842 is terminal exit
  143. No compiler/evaluator or unrelated process was stopped. The reason and
  observed state are saved in `2026-10-05/hello-v1/queue-stop.json`. No automatic
  verification job remains queued by this thread. All four Hello drafts, the
  oracle preparation evidence and pending crypto partition are preserved;
  no unverified implementation is staged or committed.

  Goal status is to be set blocked, not complete or paused. Unlock: stable
  normal macOS memory pressure with capacity for the existing 1 GiB guarded
  jobs. On explicit resume, revalidate current pressure/processes/source hashes,
  restart the preserved Hello focused runner only if its artifact report paths
  are still unused, then address actual failures and complete the full wire
  gate. Restore complete crypto/root acceptance without raising cutoffs, dropping
  cases, or treating old partial runs as passes. M0-M4 retain all requirements;
  HTTPS remains incomplete and RTC deferred. The latest verified implementation
  commit is 3267307 with its thirteen-phase wire pass.

- 2026-10-05 (Hello parser draft and independent oracle prepared):
  The previous turn made verified progress in 3267307. Live inspection confirms
  no prior guard/queue remains; macOS pressure is still warning. No compiler or
  evaluator was launched under that condition. Current crypto baseline and its
  pending partition remain unresolved; limits and all failed reports are intact.

  Prepared `wire/tls_hello.bend`, a strict ClientHello/ServerHello header+body
  parser composed with extension framing. It preserves offered uint16 suites,
  random/session bytes and parsed extensions, with separate Decode/Version/
  Compression/Overflow results. It enforces the selected TLS 1.3 legacy version,
  null compression, session length, even nonempty cipher list, required vector
  framing minima and full structural maximum sizes. The maximum encoded client
  message is 131,146 bytes; server is 65,611. It classifies the exact RFC retry
  random only for ServerHello. Negotiation, extension body/context/response
  rules, session echo, key shares, serialization and transcript/state integration
  remain work for subsequent composition. These are source intentions, not yet
  verified behavior; all four new Hello files are uncommitted and not integrated
  into check.sh until focused execution passes.

  Independent cursor-based Python oracle preparation completes 2,986 regular
  cases and seven stress cases, including actual published traces, raw and
  re-framed truncations, legacy versions, compression/session/suite boundaries,
  retry-marker mutations, unknown offers and full message/suite ranges.
  Preparation hashes are
  `387113e175c5b0891a9eb43af840663a1e9bbf2e8edd0cbbe4497e7ec135a68c`
  (regular) and `afd1ffb4d4bf904daeccd67b050780634636940f9faef90b2be5862fcbfd472f`
  (stress). `2026-10-05/hello-v1/oracle-preparation.json` binds draft sources and
  explicitly says no Bend execution. Eight closed frontend declarations and a
  field-printing diagnostic are prepared but also unexecuted.

  Queue PID 33122, exec session 2842, is confirmed live and waiting for sixty
  continuous seconds of normal pressure. It will check unchanged inputs and run
  frontend, native/Bun builds and complete regular/stress checks sequentially
  under the same 1 GiB and 120-second guards. Artifact folder:
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-05/hello-v1/`.
  Next: inspect that exact handle/process, correct concrete frontend/runtime
  failures when execution is possible, then integrate and run the complete wire
  gate before committing. Do not claim the prepared corpus as a pass or rerun
  terminated earlier jobs. All M0-M4 acceptance remains open; RTC is deferred.

- 2026-10-05 (extension framing accepted; crypto gate pressure-terminated):
  The prior turn made implementation progress and this continuation revalidated
  the same live queue, without restarting it. After sustained normal pressure,
  `moon --concurrency 1 run wire:check --force` passes all thirteen declared
  phases, no skips, under unchanged 1024 MiB aggregate/process and 120s per-phase
  limits. Guard wall time is 170.209s, aggregate peak 1011.9 MiB, individual peak
  744.1 MiB, system pressure normal. Longest phase is Bun foundations at 65.890s;
  native/Bun extensions are 5.692s/5.291s. Moon hash is `829ee913`.

  All 293 frozen source/configuration digests remain unchanged and are recorded
  in `2026-10-05/extensions-v2/wire-fresh-accepted-inputs.json`. The full log,
  command/environment and phase report share the `wire-fresh` prefix. This adds
  complete changed-wire-package acceptance to the earlier 1,766 independent
  extension cases per target; it does not prove extension body semantics,
  negotiation, live TLS/HTTPS, current crypto/root acceptance or timing/erasure.
  The extension parser, frontend/CLI/oracle, wire phase integration and README
  are now eligible for a bounded verified commit. The unaccepted crypto phase
  partition remains separate and uncommitted.

  The verified extension milestone is committed as 3267307. Queue PID
  16665/session 9934 subsequently starts the current 961-phase crypto gate;
  that run is now terminal, exit 137 after 29.424s. Seventeen frontend phases
  pass; x509_validity_test is incomplete when macOS pressure becomes warning.
  Aggregate peak is 294.7 MiB. This is a system-pressure stop, not an assertion,
  owned-process memory or deadline failure. Guard PID 23132 and the queue are
  gone; do not repoll them as live or infer complete crypto acceptance. Reports
  are `2026-10-05/crypto-baseline-retry/crypto-fresh-resource.json` and the adjacent
  log/launch file. No accepted-input success report was written for crypto.

  Current pressure remains warning, so no further heavy retry was launched.
  The complete root/crypto baseline is still open; the crypto partition changes
  remain uncommitted. Next: recheck actual system pressure before another guarded
  complete crypto run, preserving all failures and existing cutoffs. Meanwhile
  the next independent TLS unit is Hello body codecs and context-bound extension
  admission. Retained RFC 9846 sections 4.2.2/4.2.3 were read for strict length,
  version/compression fields and unknown-offer handling. M0-M4 stay open; RTC
  remains deferred and bounty untouched.

- 2026-10-05 (P-256 pressure termination; extension framing focused pass):
  Focused session 86377 is terminal, exit 137. Guard PID 2587 stopped at
  400.146s because macOS pressure changed to warning, not a P-256 assertion,
  deadline or owned-process memory failure. Aggregate peak is 85.5 MiB;
  batches 000..015 pass (64/609 cases), batch-016 is incomplete. The longest
  completed batch is 30.877s. Queued session 32428 exits 1 after verifying that
  failed report; it never launched crypto. Original PIDs 2043/2587/5752 are gone.
  Do not poll or restart those terminal handles. Their evidence is preserved in
  `2026-10-05/p256-phases/`; complete Bun P-256/package acceptance remains open.

  During independent work, read the retained current RFC 9846 section 4.3:
  uint16 extension framing, uniqueness and the separate message-context/body
  rules. New `wire/tls_extensions.bend` parses exact length-prefixed vectors,
  preserving unknown types/opaque bytes and rejecting malformed lengths,
  non-octets, duplicates and trailing input. A consuming fixed 65,536-bit type
  map avoids quadratic scans; the complete 65,535-byte payload range is admitted.
  Context, offered-extension binding, required-extension rules, PSK placement
  and body semantics remain caller-owned. This is not a Hello/negotiation owner.

  After pressure briefly returned to normal, pinned Bend 2.0.27 frontend and
  native/Bun builds pass. Seven closed checks and 1,756 ordinary plus ten stress
  cases per target pass: published vectors and all their truncations, random
  cases, all uint16 types, maximum body/vector sizes and distant duplicates.
  Regular corpus SHA is
  `302b97e4841f12c0b6b2250e5794cdc9ab05d1de2b19b889b2f37873e371dd5c`;
  stress is `11e583e5065ca00a82cbd1eec08bd12171ae2c6c6281cc87f3765cb2608212e9`.
  Diagnostic output is reconstructed from parsed records. Native/Bun ordinary
  times are 1.268s/4.504s; stress 0.250s/1.836s. Two separate frontend draft
  issues (computed-match scrutinee and missing list annotation) are corrected;
  their failures are retained. No runtime case failed. Artifact paths are
  `2026-10-05/extensions/` and `2026-10-05/extensions-v2/`, with original/final
  guarded commands, environments, source hashes and reports.

  Two new wire resource phases preserve all eleven prior phases/commands,
  yielding thirteen. The fresh package attempt was refused before launch as
  system pressure returned to warning (exit 125, zero owned memory); there is
  no complete-package pass for this change. Current lightweight queue PID 16665,
  exec session 9934, is confirmed live. It waits for sixty continuous seconds of
  normal pressure, checks frozen inputs, then runs fresh wire followed only on
  success by fresh crypto. Every compiler/evaluator remains inside the unchanged
  1024 MiB aggregate/process and 120-second phase guards. Wire reports will be
  `extensions-v2/wire-fresh-*`; crypto reports will be
  `2026-10-05/crypto-baseline-retry/crypto-fresh-*`. This fresh complete crypto
  run includes the full P-256 corpus; no partial earlier result substitutes for
  it. No unrelated machine processes were stopped or altered.

  Next: inspect session 9934 and its actual current process/report, consume the
  sequential gate results, and commit only the changes covered by completed
  acceptance. If pressure stays elevated, preserve the queue and continue
  independent work without launching competing heavy jobs. All draft crypto
  partition/extension files remain uncommitted. HTTPS and M0-M4 remain incomplete;
  RTC stays deferred and bounty untouched.

- 2026-10-05 (isolated issuer-link continuation after Name commit cc1a41c):
  The unpromoted issuer-link CLI now passes pinned typechecking in
  2.400s/546.1 MiB and native build in 15.417s/852.8 MiB. Its complete native
  corpus passes all 132 cases in 1.602s/34.1 MiB, including exact signed-byte
  retention, parent Name cross-encoding/case equivalence, altered child Names,
  duplicate counts, wrong names/keys, truncation and signature tampering.
  The intentionally invalid-time/untrusted field-holder controls still link
  mathematically: this does not validate the parent's signature or grant trust,
  CA/path constraints, validity, revocation, purpose or hostname authorization.

  Bun emission passes in 4.764s/655.7 MiB. Runtime handle 48487 is confirmed
  live queued for all 33 four-case phases; no Bun runtime acceptance is claimed
  yet. Actual shared guard PID 2587 is observed running a separate complete
  four-case P-256 candidate under `2026-10-05/p256-phases/`. No second heavy
  job is launched. Revalidate these handles before trusting this observation;
  consume their results instead of duplicating the work. Current package
  scheduling work leaves 961 declared phases, while full package/root acceptance
  remains pending. All candidate inputs/reports and `continuation-v10.json`
  are retained under `2026-10-04/name-comparison/`. Issuer source remains
  isolated; after complete Bun and final checker validation, integrate its
  exact-DER link and then compose actual chain/trust policy.

- 2026-10-05 (verified wait plus current generated-code review):
  Re-polled focused exec session 86377 and queued session 32428; PIDs 2043,
  2587 and 5752 are live and retain the expected commands. Focused Bun P-256
  advances to 64/609 cases with batch-016 active at this checkpoint. No job was
  restarted and no competing heavy job launched. The complete crypto gate is
  still queued, not passed; preserve the original report/log paths below.

  Inspected five exact functions in the newly emitted pinned P-256 JavaScript:
  multiply.go, multiply.selected, select_bytes, select_step.candidate and
  Array.to_list.go. `generated-runtime-review.json` in `2026-10-05/p256-phases/`
  binds their bodies/line positions to the generated file and current P-256,
  field and TLS schedule source hashes. The inspected scalar selector is bitwise
  and the loop counter public; this does not review every arithmetic operation
  or generated native/JIT instruction. Tagged heap/trampoline state and slice
  copies remain visible. The schedule's affine owners wrap ordinary duplicable
  byte lists; logical one-use checks do not establish physical erasure. Existing
  ECDSA retry/runtime findings remain open. TLS_PROFILE.md now reflects completed
  transcript/schedule components and this precise unresolved M2 scope.

  This documentation checkpoint makes no new protocol/runtime acceptance claim.
  Next: consume the same focused run and dependent full-package outcome, resolve
  any concrete failure, then commit the pending crypto partition only after its
  required checks pass. M0-M4 remain active; RTC expansion stays deferred.

- 2026-10-05 (P-256 phase partition prepared; focused Bun verification live):
  The prior turn made verified progress in commit 44249af. This continuation
  addresses M0's first failing current crypto phase: sixteen Bun P-256 cases
  exceeded a 120-second deadline. No primitive or expected result is changed.
  `p256_check.py` now accepts a bounded 1..16 batch size (default 16) and an
  optional complete-success JSON report. The package Bun invocation selects four
  cases per process/phase. Its 39 phases become 153; all other 808 phase entries
  remain identical and ordered, for 961 total. All assertions and the original
  180-second subprocess ceiling remain; the outer phase deadline stays 120s.

  Guarded partition verification captures the original and candidate ordered
  609-case corpus, confirms exact input/expectation equality and unchanged oracle
  and generation bodies. Corpus SHA-256 is
  `976b6ed2e68bfa8d98d361037f80345d9961ff9d33a09b86b69d0f81fc18a44d`.
  Pinned Bend 2.0.27 native/Bun evaluator builds pass, and native passes all 609
  cases in 6.390s evaluator time (27.6 MiB aggregate guarded peak). The focused
  Bun run is still live: 24/609 cases completed at this observation, batch-006
  running. This is partial evidence, not Bun or complete-package acceptance.

  Artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-10-05/p256-phases/`.
  Focused runner PID 2043, guard PID 2587, exec session 86377 were confirmed
  live. Queued gate PID 5752, exec session 32428 waits for that exact runner;
  it requires successful focused reports, identical native/Bun corpus hashes,
  final focused input binding and unchanged package sources before starting
  `moon --concurrency 1 run crypto:check --force` under the 961-phase guard.
  It writes `primary-crypto-force.log` and `primary-crypto-force-resource.json`.
  The queue does not bypass or overlap a failed focused test. All jobs retain
  1024 MiB aggregate/process cutoffs and 120-second phase/job limits.

  Next: re-poll those exact live handles/processes and consume their terminal
  evidence; do not restart solely because a report is not yet present. Inspect
  any specific failure, finish required checks before committing these pending
  five-file changes, then establish root/consumer acceptance. RTC remains
  deferred, M0-M4 open, and bounty remains untouched.

- 2026-10-05 (verified bounded Bend handshake record reassembly):
  `wire/tls_handshake_stream.bend` consumes one plaintext/authenticated decrypted
  handshake-record payload at a time, preserving complete encoded messages and
  partial headers/bodies with affine ownership. Each record admits 1..16,384
  octets; total admission and any declared encoded message are bounded at 1 MiB.
  ClientHello/ServerHello/EndOfEarlyData/Finished/KeyUpdate must end on a record
  boundary. Explicit boundary/finalization checks reject unfinished messages;
  failure consumes the owner and exposes no outputs from the failing record.
  This is framing only: body semantics, role/order, record authentication, epoch
  transitions and unsupported-message rejection remain handshake-owner duties.

  Pinned Bend 2.0.27 native and Bun each pass 936 regular scenarios plus three
  exact/cumulative/overflow stress scenarios. The independent buffered reference
  covers RFC 8448 messages, byte fragmentation, all 195 ClientHello and 656 server
  flight splits, coalescing, random input, bad lengths, alignment and closed-owner
  behavior. Regular corpus SHA-256 is
  `c4b37b58e9d09e133284c19458e3842d019f095adf37de85be23d93ba022510a`;
  stress is `04aeb1fe0b5105b342f90b994800c4d5f07f3a059c53e1c705c148e208bcbbb5`.
  Six closed frontend checks pass; two valid owner uses pass and three reuse
  attempts are rejected. A helper-cycle frontend failure and an oversized Nat
  equality-proof stack failure are retained; both are corrected. Runtime tests
  retain the complete large-length coverage.

  Fresh `moon --concurrency 1 run wire:check --force`, under build_guard with
  `--phases wire/check_phases.json --memory-mib 1024 --process-memory-mib 1024
  --timeout 120`, passes all eleven phases with zero skips: 210.053s guard wall
  time, 830.4 MiB aggregate peak, normal pressure. Longest phase is Bun foundations
  at 79.740s; new native/Bun stream phases are 14.187s/23.613s. Existing nine
  phases and shell commands are preserved identically and in order. Fresh moon
  task hash is `8dd70d86`. Launch environment, exact commands, focused reports,
  binaries, full package log/resource report and accepted source SHA digests are
  under `/Users/ozeron/.codex/artifacts/grounds/2026-10-05/handshake-stream-v4/`;
  earlier frontend evidence is under `handshake-stream/` and `handshake-stream-v3/`.

  This passes the changed wire package, not the current crypto/root baseline or
  live TLS/HTTPS acceptance. The complete crypto P-256 deadline failure remains
  unresolved. Next dependency-ready TLS work: bounded ClientHello/ServerHello and
  extension codecs, then negotiation/state/record-epoch integration with the
  verified transcript/schedule and composed certificate authentication. M0-M4
  remain open. RTC expansion remains deferred until HTTPS acceptance.

- 2026-10-05 (verified Name comparison; complete crypto baseline still fails):
  The original full-stack goal remains active and all nineteen gates remain
  open. HTTPS is the next dependency milestone. Exec session 11261 is now
  terminal, exit 124 after 977.491s: the complete 559-phase crypto attempt
  exceeds the 120-second deadline in Bun P-256 batch-00. The preceding 193
  phases pass; the failed phase's report retains a running snapshot and 365
  later phases are unexecuted. Aggregate peak is 798.8 MiB, individual 740.9
  MiB, system pressure normal. This is a deadline failure, not memory exhaustion
  or a complete package pass. Its report/log remain under
  `2026-10-04/rsa-signature-phases/`; do not restart or repoll the terminal job.

  `x509_name_match` now composes complete DER admission with supported OID-bound
  stored preparation, affine packed equality keys and multiplicity-preserving
  RDN sorting in Name sequence order. DomainComponent uses ASCII-case-only
  exact IA5 comparison; label/IDNA validation remains separate. Unknown rules,
  legacy mailbox profiles and unconfigured Teletex reject as unsupported.
  Explicit decreasing merge/sort budgets reject unfinished exhaustion, and
  signed DER remains unchanged. Fourteen closed assertions pass on pinned
  Bend 2.0.27 in 1.988s/277.2 MiB. CLI typecheck passes in 1.587s/295.3 MiB;
  native build in 9.278s/491.0 MiB and Bun emission in 1.997s/364.0 MiB.

  Both targets pass all 33,037 independent cases: 33,011 regular and 26 stress.
  The final native checker passes the complete all-mode corpus in 9.300s/81.2
  MiB. Bun passes all 258 regular and 26 stress batches in 119.329s/150.4 MiB
  and 53.921s/197.5 MiB, zero skips; longest phases are 1.386s and 13.966s.
  The complete Bun modes' group counts sum exactly to the native all-mode
  counts. Regular corpus hash is
  `e8db492c3b6546453ad7df15aed3c4d29f55201cbe4ee4a2339f368c59821f50`;
  stress hash is `cdf275e1ce9b8c9b9426031382a236fde9e04a99fd704066023b23ccdbe1dc86`.
  Phase reporting retains all six oracle/corpus/encoder ASTs and unchanged
  evaluator batching; before/after corpus hashes agree. Existing batches now
  have separate deadlines, without changing inputs, expectations or cutoffs.

  Only the four verified Name files are promoted. The package manifest retains
  every original 559 entry identically and in order, adding 288 phases for the
  owner and complete corpus (847 total). All failed frontend commands, guard
  capacity refusals, binaries, launch environments, reports and source bindings
  remain under `/Users/ozeron/.codex/artifacts/grounds/2026-10-04/name-comparison/`.
  `Name-integration-binding.json` identifies the promoted files. The unsupported
  --verdict attempt is preserved; pinned 2.0.27 uses its normal check command.
  Issuer-link source remains isolated and unverified. No complete package/root,
  issuer/signature binding, chain/trust, hostname/time, timing/erasure or TLS
  acceptance follows from this comparator milestone. Next: diagnose/bound the
  P-256 batch deadline before a fresh full crypto retry, then complete root and
  actual issuer-link/path authentication with the existing guarded workflow.

- 2026-10-05 (verified Bend TLS key schedule and Finished):
  New tls_schedule composes Bend HKDF/HMAC/Expand-Label for the selected
  SHA-256 certificate/ECDHE profile without PSK. It derives the handshake
  secret, directional handshake secrets, separate one-use Finished keys and
  directional application secrets through an affine ToApplication stage.
  Input digests/shared bytes must be exactly 32 valid octets. Finished
  verification accumulates all admitted tag bytes. Logical consumption does
  not establish physical erasure, generated timing safety, key-agreement
  admission, correct transcript timing or application-data authorization.
  Those remain handshake/runtime responsibilities and acceptance gates.

  Pinned frontend/CLI checks pass on the first attempts. Six admission/tag
  declarations pass; the ownership checker accepts application/Finished use
  and rejects handshake copying, double application derivation, double Finished
  use and cross-stage misuse. Native and optimized-JIT Bun each pass the same
  798 outputs from 182 commands: published RFC 8448 1-RTT/retry expectations,
  64 seeded random schedules, malformed widths/direct non-octets, every
  tag/transcript-byte mutation, and wrong-key rejection. Guarded corpus runs
  take 0.708s/26.2 MiB and 1.638s/86.5 MiB. Corpus SHA-256 is
  `72bbe464105110ac026ab6c4e7a7d15b893deb394d01aed4397f0de457623f2a`.

  Focused and package launches each encounter a guard refusal while verified
  isolated certificate-name jobs run in another session. They are preserved;
  queued retries wait for the specifically attributed live processes and then
  run sequentially, without overlapping heavy work or restarting those jobs.
  The wire manifest adds native/Bun schedule phases while retaining all seven
  prior phases and every existing command byte-identically and in order.
  Final forced wire package acceptance passes all nine phases, zero skips,
  in 132.217s/609.4 MiB; the longest phase is Bun foundations at 66.595s.
  All deadlines, pressure checks and aggregate/process caps are unchanged.

  Exact environments, focused and full reports, retained refusals, preservation
  audit and accepted-input hashes are under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-05/schedule-v2/`; initial
  frontend successes and the first guarded refusal are under `schedule/`.
  All source hashes match across validation. This completes a schedule
  component and the changed wire package, not a live TLS handshake or HTTPS.
  The full crypto/root baseline remains incomplete at the separately recorded
  Bun P-256 timeout. Next: integrate transcript and schedule with handshake
  framing/state and record epochs; finish certificate authentication and
  resolve the crypto baseline before end-to-end native/Bun/browser acceptance.
  RTC expansion remains deferred.


- 2026-10-05 (verified Bend transcript and complete fresh wire package):
  tls_transcript now composes the existing affine streaming SHA-256 owner with
  exact handshake framing, continuing snapshots, first-ClientHello/retry prefix
  tracking and the RFC 9846 synthetic message_hash rewrite. All invalid
  admission consumes the owner. The total admitted-input bound is 1 MiB;
  message-body validation, complete role/order state, reassembly, key schedule,
  certificate authentication and live TLS remain separate unfinished work.

  The first queued frontend run fails on a local binding before matching its
  owner in pinned Bend 2.0.27. Moving the match before the binding corrects it
  once; the original failure is retained. Final frontend/CLI checks pass, as
  do two valid ownership examples and two rejected copying/finalization cases.
  Native and optimized-JIT Bun each pass 84 independent ordinary outputs and
  six exact/cumulative-bound outputs; the long native/Bun checks take
  0.165s/5.095s, with 55.9/225.4 MiB guarded aggregate peaks. Published
  sections 3/5 exercise the retry rewrite and continuing snapshots. Exact
  source hashes are unchanged through all focused and package runs.

  The integrated wire gate first encounters a transient guard lock refusal;
  the next run reaches its whole-job 120-second cutoff after transcript and
  record checks, before completing existing transport tests. Seven ordered
  native/Bun foundation/transport/stop/TLS phases now retain the existing
  per-phase 120-second limit and 1 GiB aggregate/process cutoffs. A retained
  command-preservation audit proves every pre-existing shell command remains
  byte-identical and ordered; only transcript checks/phase declarations were
  added. Moon includes the phase manifest/helper in cache inputs.

  Final forced `moon --concurrency 1 run wire:check --force` under the phase
  guard passes all seven phases with zero skips in 182.248s / 620.6 MiB.
  The longest phase, Bun foundations, takes 114.468s. Existing TCP/UDP,
  RNG/byte benchmarks, OS signal cleanup and legacy TLS regressions all run.
  This is complete wire-package acceptance, not Bend handshake or HTTPS
  acceptance. Reports, exact launch environments, failed attempts, compiled
  artifacts, command-preservation proof and accepted-input hashes are under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-05/transcript-validation-v2/`;
  the initial frontend failure is under `transcript-validation-v1/`.

  The independent shared crypto baseline terminates at 977.491s / 798.8 MiB
  on the first Bun P-256 batch's 120-second deadline after 193 prior phases
  pass. Its 559-phase acceptance remains incomplete. Do not rerun the known
  cold root gate until required package caches/current baseline are resolved.
  Next: compose typed handshake key-schedule/Finished operations against the
  published expectations, continue M1 certificate authentication, and resolve
  the separate crypto P-256 timeout before full repository acceptance. All
  M0-M4 completion gates remain open; RTC expansion stays deferred.


- 2026-10-05 (transcript validation queued behind live baseline):
  Static review corrected explicit duplicability on the framing header fields
  before compilation. No compiler failure or passing Bend result is claimed.
  A source-hash-bound sequential validation driver is running at
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-05/transcript-validation-v1/run.py`.
  Its PID 32834 / exec session 68597 is verified live and waiting for the
  specifically attributed baseline guard PID 98355, also verified live at
  15 minutes elapsed. The baseline log still advances through Bun checks.
  The waiting process holds no guard lock and launches no compiler while
  the predecessor is live.

  Once that exact predecessor exits, the driver checks unchanged source hashes
  and runs frontend declarations, CLI frontend, ownership, native build, Bun
  emission, ordinary native/Bun corpora, and separate native/Bun stress corpora.
  Each step uses the existing 1 GiB/120-second guard; any failure, lock refusal
  or source change stops the sequence. Exact commands/environments and reports
  are retained per step. The driver does not alter or restart the predecessor.
  Next: poll session 68597 or inspect both live PIDs and the named report/log
  directory; do not launch a duplicate validation job. On terminal failure,
  inspect its first failed step and correct the cause, preserving reports and
  consulting Astra after two failures on the same bug. Transcript source remains
  uncommitted until validation and package integration are accepted.


- 2026-10-05 (continuation; isolated Name recursion correction):
  The original full-stack goal remains active; HTTPS is the next dependency
  milestone and none of the nineteen original gates is closed by this work.
  The same complete 559-phase crypto job is confirmed live through exec session
  11261 and guard/Moon PIDs 98355/98360. It completed the native portion,
  including all 774 RSA signature cases, and reached Bun field checks after
  Bun AES/GCM checks. Its final resource report does not yet exist; this is
  partial running evidence, not complete package acceptance. No second heavy
  job was started or cutoff raised.

  The isolated Name candidate now uses structurally decreasing Nat merge/sort
  budgets. Merge is bounded by the counted attributes; sixteen balanced sort
  levels suffice for a decoded 65535-octet Name. Unfinished budget exhaustion
  returns None, propagated through preparation, instead of returning partial
  keys. Shrinking attribute/RDN inputs precede the changing affine tables in
  self-call arguments. Fourteen closed assertions include exhaustion rejection.
  Static inspection also fixes the unrun duplicate-corpus generator: boundary
  loops had rebound attribute variables to complete DER Names, so its pool now
  constructs attribute triples explicitly. No accepted corpus was changed.

  Seven pre-edit files, exact candidate hashes and prior failed attempts remain
  under `/Users/ozeron/.codex/artifacts/grounds/2026-10-04/name-comparison/`;
  `prototype-inputs-v7.json` binds the current isolated candidate. Both Python
  checker ASTs parse. No v7 Bend frontend, constructor, native/Bun or issuer-link
  acceptance is claimed, and no prototype source is promoted to this repository.
  Existing untracked TLS work and unrelated bounty files remain untouched.
  Next: consume the live crypto job's terminal result, then guard v7 frontend
  verification and complete comparator/link coverage in the shared build slot.

- 2026-10-05 (unverified Bend transcript candidate; validation queued):
  Added uncommitted wire/tls_transcript.bend with an affine streaming SHA-256
  transcript, exact complete-message framing checks, first-ClientHello/retry
  prefix tracking, synthetic message_hash insertion, continuing snapshots and
  a 1 MiB total input admission bound. Record reassembly, message-body parsing
  and complete handshake role/order validation are explicitly outside this
  component. Repeated/out-of-place retry and peer-supplied message_hash reject;
  failed admission consumes the owner. This source has NOT been compiled.

  The uncommitted CLI, six closed framing checks, ownership checker and
  independent Python checker are prepared. Python parsing and corpus preparation
  pass: 41 sequences/81 expected outputs, plus three direct owner/invalid-octet
  outputs and six separately invoked exact/cumulative-bound outputs. No Bend
  result is claimed. Candidate hashes and scope are recorded in
  `2026-10-05/https-baseline/transcript-candidate.json`.

  Existing full crypto guard PID 98355 is still verified live; its log reached
  Bun primitive checks. No concurrent compiler/evaluator was launched and no
  crypto task input was edited. The five transcript candidate files remain
  untracked/uncommitted until focused native/Bun and ownership validation passes.
  Next: recheck that same live gate/report; when the shared guard is available,
  compile tls_transcript_test/CLI and run tls_transcript_type_check.py, then
  tls_transcript_check.py on native/Bun (ordinary and --stress separately),
  each under the existing resource/deadline guard. Fix findings before check.sh
  integration or a milestone commit; retain every failed attempt. Then compose
  the handshake key schedule and complete M1 certificate authentication.


- 2026-10-05 (HTTPS handshake fixture preparation while crypto gate runs):
  The same guard PID 98355 was confirmed live at start and after preparation;
  the package log advanced from native certificate compilation to independent
  native signature/DER/algorithm checks. No restart or second heavy job was
  attempted. The crypto gate remains incomplete at this observation.

  New wire/tls_handshake_vectors.py extracts pinned RFC 8448 sections 3 and 5
  into tls_handshake_vectors.json and independently validates published HKDF,
  transcript and Finished bytes with Python hashlib/hmac. Generation and the
  offline check both pass: 17 message-length checks, six extracts, 22 expands,
  18 transcript hashes, four Finished authenticators and one HelloRetryRequest
  transcript rewrite. A light mutation audit rejects 146 altered expected
  fields/transcripts. This prepares the independent evaluator for M3; it is
  not Bend handshake execution, certificate acceptance or live TLS evidence.
  The original published RSA certificate remains unsuitable for current
  key-size/trust acceptance; no such acceptance is claimed. Existing AES
  record vectors and crypto source/task inputs are untouched.

  Exact source is SHA-pinned at
  `6564d1376d1ec744fc7a9993da15ebc1b9be361908b166091f47ef605c537fba`.
  Reproduce with `python3 wire/tls_handshake_vectors.py --source <rfc8448.txt>
  --output <vectors.json>` and `--check wire/tls_handshake_vectors.json`.
  Source and validation report are under `2026-10-05/https-baseline/`.
  Next: consume the still-running package gate before any heavy work. Implement
  Bend transcript/key-schedule composition against these published expectations,
  including retry rewriting and invalid-input/role/order cases; M1 certificate
  composition and all native/Bun live TLS/HTTPS evidence remain required.


- 2026-10-05 (HTTPS goal continuation; selected TLS profile and baseline ownership):
  The prior planning turn made authoritative progress by decomposing M0-M4 and
  recording the user's RTC deferral. TLS_PROFILE.md now selects the protocol,
  algorithms, owners, exclusions and positive/negative evidence matrix for M2/M3.
  The refreshed official RFC 9846 text supersedes RFC 8446; its current official
  errata listing has five Reported entries and no Verified entries. Exact
  snapshots and hashes are under `2026-10-05/https-baseline/sources/`.
  The profile retains mandatory P-256/RSA dependencies; ECDSA-first is build
  order only. Runtime timing/key-erasure findings remain open. This is a source-
  grounded build decision, not new protocol implementation or acceptance.

  Primary HEAD is 475babf, which commits the independently verified RSA phase
  partition. No heavy job was visible at initial inspection. A second session
  launched the full crypto gate before this session's launch; the existing
  guard refused this duplicate with exit 125 and reason
  `another-guarded-job-is-running`, without starting a compiler. The refusal,
  exact launch and tracked-input hashes are retained under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-05/https-baseline/`.
  The actual running guard PID 98355 and child Moon PID 98360 were verified
  live, using `crypto/check_phases.json` and the report/log paths under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-04/rsa-signature-phases/primary-crypto-force*`.
  At the latest observation it had reached native certificate compilation;
  no complete package result exists yet. No second heavy job was started.
  All edits in this continuation are documentation, outside crypto task inputs.

  Next: inspect that same process/report before launching any further heavy
  work; consume its complete 559-phase outcome or specific failure. Then
  establish root acceptance with the required package caches. M1 certificate
  composition and all live TLS/HTTPS gates remain unproved.


- 2026-10-05 (planning only; HTTP migration decomposition):
  STACK_PLAN.md now sequences M0 current-toolchain/package acceptance, M1 composed
  certificate authentication, M2 TLS profile/private-key/runtime readiness,
  M3 independent live Bend TLS client/server interoperability, and M4 HTTPS/WSS
  integration. Each milestone has concrete build units and an evidence exit.
  No implementation or test pass is claimed by this update. All nineteen
  original full-stack gates remain open as follow-on roadmap requirements. The
  user chose to defer RTC until HTTPS works; the active goal is M0-M4 HTTPS/WSS,
  preserving existing RTC code/checks without expanding DTLS/data/media scope. The three dirty
  RSA check-reporting files are pre-existing work and remain untouched.
  Next: finish complete current crypto acceptance (now 559 declared phases;
  see the continuation entry below), then root acceptance before claiming
  acceptance for further certificate/handshake integration.


- 2026-10-05 (continuation; bounded Bun RSA signature phases):
  The original full-stack goal remains active and all nineteen gates remain
  open. On primary commit 228154d the fresh 364-phase crypto gate terminates
  at 3370.663 seconds with phase-timeout in Bun RSA signature checking:
  335 preceding phases pass; the active RSA phase reports 196 of 774 cases
  before its 120-second cutoff, and the remaining 28 phases are unexecuted.
  Peak aggregate memory is 823.0 MiB, maximum individual 732.4 MiB; this is
  a deadline failure, not memory exhaustion. Native and Bun P-256/ECDSA
  finish their complete existing corpora; Bun ECDSA passes 384 cases across
  all 100 predefined phases in 1768.632 seconds. All reports/failed logs are
  retained under `2026-10-04/name-string-preparation/`.

  The subsequent unchanged ordinary root command also terminates at its
  whole-job 120.028-second deadline while rebuilding crypto native fixtures,
  peak 526.6 MiB. This repeats the earlier cold-root condition. Astra low
  diagnoses distinct package phase-granularity and root cache-readiness
  problems before any third ordinary root retry. Complete guarded package
  caches must exist on final task inputs; do not rerun the ordinary root
  command cold or raise either deadline. No complete package/root pass is
  claimed from these partial results or the isolated modern compiler.

  `rsa_signature256_check.py` now optionally announces each unchanged
  four-case subprocess batch. A guarded independent partition check proves
  all case-generation/oracle bodies and all 774 rows identical to the
  original: published 110, peers 34, admission 52, PSS tampering 289 and
  v1.5 tampering 289. Ordered corpus digest is
  `93d55de60b6a6f1edb4a76198b30d9c0e6105e33bd71998d242bfe85e9175d35`.
  `check.sh` explicitly fixes batch size four and replaces the enclosing
  Bun RSA phase with all 196 batches, including final partial batches.
  `check_phases.json` now has 559 phases; every other original 363 entry
  remains identical and ordered. No case, algorithm, expectation or cutoff
  is removed or weakened.

  Fresh pinned Bun emission passes in 0.637 seconds/126.7 MiB. The complete
  focused optimized-JIT Bun RSA run passes all 774 cases and all 196 declared
  phases, zero skips, in 527.811 seconds/82.5 MiB aggregate (56.2 MiB maximum
  individual). Longest phase is 8.325 seconds. Partition/build/runtime logs,
  retained pre-change checker/script/manifest and hash bindings are under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-04/rsa-signature-phases/`.
  These are focused acceptance only. Next: finish the fresh complete
  559-phase crypto package gate on final inputs, inspect all later phases,
  then the unchanged ordinary root gate with validated package caches.

  In parallel light source work, isolated Name/RDN and exact-DER issuer-link
  candidates are preserved under `2026-10-04/name-comparison/`; none is
  promoted. Frontend failures reveal an elaboration boundary, numeric
  multiplicity, helper cycles and structural recursion requirements.
  Astra low reviews the repeated boundary failure before another attempt.
  Corpus/runtime/package acceptance remains pending; do not infer Name/path
  trust from candidate source or existing mathematical signature vectors.
  TLS/DTLS, secure signaling, TURN/data/media and complete trust/timing/
  erasure requirements remain unchanged.


- 2026-10-04 (Lisbon; composed certificate attribute string preparation):
  The full goal remains active; all nineteen gates remain open. The previous
  verified crypto/transcoder/browser milestone is committed as 050668e, with
  primary-source/isolated-candidate manifests and 1,169 artifact hashes bound
  separately under `compiler-package-acceptance/`. No compiler pin changes.

  New `x509_name_prepare` composes canonical octet OID validation, the shared
  schema's original tag/alphabet/scalar SIZE admission, strict string decoding
  and the authenticated Unicode 3.2 stored caseIgnoreMatch owner. Its affine
  tables return on every success or failure. Empty/oversized values cannot
  become admissible through deletion/expansion. IA5 domain/mailbox, unknown
  equality rules and unconfigured Teletex remain explicitly unsupported.
  This produces packed prepared scalars, not Name equality or chain trust.

  Pinned Bend 2.0.27 passes twelve checked admission declarations, including
  direct non-octet OID/value constructors, in 0.790s/250.6 MiB. Final native
  build passes in 3.467s/378.6 MiB; Bun emission in 1.086s/290.1 MiB. Both
  targets pass the identical complete 18,996 independent composed cases plus
  fourteen malformed-table rejections: native 3.570s/125.6 MiB, optimizing-JIT
  Bun 42.647s/188.8 MiB. All original transcoder cases remain; added cases
  exercise published folding across encodings, type/SIZE/OID/profile limits,
  marks/space/order, and full octet-bound removal/normalization expansion.
  Mixed successful/failed attributes and two fixture files retain one table
  owner. Corpus SHA-256 is
  `25693ef51ee24f4a2079829f11cb6ac2a98b2bb65fc78fc9b0c179e71c86b1e7`.
  The first frontend attempt exposes a missing duplicable byte argument; it
  is corrected once, and its separate failed log/report remain retained.

  Five phases extend the original check manifest to 364 without removing any
  original checks. These focused results do not establish complete changed
  package or repository acceptance. RFC 5280 section 7.1 and RFC 4518, official
  errata search and verified inline renderings are revisited; direct individual
  erratum fetches still fail. Existing preparation semantics retain technical
  corrections; newly refreshed 7658/9048 are hyperlink/editorial corrections.
  Exact launch environments, retained source, binaries and reports are under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-04/name-string-preparation/`.
  Next: run the fresh complete changed crypto gate and ordinary repository
  check; implement OID-bound attribute equality and multiplicity-preserving
  RDN multiset comparison in Name sequence order, then actual chain binding.
  Compiler-consumer compatibility, trust/constraints/key/timing review, Bend
  TLS/DTLS and the complete direct/relay data/media contract remain required.

- 2026-10-04 (Lisbon; complete isolated crypto gate, string decoding and browser ICE):
  The full goal remains active with all nineteen acceptance gates open. All
  heavy jobs retain sequential ownership, 1 GiB aggregate/individual sampled
  cutoffs, pressure refusal and 120-second job/declared-phase deadlines.

  The frozen isolated official Bend 2.0.34 candidate passes the complete
  original `moon --concurrency 1 run crypto:check --force`: all 354 phases,
  native and optimizing-JIT Bun, with zero skips, in 1326.039s/496.1 MiB.
  The longest phase is Bun certificate-signature checking at 102.813s.
  All 1,079 candidate inputs match their hashes before and after the run.
  This candidate predates the new decoder phases and does not change the
  primary Bend 2.0.27 pin. Two invalid launches are retained separately:
  incorrect primary cwd, then missing candidate Moon workspace configuration.
  Astra low reviews those failures before the corrected candidate launch.

  Forced candidate wire and http_core gates pass in 59.270s/432.0 MiB and
  19.882s/447.8 MiB. The further HTTP consumer run passes http_router and
  http_wire, then fails http_client's first frontend command on 93 imported
  foreign-dependent definitions; http_json is unexecuted. Astra low recommends
  preserving all seventeen equality proofs and their actual pure dependencies,
  with explicit verdict checking, rather than substituting check-only success.
  Compiler promotion and full consumer acceptance remain open.

  `x509_name_text` now transcodes strict UTF8/Printable/IA5/Universal/BMP values
  into ordered Unicode scalars, sharing Name schema syntax and rejecting
  non-octets, oversized values, UTF-16 surrogates and unsupported Teletex.
  It preserves controls/BOMs/case/spaces for the separate preparation owner.
  Pinned Bend passes twelve checked constructor examples. Native and optimizing
  Bun each pass all 9,321 independent codec/UCS-2 cases, including all surrogate
  values, seeded cross-encoding order and the exact 65,535-octet bound:
  2.116s/35.5 MiB and 5.891s/112.7 MiB. Their corpus hashes agree. Five new
  manifest phases preserve the original 354; complete primary 359-phase
  acceptance remains unproved. Initial CLI multiplicity and missing-rg launch
  failures are retained separately from corrected successful runs.

  Browser polling now uses a monotonic clock with unchanged deadlines, and
  writes launch attribution and CDP startup targets before later cutoffs.
  Guard reports add short owned-process names without collecting arguments or
  environments or changing ownership/cutoff behavior. Sixteen guard regressions
  and eight phase regressions pass. Full Chrome 154 and Chrome for Testing 153
  startup attempts still cross the aggregate cap. Their process/target evidence
  and each failed hypothesis remain recorded; Astra low is consulted after
  repeated failures. Only three exactly attributed failed profiles are removed.

  Installed Chromium 153.0.8010.12 headless shell passes the complete original
  native signed-cookie signaling/ICE browser scenario in 8.980s/321.1 MiB using
  the frozen previous native server and no accumulated UI diagnostic flags.
  Both generations select actual pairs, exchange authenticated fresh consent,
  replace both credentials on the same UDP base, reconnect, reject authentication,
  Origin and malformed messages, and shut down cleanly. An independent packet
  check verifies HMAC-SHA1/FINGERPRINT/USERNAME/transaction/nomination/consent
  evidence for both generations. The data channel remains connecting: TLS,
  DTLS, SCTP and audio/video are absent. Full Chrome startup acceptance remains
  distinct and open.

  The required primary ordinary `moon --concurrency 1 run :check` reaches the
  unchanged whole-job deadline at 120.004s/525.2 MiB during crypto native
  extension compilation. This is incomplete repository acceptance. Exact
  commands, environments, frozen candidate inputs, successful reports and all
  failed attempts are retained under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-04/compiler-package-acceptance/`.
  Next: connect decoded strings to affine Unicode preparation and ordered
  Name/RDN multiset comparison; finish faithful HTTP/compiler consumer checks
  and fresh changed-package acceptance. Trust/chain/key/timing review, Bend
  TLS/DTLS, secure signaling, IPv6/TURN, data/media and integrated direct/relay
  browser/repository acceptance remain required.

- 2026-10-04 (Lisbon; reusable sequential native compilation):
  The full goal remains active and all nineteen acceptance gates stay open.
  `tools/bend_native_parts.py` now partitions recognized Bend CPU C into
  sequential translation units without LTO, preserving every segment body,
  signature and calling-convention attribute. Runtime globals and dispatch
  have one owner. Unsupported layouts/devices, unknown shared globals, shared
  local storage and unexpected code between segments fail explicitly. Balanced
  generated CPU guards are retained; runtime-only local storage stays in the
  owner. Publication is atomic and refuses an existing or concurrently created
  output. Eleven guarded regressions pass in 4.642s/84.0 MiB, including actual
  direct/dynamic cross-unit calls, shared mutations and persistent runtime
  local storage. Both modern and pinned CPU layouts are exercised: the pinned
  frozen cookie C compiles in two units at 123.2 MiB and passes 2,675 independent
  cookie cases at 26.1 MiB.

  `bend_native.sh` selects this compiler for CPU C at least 4 MiB; small and
  Objective-C programs retain their existing path and all flags/libraries.
  Signaling always uses sequential units and preserves the fixture-local
  Apple Clang 21 arm64 stack-probe workaround. Its build owns two fixed,
  ordered phases, emission then compilation/linking, in the complete RTC
  manifest and a dedicated standalone manifest. All memory/pressure cutoffs
  remain unchanged; each phase retains its 120-second deadline. All five
  consuming packages include the new tool in Moon cache inputs.

  Isolated official Bend 2.0.34 compatibility is rebuilt from current e4acfd6
  with the full prior compatibility patch, preserved current crypto cache
  inputs and fifteen further argv adapters. The primary 2.0.27 pin is unchanged.
  Fresh isolated JSON package acceptance passes in 34.006s/407.5 MiB, including
  the complete native 318-case suite and 706 independent Python-json cases.
  The separate complete Bun 318-case suite passes in 92.690s/326.6 MiB.
  Isolated io/utf8 checks pass forced in 2.211s/205.5 MiB. These results do not
  establish complete compiler compatibility or repository acceptance.

  Two conservative source-build validation failures reveal legitimate generated
  CPU wrappers and runtime-only local statics. Astra low reviews both before
  another attempt; the corrected parser retains the wrappers and suffix.
  A combined non-JIT build then times out at 120.040s/887.2 MiB; optimizing
  frontend JIT reaches 1026.0 MiB and is stopped. Astra low reviews those two
  failures before the fixed two-phase integration. The final whole isolated
  source build passes in 145.342s: emission 94.324s/905.2 MiB, then all 24 units
  and linking 50.824s/485.4 MiB. An audit verifies all 2,188 body hashes/order,
  one definition per segment, and sixteen host globals plus dispatch in one
  runtime owner; device globals are absent. The final executable passes all
  48 real signaling scenarios in 2.233s/33.3 MiB and actual cookie expiry,
  socket/UDP cleanup, expired/stale denial and fresh reconnect in 3.350s/31.0 MiB.
  Earlier successful standalone compilation and native runs are retained too.

  Fresh primary http_server acceptance initially fails because a wall-clock
  duration reads about 930 seconds while the guard's monotonic phase lasts
  12.170s. The elapsed-time fixture now uses a monotonic clock with identical
  thresholds. Its rerun passes eleven phases then hits 1028.9 MiB during
  multipart compilation. Both multipart fixtures now release Bend before C
  compilation, preserving all fuzz/client scenarios. Final primary
  `moon --concurrency 1 run http_server:check --force` passes all thirteen phases
  without skips in 100.723s/913.9 MiB; http_core passes forced in
  33.994s/546.1 MiB and wire in 74.841s/603.4 MiB. Crypto passes 48 of 354 phases
  before macOS warning pressure stops it at 52.824s/531.4 MiB. RTC passes
  thirty phases before pinned signaling C emission hits 1025.4 MiB at
  232.607s overall. These incomplete crypto/RTC gates are not acceptance.
  The required ordinary `moon --concurrency 1 run :check` reaches its unchanged
  whole-job deadline at 120.007s/513.8 MiB during crypto native validity builds.
  Repository and final forced repository acceptance remain incomplete.

  Exact commands/environments, all failed attempts, complete compatibility
  preparation, frozen candidate inputs, generated C/parts/objects, body/symbol
  audits and native/Bun/package reports are under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-04/compiler-acceptance/`.
  Next: complete all affected isolated compiler/ABI package checks before
  promotion, resolve Chrome startup with process-role evidence, and finish
  trust/Name/key/timing review before Bend TLS/DTLS and secure signaling.
  IPv6/TURN, SCTP/data, encrypted audio/video and complete fresh direct/relay
  browser/repository gates remain required. No scope or check is removed.

- 2026-10-04 (Lisbon; retained transport packing and bounded native diagnostic):
  The full goal remains active with all nineteen acceptance boxes open. The
  user's rule is now explicit in STACK_PLAN: after two failed attempts on the
  same bug, consult an Astra subagent at low reasoning before another attempt.
  All heavy jobs remain sequential under 1024-MiB aggregate/individual sampled
  cutoffs, macOS pressure refusal and 120-second job/phase deadlines.

  The retained change packs the shared UDP adapter's complete transport owner
  across IO, then factors the existing reply gate into current_reply_route.
  The notice-based current_reply API still applies the exact original closed,
  generation, registration, current/previous slot and lifetime checks. Pinned
  full signaling type checks pass: initially 7.222s/660.4 MiB, then the retained
  route candidate 7.432s/642.2 MiB. Pinned C emission fails at the unchanged
  cutoff in three preserved attempts, including the retained candidate at
  17.042s/1024.9 MiB. No incomplete C is accepted as an executable.

  Fresh pinned Bun emission of the retained candidate passes in 17.723s at
  825.1 MiB. All 48 real HTTP/WS authentication, Origin, malformed-input,
  restart/reconnect and UDP-cleanup scenarios pass in 3.952s/162.6 MiB; actual
  signed-cookie expiry, socket/UDP cleanup, expired/stale denial and fresh
  reconnect pass in 3.712s/112.2 MiB (observed expiry 2.528s). One earlier
  invocation fails before fixture startup because an unsupported JSC variable
  was supplied; the corrected evaluator uses optimizing JIT/DFG and the existing
  forceRAMSize setting. A pressure-refused attempt supplies no runtime proof.

  Isolated official Bend 2.0.34 retains the same nineteen-file OS-effect ABI
  overlay and leaves the primary 2.0.27 pin unchanged. Modern C emission passes
  at 51.399s/894.6 MiB. Shared-owner packing and reply factoring reduce generated
  WL_SIG width from 229 to 196 to 175 parameters and C from 14,682,028 to
  13,955,685 bytes. These are syntactic metrics, not timing/liveness evidence.
  Monolithic Apple Clang -O3 still crosses the individual cutoff at 4.967s.
  Astra low is consulted after two failed compiler rounds. Its probe_owned and
  consent-update helper experiments both typecheck and emit modern C but leave
  the signature at 175 and add generated bytes. After those two unsuccessful
  reductions Astra low is consulted again; both experiments are reverted from
  the primary source and retained only as frozen negative evidence.

  The recommended C translation-unit experiment succeeds. A first 16 demanding
  segment batch compiles at 267.7 MiB. The complete frozen route C is partitioned
  into 49 units and linked through fifty mandatory sequential phases, taking
  68.498s at 323.6 MiB, longest phase 3.461s. Original signatures, preserve_none,
  noinline, musttail calls, IDs and segment bodies are retained; external linkage
  connects units, without LTO. An independent audit proves all 2,188 bodies have
  identical hashes, occur once and retain order. All seventeen host runtime
  globals, including the allocator and dispatch table, have one definition;
  six device globals are absent in this CPU artifact. A first runtime-unit
  attempt fails on an omitted dispatch-table expansion macro; its source and
  failure remain intact, and the corrected attempt uses a new artifact tree.

  The isolated modern split native executable passes the same 48 actual
  signaling scenarios in 2.229s/34.1 MiB and complete expiry/cleanup checks in
  3.255s/31.3 MiB (observed expiry 2.600s). This is modern diagnostic evidence,
  not pinned native or whole-package acceptance. Browser checks remain open:
  default Chrome startup crosses the aggregate cap at 1073.9 MiB; disabling GPU
  reaches 1028.4 MiB; additionally disabling speculative spare-renderer
  prewarming reaches 1065.1 MiB. Every failed attempt is retained; no security,
  Origin, cookie, navigation, ICE or lifecycle scenario is removed. Astra low
  reviews the failures before retries. The fixture now merges disable-features
  arguments into one switch so optional resource settings retain its required
  mDNS configuration; default behavior and all checks remain.

  Required rtc:check --force first stops at the existing integrity proof's
  120-second phase deadline with compiler JIT disabled (122.083s/162.0 MiB).
  Restoring optimizing compiler JIT under the same limits passes both preflights,
  every frontend phase, native cookie build plus 374 independent cookie cases,
  and native SDP build plus 90 independent cases. The complete gate then stops
  in pinned signaling-server C emission at 282.239s/1025.1 MiB. Thirty phases
  pass; the remaining phases are unexecuted, not skipped or accepted. The
  ordinary `moon --concurrency 1 run :check` also runs with optimizing JIT and
  the same limits, then reaches its 120-second whole-job deadline during crypto
  native builds (120.014s/530.7 MiB). Neither incomplete gate is accepted.

  Exact commands, separate compiler/evaluator environments, all attempts,
  isolated ABI preparation, reverted experiments, generated profiles, full
  split sources/manifests/body/global audits and native/Bun evidence are under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-03/transport-owner-packing/`.
  Next: resolve primary compiler/complete package acceptance and Chrome's
  aggregate startup footprint without another unchanged blind retry; validate
  any promoted compiler/ABI with all affected consumers and complete checks.
  Crypto/package acceptance, runtime/key/timing review, trust/chain/Name work,
  Bend TLS/DTLS, browser HTTPS/WSS, IPv6/TURN, SCTP/data and encrypted media plus
  integrated direct/relay evidence remain required. No full acceptance box is
  checked and no required scope is removed.

- 2026-10-03 (Lisbon; pressure diagnosis and external recovery):
  The previous continuation made progress by saving the shared transport-owner
  packing draft; the code is still uncommitted and unverified. Current source
  and diff checks confirm that draft is preserved. Fresh native process
  enumeration finds no owned Bend process. Fresh sysctl and guard observations
  still report kern.memorystatus_vm_pressure_level=2, warning. The same external
  memory-pressure condition has prevented the required next checks across
  three consecutive goal turns: root execution stopped on warning, the next
  typecheck was refused before launch, and this continuation confirms warning
  remains. There is no live task process to poll or identified owned compiler
  to terminate at that observation.

  Astra low is consulted after the two failed guarded attempts on this same
  condition, before any further attempt. Its read-only primary Apple XNU
  review confirms the sysctl handler converts the internal pressure enum to
  dispatch flags; the guard's warning interpretation is correct. Fresh local
  VM observations show 24 GiB physical memory, about 8.43 GiB occupied by the
  compressor and 2,910.88 MiB swap used. These are current occupancy snapshots;
  cumulative counters do not prove current swapping activity, and another
  memory-availability statistic does not override the kernel warning. No
  pressure check is bypassed, no limit is raised, and no other application is
  closed or terminated.

  During the final blocking audit, pressure returns normal (1), and the fresh
  owned-process scan still finds no Bend job. The audit assertion rejects its
  stale warning assumption before writing a blocked report or calling the
  goal status tool. No goal status change occurs: the full goal stays active.
  The exact guarded pinned typecheck resumes in a new attempt artifact;
  earlier pressure failures remain intact. Subsequent compiler results and
  the remaining emission/Clang/native/Bun/package checks are recorded in this ledger.
  The recovery is an observed external state change, not an effect of a guard
  modification or application termination. All nineteen acceptance boxes
  remain open and the original 1-GiB/pressure/time limits remain.

- 2026-10-03 (Lisbon; shared UDP transport-owner packing draft):
  The preceding turn made progress at `bb0f8a9`, recording complete command
  preservation plus fresh full P-256/native ECDSA evidence. This continuation
  implements the next focused source change recommended by Astra low after
  the repeated native signaling build failures. The shared fixture adapter's
  Driver now stores the entire T.State in a recursive singleton; its only
  external caller, signaling_server, packs/unpacks that internal representation.
  No transport field, candidate, credential, consent/restart owner, packet
  decision or existing scenario is removed. Protocol and wire-effect APIs
  remain unchanged.

  Updates pack the replacement owner before Output.events. Send acknowledgements
  read the clock before unpacking, and restart computes the complete replacement
  before its output/application continuations. Begin_due's original closed,
  Running and probe_due predicate is calculated in a pure helper; IO retains
  the packed driver. Empty/multiple internal singleton owners fail admission
  or stop the signaling connection without transmitting. The complete existing
  live signaling, expiry and browser checks remain required.

  macOS pressure is warning on fresh observations throughout this continuation.
  A real guarded pinned `bend rtc/examples/signaling_server.bend --check-only`
  attempt is refused before launch with reason system-memory-pressure-before-launch,
  exit 125, zero child samples/allocated peak and 0.002s. No compiler is run,
  so this is not a compiler failure or passing type check. No further heavy
  job is attempted while pressure remains warning; the 1024/1024-MiB caps,
  pressure refusal and 120-second deadlines are retained. Source diff checks
  pass, but the draft remains uncommitted and unverified. Guard report, explicit
  command/environment and source hashes are retained under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-03/transport-owner-packing/`.

  Next: when pressure is normal, run this exact guarded type check, then one
  pinned C emission after the source change. Inspect calling-convention width
  and generated size before separately guarded Clang and the complete native
  live/expiry checks. Repeat Bun emission/live checks, then fresh complete RTC
  and crypto gates plus ordinary root validation. Consult Astra low again
  after two failed rounds on any same code/build bug before another attempt;
  a guard refusal before launch supplies no compiler diagnosis. Native/browser
  acceptance, generated-runtime/key lifecycle review, Bend TLS/DTLS, IPv6/TURN,
  SCTP/data/media and integrated direct/relay remain open. All nineteen contract
  boxes remain open and the goal remains active.

- 2026-10-03 (Lisbon; complete check sequences and preserved crypto batches):
  This continuation declares every original crypto and RTC command as an
  ordered resource phase under the existing supervisor. Crypto retains all
  217 commands, including native long/iterated checks, environment overrides,
  redirects and complete corpora. RTC retains all 160 preflight, frontend,
  native/Bun packet/lifecycle and browser commands. Shared temporary outputs
  and failure/cleanup behavior remain. Manifests and the announcement helper
  are explicit Moon cache inputs. Absent Bun/Chrome branches record individual
  optional skips; an installed evaluator/browser failure remains a failure.
  A saved comparison proves all original command arguments and order, with
  only the two crypto oracle phase-reporting flags added.

  Fresh forced crypto execution of the initial 217-phase sequence passes all
  126 mandatory native phases, all 46 Bun emissions and the first thirteen
  Bun oracles. The Bun P-256 oracle then exceeds its whole-phase 120-second
  deadline after 16/609 cases. The guard stops it at 843.693s overall,
  647.5 MiB aggregate / 557.6 MiB individual. This is a failed package gate;
  the full initial manifest and all 185 passed phases remain in the report.
  Earlier evidence already recorded the complete Bun P-256 suite taking
  952.617s and the ECDSA suite exceeding a whole-job deadline.

  P-256 now optionally announces its existing 39 sixteen-case batches;
  ECDSA similarly announces its existing 100 four-case batches across the
  vectors/signing/tampering/rejection/OpenSSL sections. Case generation,
  independent oracles, operation order and assertions are unchanged; no
  corpus is shortened. The complete crypto manifest consequently has 354
  phases: 126 mandatory and 228 optional Bun phases. Default native CLI
  invocations still work. One outer guard retains the 1024/1024-MiB sampled
  caps, pressure checks and lock across every batch; each declared phase
  retains 120s and startup/transitions/cleanup retain ten-second idle bounds.

  Fresh focused P-256 native passes all 609 cases in 4.246s guarded / 25.2 MiB.
  Fresh focused Bun passes all 609 in 876.278s guarded / 876.199s oracle,
  87.2 MiB aggregate / 67.4 MiB individual. All 39 phases pass without skips;
  the longest is 77.103s. Fresh ECDSA native passes all 384 cases and all 100
  batch boundaries in 17.276s guarded / 47.5 MiB; its longest batch is 0.998s.
  This native diagnostic deliberately uses the Bun batch names to validate
  their declared sequence; its command and case report identify native
  executables. It provides no fresh Bun ECDSA acceptance. Emitted programs
  from the forced run are preserved with hashes; arithmetic sources are
  unchanged. Shell syntax, source/corpus preservation and diff checks pass.

  Required ordinary `PYTHONDONTWRITEBYTECODE=1 moon --concurrency 1 run :check`
  is stopped by system memory pressure at 57.877s, 443.3 MiB aggregate /
  358.3 MiB individual, during native crypto compilation through chacha_cli.
  The pressure state is warning; no further heavy job is launched while it
  remains warning. This is not a repository pass or a compiler diagnosis.
  A fresh full 354-phase crypto gate, Bun ECDSA and the full RTC migration
  gate remain pending. No signed-cookie native/browser acceptance is added.

  The user's escalation rule remains: after two failed attempts on the same
  bug, consult Astra low before another attempt. The native signed signaling
  C-emission/Clang memory blocker has prior repeated failures, so Astra low is
  consulted again before re-entering that build through the RTC gate. Its
  generated-C inspection identifies the flattened T.State retained by shared
  ice_transport_effects continuations as the next resource target. Suggested
  next change: retain the complete transport owner in a recursive singleton,
  pack before event/output IO, and calculate begin_due admission in a pure
  helper without holding unpacked state across IO. This advice is not yet
  implemented or validated; it does not justify another unchanged full run.

  Exact commands, source/compiled-input hashes, original command inventories,
  comparison proof, terminal guard reports and raw logs are retained under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-03/crypto-phases/`.
  The primary compiler remains Bend 2.0.27; Bun is actually 1.3.13 despite
  its SDK-directory label. Compiler JIT is disabled with a 128-MiB GC hint;
  Bun evaluators enable optimizing JIT/DFG with a 64-MiB hint or their original
  smaller explicit hints. These are recorded invocation settings, not quotas.
  Next: when system pressure permits, complete fresh crypto/RTC verification
  and the focused native transport packing diagnostic, retaining both targets
  and the full browser/native/direct/relay/media scope. Compose the root
  supervisor without claiming cached/subset checks as final acceptance. All
  nineteen full-stack acceptance boxes remain open; the goal stays active.

- 2026-10-03 (Lisbon; complete HTTP gate under enumerated resource phases):
  The previous turn made progress by committing and freezing the runtime-context
  and signed-cookie milestone at `01b09ed`. This continuation replaces the
  cumulative HTTP check timeout with an ordered phase supervisor. One outer
  guard retains the shared lock, pressure checks and 1024/1024-MiB sampled
  limits across Moon and its observed descendants. Each declared phase keeps
  the existing 120-second deadline; startup, transitions and final cleanup
  have ten-second idle bounds. The guard clock and acknowledged private local
  socket enforce the sequence. Missing, repeated, overlapping, out-of-order or
  failed phases reject the run; only declared optional phases may record a
  skip. A zero task exit cannot substitute for a complete phase sequence.
  Ordinary jobs retain a single total 120-second timeout.

  Darwin sampling, preflight and test cleanup now use in-process libproc
  enumeration and BSD metadata. Public short metadata discovers ancestry
  across UIDs; full birth identity and memory measurements apply to owned
  candidates. Observed ownership survives process-group changes/reparenting,
  PID reuse rejects stale ownership and a birth change during measurement
  fails closed. New owners are registered before a later sample failure;
  cleanup continues through every independently verified owner. Absent/zombie
  observations permit zero memory, while unreadable live owners still fail and
  retain diagnostic metadata. Linux retains RSS/proc birth tracking; this
  continuation's executions are macOS arm64 evidence, not Linux validation.
  A daemon losing its parent before its first observation remains unsupported.

  The first two nested test attempts fail with EPERM on short-lived owned
  processes. Astra low identifies the sampler's setuid-root `/bin/ps` as a
  likely cause. Native full-BSD global enumeration then fails on a cross-UID
  candidate; public short-BSD enumeration fixes that. The next test reaches
  detached-child allocation but its cleanup helper still launches `ps`.
  After the two further failures Astra low is consulted again; both sampler
  and Darwin test helper now avoid that subprocess. Historical exact failed
  PID identity was not captured, so these explanations remain supported
  diagnoses rather than retrospectively proved identities. Four failed jobs
  and all subsequent passing runs are retained. Live-read failures are never
  ignored or treated as a passing sample.

  All 24 final guard/supervisor tests pass under a real outer guard in 9.235s
  at 224.1 MiB aggregate. They cover default/individual/aggregate memory,
  lock exclusion, pressure refusal/termination, interruption, unreadable live
  processes, native identity/PID reuse, partial-sample cleanup, detached-child
  memory/timeout and preservation of unrelated processes, retained memory
  across phases, separate deadlines and incomplete/invalid/failed sequences.
  Shell syntax and diff checks pass. No Bend protocol/effect API is changed.

  `http/server/check.sh` declares thirteen phases in `check_phases.json`,
  shares the original temporary outputs and stops/waits for each fixture before
  ending its phase. Every original non-cleanup line and argument remains in
  order; no check case is removed. The manifest, announcement helper and native
  build adapter are explicit Moon inputs. Fresh
  `PYTHONDONTWRITEBYTECODE=1 moon --concurrency 1 run http_server:check --force`
  under `tools/build_guard.py --phases http/server/check_phases.json` passes all
  thirteen phases with no skips: 243.552s guarded / 242.933s Moon total,
  991.3 MiB aggregate and 681.9 MiB individual. Longest phase is cold checking
  at 40.624s; every phase is below 120s. This includes native/Bun runtime
  context, 4,000 ab requests, all previous HTTP/middleware/stream/shutdown,
  legacy OpenSSL TLS/proxy, auth/CORS, both WebSocket proof scopes and live
  behavior, 200 multipart differential cases plus binary client transfer, and
  every original cold example. The old whole-job 120s failures remain valid
  historical records; this new pass uses explicit per-phase timeout scope.

  Required ordinary `PYTHONDONTWRITEBYTECODE=1 moon --concurrency 1 run :check`
  still times out at 120.014s / 441.8 MiB during crypto compilation through the
  x509_key_cli frontend. It is not a repository pass. Exact commands, wrapper/
  compiler identities, primary source hashes, manifest hash, phase peaks and
  durations, Moon report, failed attempts and raw logs are retained under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-03/phase-supervisor/`.
  Compiler JIT/128-MiB GC and optimizing-JIT Bun/64-MiB GC settings are local
  invocation metadata; these hints do not replace the aggregate guard.

  Next: enumerate crypto's existing frontend/build/oracle steps without changing
  any arguments, corpus scopes or cache inputs, then migrate RTC and compose
  a root phase manifest. Complete native signed signaling and a bounded normal
  Chrome run, generated-runtime/key lifecycle review and the remaining Bend
  TLS/DTLS/data/media/direct/relay work. All nineteen full-stack acceptance
  boxes remain open and the original goal remains active.

- 2026-10-03 (Lisbon; runtime HTTP context and Bend-signed signaling cookie):
  The preceding instruction-only turn was no progress; this continuation changes
  authoritative source and supplies fresh focused evidence. Added
  `Server.serve_out_context(~C, ~handler, context, cfg)` for immutable Data
  configuration supplied at runtime. Original documented serve APIs share this
  accept/parse/respond path with Unit context. The effect-created context
  fixture passes native and optimizing-JIT Bun whole responses, streaming,
  keep-alive socket reuse, 32 concurrent clients and graceful shutdown.

  `rtc/signaling_cookie.bend` owns a synthetic signing key, an exact versioned
  purpose/session/issuing-deadline payload and trusted monotonic expiry. It uses
  Bend HMAC-SHA256, checks Host/Origin before authentication and rejects missing
  or duplicate Cookie fields/matching pairs, malformed/changed MACs, wrong
  claims and raw values beyond 1,024 characters before upgrade/UDP allocation.
  Existing cookie quote/percent decoding is retained. The live fixture mints
  its cookie in Bend and carries the owner through the runtime server context;
  legacy unsigned selector admission is rejected. `GROUNDS_SIGNALING_TTL_MS`
  bounds issuer lifetime to 1–300000 ms; an upgraded connection ends at the
  earlier of its original 45-second limit or the issuer deadline. Restart
  never extends either deadline. The full signaling owner is stored in a
  recursive singleton across IO continuations to reduce generated calling
  convention width. No ICE/protocol state or existing scenario is removed.

  Pinned Bend 2.0.27 native and Bun each pass 374 independent Python-HMAC
  admission/parsing/tampering/expiry cases (0.658s / 0.617s guarded;
  22.9 / 98.5 MiB aggregate). The final packed Bun server passes all 48 actual
  HTTP/WS admission, malformed, restart/reconnect, connection-cap and UDP
  cleanup scenarios (3.723s, 156.1 MiB). Actual 2500-ms cookie expiry closes
  the admitted WebSocket, releases its UDP port, rejects expired and prior
  issuer cookies and permits a freshly minted reconnect (2.538s measured
  expiry; 3.793s guarded, 109.0 MiB). Native/Bun HTTP context runs take
  0.975 / 2.202s at 26.3 / 110.2 MiB. The native policy executable's undefined
  symbols contain no host crypto or dynamic loader; emitted policy and final
  server JS contain no legacy-cookie/host-HMAC references. This cookie-specific
  audit does not prove whole-native-server dependencies, timing or erasure.
  RTC transitive cache-input checks, Python and shell syntax, and diff checks
  pass. New focused checks are mandatory in package scripts.

  All 39 terminal jobs use sequential 1024/1024-MiB sampled memory cutoffs,
  pressure checks, nice 10 and a 120-second deadline. Compiler JIT is disabled
  with a 128-MiB GC hint; Bun evaluators explicitly enable JIT/DFG with a
  64-MiB hint. The final pinned JS emission passes at 834.3 MiB / 16.562s.
  Pinned full native C emission remains above the cap: 128/64-MiB hints and the
  packed-state version are all cut off. Astra low was consulted after the two
  repeated C failures, the two modern binding-ABI failures, repeated Clang
  failures, browser startup failures and the repeated whole-gate deadline.
  A shared runtime-handler hypothesis is rejected by a tiny type-check probe
  (functions are Type rather than duplicable Data), without rewriting the API.
  A non-tail Base Nat.min overflow in the initial live fixture is fixed by
  comparing and retaining the earlier clock; final live/expiry tests pass.

  Isolated official Bend 2.0.34 uses the previously recorded custom-effect ABI
  draft and explicit wildcard bind arguments, including two transitive UDP
  helpers. Primary pin/protocol modules are not upgraded. Its packed C emission
  passes at 906.4 MiB / 50.675s. Compared with the unpacked isolated C, shared
  WL_SIG shrinks from 252 to 229 parameters and output from 16,233,291 to
  14,682,028 bytes. Clang still exceeds the 1-GiB cap, including an O1 trial
  before packing and O3 after packing; no full native signaling success is
  claimed. The emitted calling convention and large flattened pure/IO state
  remain a concrete compiler/resource problem, not a closed runtime audit.

  Real Chrome 154.0.8037.93 verification is incomplete. Default startup exceeds
  the aggregate cutoff (1192.3 MiB sampled overshoot). A diagnostic single-
  process profile stays at 836.0 MiB but Chrome SIGSEGVs before Page.navigate;
  its zero completed rounds do not constitute a protocol test. Astra's ordinary
  multiprocess profile preserves sandbox/Origin/site isolation and reduces
  optional background work, but still hits the cap (1083.8 MiB). No Origin or
  protocol check is relaxed. Diagnostic Chrome arguments are explicitly recorded
  via optional GROUNDS_CHROME_FLAGS. Sampled cutoffs can overshoot; they are
  not kernel-enforced quotas. None of these browser jobs is passing acceptance.

  Required `PYTHONDONTWRITEBYTECODE=1 moon --concurrency 1 run
  http_server:check rtc:check --force` times out at 120.011s / 775.7 MiB after
  HTTP context, hello/probes/timeouts/ab, middleware, streaming/shutdown,
  existing OpenSSL TLS/proxy, auth and CORS evidence. Remaining WebSocket,
  multipart/cold and RTC stages are incomplete. Required
  `PYTHONDONTWRITEBYTECODE=1 moon --concurrency 1 run :check` times out at
  120.013s / 451.0 MiB during native crypto adapter compilation through
  x509_key_cli. Neither command is a passing package/repository gate. Exact
  PATH/wrappers, commands, source/generated hashes, failures and raw logs are
  retained under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-03/signed-signaling-cookie/`.

  Next: implement an enumerated phase supervisor that monitors Moon and all
  descendants under the existing 1-GiB aggregate/pressure limits, accepts each
  expected phase exactly once with its own 120-second deadline and rejects
  overlaps/missing/failed phases. Preserve all check bodies, shared temporary
  outputs, cache/input identity and cleanup; stop/wait for fixture servers when
  their phases finish. Test supervisor invariants before migrating HTTP,
  crypto and RTC gates. Continue reducing the full native calling convention
  and establishing a bounded normal Chrome run. Production key issuance,
  rotation/revocation, generated-runtime timing/erasure, Bend HTTPS/WSS and all
  TLS/DTLS/data/media/direct/relay contract requirements remain open. Every one
  of the 19 full-stack acceptance boxes stays unchecked and the goal active.

- 2026-10-03 (Lisbon; explicit Bend HTTP cookie signing and verification):
  Added `http/core/cookie_bend.bend` with IO `sign`/`verify` result shapes
  compatible with the legacy cookie API, backed by a separate pure Bend
  `cookie_crypto.bend` owner and shared HMAC-SHA256. Ordinary cookie parsing,
  percent encoding, setting/clearing and legacy OpenSSL effects are unchanged.
  The new path runs on native and Bun and authenticates exact UTF-8 bytes,
  including embedded dots, NUL and non-normalized Unicode. It requires a dot
  plus a full 64-character ASCII hex tag, accepts upper/lowercase hex and
  reduces XOR/OR across every MAC byte before returning the value. Invalid
  scalars, framing, hex, keys or signatures reject; current fixtures cover
  valid UTF-8 only, so direct invalid-scalar constructor tests remain pending.

  Independent Python HMAC and two literal RFC 4231 full SHA-256 vectors check
  2,675 cases on pinned Bend 2.0.27 and scoped official 2.0.34, each on native
  and optimizing-JIT Bun. Each final module report contains 226 sign cases,
  226 valid verifications, 226 uppercase tags, 226 wrong keys, 226 changed
  values, 960 changed hex digits, 512 non-hex mutations and 73 malformed
  envelopes. Inputs include key/hash-block boundaries, deterministic random
  sequences and 4,096-byte values. Shared corpus SHA-256 is
  `13bd95e459b92df5901e62f2a0faafa2f5d0be43aa2b93bbca81543d57b559d5`.
  Final focused pinned/modern native runs take 0.880/0.658 s at
  26.6/26.7 MiB aggregate; Bun takes 4.443/2.381 s at 86.2/79.6 MiB.
  Generated pinned C, both JS programs and pinned native undefined symbols
  contain no legacy crypto effect, OpenSSL/host HMAC or dynamic crypto loader.
  Source comparisons and emitted imports do not prove runtime timing safety.

  The first JSON cookie harness crosses the old 320 MiB compiler limit.
  A test-only binary fixture reader retains all cases and lowers final pinned
  native/JS builds to 110.9/53.1 MiB aggregate (2.639/0.536 s); modern is
  111.4/65.4 MiB (1.862/0.329 s). Cookie crypto is an explicit sibling module,
  keeping ordinary HTTP imports independent of cryptographic implementation.
  Existing method tests are unchanged in scope: all 8,320 cases now run in
  256-record batches to release evaluator fixture allocations. Earlier forced
  HTTP runs under 384 MiB fail during the large method suite; after batching,
  all 93 original units pass before the multipart proof hits that old cap.
  A smaller compiler GC hint did not resolve those earlier package failures.

  With the user-requested 1 GiB cap, fresh forced
  `PYTHONDONTWRITEBYTECODE=1 moon --concurrency 1 run http_core:check --force`
  passes in 72.873 s guarded / 72.264 s reported by moon, at 471.8 MiB aggregate
  and 295.5 MiB individual. It checks Base64 and method cases on both backends,
  every original unit/proof scope, legacy signing, the new cookie corpus on
  both backends and all three existing cold-type examples. Nothing is skipped.
  Exact PATH/compiler/runtime wrappers and guard limits are recorded. The
  ordinary source `cookie.bend` remains byte-identical to the prior commit.
  Fresh root `moon --concurrency 1 run :check` under the new cap progresses
  through the crypto frontend/proof phase and into native builds, then times
  out during RSA integer compilation at 120.004 s (435.8 MiB aggregate,
  357.7 MiB individual). Crypto runs fresh; the root gate does not complete.
  The timeout is retained and no repository acceptance is claimed.

  `COOKIE_CRYPTO_REVIEW.md` records pending generated-code/native-optimization/
  Bun-JIT and secret-erasure/lifetime findings. All keys are synthetic;
  application expiration, purpose/session binding, key lifecycle and secure
  signaling remain required. RFC 2104/4231 and errata were refreshed; verified
  2104 erratum 501 and held-for-update 4231 erratum 3853 are editorial and
  do not change the tested full SHA-256 vectors. Artifacts, final module
  identities, independent reports and all failed/successful guard records are
  under `/Users/ozeron/.codex/artifacts/grounds/2026-10-03/http-bend-cookies/`.
  The user clarified that Astra low reasoning should be consulted after
  two failed rounds on the same bug. All nineteen acceptance boxes remain open.
  Next: direct invalid-scalar coverage and runtime/key-owner review, then
  actual Bend-cookie authenticated signaling, complete Bend TLS and HTTPS/WSS.

- 2026-10-03 (Lisbon; user-authorized 1 GiB resource guard):
  The user explicitly requested a one-gigabyte RAM limit. Changed the default
  aggregate owned-process-tree and individual-process limits to 1024 MiB,
  superseding the prior 384/320 MiB compiler and 128/96 MiB evaluator limits.
  Jobs remain sequential under the shared lock, with macOS pressure checks,
  owned-group cleanup, 20 ms sampling and the existing 120-second timeout.
  All 13 guard tests pass in 6.748 s, including default limits, memory and
  individual cutoffs, failed commands, lock exclusion, timeout, interruption,
  child cleanup and pressure refusal/termination. This is a sampled guard
  cutoff; previous reports retain the limits actually used at their time.
  The current continuation runner is archived under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-03/http-bend-cookies/run_job.py`
  and explicitly records 1024/1024 MiB for each new job. The original contract's
  nineteen acceptance gates and 120-second job timeout are unchanged.
  The user also requested an Astra low-reasoning subagent for persistent
  blockers. Its read-only cookie/package review identifies the package timeout
  and direct invalid-scalar constructor coverage as remaining follow-ups;
  no concrete cookie functional defect was found. No extra heavy job ran.

- 2026-10-03 (Lisbon; composed Unicode 3.2 stored-value preparation):
  Added pure Bend literal mapping, optional published B.2 folding, exact NFKC,
  post-normalization prohibition and combining-mark-aware stored SPACE handling.
  Authenticated retained tables use the existing NFKC owner and a new 21,284-byte
  preparation asset. Asset SHA-256 is
  `ad6aa93b373aa4b8a3c46a0ce5098ac93b934704fc85dde1d1b19916c3aa387c`.
  Independent regeneration checks all 1,371 mappings, 396 unassigned ranges
  and 112 definitive mark ranges and reproduces all three generated files.
  C/JS only supply file bytes; Unicode transformations remain in Bend.

  A preflight counts decomposed storage before allocating the full packed
  buffer; a bounded preceding-scalar cache holds at most 72 packed values.
  No full folded linked list is materialized. Whole-input canonical ordering
  and composition precede prohibition. Private-use rejection moves earlier
  only after auditing all 137,468 values for unchanged literal mapping,
  absence from B.2, identity NFKC, zero CCC and no composition participation.
  Other prohibition remains after normalization. SPACE handling compacts
  runs and expands backward in the same array; normative marks, including
  CCC-zero marks and appendix exceptions, determine protected SPACE.
  Existing public property APIs and Name/policy sources remain unchanged.

  Final sealed sources pass on pinned Bend 2.0.27 and scoped official 2.0.34,
  each on native and optimizing-JIT Bun. Each target checks 97,731 cases in
  exact mode and another 97,731 in folded mode: 22 literals, 84,960 official
  normalization input sequences, 1,371 published-fold neighborhoods, 2,048
  deterministic random sequences and 9,330 exhaustive short SPACE/mark/
  deletion neighborhoods. All eight reports are complete, start at zero and
  each reject 14 corrupted/truncated/extended assets. Folded corpus SHA-256 is
  `a4188b91164e8dc4280c8a30e7933ed703fb6af38de624a778aab986df02dfc6`;
  exact corpus is
  `296fd9460a711fcff81b1dcd8b01248a73809f4a46e692b004a7a6bf338da599`.
  Each target also passes 2,244,608 property/mapping regression checks over
  1,122,304 code points, corpus SHA-256
  `a2f70f2d299fa869b928c4bded9524df7ab371d0cf467c048e9bb06dd30b88ca`.
  Nine folded stress cases pass per target, checking every output including
  458,747-scalar prepared compatibility expansion and ordering/stability,
  protected SPACE, full folding, all-space and scalar admission boundaries.
  The 65,535-scalar U+33C6 fixture encodes to 196,605 UTF-8 bytes: it tests
  scalar capacity, not a DER byte-valid Name. Caller-owned transcoding and
  the enclosing 65,535-byte bound remain required. Nine preparation and eight
  property assertions pass both frontends; no kernel verdict is claimed.

  Final pinned/modern builds take 19.063/10.819 s at 175.7/161.4 MiB
  aggregate and 171.8/141.0 MiB individual. Final Bun corpus uses an explicit
  8 MiB GC hint with JIT/DFG enabled. Pinned folded/exact checks take
  102.336/102.348 s at 112.5/110.5 MiB aggregate and 86.6/84.4 MiB individual;
  modern takes 41.703/39.243 s at 100.3/98.4 MiB aggregate and 73.9/72.2 MiB
  individual. Stress explicitly uses a 4 MiB hint: pinned/modern pass in
  17.672/6.109 s at 118.2/109.9 MiB aggregate and 93.5/85.0 MiB individual.
  Earlier growing-buffer, separate-output and partial-cache attempts fail
  within mapping. Diverse exact fixtures require stable private-use admission;
  final pinned stress still crosses the process cutoff with the 8 MiB hint.
  Failed runs are retained, and final accepted evidence names the 4 MiB runs.
  Guards remain unchanged: compiler 384/320 MiB, evaluator 128/96 MiB,
  120 s timeout. Every heavy job is sequential; pressure stays normal.

  Added eleven mandatory preparation build/check steps and the asset metadata
  cache input. Fresh forced crypto still stops during proof/compiler work at
  the aggregate cutoff: 387.9 MiB / 296.6 MiB individual, 33.820 s.
  Fresh root `moon --concurrency 1 run :check` also stops in fresh crypto:
  386.4 / 306.1 MiB, 26.907 s. Neither gate completes; no package/repository
  acceptance follows. Exact commands, runtime wrappers and fresh/cache status
  are retained. No compiler pin, input, memory cutoff or timeout is relaxed.
  Docs/ledger change after gates; the tested 13 source/data/checker inputs
  remain byte-identical. Of 720 prior tracked inputs, only the property module,
  package checks/cache inputs and README/ledger change; 715 remain identical.

  Final source/program identities, all sixteen accepted runtime reports,
  audits and successful/failing command/log/resource records are frozen under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-03/unicode-stored-preparation/`.
  `accepted-verification-jobs.json` identifies the final reports; earlier
  programs/reports remain exploratory. `evidence.json` binds the local commit.

  All nineteen full-stack acceptance boxes remain open. Next: integrate
  string-tag transcoding and Name/RDN equality; resolve package/compiler and
  standalone-fold limits. Continue Teletex/IDNA, subtree/constraints,
  trust/time/hostname, TLS/DTLS and integrated direct/relay browser data/media.

- 2026-10-03 (Lisbon; exact Unicode 3.2 NFKC with packed storage):
  Added the pure Bend NFKC owner, authenticated binary table loader,
  compatibility/Hangul decomposition, stable canonical ordering and blocked
  canonical/Hangul composition. Growing packed scalar/CCC storage retains the
  affine tables and composes in place. Already ordered expansion allocates no
  ordering keys; other input uses four stable radix passes by starter segment
  and CCC, avoiding quadratic mark insertion. Input rejects non-scalars and
  more than 262,140 scalars; empty input remains a valid empty result.
  This admits every prior fourfold B.2 scalar expansion of a 65,535-byte Name
  value. Prohibited/unassigned values remain for the required later check;
  literal mapping, folding and SPACE preparation are not yet composed here.

  The 87,660-byte asset contains 5,143 expanded decomposition rows, 327 CCC
  rows and 917 canonical composition pairs. Bend SHA-256 authenticates exact
  bytes before table construction; OS effects only supply bytes. Added the
  SHA-pinned offline generator, format/provenance JSON, small Bend metadata
  and deterministic gzip of the complete official 3.2 normalization corpus.
  All four generated files reproduce exactly from the archived official
  UnicodeData/exclusions/NormalizationTest sources. Asset SHA-256 is
  `c5253e66db1ca6f2e156702d0e74adf49af620d95862c259d397dd5b821e6541`.
  An independent frozen-UCD audit checks every mapping, every nonzero CCC
  throughout the repertoire and every composition pair. Original Unicode 3.2
  pre-Corrigendum-4 mappings remain for all five historical CJK exceptions;
  using the newer decomposition-property strings would change these results.

  Final pinned Bend 2.0.27 and scoped official 2.0.34 native and optimizing-JIT
  Bun each pass all 84,960 official NFKC results (16,992 rows, all five columns),
  1,050 fixed/deterministic-random sequence cases and seven corrupt/truncated/
  extended-asset rejections. All four official/differential corpus hashes are
  `14af0910376aade482a7c95fd254106efb03db48bdc9a53ce3ed19e484625d19`.
  Each also checks all 1,114,112 Unicode code points plus 8,192 invalid-range
  U32 values: 1,122,304 checks, identical corpus hash
  `2ad5780fe9ae1af30aa613d2c1ea0e07dfa85f016632c0b22e14a395960bb2a2`.
  Separate stress processes check every output of exactly 65,535-byte UTF-8
  inputs: 18-fold U+FDFA expansion (393,210 outputs), reversed combining-class
  ordering and equal-class stability (32,767 outputs each), plus the
  262,140/262,141 scalar validation boundary. All four targets pass all four
  stress cases. Fourteen literal assertions check through both frontends;
  no separate kernel --verdict claim follows. Added all 13 mandatory
  frontend/native/Bun build/check steps and binary/gzip/provenance cache inputs.

  An earlier numeric/String literal-pattern stress fixture inflates pinned
  build memory to 263.3 MiB; enum/Bool dispatch lowers it to 128.9 MiB with
  the final lazy-key core. Final pinned normal/matrix build is 130.9 MiB
  aggregate / 110.4 MiB individual / 8.132 s; modern full build is
  132.7 / 112.2 MiB / 9.336 s. Native official checks take 4.848 s pinned
  and 4.788 s modern at 30.4 / 30.3 MiB aggregate; scalar checks take
  1.241 / 1.261 s at 28.5 / 28.6 MiB. Native stress takes 0.760 / 0.746 s
  at 37.4 / 40.9 MiB. Bun official checks take 48.641 / 25.716 s at
  117.2 / 102.7 MiB aggregate and 93.0 / 79.1 MiB individual.

  Pinned Bun expansion and scalar processes hit the unchanged 96 MiB
  individual guard with the 64 MiB GC hint, including an expansion attempt
  after lazy ordering-key allocation. A 32 MiB GC hint resolves these final
  packed-buffer suites without changing inputs, limits or JIT/DFG settings.
  The mandatory Bun matrix/stress steps set that hint explicitly. Final
  pinned matrix/stress pass at 108.5 / 113.5 MiB aggregate, 86.1 / 88.2 MiB
  individual, 18.032 / 4.478 s; modern passes at 115.5 / 114.7 MiB aggregate,
  93.3 / 89.5 MiB individual, 5.632 / 1.498 s. All jobs remain sequential,
  guards remain 384/320 MiB compiler and 128/96 MiB evaluation, and system
  pressure remains normal. This does not resolve the previous folding
  module's separate large linked-list failure; that test remains mandatory.

  Fresh guarded `PYTHONDONTWRITEBYTECODE=1 moon --concurrency 1 run
  crypto:check --force` still stops during the proof/compiler phase at the
  aggregate cutoff: 392.5 MiB / 300.3 MiB individual, 32.804 s. Fresh guarded
  `PYTHONDONTWRITEBYTECODE=1 moon --concurrency 1 run :check` stops in fresh
  crypto at 391.2 / 316.0 MiB, 32.563 s; only io is reported cached before
  that stop. Neither gate completes or establishes package/repository
  acceptance. Exact environment/PATH/compiler/runtime wrapper are recorded;
  the wrapper preserves the 32 MiB hint for the explicit matrix/stress steps.
  Docs/ledger update after those gate failures; tested production inputs are
  unchanged. All 698 prior inputs outside docs/gate configuration remain
  identical, including every existing Name/policy source and fixture.

  Focused final source/program hashes, corpus/data/regeneration reports,
  exact commands and all successful/failing guard reports are frozen under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-03/unicode-normalization-owner/`.
  Earlier eager-key programs/reports remain exploratory evidence; final
  evidence.json identifies the tested lazy-key source and programs explicitly.
  All existing Name/policy sources and required fixtures remain unchanged.

  The full 19-item goal remains active with every acceptance box open.
  Next: compose streaming stored-value mapping/folding into NFKC, then
  post-normalization prohibition and combining-mark-aware SPACE preparation;
  resolve the remaining compiler/package and standalone-fold limits. Continue
  Name/RDN equality, subtree/constraints, Teletex/IDNA, trust/time/hostname,
  TLS/DTLS and direct/relay browser data/media across the complete contract.

- 2026-10-03 (Lisbon; complete RFC 3454 B.2 mapping coverage):
  Added `unicode32_fold`, a shared retained-array sorted-key lookup, SHA-pinned
  offline generator, generated Nat constants/provenance, all 1,371 published
  B.2 vectors, 13 frontend assertions, a full scalar/short-list CLI/oracle and
  separate large-expansion CLI. All production case folding stays in Bend.
  `code` preserves identity when a valid scalar is absent from B.2;
  `map_code` composes RFC 4518 literal deletion/SPACE mapping before folding;
  `string` preserves multi-scalar expansion order and rejects an invalid
  interior scalar. Legitimate deletion remains distinct from invalid input.
  Tables use 2,742 index integers and 1,561 output scalars; the largest
  published mapping is U+33C6 -> U+0063 U+2215 U+006B U+0067. Added nine mandatory
  frontend/native/Bun build/check steps to crypto/check.sh. No existing
  certificate policy or fixture changes, no runtime host Unicode delegation.

  Refreshed primary RFC 4518/3454 and Unicode Corrigendum 4 pages. The B.2
  oracle uses the published vectors and the independent frozen-3.2 property
  oracle, not the production packed descriptors. Host Python stringprep B.2
  uses current Unicode lower(): it incorrectly changes U+13A0 and
  unassigned-in-3.2 U+1C90 for this profile. Those literal identity cases are
  retained. Three generated artifacts reproduce exactly from the archived
  RFC source. Official 3.2 normalization data, complete vectors, composition
  exclusions and UAX 15 version 22 are prepared; no NFKC pass follows from
  downloading them. Preserve the five pre-Corrigendum-4 CJK mappings when
  implementing the required 3.2 normalization behavior.

  Initial computed-scrutinee/consumed-binder frontend errors are corrected.
  A monolithic generated JS literal overflows Bun's loader stack; splitting
  constants into <=128-integer chunks resolves it. Pinned word-literal
  generation hits the 320 MiB process cutoff. Nat constants with Bend
  conversion at table initialization pass both frontends/backends. Final
  pinned native/JS matrix+stress build is 208.2 MiB aggregate / 204.2 MiB
  individual, 16.848 s; modern is 195.5 / 175.1 MiB, 13.677 s. Both versions
  check all 13 literal assertions; no separate --verdict kernel claim follows.

  Pinned 2.0.27 and scoped official 2.0.34 native and optimizing-JIT Bun each
  pass 2,244,608 folding/literal-plus-folding checks over every Unicode code
  point plus 8,192 out-of-repertoire U32 values, and eight whole-list cases.
  All four scalar corpora have SHA-256
  `1db093543c466dc99878dcfb2b7d1bd9c3e1cbd285387f59465b43eb0c9cf1f2`.
  Both native targets and modern Bun also check all 262,140 outputs of a
  separate 65,535-scalar U+33C6 expansion. Final combined matrix/stress jobs
  are 28.0 MiB / 3.016 s pinned native, 27.7 MiB / 2.801 s modern native, and
  106.9 MiB aggregate / 81.2 MiB individual / 4.477 s modern Bun.

  Pinned Bun completes the scalar/short-list report, then its separate
  expansion process hits the unchanged 96 MiB individual guard at 99.1 MiB
  (124.8 MiB aggregate, 11.267 s for both sequential phases). Earlier
  monolithic attempts, a smaller GC hint and an owned tail-loop reversal
  also fail the guard. A persistent diagnostic capture proves all 8,776
  matrix/short-list lines complete before that monolithic large test.
  The source retains the original long test and mandatory check; neither
  input size nor cutoff is reduced to claim pinned large-input acceptance.
  All successful/failing jobs remain sequential, JIT/DFG stay enabled for
  evaluation, no cutoffs rise, and system memory pressure stays normal.

  Fresh guarded `PYTHONDONTWRITEBYTECODE=1 moon --concurrency 1 run
  crypto:check --force` stops before package completion at the aggregate
  cutoff: 386.8 MiB / 303.6 MiB individual, 32.570 s. Fresh guarded
  `PYTHONDONTWRITEBYTECODE=1 moon --concurrency 1 run :check` also stops
  in fresh crypto at the aggregate cutoff: 385.9 MiB / 305.2 MiB individual,
  32.923 s; io/utf8 are cached. Ledger/docs update after these failed gates;
  tested source inputs are unchanged. These package results do not establish
  package/repository acceptance. Focused fold sources, programs and complete
  corpus reports are frozen under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-03/unicode-normalize/`;
  fold-evidence.json separates final acceptance inputs from exploratory programs.
  All previous Name/policy sources and required cases remain unchanged.

  The full 19-item goal remains active with every acceptance box open.
  Next: implement exact Unicode 3.2 NFKC against the complete official vectors
  with bounded scalar storage, then full stored-value prohibition and
  combining-mark-aware SPACE preparation. Resolve pinned large-list and
  compiler/package limits without relaxing guards; compose Name/RDN equality,
  subtree/constraints, Teletex/IDNA, trust/time/hostname and complete TLS/DTLS,
  direct/relay browser data/media and the remaining full contract.

- 2026-10-03 (Lisbon; full Unicode 3.2 property/mapping foundation):
  Added `unicode32_profile.bend`, deterministic generated range constants/JSON,
  an SHA-pinned offline generator, eight literal proof assertions, a compact
  matrix CLI and independent Python oracle; added all five frontend/native/Bun
  build/check steps to crypto/check.sh. All production property and literal
  mapping logic is in Bend. The 396 RFC 3454 A.1 unassigned intervals and 112
  RFC 4518 Appendix A combining-mark intervals use retained affine arrays and
  bounded binary search. Flags cover literal deletion, SPACE mapping,
  post-normalization prohibition and combining marks. Mapping preserves the
  distinction between legitimate removal and invalid scalar input; prohibited
  characters remain mapped until the required later normalization/check stage.

  Reviewed RFC 5280 7.1, RFC 4518, RFC 3454 and RFC 9549. Official search results
  list verified RFC 4518 errata 860/1757/1758/7213; direct live listing and query
  opens fail, so the search snapshot is not claimed as a fresh direct refresh.
  Applied 860's FE00-FE0F deletion range. The first independent run detects
  U+05BD's Unicode-category/definitive-appendix discrepancy. Audited the entire
  repertoire: the normative appendix excludes that UCD mark and includes
  U+094E/U+094F, which UCD 3.2 leaves unassigned. The oracle now honors the
  explicitly definitive appendix through three recorded exceptions; Bend's
  generated table is unchanged. No unverified spec correction is adopted.
  Initial consumed-binder/forward-definition frontend errors are corrected
  with explicit search state and continuation helpers before adoption.

  Pinned 2.0.27 and scoped official 2.0.34 both build native and JS and check all
  eight literals' frontends. Modern final build passes at 98.0 MiB aggregate /
  77.6 MiB individual, 2.078 s; pinned build/proofs at 122.4 / 118.5 MiB,
  4.251 s. No separate --verdict kernel claim follows. Native and optimizing-JIT
  Bun on both versions each pass 2,244,608 property/mapping checks over all
  1,114,112 Unicode code points plus 8,192 out-of-repertoire U32 values.
  All four corpora are identical: SHA-256
  `a2f70f2d299fa869b928c4bded9524df7ab371d0cf467c048e9bb06dd30b88ca`.
  Modern native is 32.1 MiB / 0.834 s; modern Bun 88.4 MiB aggregate /
  63.5 MiB individual, 2.053 s. Both pinned runtime runs together finish at
  102.4 / 75.8 MiB in 8.536 s. JIT and DFG remain enabled.

  Exact official UnicodeData-3.2.0 and complete NormalizationTest-3.2.0 source
  snapshots are prepared for the next owner. The original capped normalization
  snapshot and an incorrect end-marker assertion are rejected/archived; the
  accepted download is 2,025,975 bytes with the actual END OF FILE marker.
  Source hashes and completeness are recorded; downloading these vectors is
  not a normalization implementation or pass. The offline generator exactly
  reproduces both primary range artifacts, and all tested Bend sources match
  primary. All prior Name/policy sources and acceptance cases remain present.

  Fresh `PYTHONDONTWRITEBYTECODE=1 moon --concurrency 1 run crypto:check --force`
  and `PYTHONDONTWRITEBYTECODE=1 moon --concurrency 1 run :check` stop under
  unchanged aggregate cutoffs in crypto before package completion:
  387.8 MiB / 302.4 MiB individual, 30.772 s; 397.9 / 320.0 MiB, 29.932 s.
  Root io/utf8 results are cached; crypto is fresh. No package or repository
  success is claimed. All heavy jobs are sequential, pressure normal, no owned
  job remains, and bounty/ is untouched. Source/program/corpus hashes, commands,
  regeneration/category audits, source provenance and all resource reports:
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-03/unicode32/evidence.json`.

  Next: add full RFC 3454 B.2 case folding and Unicode 3.2 NFKC using the pinned
  source/vector snapshots; compose stored-value space handling and normalized
  RDN/Name equality/subtree processing afterward. Teletex, IDNA/constraints,
  complete authorization and toolchain/package compatibility remain required.
  This property owner is not yet composed into certificate authorization.
  The full original goal remains active; all 19 acceptance boxes remain open.

- 2026-10-03 (Lisbon; compiler workload reduction and adopted Name policy):
  Traced a diagnostic copy of official Bend 2.0.34 source at exact release commit
  `7d8a3eb036042c6549461054d25a10f26d361c5c`. Re-fetched and hashed bend.ts,
  comp.ts and Base; they exactly match the prior archived official sources.
  Stderr-only stage/definition memory and cache-count instrumentation changes
  no compiler pass and is neither installed nor an acceptance compiler. The
  original focused policy probe checks, then stops while preparing
  `x509_name_schema.printable` for emission. Its 12 U32 literal branches add
  about 26.6 MiB RSS during checking. Replacing those branches with equivalent
  ranges moves the diagnostic past preparation into multiple C emission passes,
  but does not alone qualify the complete CLI. Exact OID comparison and grouped
  standard-attribute predicates then remove the remaining Name pattern workload.
  These traces establish a useful workload cause, not a proven heap leak or
  precise live-allocation attribution. No guard or global toolchain is changed.

  The final scoped official 2.0.34 integrated policy proof frontend, native
  build and JS generation pass at 313.3 MiB aggregate / 309.4 MiB individual,
  24.677 s. The Name proof/native/JS build passes at 192.2 / 188.3 MiB,
  14.896 s, versus the prior final 289.9 MiB aggregate build. Modern native and
  optimizing-JIT Bun each pass 11,195 Name cases (original 8,507 retained plus
  2,688 independent attribute arc/tag/length cases; corpus SHA-256
  `eef7bb5d8d1c18f795de63d1d53d37c89992241fbe3e6f6a823d83a88357d727`)
  and 28,319 complete extension/TLS-purpose cases (original policy matrix
  retained; corpus `ddd2aedb4463a88bb52782fd45dffe312d78bf8b6784f3f487c1638bc9785b12`).
  The four runtime runs finish in 48.588 s at 109.7 / 75.6 MiB under unchanged
  evaluator limits, JIT and DFG enabled.

  Adopted shared Name admission into primary `certificate` and
  `tls13_certificate`: reject malformed issuer/subject schema and an empty
  issuer; require nonempty subjects for CA or cRLSign use even with critical SAN.
  All seven signed admission gaps recorded by the previous baseline are now
  rejected; 13 signed controls and all four TLS role/any-purpose combinations
  pass. The five-field Admission API and exact extension metadata are preserved.
  Unknown attributes/nonempty Teletex remain structurally deferred, so this is
  partial policy processing, not Name equality, trust or peer authorization.
  Fixture `future_profile_expected` becomes `policy_expected`; verified exact
  metadata-only equivalence changes no certificate, key or expected decision.
  Prior independent OpenSSL and frozen native/Bun signature evidence is reused
  from the Name milestone, not represented as a fresh mathematical run here.

  Pinned 2.0.27 now checks the seven literal Name declarations' frontend, but
  Name CLI generation reaches the individual cutoff: 324.7 MiB aggregate /
  320.7 MiB individual, 5.208 s. Pinned whole-policy proof checking itself stops
  at its individual cutoff: 322.5 / 320.6 MiB, 2.927 s. No pinned runtime or
  separate kernel-verdict pass is claimed. Fresh
  `PYTHONDONTWRITEBYTECODE=1 moon --concurrency 1 run crypto:check --force`
  and `PYTHONDONTWRITEBYTECODE=1 moon --concurrency 1 run :check` both stop in
  crypto before package completion: 390.9 / 306.8 MiB, 25.906 s, and
  391.0 / 312.6 MiB, 25.784 s aggregate cutoffs. Root io/utf8 results are cached;
  crypto is fresh. These are failed gates, not repository acceptance.

  Commands, exact source/candidate/primary and generated-program hashes,
  source provenance, diagnostic traces, complete runtime reports and all
  resource reports are frozen in
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-03/compiler-name/evidence.json`.
  All heavy jobs are sequential, limits unchanged, pressure normal; no owned
  job remains. Primary toolchain/effects stay pinned and bounty/ is untouched.
  Next: implement required Name normalization/comparison and constraints from
  the shared schema, continuing compiler/package compatibility separately.
  The full original goal remains active; all 19 acceptance boxes remain open.

- 2026-10-03 (Lisbon; typed Name schema and exact RDN/attribute retention):
  Added one shared `x509_name_schema.bend` owner for Name/RDN/attribute framing,
  complete-DER SET member ordering and selected attribute/string syntax. The
  retention owner `x509_name.bend` first validates the whole Name, then retains
  each exact OID, value tag/body and original attribute encoding with RDN order.
  The certificate adapter extracts actual issuer/subject fields and rejects an
  empty issuer; it permits structurally empty subjects without granting a profile
  or trust decision. Unknown attribute types and nonempty Teletex values remain
  explicitly deferred. Known DirectoryStrings check UTF-8, PrintableString,
  UCS-2 BMPString and UniversalString scalars and character-count SIZE bounds;
  country/serial/qualifier and DC/email attributes require their declared tags.
  The shared parser retains the DER owner's one-octet-tag/65535-octet boundary.
  Country registration, mailbox/DC profiles, T.61 interpretation, prohibited
  character processing, IDNA, normalized Name equality, constraints and complete
  authorization remain required. No CN/service-identity fallback was added.

  Final scoped official Bend 2.0.34 native and optimizing-JIT Bun each passed
  8,507 independent cases (corpus SHA-256
  `4887faa61d6443f8dbffe5d8ce3df36e60508f24ed340a3c1821170b79f5625f`).
  Coverage includes all octets for selected string tags, Unicode/count/tag/SIZE
  boundaries, canonical and malformed OIDs, full encoding versus OID-only SET
  order, equal SET members, preserved RDN order, every sample truncation/bit
  mutation, invalid later attributes, many RDNs/SET members, input bounds and
  actual certificate fields. Thirteen new public synthetic signed fixtures cover
  Unicode, malformed/deferred Names and future empty-CA/CRL controls. All 13
  signatures pass independent OpenSSL 3.6.4 digest verification. Frozen verified
  Bend math programs accept all originals and reject all signature-bit mutations
  per target (26 cases each), independently of Name or certificate authorization.
  Synthetic private keys were destroyed with the generator's temporary directory.
  Fixture `future_profile_expected` values describe unfinished composition.

  Final seven-literal proof frontend, native build and JS generation pass on
  official 2.0.34 (289.9 MiB aggregate / 285.9 MiB individual, 22.172 s).
  These proof frontend checks are not a separate `--verdict` kernel claim.
  Both final runtime corpora pass in one sequential job at 91.7 MiB aggregate /
  60.7 MiB individual, 10.303 s. Final pinned 2.0.27 Name proof checking hits its
  individual cutoff at 327.1 MiB / 2.521 s; no pinned Name pass is claimed.

  Attempted to integrate Name validation and CA/CRL nonempty-subject requirements
  into whole-certificate extension/TLS-purpose admission. Baseline signed controls
  reproduce seven missing rejections. The new whole-policy CLI and focused probe
  hit compiler cutoffs (324.4–331.5 MiB aggregate). Separate adapter/schema owners,
  bounded U32 character counts, a lower compiler GC hint, shared diagnostic CLI
  and shared issuer/subject traversal did not qualify that integration. The shared
  CLI also exposed a Data/Type mismatch and structurally unproved IO-returned
  recursion; its rejected source is archived. The successful Name schema/retention
  seam remains, but all unverified policy changes were archived and restored out
  of primary source. Primary extension policy and its CLI/checker exactly match
  `b1941fa`; its seven admission gaps remain open. No failing formatter/SDK change
  or additional policy runtime claim was adopted.

  Fresh `PYTHONDONTWRITEBYTECODE=1 moon --concurrency 1 run crypto:check --force`
  and `PYTHONDONTWRITEBYTECODE=1 moon --concurrency 1 run :check` both stop during
  crypto checking, before package completion: 394.9 MiB / 28.533 s and 389.8 MiB /
  28.019 s aggregate cutoffs respectively. These are failed fresh gates, not
  package acceptance. All heavy jobs were sequential under unchanged guards;
  pressure stayed normal and no owned job remains. Exact primary/candidate input
  and final program hashes, commands, results, original/reproducible generators,
  rejected source and resource reports are frozen in
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-03/name/evidence.json`.
  Read current RFC 5280 sections 4.1.2.4/4.1.2.6/Appendix A, X.690 8.23/10.2/11.6,
  RFC 6818, RFC 9549 and RFC 4518. This turn's direct/search errata refreshes failed;
  the prior six-verified-entry RFC 5280 snapshot remains the last successful one.
  Next action: resolve compiler compatibility for the complete policy owner so
  the archived Name/empty-CA/CRL changes can receive actual native/Bun integration
  evidence; continue required Name normalization and constraints independently.
  The whole original goal stays active and all 19 acceptance boxes remain open.

- 2026-10-03 (Lisbon; selected SAN admission and empty-subject binding):
  Added `x509_san.bend`, its CLI, six closed literal proof assertions, an
  independent Python oracle and six synthetic public signed certificates.
  Every DNS/IP name is checked, including invalid names after a usable name.
  Complete DNS/IP-only critical SAN is processed; other framed forms remain
  deferred and reject a critical SAN. Empty subjects require a present critical
  supported SAN. Whole-certificate extension/TLS-purpose admission now applies
  this rule while preserving the five-field Admission constructor and exact
  SAN bytes/criticality for subsequent identity processing. A-label spelling is
  checked, not IDNA decoding/validation. Nonempty Name schema, other GeneralName
  schemas, constraints, trust, time and complete peer authorization remain open.
  Native and optimizing-JIT Bun on the isolated official Bend 2.0.34 candidate
  each passed 1,841 standalone SAN and 28,044 whole-policy cases. Existing policy
  cases were retained; malformed SAN expectations now reflect its known handler.
  Independent OpenSSL 3.6.4 strict verification agrees on the supported empty/
  named-subject fixtures; it admits the critical URI fixture that this selected
  owner rejects as unsupported. Frozen previously verified Bend signature
  programs accept all six originals and reject all six signature-bit mutations
  per target; this establishes signature math separately from profile admission.
  Pinned 2.0.27 passes the six literal assertions' proof frontend, but whole SAN
  CLI generation reaches its individual memory cutoff (330.2 MiB aggregate,
  326.3 MiB individual, 6.433 s). No pinned SAN runtime pass is claimed.
  Fresh `PYTHONDONTWRITEBYTECODE=1 moon --concurrency 1 run crypto:check --force`
  and `PYTHONDONTWRITEBYTECODE=1 moon --concurrency 1 run :check` both stop under
  existing compiler limits before package completion: respectively 386.6 MiB /
  29.183 s aggregate cutoff and 397.2 MiB / 28.737 s individual cutoff.
  These are failed gates, not cache or package acceptance. Passing modern runtime
  checks peaked at 106.9 MiB aggregate / 73.1 MiB individual in 41.956 s.
  All heavy jobs were sequential, pressure remained normal, and no owned jobs
  remain. Commands, exact primary/candidate input manifests, build/program hashes,
  corpus reports, signature results and resource failures are frozen in
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-03/san/evidence.json`.
  Read current RFC 5280 SAN/subject text and RFC 9549's updated IDNA/name-constraint
  requirements. The direct RFC 5280 errata listing now works: reviewed verified
  entries 3579/5802/5938/6414/7658/7661; none changes the empty-subject/SAN rule.
  RFC 9525's official refresh still fails; that fresh review remains outstanding.
  Next bounded dependency: validate Name/RDN/attribute schema with canonical SET
  ordering and typed string bounds, then implement Name comparison/constraints
  against updated requirements and compose certificate authorization. Runtime/
  package compatibility remains an independent blocker. The full goal stays
  active; all 19 complete-stack acceptance boxes remain open.

- 2026-10-03 (Lisbon; independent string pipeline diagnostics):
  Four small optimizing-JIT Bun programs independently build/count/reverse
  500,000-character strings, compare two complete outputs, and read/reconstruct
  their first character. All pass within unchanged evaluator limits (67.1–94.3
  MiB aggregate). This narrows the problem but does not identify its cause.
  Applying a similar completion helper to the full JSON candidate, retaining
  original comparisons, still fails at case 33 (500 nested arrays). The prior
  chunk-reading variant and a 256-character block experiment also fail; observed
  marked-suite peaks are 96.5–117.5 MiB. No experimental change was adopted.
  Archived rejected source and verified exact restoration of all 998 baseline
  inputs. All 17 jobs were sequential and pressure remained normal. Commands,
  source/program hashes, logs, resource reports and limitations are in
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-03/json-complete/evidence.json`.
  Primary JSON source is unchanged. Full Bun/package acceptance remains open;
  continue certificate dependencies rather than repeat failing formatter probes.

- 2026-10-03 (Lisbon; isolated official Bun release comparison):
  Compared the recorded 318-case candidate with official Bun 1.4.2, published
  2026-09-05 according to GitHub release metadata retrieved on 2026-10-03.
  Downloaded the macOS arm64 archive into artifacts only, checked both GitHub's
  asset SHA-256 and the release SHASUMS, extracted only its expected executable,
  and confirmed the binary reports 1.4.2 under the guard. Archive SHA-256 is
  `90987a3a16d7db556d886ac3d551e7b6d3edf0a1cf43acaed622e8676be1d12f`.
  Unchanged full conformance still reached the individual cutoff (104.3 MiB,
  0.905 s); the rejected chunk-reading formatter also failed (110.4 MiB,
  0.200 s). Runtime option output confirms JIT and DFG remained enabled.
  These are resource failures, not passing conformance results or evidence of
  the allocation cause. Sequential guards retained all existing limits and
  reported normal pressure. The download itself peaked at 40.0 MiB.
  Commands, release/asset metadata, official checksum verification, binary and
  program hashes, logs and resource reports are recorded in
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-03/bun-comparison/evidence.json`.
  Global tools, SDK sources and `bounty/` remain unchanged. This extends the
  prior diagnostic ledger; it does not qualify a toolchain upgrade or any of
  the 19 full-stack acceptance boxes. The goal remains active. Next bounded
  dependency work: inspect runtime allocation at the formatter/read boundary
  with independent small programs before changing further algorithms; continue
  certificate schema/critical-policy work independently if compatibility gates
  remain resource-blocked.

- 2026-10-03 (Lisbon; bounded JSON formatter/runtime diagnostics):
  Resumed the active full-stack goal from hostname commit `fedfa34`. Verified
  all 998 inputs of that milestone's official Bend 2.0.34 candidate before
  making a separate private copy. Primary source and `bounty/` were untouched.
  Tested separate indentation chunks, 32-character reversal blocks, their
  combination in both formatters, and reading each chunk before joining it.
  Full-suite attempts retain every original case and comparison; the isolated
  phase probe retains original case 33, the 500-level nested-array fixture.
  All runtime attempts kept optimizing JIT enabled and the existing 128-MiB
  aggregate / 96-MiB individual / 120-second cutoffs. No formatter change passed
  the full Bun conformance gate; observed runtime peaks were 98.5–123.0 MiB.
  Changing GC hints, serializing JIT/GC without disabling JIT or DFG, and an
  immediate allocator-purge diagnostic also failed to establish a passing gate.
  Bun validated the serial JIT/GC flags and reported JIT/DFG enabled. The GC/JIT
  log shows full collections and Baseline/DFG/FTL compilation of the small
  character counter. These observations do not identify the allocation cause.
  Additional heap/RSS measurements were inserted only into diagnostic IO.print
  effects; instrumentation changes timing and cannot qualify as acceptance.
  One diagnostic used an invalid option (`gcLogLevel`); Bun rejected it before
  running, and the corrected diagnostic used `logGC=1`.
  No changes from these experiments were adopted. Archived rejected source and
  generated programs, then restored the private candidate and reverified all
  998 hashes. Durable commands, logs, resource reports, program hashes, option
  source references and limitations are in
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-03/json-indent/evidence.json`.
  All 18 jobs ran sequentially, pressure remained normal, and no owned jobs
  remained after cleanup. No full repository/package gate was rerun for this
  documentation-only update; previously recorded gate failures remain open.
  Next action: compare an isolated hash-verified official Bun release with the
  unchanged 318-case candidate and the same guards, retaining optimizing JIT;
  avoid global installation or SDK adoption until complete package gates pass.
  All 19 full-stack acceptance boxes remain open and the goal stays active.

- 2026-10-03 (Lisbon; typed DNS/IP and actual SAN-field identity matching):
  The previous turn made progress with EKU/purpose commit 799f52d. New
  x509_identity.bend supplies pure ASCII LDH/A-label DNS and exact IP comparison.
  DNS comparison folds ASCII case, limits labels to 63 bytes and domains to
  253 bytes, and accepts only a complete leftmost wildcard followed by a
  nonempty suffix, matching one reference label. Partial/multiple wildcards,
  empty labels, invalid reference syntax and prefixes/suffixes cannot match.
  IP comparison requires 4 or 16 valid octets on both sides and exact equality;
  IPv4-mapped IPv6 is not an alias. Reference DNS/IP type is selected before
  matching from the trusted original authority; name matching does not resolve
  DNS, infer a type or fall back across types.

  x509_hostname.bend frames the whole nonempty bounded GeneralNames sequence
  before matching. It checks choice tags, nonempty IA5 encodings, exact IP
  sizes and registered OID canonicality, preserving every entry and its order.
  Its extension/certificate query reads the actual exact SAN OID through strict
  envelope/duplicate/field extraction. Absent SAN never falls back to subject
  CN. OtherName/X.400/directoryName/EDI constructed contents remain raw and
  semantically pending; retaining them is not schema admission. DNS/mailbox/URI
  profile validation, empty-subject/critical-SAN binding, URI/SRV matching,
  Unicode/IDNA conversion/validation, textual-IP reference construction, Name
  constraints, signatures/purpose/time/chain/trust/revocation and full peer
  authorization remain required. Inputs for these matchers use ASCII DNS
  bytes without a terminal root dot or raw network-order IP bytes. No live TLS
  path consumes the result. The critical registry is unchanged: critical SAN
  stays unsupported and noncritical SAN stays deferred until its complete owner
  exists. All earlier crypto/protocol behavior and fixtures remain unchanged.

  Standards: RFC 9525 sections 6.2–6.4 and RFC 5280 section 4.2.1.6. The official
  RFC 9525 errata endpoint and verified query both returned Internal Error;
  a fresh verified review remains outstanding. Fifteen synthetic public-only
  RSA-2048/SHA256 signed certificates are generated and self-signature checked
  by OpenSSL 3.6.4 with explicit time bypass/local fixture trust. The independent
  reference captures 150 X509_check_host/X509_check_ip results; hostname flags
  are NO_PARTIAL_WILDCARDS | NEVER_CHECK_SUBJECT (36). References cover exact,
  case, one-label wildcard, partial/multiple wildcards, A-labels, IPv4/IPv6,
  mixed IDs, DNS-looking IP strings, alternate DNS entries, URI/email-only and
  absent SAN. Type construction remains the application owner's responsibility.
  Fixture private keys are discarded with their temporary directory. No trust,
  time, hostname-plus-chain or signing-erasure acceptance is implied.

  Core comparison passes an identical 5,900-case corpus on native and optimizing
  Bun with both pinned Bend 2.0.27 and isolated official 2.0.34. Each modern
  whole-hostname target additionally passes 2,447 framing/SAN/certificate cases,
  8,347 combined; both combined hashes match. Cases include all octets at
  selected DNS/IP positions, label/domain/IP length bounds, literal policy
  anchors, randomized names, type separation, all GeneralName tags, malformed
  later framing, every truncation/bit mutation of a SAN fixture, 8,192 entries,
  exact 4,096/65,535/65,536 input boundaries, field order and actual certificate
  versions/OIDs/duplicate handling. Six core and three framing closed checks
  pass both frontends; no kernel verdict follows.

  Pinned core generation passes at 113.8 MiB aggregate / 111.7 individual /
  5.675s. Its combined native/Bun checks pass at 90.7 / 61.8 MiB / 8.838s.
  Modern frontend/builds pass at 275.8 / 255.3 MiB / 24.704s; all four modern
  runtime runs together pass at 92.3 / 61.8 MiB / 20.217s. Evaluators retain
  128/96 MiB limits, RAM hint 64 MiB and JIT/DFG enabled. Pinned hostname test
  frontend passes at 294.6 MiB / 2.800s. The larger whole-hostname CLI frontend
  reaches the unchanged individual cutoff (323.6 MiB individual, 325.5 aggregate,
  3.245s), before native or JS generation. No pinned whole-hostname runtime
  pass is claimed. Initial type errors were corrected by declaring shareable
  Name records as Data and explicitly duplicating a consumed tag parameter.

  Required primary gates run sequentially with moon --concurrency 1. Forced
  crypto:check stops during field256 native emission at the aggregate cutoff
  (384.7 MiB aggregate / 295.5 individual / 71.654s). Root :check reaches the
  same unchanged stage and cutoff (385.6 / 306.0 MiB / 69.784s). No complete
  package/repository pass follows. Pressure remains normal; all owned job
  processes are cleaned up after terminal results. No limit is raised. Removing
  the ten new identity/hostname commands reproduces the prior driver exactly;
  it now contains 169 commands. All new cases run in the package driver.

  Sources, 998-input isolated derivative checkout, generated programs, exact
  commands, reference fixtures, hashes and resource evidence live under
  /Users/ozeron/.codex/artifacts/grounds/2026-10-03/hostname/; shared guard command/
  log/resource records remain in compiler-compatibility/validation/hostname-*.
  The previous 990-file EKU checkout is verified before copying and unchanged.
  Final staging removes one extra EOF newline in x509_identity.bend; exact
  byte comparison and separate committed-input hashes record this whitespace-only
  difference from the frozen verified inputs. No behavior changes or test reruns.
  STACK_PLAN.md and its 19 acceptance boxes remain unchanged/open.
  Next: prioritize the outstanding compiler compatibility/adoption gates so
  whole-package verification can advance, then complete SAN/Name/IDNA profile
  processing and compose chain/trust/time/purpose/identity before live TLS.

- 2026-10-03 (Lisbon; EKU and TLS certificate-purpose permission):
  x509_eku.bend decodes complete nonempty canonical DER purpose sequences,
  retaining arbitrary-size OID arcs, unknown purposes, order and repeated
  purpose OIDs. Exact matching happens after the entire payload validates;
  a matching first item cannot conceal malformed later entries. Absent EKU
  permits a valid purpose query. anyExtendedKeyUsage requires an explicit
  application policy; strict callers require the particular purpose. TLS 1.3
  permission intersects serverAuth/clientAuth with digitalSignature whenever
  KU is present. The extension registry now processes EKU in both criticality
  forms, preserving the existing Admission constructor and retaining validated
  EKU, including its critical flag, for purpose processing. Complete-envelope,
  duplicate, unsupported-critical and BC/KU consistency checks run before the
  certificate/extension TLS-purpose helpers. None of this authorizes a peer.

  Standards: RFC 5280 section 4.2.1.12 and current TLS 1.3 RFC 9846 section
  4.5.1.2, published July 2026 and replacing RFC 8446. The official RFC 5280
  and RFC 9846 errata endpoints again returned Internal Error; a successful
  fresh verified-errata review is outstanding. Compatible signature schemes,
  issuer profiles, Name/hostname, trusted time, chain/trust, revocation and
  remaining recognized extension handlers remain separate required work.

  Final standalone native and optimizing-JIT Bun runs each pass an identical
  14,565-case corpus on both pinned Bend 2.0.27 and isolated official 2.0.34.
  The corpus includes every nonempty KU mask crossed with purpose/policy,
  malformed/truncated/mutated DER, arbitrary-size arcs, duplicate purposes,
  absent versus malformed extensions, invalid/exact/prefix queries and exact
  4,096/65,535/65,536-byte bounds. Six new EKU and five existing policy closed
  declarations pass both frontends; no kernel --verdict claim follows.
  Combined pinned native/Bun: 27.462s, 109.6 MiB aggregate / 79.7 MiB individual.
  Combined modern standalone: 26.253s, 75.8 / 44.3 MiB. Both use unchanged
  evaluator limits 128/96 MiB, 64 MiB RAM hint and JIT/DFG enabled.

  Whole-extension/certificate policy passes an identical 24,610-case corpus
  on both modern targets, retaining all 19,515 historical cases while updating
  opaque-EKU expectations to recognized-payload validation and adding purpose
  checks. Nine new public-only synthetic signed fixtures reproduce 18 OpenSSL
  3.6.4 general SSL-purpose results and pass Bend signature math on both
  targets. Their TLS 1.3 references additionally require digitalSignature:
  keyEncipherment-only server usage is permitted by the general OpenSSL purpose
  check but denied for TLS 1.3. Reference time bypass and local fixture trust
  are explicit; these are not hostname/time/trust acceptance. Four prior
  signed unsupported-critical fixtures remain rejected by policy despite valid
  Bend signatures; their four criticality-only controls admit metadata and
  fail signature math. Combined policy checks: 38.131s, 96.4 MiB aggregate /
  64.0 MiB individual, with the same evaluator limits and optimizing JIT.

  Standalone pinned native/JS generation passes in 5.854s at 163.3 MiB aggregate /
  159.4 MiB individual. Modern builds/frontend checks pass in 26.754s at 242.2 /
  238.1 MiB. Pinned combined-policy frontend checks pass, but native emission
  reaches the unchanged individual cutoff (320.3 MiB; 324.3 aggregate; 7.038s);
  separate JS emission reaches 320.8 MiB / 4.473s. No limits are raised or pinned
  whole-policy runtime pass claimed. One initial CLI frontend failure from a
  computed match scrutinee was corrected with ordinary parameter dispatch.
  Two preliminary standalone passes had nondeterministic Python permutation
  ordering; sorted ordering is used in all four final matching corpus hashes.

  Required primary gates run sequentially with moon --concurrency 1: forced
  crypto:check reaches the aggregate cutoff during field256 native emission
  (386.2 MiB aggregate / 298.0 individual / 68.941s); root :check reaches the
  same stage and cutoff (384.4 / 306.7 MiB / 67.633s). These are not passed
  package/repository gates. Every guarded stage reports normal pressure, and
  owned processes are cleaned up after completion/cutoff. The complete original
  check driver is preserved byte-for-byte after removing exactly five new EKU
  commands; it now has 159 commands. No cryptographic math or existing fixtures
  are changed. Compiler upgrade/adoption remains unproved.

  Sources, isolated derivative checkout, generated targets, exact commands,
  source/tool hashes, OpenSSL references and resource reports are under
  /Users/ozeron/.codex/artifacts/grounds/2026-10-03/eku/; reports from the shared
  guard runner remain under compiler-compatibility/validation/eku-*. Previous
  985-file modern inputs are verified before copying and remain unchanged.
  STACK_PLAN.md and all 19 full-stack acceptance boxes remain unchanged/open.
  Next: implement SAN and hostname identity admission, then Name/chain/trust
  composition; continue compiler compatibility and required secure-stack work.

- 2026-10-03 (Lisbon; certificate critical-extension processing):
  The previous goal turn made progress with committed constraint decoders and
  complete Bun ECDSA section evidence. x509_extension_policy.bend now admits
  actual certificate extension fields through the existing strict envelope/OID/
  duplicate decoder, processes basic constraints and key usage regardless of
  criticality, and applies their local consistency policy. Its registry uses
  exact OID contents; longer prefixes cannot masquerade as recognized IDs.
  Unsupported critical entries reject the result. Other noncritical entries
  retain exact OID/payload bytes and their original order for later identity and
  purpose owners. Recognized payload bytes and criticality flags also survive.
  Absent extensions are distinct from malformed or empty present sequences.
  This is a partial processing result, not a certificate or peer authorization.
  EKU, SAN, identifiers, Name constraints, policy and remaining required handlers,
  issuer criticality, key/purpose profiles, Name/hostname, time, chain/trust and
  revocation composition remain open. No live TLS path consumes this result.

  Final independent native and optimizing-JIT Bun runs using isolated official
  Bend 2.0.34 each pass an identical 19,515-case corpus. It includes every
  recognized payload regression in both criticality forms, 8,176 bit/criticality/
  order/policy combinations, malformed and duplicate envelopes, exact input
  boundaries, deferred-field order, certificate-version extraction and every
  truncation of a complete fixture. Four existing signed-invalid certificates
  pass the unchanged Bend mathematical verifier but fail extension policy due
  to unsupported critical entries. Four controls changing only those critical
  flags pass extension processing and fail Bend signature verification; the
  policy and signature obligations remain distinct. The final combined runs
  take 27.335s and peak at 108.2 MiB aggregate / 81.1 MiB individual, under the
  unchanged 128/96 MiB evaluator limits and 64 MiB RAM hint, JIT/DFG enabled.
  Modern build passes at 223.7 MiB aggregate / 219.7 MiB individual / 18.349s.
  Both versions pass frontend checks and five closed declarations (272.4 MiB
  aggregate / 4.276s); no kernel verdict is claimed.

  Pinned 2.0.27 native emission cuts off at 320.4 MiB individual / 7.586s.
  A smaller 64 MiB compiler RAM hint still cuts off at 320.2 MiB / 7.491s.
  Separate JS emission also cuts off at 321.0 MiB / 3.762s. These are incomplete
  pinned builds, not passing runtime evidence; the compiler pin remains intact.
  Required primary `moon --concurrency 1 run crypto:check --force` reaches
  aggregate cutoff at 391.2 MiB / 307.0 MiB individual / 25.135s. Milestone
  `moon --concurrency 1 run :check` cuts off during crypto frontend checks at
  384.5 MiB / 310.4 MiB individual / 24.386s. Both have terminal reports and
  normal pressure. Sampled overshoot is retained; no memory/time cutoff changes.
  The first source-evidence capture also hits the small evaluator cutoff while
  hashing binaries in memory (107.8 MiB / 0.339s). Streaming SHA-256 capture
  resolves that artifact-only allocation, passing at 23.7 MiB / 0.391s.
  All 149 previous check commands remain in order; five additions make 154.
  Preexisting crypto/IO/math/vector sources and all 981 prior isolated inputs
  remain unchanged. New inputs freeze 157 primary and 985 isolated files, with
  four identical new sources. Used mathematical verifier binaries and compiler/
  Base/Bun/Moon identities match the earlier frozen evidence.
  RFC 5280 section 4.2 was refreshed; both official verified-errata forms return
  Internal Error, so no correction is inferred. Artifacts:
  /Users/ozeron/.codex/artifacts/grounds/2026-10-03/extension-policy/, including
  evidence.json, source-snapshot/, primary-inputs.json, modern-inputs.json, final
  native/Bun reports/targets and scripts. Unique extension-policy-* guard command,
  log and resource files remain in the compiler-compatibility validation directory.
  Next: implement EKU purpose admission/intersection and extend the registry,
  then SAN/hostname and Name/chain/trust composition. Continue compiler/package
  resource integration and the outstanding optimizing-JIT JSON/extension gates.
  All 19 full-stack acceptance boxes remain open; the goal remains active.

- 2026-10-03 (Lisbon; Bun crypto completion by sections and constraint payloads):
  The resumed inventory finishes all 25 remaining original Bun commands with
  optimizing JIT/DFG enabled, unchanged 128/96 MiB limits and 120-second jobs.
  Twenty-three pass, including all 4,825 certificate-signature cases at
  98.391s / 98.9 MiB aggregate / 70.4 MiB individual. The complete ECDSA command
  times out at 120.018s after vectors/signing; every case subsequently passes
  through its five existing sections. Their 384 case/group counts and eight
  OpenSSL interop actions match the complete original native suite exactly.
  The largest section takes 85.839s; maximum aggregate peak is 103.7 MiB.
  Original extension-envelope testing hits the individual cutoff at 102.9 MiB
  (133.3 MiB aggregate sampled overshoot) after 31.582s. Its optimizing-JIT
  acceptance remains open. All original source/program hashes are unchanged.
  Section evidence does not turn the timed-out command into a package pass.
  Durable continuation evidence remains in the 2026-10-02 compiler-compatibility
  validation directory: crypto-bun-continuation-evidence.json,
  crypto-ecdsa-bun-sections-evidence.json and their per-command reports/logs.

  x509_constraints.bend adds strict basic-constraints and key-usage payload
  decoders, exact arbitrary-size nonnegative path limits, bounded-depth
  comparison without wrap, and a local encoded-payload consistency boundary.
  Present malformed payloads cannot become absent extensions. DER default
  FALSE must be omitted; path limits require cA TRUE; key usage requires at
  least one of nine known bits, minimal named-bit-list length and zero padding.
  Local policy checks keyCertSign/cA, a present usage's keyCertSign when a path
  limit exists, and rejects undefined encipherOnly/decipherOnly without
  keyAgreement. Absent usage is not an issuer-profile authorization. The
  caller still owns non-self-issued intermediate counting. No trust, Name,
  critical-extension handling, hostname, revocation, clock or chain decision
  is supplied by these payload helpers.
  Final native and optimizing-JIT Bun runs on both pinned Bend 2.0.27 and
  isolated official 2.0.34 each pass the same 7,657 independent integer/bit-set
  cases, including RFC Appendix C payloads, all 511 nonempty usage combinations,
  1,533 cross-field combinations, absence/error separation, arbitrary-size limits,
  malformed/padding/length/truncation cases and the exact 65,535-byte bound.
  Eight closed declarations pass frontend checking; no kernel verdict is claimed.
  The final build stage peaks at 156.4 MiB aggregate / 152.3 MiB individual
  (10.413s). All four runtime runs together peak at 78.1 MiB aggregate /
  49.6 MiB individual (18.803s), with the unchanged 64 MiB RAM hint.
  Every preexisting crypto/math/IO source is retained. All 144 prior check
  commands remain in order; five additions make 149. Frozen inputs cover 153
  primary files and 981 isolated source/generated files, with the four new
  sources identical between trees. Compiler adoption is not implied.
  Required primary `moon --concurrency 1 run crypto:check --force` cuts off
  at 394.4 MiB aggregate / 309.1 MiB individual / 23.102s. Milestone
  `moon --concurrency 1 run :check` reaches the field256 native frontend and
  cuts off at 386.1 MiB aggregate / 311.7 MiB individual / 67.516s. Both are
  terminal failures under normal pressure, with sampled overshoot recorded;
  package/root acceptance remains incomplete. No limits were increased.
  RFC 5280 sections 4.2.1.3/4.2.1.9 and Appendices B/C were refreshed. Both
  official verified-errata forms returned Internal Error; no correction is inferred.
  New artifacts: /Users/ozeron/.codex/artifacts/grounds/2026-10-03/constraints/,
  including evidence.json, primary-inputs.json, modern-inputs.json, four final
  runtime reports/targets and build/check scripts. Guard command/log/resource
  files retain unique constraints-* names in the existing validation directory.
  Next: admit known extension payloads through an explicit critical-extension
  policy owner, then implement Name/SAN/hostname and chain/trust composition.
  Continue bounded package integration and diagnose optimizing-JIT extension
  and JSON boundaries without removing cases or increasing limits. All 19
  complete-stack acceptance boxes remain open; the full goal stays active.

- 2026-10-03 (Lisbon; bounded crypto inventory and streaming SHA-256):
  The previous turn made progress: 7a1bdab fixes traffic-owner test imports and
  adds positive controls. Isolated staging now preserves all 139 original
  crypto commands in order, with one existing guarded job per command. Every
  frontend check, all 32 native builds, all 26 native differential/lifecycle
  checks and all 32 JS emissions pass. This is staged command evidence, not a
  forced Moon package result. The first Bun runtime check cuts off at 131.1 MiB
  aggregate / 105.7 MiB individual / 0.764s. A diagnostic identifies the original
  published million-byte SHA-256 vector; that vector is not reduced or removed.
  sha256_stream.bend adds an affine byte-aligned owner with fewer than 64
  pending bytes, exact two-word length accounting, strict malformed/overflow
  rejection and one final padding operation, reusing unchanged Bend compression.
  sha256_file.bend performs 4 KiB OS reads through that owner, tolerates short
  reads and closes on EOF/error/rejected state. Two decreasing IO counters cover
  more one-byte reads than the SHA length limit. The existing file CLI now uses
  this path; whole-list SHA/HMAC/HKDF APIs and implementations are unchanged.
  Original native/Bun SHA-256, HMAC and HKDF checks pass: 29/11 cases, three
  RFC 5869 cases and seven length boundaries, including the million-byte vector.
  With isolated Bend 2.0.34, Bun peak is 80.5 MiB aggregate / 57.0 MiB individual
  / 2.185s. Optimizing JIT/DFG and the 64 MiB RAM hint remain enabled.
  Native and Bun additionally pass 275 chunk partitions, 30 exact length
  encodings, 12 malformed/carry/overflow guards, two real FIFO streams, IO refuel
  and four error cases. In each engine one process completes 200 ordinary hashes
  and 200 counter-overflow failures under a 64-descriptor limit. Two valid owner
  probes compile; copying and repeated finalization fail at the intended location.
  An initial test-adapter failure used raw IO.args on Bend 2.0.34; its checked
  adapter now uses the existing Io.args wrapper. Pinned 2.0.27 keeps IO.args.
  A clean primary-derived pinned checkout passes the same native/Bun original
  and streaming checks at 94.5 MiB aggregate / 69.3 MiB individual / 5.677s;
  its largest build stage is 311.2 MiB aggregate / 307.3 MiB individual. Primary
  source matches this checked proposal. check.sh retains all 139 commands in
  order and adds five checks/builds (144 total); existing Moon globs cover them.
  Primary `moon --concurrency 1 run crypto:check --force` reaches aggregate
  cutoff at 393.7 MiB / 22.137s. Milestone `moon --concurrency 1 run :check`
  reaches the field256 native frontend then cuts off at 384.7 MiB / 65.823s.
  Both have normal pressure and terminal guard reports; neither is acceptance.
  Cutoffs stay unchanged, and sampled overshoot is recorded rather than hidden.
  Both official RFC 6234 errata queries return Internal Error; refreshed sections
  4.1/6.2 supply the padding/length specification, with no new correction inferred.
  Durable artifacts under
  /Users/ozeron/.codex/artifacts/grounds/2026-10-02/compiler-compatibility/validation/:
  crypto-stages/plan.json and per-stage logs/resource reports, sha-stream-evidence.json,
  sha-stream-pinned-final-inputs.json, sha-stream-properties-lifecycle-resource.json,
  sha-stream-pinned-full-checks-resource.json, and the
  sha-stream-primary-crypto-forced / sha-stream-primary-root-check command/log/resource
  reports. Parent sha-stream-inputs.json freezes 977 source/generated inputs.
  Next: finish the remaining 25 original Bun crypto checks with preserved source
  and executable identities, then integrate bounded full-package verification.
  JSON Bun conformance, other package/root gates, compiler adoption, secret
  timing/erasure review and all 19 full-stack acceptance boxes remain open.

- 2026-10-03 (Lisbon; bounded JSON follow-up and traffic-owner test fix):
  Two JSON experiments are rejected and archived: private per-mode fast-parser
  dispatch still exceeds Bun's individual cutoff, and streaming fixture scoring
  still cuts off at 115.3 MiB / 0.417s. The native-passing JSON candidate is
  restored exactly. Verification covers all 972 expected source/generated
  inputs; only the separate crypto type-checker fix below differs. The original
  114-file compatibility-json.patch and native gate freeze remain unchanged.
  A diagnostic reaches original case 33, i_structure_500_nested_arrays.json.
  Phase markers show fast pretty construction completes before the reference
  pretty construction cuts off at 116.8 MiB / 0.410s under the 64 MiB RAM hint.
  Reading the fast output first changes the last completed phase but still cuts
  off. Official comp.ts lines 345-354 represent String with native JS strings,
  concatenation and codepoint-aware slices; per-character SCon heap objects are
  not inferred for Bun. These markers do not establish the precise string/JIT
  allocation cause. Unchanged full-suite runs with 8 and 4 MiB RAM hints also
  cut off, at 102.1 MiB / 0.205s and 99.6 MiB / 0.156s respectively. Optimizing
  JIT remains enabled and no memory/time cutoff is increased. No experimental
  parser or fixture-loop change is retained; full Bun conformance stays open.
  Fresh isolated `moon --concurrency 1 run crypto:check --force` identifies an
  import failure in traffic_type_check.py before its intended ownership test:
  a system temporary fixture imports through the hidden .codex artifact path,
  which Bend 2.0.34 rejects. Module-local temporary fixtures now import
  ../traffic.bend. Both original copy probes and the direction-confusion probe
  remain unchanged; two positive retirement controls prevent a general compiler
  failure from masquerading as successful negative tests. All five probes pass
  on isolated Bend 2.0.34 (92.8 MiB aggregate / 1.750s), isolated pinned 2.0.27
  (69.7 MiB / 2.042s), and the primary pinned-compiler sources (69.1 MiB / 2.135s).
  A full isolated retry passes the frontend/ownership checks and reaches native
  X25519 compilation, then the unchanged guard timeout stops it at 120.007s:
  322.8 MiB aggregate / 238.8 MiB individual, normal pressure. This is an
  incomplete gate, not crypto package acceptance or mathematical validity.
  Durable evidence lives in
  /Users/ozeron/.codex/artifacts/grounds/2026-10-02/compiler-compatibility/validation/:
  json-resource-followup-evidence.json, json-followup-source-evidence-resource.json,
  crypto-traffic-owner-positive-controls-resource.json,
  crypto-traffic-owner-primary-pinned-resource.json, and
  crypto-forced-local-owner-imports-command.json/-resource.json/.log.
  traffic-owner-inputs.json freezes the isolated derivative candidate at the
  parent artifact root. Next: preserve every crypto command in bounded build
  and evaluation stages, then complete fresh native/Bun package verification.
  JSON Bun memory diagnosis, remaining package/root gates, compiler adoption and
  all 19 full-stack acceptance boxes remain open. The full goal stays active.

- 2026-10-03 (Lisbon; full isolated native JSON gate passes):
  The interrupted run is terminal, not restarted: its guard records aggregate
  cutoff at 388.8 MiB / 35.163s, with no surviving owned jobs. The goal runtime
  contained no active objective after interruption; the user's resume request
  restores the full 19-item contract without narrowing scope. Primary is 1bed380,
  clean except unrelated bounty/. Pressure is normal and swap has fallen to
  about 3.02 GiB; no attribution to a specific process is inferred.
  Stage isolation establishes that original suite frontend checking passes at
  109.0 MiB / 1.603s, C emission at 311.4 MiB / 7.202s and separate clang at
  258.5 MiB / 2.317s. The standalone original native suite passes all 318 cases
  at 36.7 MiB / 0.715s. An earlier runtime launch was refused on warning-level
  pressure, before execution; it is retried only after fresh normal pressure.
  scripts/native.sh separates Bend emission from clang with the official CPU
  flags, honors CC and rejects device/GPU framework dependencies for these CPU
  fixtures. Check and integration command substitution reverses exactly; no
  checks or cases are removed. Moon's retained heap still makes aggregate
  conformance emission too large. A diagnostic dynamic-input suite runner emits
  C at 202.3 MiB / 5.989s, establishing that embedding the corpus adds substantial
  compiler work; this diagnostic is not suite acceptance.
  gen_suite.py retains the complete original pure cases() definition and every
  expression, but additionally writes ignored suite-data/ files containing kind,
  original name and exact input bytes. The Bend loader reads all 318 fixtures
  before the one unchanged S.run. Native and Bun 1.3.13 loaded-value dumps match
  independently recovered original names, expectations, every text codepoint,
  invalid UTF-8 byte and case order. All three large rep expressions are retained
  and independently materialized. Unknown kind, missing LF, empty name and
  missing file fail before partial output on both engines: eight checks pass.
  A dump-verifier splitlines mistake is preserved; LF-only framing correctly
  retains legal Unicode line-separator data. No parser is used to read a manifest.
  Fresh isolated `moon --concurrency 1 run json:check --force` passes the entire
  native gate: four cold fixtures, six metadata regressions, unit/proof frontend
  checks, 318 conformance cases, all stress/big-number reads/CLI checks and 706
  independent integration cases (376 valid, 330 invalid; seed 1). Stress includes
  100k escapes/items/digits/depth, 20k fields and 4,003,999-char pretty output.
  Task 64.618861083s / guard 65.268s, 304.1 MiB aggregate / 218.6 MiB individual,
  normal pressure, full hash
  `808f1e3750772567cae777520e17c232c95b8adfcb0165f5e453ed57ae0c5887`.
  Saved Moon metadata proves passed exit-zero task execution with cache disabled;
  its timestamps are October 2 UTC. Proof checks remain frontend checks, not
  --verdict kernel validity. Only README fixture documentation changes afterward;
  reverse removal recovers its exact gate hash. All other gate hashes match.
  Additional full Bun conformance remains incomplete: JIT/DFG-enabled runs hit
  the unchanged 96 MiB individual cutoff at 111.3 MiB / 0.464s (64 MiB RAM hint)
  and 102.1 MiB / 0.425s (32 MiB hint). A diagnostic prints both load-start and
  fixtures-loaded before its 111.5 MiB cutoff, locating remaining work in parser
  execution rather than fixture loading; it does not identify the exact allocator
  or JIT operation. No cutoff increases, JIT disabling or compiler patch is used.
  Native gate success is not reported as Bun, compiler adoption or full-stack
  acceptance. Source-only prepare-json.py replays all 972 source/generated hashes
  in 1.448s / 43.9 MiB and emits a 114-file compatibility-json.patch that applies
  to primary without edits. Generated fixtures are rebuilt, not added as duplicate
  tracked corpus files. Previous 93/97/99-file recipes, patches and freezes remain
  immutable. Official compiler/Base hashes are refreshed unchanged; selected Bun
  is verified as 1.3.13 despite its 1.1.42 directory name.
  Artifacts under the existing compiler-compatibility/ root include
  validation/json-full-gate-evidence.json, json-runtime-fixtures-moon-metadata/,
  json-runtime-fixtures-identity.json, native-lf/bun loaded-value identity files,
  json-fixture-failure-evidence.json, json-gate-provenance-and-bun-stage.json,
  each named job's command/log/resource reports, json-inputs.json, json-files/,
  prepare-json.py, json-preparation.json and compatibility-json.patch.
  Next: reduce the large generated step dispatch's Bun parser workload while
  preserving all 606 transitions, six APIs and every case; locate the exact
  resource cause and rerun affected native/Bun gates. Finish all remaining forced
  package/root checks before pin adoption. Primary stays Bend 2.0.27; all 19
  full-stack gates remain open, with bounty/ untouched and unstaged.

- 2026-10-02 (JSON cold gates pass; conformance build still bounded out):
  Fresh process inventory finds no surviving Bend/Bun/Moon/compiler jobs and
  macOS pressure is normal; retained swap is 4.64 GiB. All heavy work stays
  sequential, nice-10, with unchanged 384/320 MiB compiler/package or 128/96
  MiB standalone budgets, 120-second deadlines and fail-closed pressure checks.
  These are sampled cutoffs, not OS allocation quotas; overshoot remains
  possible. No global compiler/runtime change or cutoff increase is made.
  The isolated shared character classifier retains all 606 original transition
  templates and six public parser headers. It uses 38 literal codepoint tags,
  an Other tag and a balanced U32 comparison tree with at most six comparisons.
  All 263 source probes agree; this is source evidence, not executed classifier
  conformance. Curried continuations still exceed the individual cutoff.
  Unary-record continuations and work records containing the input tail check
  but fail the mandatory cold gate. Their generated C retains shared string
  constructors; all rejected sources and reports remain archived.
  The latest layout keeps the input separate from the work state, makes direct
  recursion consume the input first, and calls that driver directly at both
  compact/pretty entry points with identical input/fuel. Fatal/EOF/fuel order,
  raw characters, transition bodies, counters and immediate errors are retained.
  The CLI frontend now passes in 1.450s / 108.3 MiB aggregate; its actual emitted
  C cold gate passes in 3.096s / 201.1 MiB aggregate, without shared constructors.
  The first full forced JSON check passes all four cold fixtures, six metadata
  regressions and unit frontend checks, then rejects old internal helper names
  such as arr_f.3 under the official 2.0.34 identifier grammar. Collision-checked
  renames to arr_f.n3 and corresponding helpers in four proof files and the
  layout generator reverse exactly to the original files; claims, bodies,
  literals and comments are unchanged modulo those identifiers. The proof
  generators reproduce all 652 frozen inputs. PROOF --check-only passes in
  14.715s / 173.0 MiB. These are frontend checks, not --verdict kernel validation.
  The subsequent forced JSON gate passes those cold/unit/proof stages, then
  stops while building the unchanged 318-case native conformance suite: aggregate
  cutoff at 385.1 MiB / 38.823s, maximum individual 319.8 MiB, normal pressure.
  A fixture-helper extraction preserves every case expression/order exactly
  but still crosses the individual cutoff at 320.1 MiB / 6.480s. It is rejected,
  archived and restored; all 652 proof-name candidate hashes match again in
  0.239s / 82.4 MiB. Conformance runtime, stress, reads, CLI and independent
  integration stages have not run. No full JSON or repository acceptance is
  claimed. The killed Moon run has no completed report; copied cache metadata
  is explicitly stale, with the guard report and live log recording the attempt.
  Evidence remains under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/compiler-compatibility/`:
  validation/json-cold-progress-evidence.json, json-char-input-direct-source-identity.json,
  json-proof-helper-names-identity.json, json-proof-helper-names-inputs.json,
  json-suite-helpers-identity.json and each named job's command/log/resource report.
  The current unadopted candidate differs in seven files from the accepted
  99-file router draft; that patch/recipe and all historical freezes are unchanged.
  Release string literals use lazy Lit nodes, so character pattern expansion
  does not establish the remaining allocation site. Next: isolate suite
  --check-only from C emission under the same budgets, then reduce the verified
  workload while retaining all 318 cases before the full JSON and remaining
  forced package/root gates. Primary remains pinned to Bend 2.0.27; all 19
  complete-stack requirements stay open. bounty/ is untouched and unstaged.

- 2026-10-02 (JSON pattern expansion diagnosis; failed layouts retired):
  The preceding user-triggered turn verified that no Bend/Bun/Moon/clang jobs
  remained and macOS memory pressure was normal; retained swap was 4.8 GiB.
  This continuation keeps Bend builds stopped and inspects the unmodified
  official 2.0.34 frontend source. Four previously attempted isolated JSON
  layouts remain unaccepted: mutually referring per-mode helpers fail the
  filled-definition rule; mode-before-fuel nesting fails the consumed-binder
  rule; fuel-first nesting and continuation helpers still cross the unchanged
  320 MiB individual cutoff during --check-only. The continuation attempt is
  terminal at 322.3 MiB / 4.260 seconds. The unchanged JSON specification alone
  passes frontend checking at 88.5 MiB / 1.204 seconds. None of these results
  completes the JSON package, runtime, conformance or proof gates.
  Official parse_patt expands character literals through Chr/U32 into 32-bit
  WCon/Bool patterns. A source-only topology model counts 19,892 Mat nodes per
  original loop versus 517 with hypothetical atomic character tags; NInt alone
  expands its 23 transition rows to 2,362 nodes. An independent diagnostic calls
  the release's unmodified match_flatten with original patterns and synthetic
  bodies. All 70 per-mode comparisons agree, covering all 35 modes and 303
  transitions in both representations. It passes in 0.273 seconds / 72.2 MiB
  under the unchanged standalone 128/96/120 guard, with normal pressure.
  No Bend loader, type checker, emitter or package build runs in this diagnostic.
  It uses Bun 1.3.9 with evaluator JIT enabled and collects only discarded
  synthetic diagnostic trees between modes. This confirms pattern topology,
  not the precise compiler allocation site or a fix. Splitting modes retains
  the expanded literal patterns; a classifier is the next hypothesis to test.
  The earlier diagnostic attempts are retained: Python initially rejects Bend's
  braced Unicode escape, Node cannot locate the release Base, and a full-matrix
  Bun count crosses the 96 MiB individual cutoff at 105.2 MiB in 0.273 seconds.
  No cutoff is raised; sampled limits can overshoot. Mode-sized analysis retains
  every original transition and is not a reduced parser acceptance suite.
  All four rejected layouts preserve 606 generator transition templates and
  six public headers, which does not establish their dispatch or runtime
  semantics. The latest experiment and its full source freeze are archived;
  the disposable checkout is restored to all 652 exact router-pair draft hashes
  in 0.231 seconds / 24.8 MiB, without compilation. Primary parser, compiler
  pin, accepted 99-file draft patch and previous gate freezes are unchanged.
  Evidence under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/compiler-compatibility/`
  includes official-source/frontend-source-provenance.json,
  validation/json-match-analysis.json, json-match-release-mode-crosscheck.json,
  json-frontend-diagnosis-evidence.json, json-continuation-inputs.json,
  json-static-match-* logs/resource reports and json-restore-tested-draft-*;
  history/ retains every rejected layout and failed diagnostic source.
  Next: implement a shared Bend character classifier in the isolated draft,
  preserving raw chars, fatal/EOF/fuel precedence, all six APIs, every original
  transition and all parser/layout/proof/conformance cases. Establish its
  unchanged-budget frontend/runtime gates before rerunning the full JSON gate
  and remaining forced package/root checks. Primary remains Bend 2.0.27;
  all 19 full-stack requirements, secure direct/relay data/media and timing/
  private-secret ownership remain open. bounty/ stays untouched and unstaged.

- 2026-10-02 (compiler recipe replay, three more forced gates, JSON cutoff diagnosis):
  The preceding turn made progress in 5d43366 with fresh isolated HTTP core and
  UTF-8 gates. Current primary is clean apart from unrelated bounty/. Fresh
  normal-pressure evidence allowed the previously refused source-only replay:
  prepare-gates.py reconstructs all 652 tested inputs exactly, emits a 97-file
  primary-applicable patch, and passes in 1.846 seconds / 33.3 MiB aggregate.
  Sequential forced IO and HTTP wire checks then pass under unchanged
  384/320/120 compiler/package cutoffs: IO task 427ms / guard 1.139 seconds,
  154.2 MiB aggregate / 74.0 MiB individual; HTTP wire task 32.527 seconds /
  guard 33.094 seconds, 240.8 MiB aggregate / 123.8 MiB individual. Moon
  metadata records fresh passed task execution/exit zero for both.
  Router's first forced gate passes units but rejects the law helper Pair,
  which collides with the new Base.Pair. In the isolated draft only, seven
  law-helper identifiers and two proof references become SegmentPair; reverse
  substitution reproduces both original files exactly. No routing implementation
  or case is altered. The complete forced router gate then passes: task 2.816
  seconds / guard 3.409 seconds, 192.2 MiB aggregate / 75.4 MiB individual,
  including the original laws, route example and cold check. The earlier failure
  is retained. The two helper files are absent from IO/HTTP wire's recorded
  task hash inputs, preserving their unaffected fresh evidence.
  prepare-router.py and its 16-file overlay replay all 652 candidate hashes
  exactly (1.176 seconds / 32.8 MiB aggregate); compatibility-router.patch has
  99 changed/added files, targets source state 8b2d420 and passes git apply
  --check on current primary. Its SHA-256 is
  38e6dc50fedcb005b41e83f983c97b00c940a6d3451e81db98b866905dbffd8d.
  Neither that patch nor the compiler pin is adopted. The older 93/97-file
  patch/recipe/source freezes remain historical and unchanged.
  The complete forced JSON gate still fails at its first mandatory cold check.
  With the waiting Python validation driver it reaches the aggregate cutoff
  at 387.8 MiB (5.340 seconds, 257.5 MiB individual). A direct guarded Moon
  launcher removes that driver's measured 22.5 MiB overhead but still cuts off
  at 385.5 MiB (5.459 seconds, 276.9 MiB individual). A compiler-only 64 MiB
  reported-RAM hint, retaining disabled compiler JIT, enabled evaluator JIT and
  every original source/case, still cuts off at 384.1 MiB (5.299 seconds,
  270.6 MiB individual). No hard limit is increased. A focused diagnostic
  runs only the first required json/main.bend cold check without Moon; it
  crosses the individual cutoff at 322.3 MiB / 342.3 MiB aggregate in 4.407
  seconds. The compiler frontend itself therefore requires work; removing
  controllers or changing the RAM hint is insufficient. This focused failure
  cannot substitute for the full JSON gate. All jobs are terminal and all 652
  retained source hashes remain unchanged after generator execution and cleanup.
  Artifacts remain under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/compiler-compatibility/`:
  gates-preparation.json, router-preparation.json, compatibility-router.patch,
  prepare-router.py, router-inputs.json and validation/gates-replay-evidence.json,
  validation/router-and-json-gates-evidence.json, all forced-io/http-wire/router
  logs/resource/Moon reports, and the four JSON failure/diagnostic reports.
  Next: profile/refactor the JSON frontend workload with APIs and all original
  parser/layout/proof/conformance cases preserved, then finish remaining forced
  package and repository checks before compiler adoption. Primary Bend remains
  2.0.27. The full 19-item contract, timing/private-secret ownership and secure
  direct/relay browser data/media evidence remain open; bounty/ is untouched.

- 2026-10-02 (fresh isolated HTTP core and separate UTF-8 gates):
  The previous goal turn made source/verification progress in 8b2d420: dual
  constructor-table admission and shared cold-checker cache inputs. This turn
  resumed one guarded job at a time after normal-pressure preflight, preserving
  the 384 MiB aggregate / 320 MiB individual / 120-second compiler/package
  cutoffs. In the retained disposable official-2.0.34 checkout, the three exact
  HTTP cold fixtures pass (5.998 seconds, 199.8 MiB aggregate / 158.1 MiB
  individual), then `moon --concurrency 1 run http_core:check --force` passes
  fresh: task 44.026 seconds, overall guard 44.670 seconds, peak 380.8 MiB
  aggregate / 157.1 MiB individual. Native and optimizing Bun each pass all 838
  Base64 cases and 8,320 method cases. All 93 original unit definitions, eight
  public laws, 17 contract and 100 proof declarations, example/cookie execution
  and all three cold fixtures pass. Cookie/multipart proof scopes retain all
  original pure definition bodies while excluding only cookie sign/verify
  foreign declarations; original APIs/effects remain present and retain their
  separate native/Bun compatibility checks. This is frontend proof checking,
  not a claimed proven-kernel --verdict result or generated-code timing safety.
  Only after that job exited, the separate
  `moon --concurrency 1 run utf8:check --force` passes: task 723ms, guard 1.453
  seconds, peak 158.9 MiB aggregate / 74.0 MiB individual. Its Moon run report
  records passed task execution/exit zero and skipped output hydration. HTTP's
  project dependency does not itself execute UTF-8. The 652 frozen candidate
  input hashes match before and after all three jobs. Compiler JIT remains
  disabled with a 128 MiB reported-RAM hint; package Bun execution uses --smol,
  a 64 MiB hint and enabled JIT/DFG. These hints are not hard allocation quotas.
  Evidence is under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/compiler-compatibility/validation/`:
  `focused-http-cold-*`, `forced-http-core-cold-*`, `forced-utf8-cold-*`,
  `http-cold-gate-evidence.json` and `http-cold-gate-moon-metadata/` (task logs,
  hashes, last-run statuses and UTF-8 execution report). The older 93-file
  compatibility.patch still passes git apply --check against primary and is
  unchanged. A 14-file gate overlay, gate-inputs.json and prepare-gates.py now
  describe an exact candidate reconstruction and a primary-targeted adoption
  patch preserving newer primary docs. That source-only recipe has syntax
  validation but no execution result: the next guard preflight refused it on
  macOS warning pressure (level 2), launched no child and recorded zero peak.
  A fresh observation confirms warning pressure and no Bend/Bun/Moon/clang
  jobs. Do not attribute that pressure or retained swap to a current Grounds
  job. No compiler jobs are restarted or cutoffs raised. No new patch/replay
  acceptance is claimed; compatibility-gates.patch does not yet exist.
  Next: after fresh normal-pressure evidence, replay prepare-gates.py under the
  standalone 128/96/120 guard, then run remaining changed-package and repository
  gates before compiler adoption. Primary remains Bend 2.0.27; the isolated
  OpenSSL/ENOSYS compatibility successes do not satisfy Bend TLS/cookie crypto.
  All 19 full-stack acceptance items, secure browser direct/relay data/media,
  timing/private-secret ownership and full fresh repository acceptance remain
  open. `bounty/` remains untouched and unstaged.

- 2026-10-02 (resource-control review and cold-type checker compatibility):
  The preceding turn refreshed live process/memory evidence after the user's
  renewed memory complaint. This continuation makes source and verification
  progress without starting Bend, Bun, clang or package builds. Fresh process
  inspection finds no such jobs, and macOS pressure remains normal (level 1).
  This does not attribute retained swap to any current process or prove full
  machine recovery. The existing guard was reviewed without changing limits:
  one shared lock, sampled owned process-group memory and pressure checks,
  immediate owned-group cleanup on cutoff/interruption, and fail-closed pressure
  reads. All 13 small Python subprocess guard tests pass in 6.863 seconds with
  `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tools.build_guard_test -v`.
  These are sampled cutoffs, not OS allocation quotas; detached groups remain
  unsupported. Compiler/package budgets stay 384 MiB aggregate / 320 MiB per
  process / 120 seconds, and standalone evaluator budgets stay 128 / 96 / 120.
  No limits were raised, compiler/kernel modified or global compiler upgraded.
  `json/scripts/cold.py` now understands both the pinned 2.0.27 CID_HOT_T and
  official 2.0.34 CID_T hot column. It verifies the runtime accessor, boolean
  flags and constructor-ID/table correspondence, and fails explicitly for
  missing, ambiguous, malformed or unfamiliar metadata. Hot types still fail
  the gate; missing program arguments and compiler failures also fail. Six
  metadata/CLI regression tests pass without invoking Bend (0.964 seconds,
  61.0 MiB aggregate / 23.1 MiB individual), and run before compilation in the
  JSON package check. Seven cached package manifests now include the shared
  checker; HTTP server already included it and JSON has caching disabled.
  Independent retained-C checks cover five old/new generated programs in
  0.135 seconds / 23.3 MiB: the old transport fixtures report 210 and 182 hot
  constructors, new cookie/TLS fixtures report zero, and the field fixture
  still reports eight. Injecting sharing into an actually cold constructor is
  detected in each. The first retained-C fixture mutation incorrectly targeted
  an already-hot constructor in one program; a freeze assertion caught this,
  and the corrected v2 evidence retains that failed attempt. No correctness or
  constant-time conclusion follows from the cold metadata alone.
  Artifacts are under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/compiler-compatibility/validation/`:
  `resource-controls-review-evidence.json`, `resource-controls-review-tests.log`,
  `cold-metadata-regressions-*`, `cold-retained-metadata-v2-*`,
  `cold-retained-observations-v2.json`, and the 652-input
  `forced-http-core-cold-inputs.json` source freeze. The checker/cache changes
  are also copied into the disposable forced checkout, preserving its pure
  scope helper changes; the previously accepted 93-file compatibility patch
  and its historical freezes remain unchanged. Primary Bend remains 2.0.27.
  The latest isolated forced HTTP core attempt, `forced-http-core-scoped2`,
  passed its existing units, eight laws, examples and cookie oracle, then failed
  on the old cold-table reader (40.256 seconds, 376.1 MiB aggregate / 157.0 MiB
  individual). It has not been rerun after this fix. UTF-8 was not automatically
  checked by that Moon target: its separate forced gate remains required.
  Next: run the three focused HTTP cold checks sequentially under the unchanged
  compiler guard, then separate forced HTTP core and UTF-8 checks; retain fresh
  source/gate evidence before revising the compatibility recipe or compiler pin.
  Full package/root compatibility, secure integration, timing/secret ownership
  and all 19 full-stack acceptance items remain open. `bounty/` stays untouched.

- 2026-10-02 (full-size RNG formatter gate resolved in isolated compatibility draft):
  The previous turn progressed by preserving failed experiments, restoring all
  frozen inputs and correcting resource docs (8bcbeba). This turn targets the
  formatter with small guarded diagnostics and sequential bounded builds;
  full package/root gates are not restarted. Instrumented generated JavaScript
  on sizes 0/1/16/256/4096/4097 confirms exactly two u32_to_word calls per byte.
  Each builds 32 WCon nodes, at least 67,108,864 temporary nodes over 1 MiB.
  The first diagnostic incorrectly registers its exit handler after the CLI's
  exit and fails to capture the counter; that failure and initial script remain.
  The corrected diagnostic passes at 43.3 MiB aggregate. This measures allocation
  work, not peak live memory or secret timing. The Bend chunk counter now uses
  Nat fuel; generated take decrements a numeric Nat without those conversions.
  Chunk size remains 4096, and the original 1 MiB RNG contract/oracle is intact.
  A CLI-only custom OS write effect mirrors Base write and invokes synchronous
  Bun collection after public writes of at least 8192 characters. Native simply
  writes and frees its temporary text. Host RNG acquisition code is unchanged.
  Nat fuel with ordinary IO.write still fails the process cutoff at 127.2 MiB
  individual / 146.6 MiB aggregate; that rejected source/report is retained.
  The Nat/write-GC candidate passes the unchanged 20-case real RNG matrix on
  native (0.903s, 28.2 MiB individual / 40.1 aggregate), Bun 1.3.13 (2.502s,
  91.2 / 112.8 MiB), and Bun 1.3.9 (2.553s, 89.7 / 111.2 MiB). The independent
  20-case deterministic exact-byte/chunk-boundary printer matrix also passes:
  native 0.808s at 23.6 / 24.5 MiB, Bun 1.3.13 2.924s at 94.0 / 119.8 MiB,
  and Bun 1.3.9 2.516s at 92.7 / 118.5 MiB. Both matrices retain 1 MiB.
  RNG OS-effect tests now use the registered newer ABI rather than bypassing
  registration; all 12 existing guard/chunk/order/failure/buffer-clear cases pass
  on both Bun versions. Each also passes 19 new printer OS-effect cases for exact
  UTF-8 output, collection thresholds, missing GC support and write failures.
  The standalone C OS-read harness is prepared from the actual effect source,
  expanding CID tokens to undefined macros to exclude only the Bend ABI region;
  all nine unchanged zero/short/interruption/error cases pass with clang
  -std=c11 -O2 -Wall -Wextra -Werror. This simulates Linux syscall outcomes,
  not a live Linux kernel, and does not substitute for compiled runtime tests.
  Standalone C/JS generation uses unmodified official Bend 2.0.34, BANGS=0 and
  clang 21; generation peaks below 60 MiB, clang below 89 MiB aggregate.
  All jobs use the primary guard, sequential nice-10 execution, unchanged
  384/320 MiB compiler or 128/96 MiB evaluator budgets and 120-second deadlines.
  Compiler JIT is disabled with a 128 MiB reported-RAM hint; evaluators explicitly
  enable JIT/DFG with --smol and a 64 MiB hint. These sampled protections can
  overshoot and miss fast processes; the results do not prove hard quotas,
  erasure/constant-time behavior, entropy quality, or machine swap ownership.
  Fresh --version observations confirm Bun 1.3.13 and 1.3.9. The compiler and
  Base source still match official release provenance. The compatibility patch
  now has 93 changed/added files and applies cleanly to primary; its fresh recipe
  overlays seven tested RNG/test files. All 650 checkout input hashes, generated
  target hashes, exact commands, observations and terminal reports are frozen in
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/compiler-compatibility/validation/natcounter-evidence.json`.
  A fresh source-only replay of the updated recipe reconstructs every one of
  those 650 inputs with identical hashes, and its patch also applies cleanly;
  it runs no compiler/evaluator and passes at 37.5 MiB aggregate in 1.402s.
  Replay artifacts are validation/natcounter-replay-evidence.json and
  validation/natcounter-replay/. Patch ordering may differ; resulting inputs
  are compared exactly. Primary package/browser acceptance remains separate.
  Prior recipes, manifests and failed candidates remain in history/; no failed
  result is overwritten. The patch SHA-256 is
  9142e13642a21d326cfa1000d97ca28998d06fe41f374ea7a3a8a61f7cc5cf47.
  Primary protocol source/compiler pin remains unchanged at 2.0.27. Next: finish
  signal/cookie/TLS and remaining custom-effect lifecycle compatibility, then
  changed-package/repository gates before considering compiler adoption. Resume
  certificate semantics/trust/hostname and TLS/DTLS integration after those
  dependencies. Browser integrated data/media remains pending, the full goal
  stays active, and all 19 complete-stack acceptance items remain open.

- 2026-10-02 (RNG allocation evidence and experiment cleanup after memory complaint):
  The preceding response verified that no compiler/evaluator was live, but did
  not advance implementation. This continuation launches no Bend compiler,
  generated evaluator or package/root gate. Saved diagnostic evidence from the
  interrupted investigation changes the next action: `rng_count` traverses the
  entire 1,048,576-byte result, rejects non-octets and prints count:1048576 on
  Bun 1.3.13 at 78.3 MiB individual/group in 0.411s. Counting fits the unchanged
  96 MiB cutoff; that does not prove the complete formatting/output path fits.
  The chunk-loop printer fails at 121.3 MiB individual, the temporary host-RNG
  GC trial at 110.2 MiB, and the custom write/GC trial at 100.8 MiB. All three
  retain the full oracle and end in process-memory-cutoff/137. The initial
  chunk-loop build failed type checking; its mistakenly launched dependent
  oracle reports a missing JS file and is excluded from runtime evidence.
  Inspection of generated take/reverse finds reversed-string construction and
  character slicing/prepending; this narrows candidates for investigation but
  does not attribute the measured peak or establish a fix. No acceptance size,
  case, JIT setting or memory limit is reduced or raised to force success.
  Four current experiment source files are preserved in
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/compiler-compatibility/history/chunkloop-rng/`;
  its evidence.json binds source/generated hashes and all newer terminal reports.
  The two experimental random_print effects are removed from the isolated
  compatibility checkout, its RNG printer is restored, and every one of the
  646 frozen checkout inputs matches validation/evidence.json again.
  compatibility.patch retains SHA-256
  a968550b8ff430b3594b39f39a853a1adf7a4ec40324927bdd8b4355dd4fef1c.
  The first guarded file archiver fails closed at 23.1 MiB because macOS denies
  physical-footprint measurement of its ps child (exit 125). Its partial source
  restoration is independently verified before resuming; the failure report is
  retained. Inventory is then taken separately, and the completed file archiver
  passes at 23.2 MiB with 128/96 MiB budgets and a 120-second deadline. The fresh
  inventory has no Bend/Bun/Clang/Moon jobs; macOS pressure is normal and swap
  remains 5,488.75 MiB, without attributing swap or the reported historical peaks.
  Package docs now distinguish the count diagnostic from full output acceptance
  and remove an obsolete 512/640 MiB recovery instruction. Primary compiler and
  protocol source remain unchanged. Next: profile and reduce formatter temporary
  allocation before another bounded candidate evaluation, preserving the full
  1 MiB/output contract and native/Bun exact-byte checks. Do not automatically
  restart full gates after the complaint. Forced package/root and browser checks
  remain pending; every one of the 19 full-stack acceptance items stays open.

- 2026-10-02 (bounded compiler compatibility evidence): The previous goal turn
  made progress via 1de798a and an isolated upgrade draft. This continuation
  tests that draft using the updated primary guard, one nice-10 job at a time,
  384/320 MiB compiler or 128/96 MiB evaluator cutoffs and 120-second deadlines.
  Official unmodified Bend 2.0.34 now emits the complete field256 CLI's CPU C
  in 5.333s at 196.3 MiB, clang 21 -O3 builds it in 1.385s at 122.9 MiB, and
  JS generation passes in 2.768s at 173.4 MiB. BANGS=0 was inspected. Native
  and both tested Bun binaries pass all 4,178 unchanged bigint/arithmetic,
  carry/borrow, reduction, inversion/canonical and malformed cases. Native
  takes 1.599s (23.3 MiB aggregate); Bun 1.3.9 takes 5.852s (70.5 MiB), and
  Bun 1.3.13 takes 5.786s (73.6 MiB). Actual --version observations identify
  the .bun executable as 1.3.9 and the selected mise binary as 1.3.13, despite
  its directory label 1.1.42. The optimizing-JIT evaluator configuration explicitly
  enables useJIT/useDFGJIT, with --smol and a 64 MiB reported-RAM GC hint.
  Compiler invocations disable JIT and use the 128 MiB hint; these are separate
  invocation configurations, not memory quotas or timing/erasure evidence.
  The draft Io.args needed correction: a match is not an IO-block term, and
  List<String> is affine. It now returns List.tail(&1, String, values).
  All eight empty/option/delimiter/space/Unicode byte-preservation cases pass
  on native/Bun. The first Bun invocation fails because Bun consumes its host
  delimiter; an independent process.argv probe confirms exactly one removed
  delimiter. Supplying that host delimiter separately preserves every expected
  Bend argument. The original failed invocation and probe remain retained.
  Native socket compilation exposed another ABI change: io_wait_time was
  removed and parked deadlines are now IoWork.time. The isolated C adapter
  updates all five reads; native/Bun each pass all 22 UDP literal/ephemeral,
  byte, same-port-IP, invalid-bind, descriptor and cleanup cases, the real TCP
  echo of all 256 octets, and receive-timeout none/data/closed outcomes.
  The unchanged native RNG oracle passes all 20 cases, including 1 MiB and
  invalid bounds. The complete Bun run fails the 96 MiB individual cutoff.
  A phase-traced repeat of the unchanged full oracle confirms the failure
  occurs at the 1,048,576-byte request (148.2 MiB aggregate sampled peak).
  Chunked and incremental Bend printer experiments do not clear that gate;
  a smaller GC hint also fails. The last incremental experiment's independent
  deterministic printer oracle passes all 20 exact-byte/chunk-boundary native
  cases, but Bun again crosses its cutoff. Those printer changes are rejected
  and removed from the compatibility draft; the full source snapshot and
  generated targets remain under history/stream-rng. No RNG size or oracle
  case is reduced. This is an unresolved byte-list/runtime allocation gate,
  not proof that switching the compiler fixes the whole stack's memory use.
  The current 87-file patch includes the affine argv and parked-deadline fixes,
  applies cleanly, and preserves the full acceptance contract. The official
  compiler binary still matches the retained release-provenance SHA-256.
  Frozen source/generated hashes, exact guarded commands, actual runtime flags,
  all terminal results and rejected initial/streaming drafts are in
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/compiler-compatibility/`;
  validation/evidence.json binds the accepted scope, and the subsequent phase
  diagnostic/freeze resource reports are retained separately. All observed
  owned job peaks stay below 197 MiB in this turn; cutoffs can overshoot and
  fast processes can be missed. A fresh final process inventory finds no
  Bend/Bun/Moon/Clang jobs. Normal pressure samples do not establish full
  machine recovery or attribute swap ownership.
  The primary pin remains 2.0.27. Full custom-effect/cookie/signal/TLS behavior,
  changed-package forced checks, the repository gate and browser integration
  remain pending; no package or repository success is claimed or rerun here.
  Next: measure and resolve large-byte-list allocation, preserving the 1 MiB
  RNG contract and original checks, then finish the remaining effect/lifecycle
  and package gates before adopting the upgrade. Continue certificate semantic,
  trust/hostname and TLS/DTLS integration after those dependencies. All 19
  complete-stack acceptance items remain open; the full goal stays active.

- 2026-10-02 (resource defaults and isolated compiler compatibility draft):
  After the renewed memory complaint, a fresh process inventory finds no
  Bend/Bun/Moon/Clang build jobs. macOS reports normal pressure at that sample
  and 7,984.81 MiB swap in use; this does not attribute swap to Bend or prove
  recovery from the historical multi-gigabyte builds. No Bend compiler or
  generated-program evaluator is launched in this continuation. The previous response refreshed resource
  evidence; this turn changes the resource defaults and prepares the next
  compatibility dependency without a build.
  `tools/build_guard.py` now defaults to 384 MiB aggregate, 320 MiB per process
  and 120 seconds, replacing 512 MiB aggregate / no individual limit / one hour.
  Existing explicit evaluator budgets remain 128/96 MiB. Updated documentation
  no longer directs current recovery work to the larger historical limits.
  A real subprocess test omits all three options and verifies the configured
  defaults in its report. All 13 safety tests pass fresh in 6.681s via
  `PYTHONDONTWRITEBYTECODE=1 nice -n 10 python3 tools/build_guard_test.py`;
  the driver never invokes Bend. Cutoffs remain sampled and can overshoot.
  Artifact log, command, duration and source hashes:
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/resource-defaults/`.
  Official Bend 2.0.34 tagged changelog/compiler source and bundled effects
  guide confirm three breaking interfaces: argv[0] in IO.args, explicit host
  in TCP.listen/UDP.bind, and namespace-aware CID plus JS io_eff registration.
  Prepared an unverified compatibility patch in an isolated archive of
  6fa32a7: 87 changed files, 79 argument calls in 73 files, ten wildcard binds
  preserving the old IPv4 behavior, and all 24 custom effects (including legacy
  cookie compatibility). A shared Io.args preserves user arguments excluding
  argv[0]; crypto Moon inputs include that dependency. The draft pin is 2.0.34;
  the primary repository and installed compiler remain 2.0.27. No compiler,
  kernel or protocol implementation is replaced. Preparation passes at 35.9
  MiB aggregate under 128/96 MiB cutoffs, in 2.124s. The patch, source hashes,
  official tagged references, preparation script and resource report are in
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/compiler-compatibility/`.
  This is source preparation, not a compatibility pass or compiler-memory fix.
  Full package/repository and browser acceptance remain pending; their last
  failures remain recorded, and none is rerun here.
  Next: review the isolated effect/name/argv changes, then obtain bounded native
  and Bun compatibility evidence beginning with the complete field256 matrix
  and socket/RNG/cookie lifecycle checks, before adopting the draft pin. Compiler
  work stays stopped during the current resource investigation. Use the updated
  primary guard with explicit budgets for any later isolated validation.
  All 19 complete-stack acceptance items remain open; the full goal is active.

- 2026-10-02 (canonical OID and extension envelope owner): Added
  `crypto/oid.bend` and `x509_extensions.bend`, a batch fixture CLI, independent
  numeric OID/re-encoding and exact-envelope oracle, and six closed compiler
  checks. OIDs retain canonical contents without narrowing large arcs. Exact
  nonempty extension sequences admit OID / optional canonical TRUE / primitive
  OCTET STRING fields, reject explicit default FALSE and duplicate identities,
  and retain order and opaque payloads. Optional absent extensions yield an
  empty list. Known payloads, critical-extension policy, Name semantics,
  constraints/trust/hostname and handshake composition remain required; this
  does not authorize a certificate or change signed bytes.
  A complete baseline-JIT run exposed Base string-comparison stack overflow on
  8,192-octet shared OID prefixes. The final affine map uses fixed eight-character
  FNV-1a bucket keys, with tail-recursive complete-byte identity checks inside
  collision buckets. Hash equality never establishes OID identity; both orders
  of the costarring/liquid collision and exact duplicates are covered. Collision
  bucket scans can be quadratic in the worst case; no adversarial-work or timing
  guarantee is claimed. The CLI accumulates fields/rows without recursive joins
  or long-field append copies. Prior failed source/generated targets are retained.
  Native and baseline-JIT Bun each pass all 67,731 cases and four CLI errors,
  including X.690's published OID, every one/two-octet content, large arcs,
  critical flags, DER/default/field aliases, truncation/tampering, duplicate
  positions/collisions, 128–8,000 unique entries, long prefixes, exact byte
  boundaries and eight frozen OpenSSL certificate fields. Times are
  11.205/30.059s, aggregate peaks 34.6/112.9 MiB; Bun individual peak 76.5 MiB.
  Six compiler checks pass at 77.4 MiB; BendTT --verdict was not run. A fresh
  primary-source native repeat using the retained executable passes in 9.509s,
  peak 40.4 MiB. All 12 matrix input hashes match. Provenance validation passes
  at 24.7 MiB: 443 prior code/fixture/script inputs unchanged except five
  check.sh additions (all 143 prior lines preserved), and all 74 extracted
  official compiler files still match the previously verified archive.
  Official unmodified Bend 2.0.34 C/JS plus clang 21 -O3 generation passes in
  12.785s, peak 169.7 MiB; repository mise stays 2.0.27. Compiler environment is
  BEND_NO_TELEMETRY=1, BUN_OPTIONS=--smol, forceRAMSize=134217728, useJIT=false.
  The complete Bun result explicitly uses --smol, forceRAMSize=67108864,
  useJIT=true and useDFGJIT=false. Default optimizing-JIT acceptance remains
  unresolved: the final large-input diagnostic still crosses the 96 MiB cutoff
  at 4,096 entries. The package check retains its ordinary Bun command.
  Every job is sequential and nice 10, with 120-second deadlines and unchanged
  384/320 MiB compiler or 128/96 MiB evaluator/provenance sampled cutoffs.
  Warning-pressure preflight refusals and runtime failures remain retained;
  cutoffs can overshoot and are not kernel quotas. The 13 guard safety tests
  pass, and guard source is unchanged.
  Fresh `moon --concurrency 1 run crypto:check --force` stops at pinned Bend
  2.0.27 field256 CPU generation after 62.383s: exit 137, peaks 386.6/327.7 MiB.
  The subsequent `moon --concurrency 1 run :check` hydrates cached io:check,
  then stops during crypto after 22.953s: exit 137, peaks 371.7/327.3 MiB.
  These bounded attempts use the compiler environment and budgets above; neither
  establishes full package/repository acceptance, and no browser gate is rerun.
  Artifacts, exact commands, manifests, retained failures and targets:
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/x509-extensions/`.
  See `crypto/X509_EXTENSIONS_REVIEW.md`. RFC 5280 section 4.2 and ITU-T X.690
  02/2021 sections 8.19/10.2/11.1/11.5 were inspected; known semantic/path updates
  and verified errata remain obligations for later policy owners.
  Next: resolve the pinned compiler/runtime memory and compatibility gates with
  the verified official compiler in isolation, then complete Name and known
  extension/critical policies, constraints/trust/hostname and TLS integration.
  All 19 complete-stack acceptance items remain open; the full goal is active.

- 2026-10-02 (guard review and extension allocation investigation): All 13
  guard self-tests pass fresh in 6.852s, with no Bend build. Two attempts to
  wrap the test driver in another guard fail closed on memory-read denial
  (30.8/63.7 MiB sampled aggregate peaks); this host's root-owned setuid `ps`
  helper is incompatible with that outer monitor. The documented driver guards
  each small test workload. A speculative exit-race change was removed; guard
  source/tests are unchanged. `tools/README.md` records the test-driver boundary
  and current focused budgets.
  The isolated extension matrix's normal optimizing-JIT Bun run exits 137 at
  the existing 96 MiB individual cutoff, sampled 123.0 MiB individual / 153.1
  MiB aggregate. A diagnostic localizes the failure to 8,000 distinct extension
  entries in 63,876 bytes. The draft printer now accumulates rows directly, and
  duplicate admission reuses Base `Map.seek` for comparison and insertion
  instead of a separate has/set traversal. Both rebuilds pass, at 172.1/170.0
  MiB aggregate peaks, but neither clears the Bun runtime cutoff. A smaller GC
  hint also fails. Generated targets from before each change are preserved.
  An admission-only fixture still fails with optimizing JIT (116.6 MiB
  individual), then passes with all JIT disabled (38.2 MiB) and with only DFG
  disabled (54.6 MiB, retaining baseline JIT). These are diagnostic cases, not
  replacement whole-matrix acceptance. The attempted complete baseline-JIT
  matrix was refused before launch at system warning pressure (exit 125,
  peak 0); fresh pressure reads remain level 2, swap occupied 3289.75 MiB.
  No limits are raised, no compiler patch/global upgrade is adopted, and no
  protocol sources are adopted into the primary checkout. The original native
  67,725-case result predates the printer/Map changes; fresh final-source native
  and complete Bun matrices and five compiler checks remain required.
  All reports, source/generated snapshots, `guard-review.json` and
  `X509_EXTENSIONS_REVIEW.draft.md` are in
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/x509-extensions/`.
  Next: after normal pressure passes preflight, run the unchanged complete
  native and baseline-JIT Bun matrices sequentially under 128/96 MiB and
  120 seconds; retain the optimizing-JIT failure as an unresolved runtime gate.
  Verify compiler declarations and source/compiler provenance before any
  adoption. Full package/repository/browser gates remain pending, and all 19
  complete-stack boxes remain open.

- 2026-10-02 (renewed memory complaint; heavy work stopped): Interrupted the
  last retained terminal handle and verified no Grounds/Bend build or checker
  process remained. No new compiler or evaluator was launched after this
  complaint. Fresh macOS pressure was level 1 (normal), with 3577.81 MiB swap
  occupied; this does not establish the cause of the reported 15 GB / 7 GB
  peaks or that all memory effects have cleared. The earlier unsafe overlap
  incident remains recorded below. Before this complaint, pressure recovered
  enough for isolated extension preparation, C/JS generation and native
  evaluation to finish: generation exit 0, 172.9 MiB aggregate peak; native
  67,725 cases and four CLI errors, exit 0, 38.5 MiB aggregate peak. The original
  refused preparation report is preserved. Bun and compiler checks remain
  pending; draft sources have not been adopted and no extension milestone is
  committed. Resource reports and `memory-complaint-checkpoint.json` are in
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/x509-extensions/`.
  Next: review resource safeguards before any further compiler/evaluator
  launch. Sampled cutoffs can overshoot and are not kernel allocation quotas.
  The full goal remains incomplete; all 19 stack acceptance boxes remain open.

- 2026-10-02 (OID/extension draft; pressure preflight refused): After time
  commit `d0628e3`, prepared isolated `oid.bend`, `x509_extensions.bend`, fixture
  CLI, five compiler-check declarations and an independent Python numeric-OID/
  re-encoding and extension-envelope matrix. The proposed decoder retains
  canonical OID contents without narrowing arc values to U32, checks exact
  extension fields/critical BOOLEAN/default omission, preserves opaque payloads
  and order, and uses an affine Base Map keyed by canonical OID hex for duplicate
  detection. Known payload/critical-extension recognition, Name semantics and
  constraints/trust remain future owners. No source adoption or passing result
  is claimed. The matrix is prepared, not run: published X.690 {2,999,3}, every
  one/two-octet OID content, large numeric arcs, all critical BOOLEAN values,
  field/DER aliases/truncations/tampering, duplicate positions, 128–8,000 unique
  records, long shared OID prefixes, exact 65,535/65,536-byte boundaries and
  eight frozen OpenSSL certificates with absent/present extensions.
  Even isolated checkout preparation was refused before launch by the existing
  guard: exit 125, `system-memory-pressure-before-launch`, peak 0 MiB. Fresh
  sysctl observations remained pressure level 2 (warning), swap used 2504.56 MiB.
  A process scan found no owned build/check candidates. No unrelated process
  was stopped, no guard was weakened, and no compiler/evaluator ran. Draft
  sources remain outside the primary checkout at
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/x509-extensions/`; dependency
  checkout is not yet populated. `preparation-resource.json` preserves the
  terminal refusal, and `verification-checkpoint.json` records paths and next
  action. RFC 5280 §4.2 and official ITU-T X.690 (02/2021) §§8.19/11.1/11.5
  were inspected. Next: once normal pressure passes preflight, run `prepare.py`
  to populate the frozen `d0628e3` dependencies, then `build.sh`, the native/Bun
  matrices and compiler checks sequentially, retaining fresh report names and
  existing 384/320 or 128/96 MiB cutoffs with 120-second deadlines. Resolve any
  failures before adoption and package wiring. All 19 full-stack boxes remain
  open; this external resource condition does not complete or narrow the goal.

- 2026-10-02 (certificate civil-time and validity owner): Added
  `crypto/x509_validity.bend` to decode complete DER UTCTime/GeneralizedTime,
  reject malformed/calendar-invalid values, retain ordered validity intervals
  and check inclusive endpoints against caller-supplied civil UTC seconds since
  0001-01-01. Gregorian leap centuries, UTCTime's 1950–2049 mapping, years 1–9999,
  complete seconds/Z and exact two-field DER framing are checked. Generalized
  dates before 2050 remain parseable; issuance-profile enforcement is separate.
  Leap-second encodings remain unsupported. The caller must supply a trusted
  wall clock, not monotonic IO.now; host-clock conversion/skew policy and
  composition with signature, Name/extensions, constraints/trust/hostname and
  TLS handshakes remain required. Original certificate and crypto code/fixtures
  are unchanged. The signed bad-time-content fixture now fails this time owner
  while retaining its valid mathematical signature; no trust result is claimed.
  Fresh native and normal-JIT Bun each pass 31,545 Python-datetime oracle cases
  plus four CLI error checks in 5.823/17.586s, peak 30.0/64.0 MiB aggregate (Bun
  individual 39.1 MiB). Cases include three published RFC 5280 Appendix C
  validity examples and the year-9999 sentinel, every year's February 29/final
  second, every UTC year, month/day grids, all time-body octet substitutions,
  every tag/truncation, clock ranges, time/DER aliases, ordered/reversed/random
  intervals, inclusive/equal/mixed-year endpoints, validity shape/input bounds
  and fields extracted from eight frozen OpenSSL certificates. Primary-source
  native repeats all cases using the retained executable in 5.520s, peak
  28.5 MiB; all 11 input hashes match. Four smaller epoch/calendar/input-admission
  closed checks pass compiler checking at 74.9 MiB; kernel --verdict was not run.
  A preceding closed proof file with large timestamps reported compiler stack
  overflow at 87.1 MiB; it and its log are preserved. Large timestamp cases
  pass at runtime on both targets. Initial literal/forward-definition errors
  are also retained as failed attempts; no supported runtime year is removed.
  Official unmodified Bend 2.0.34 C/JS plus clang -O3 generation passes in
  12.057s, peak 174.0/172.0 MiB aggregate/individual. All 74 extracted compiler
  files still match the verified signature-milestone release archive; no global
  compiler upgrade or kernel patch is made. Existing compiler/package migration
  gates remain pending. Jobs retain sequential nice 10, 120-second deadlines,
  sampled 384/320 MiB compiler or 128/96 MiB evaluator/provenance cutoffs, normal
  pressure samples and the preceding milestone's compiler/Bun environment.
  Fresh RFC 5280 validity rules/Appendix C were inspected; official errata fetch
  failed, so today's retained six Verified records were re-inspected. None
  revises time rules; their remaining EKU/path/Name/policy requirements and
  current RFC updates remain for future owners. See `X509_VALIDITY_REVIEW.md`.
  Artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/x509-validity/`,
  including exact commands/resource logs, successful/failed sources, generated
  targets, compiler/source/errata hashes and `evidence.json`. All 439 prior
  source/fixture/script inputs other than check.sh remain unchanged; five added
  package commands preserve all 138 prior lines. Full forced crypto/repository/
  browser gates remain pending and full-stack builds stay stopped after the
  resource incident. All 19 stack boxes remain open. Next: Name/extension
  admission and constraints, followed by certificate policy/trust/hostname,
  trusted clock and TLS scheme/handshake composition.

- 2026-10-02 (mathematical certificate issuer-signature verification):
  Adopted `crypto/x509_signature.bend`, which admits an explicit issuer SPKI
  and complete certificate, binds RSA/PSS/P-256 key/profile restrictions,
  hashes original encoded TBSCertificate bytes with Bend SHA-256, and verifies
  RSA PSS/v1.5 or strict-DER P-256 ECDSA with existing Bend public primitives.
  Subject keys are never substituted for issuer keys. It imports no private
  signing facade and changes no existing crypto arithmetic/admission rule.
  Time/Name/extension semantics, constraints, issuer selection, chain/trust/
  hostname, TLS wire schemes and handshakes remain required. Fresh public peer
  fixtures deliberately include invalid time contents, wrong SAN and unknown
  critical extensions: signature success must not authorize those certificates.
  Their synthetic private keys were removed before public export. See
  `crypto/X509_SIGNATURE_REVIEW.md` for the exact API, standards and limits.
  Retained native and normal-JIT Bun runs each pass 4,825 whole-verifier cases
  and three CLI error checks in 7.314/96.892s, peak 29.1/96.8 MiB aggregate
  (Bun individual 70.3 MiB). Cases include all certificate truncations, every
  signature-byte mutation, TBS field edges, wrong/malformed issuer keys,
  signature width/DER/range, all signature unused-bits values, profile binding,
  parameter equivalences, PSS-only/minimum-salt keys and large input bounds.
  The unchanged RSA checker passes all 774 cases, including published NIST and
  OpenSSL fixtures, on both targets in 2.616/24.045s. An artifact-only public
  ECDSA adapter through the signature module passes 32 NIST/RFC 6979 verification
  vectors per target in 1.373/28.350s; this does not verify private signing or
  the entire ECDSA matrix. Existing 31 algorithm/SPKI/certificate/RSA/ECDSA
  closed checks pass compiler checking; kernel `--verdict` was not run.
  Whole C/JS generation and clang -O3 instead use the official unmodified Bend
  2.0.34 arm64 release and pass at 241.5 MiB aggregate/239.5 MiB individual.
  All 74 extracted files match the retained release archive SHA-256
  `a60c820c0ced758d8ace839507ff6c508a204ce4ef0f45e1089ed7bc73e8c267`.
  The earlier 2.0.27 whole-generation cutoffs, GC experiment and exact-OID
  experiment remain retained and unadopted. No compiler/kernel patch is used
  as acceptance evidence. The repository/global pin remains 2.0.27; a broader
  upgrade still needs API/runtime/package compatibility checks. The new fixture
  CLI requires `verify` in the first or second argument position to support the
  changed upstream IO.args convention; existing CLI adapters remain unchanged.
  The latest complaint response confirmed no remaining Bend/owned check jobs,
  normal macOS pressure and 8518.56 MiB swap still used. During adoption no heavy
  build was restarted. Fresh provenance/adoption checking peaks at 22.7/24.7
  MiB. A fresh primary-source native run using the retained executable passes
  all 4,825 cases in 6.769s, peak 29.0 MiB; all 24 matrix input hashes match.
  Sequential jobs retain nice 10, 120-second deadlines, 384/320 MiB compiler
  and 128/96 MiB evaluator/provenance cutoffs with normal pressure observations.
  Cutoffs are sampled, can overshoot and are not OS quotas. Compiler environment
  is `BEND_NO_TELEMETRY=1 BUN_OPTIONS=--smol BUN_JSC_forceRAMSize=134217728
  BUN_JSC_useJIT=false`; generated Bun uses normal JIT with
  `BUN_OPTIONS=--smol BUN_JSC_forceRAMSize=67108864`. Versions remain Bun 1.3.13,
  Python 3.12.8, Apple clang 21, and OpenSSL 3.6.4 for public peer preparation.
  Artifact directory: `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/x509-signature/`.
  `build.sh`, `build-published.sh`, resource reports and `evidence.json` retain
  exact commands; `compiler-provenance.json` binds archive/extraction/generated
  outputs, and `validated-inputs.json` binds adopted code to all matrix inputs.
  `crypto/check.sh` adds five commands while preserving all 133 original lines;
  previous source/fixture/script inputs remain unchanged. Existing Moon globs
  cover the new code. Full forced crypto/repository/browser gates remain pending
  and stopped after the memory complaint. No private-operation, timing/erasure
  or live-secret approval follows; all 19 full-stack boxes remain open. Next:
  implement strict time/Name/extension semantics, constraints/trust/hostname,
  TLS signature-scheme admission and certificate/handshake ownership.

- 2026-10-02 (issuer-signature integration draft; bounded compiler failure):
  After framing commit `9c0ff13`, the isolated `x509_signature.bend` draft
  connects issuer SPKI admission, certificate algorithm compatibility, original
  TBS SHA-256, RSA PSS/v1.5 and strict-DER P-256 ECDSA verification. Its initial
  whole CLI type-check passes with unmodified Bend 2.0.27 source, peak 290.3 MiB.
  Native generation then crosses the unchanged 320 MiB individual cutoff.
  Diagnostic output reaches C `compile-book` preparation but no per-function
  emission before cutoff. An isolated compiler experiment adds full GC only
  at C emission start/after emitter cache clearing; it still cuts off at
  322.6 MiB. The language kernel is byte-identical to upstream. This unsuccessful
  compiler patch is not adopted or used as acceptance evidence. Unmodified
  source JS generation also cuts off. Removing an unnecessary ECDSA private
  signing-facade import retains public verification/strict DER but both final
  C/JS generation still cut off at 320.6/320.8 MiB. No verifier runtime result
  or source-module adoption is claimed; drafts remain in the artifact checkout.
  Four fresh public fixtures prepare RSA-v1.5/PSS issuers with P-256 subjects,
  an ECDSA issuer with an RSA subject, and a mathematically signed certificate
  with deliberately invalid time contents. Fixtures also retain a wrong SAN
  and unknown critical extension to prevent confusing signature validity with
  trust. OpenSSL 3.6.4 independently verifies each signed TBS; all temporary
  synthetic private keys are removed before public export. Peer preparation
  passes at 32.3 MiB. Independent Python bigint/affine verification validates
  21 expected cases, including subject-versus-issuer keys, signature tampering,
  trailing bytes, NULL/absent equivalence and PSS-only/restricted-key bindings.
  These are peer/oracle results, not Bend results. Every job stays sequential,
  nice 10, with 120-second deadlines and normal pressure observations under
  existing 384/320 MiB compiler or 128/96 MiB preparation/evaluation cutoffs;
  no limits are raised and full gates remain stopped. See the framing artifact
  directory's `signature-followup.json`, exact resource/log files, isolated GC
  patch/provenance, `signature-peer-vectors.json` and `signature-oracle-check.py`.
  Next: localize whole-verifier preparation allocation and reduce retained
  compiler/source graph without dropping supported signature algorithms;
  compare any compiler change against known generated C before runtime tests.
  Continue semantic certificate/time/Name/extensions and trust/TLS integration;
  all 19 full-stack acceptance boxes remain open.

- 2026-10-02 (certificate field framing; source-native build):
  `crypto/x509_certificate.bend` extracts one complete, bounded certificate
  envelope in Bend and retains original TBSCertificate bytes. Affine public
  Header/Identity/Tail records retain signed serial INTEGER contents, version,
  inner algorithm, issuer/validity/subject/SPKI SEQUENCE encodings, optional
  IDs/extensions and signature payload. A bounded six-field walk admits
  mandatory tags/order; absent v1 versus explicit v2/v3, minimal signed serial
  framing, exact two Time tags, version/ordered optional fields, BIT STRING
  padding and nonempty v3 extension wrapping are checked. Inner/outer supported
  SHA-256 RSA PSS/v1.5 or P-256 ECDSA profiles must agree. Root octets/65,535-byte
  admission and DER length/trailing-field checks remain in the existing framer.
  Time/calendar/order/current-time, Name/RDN, subject-key and extension-item
  semantics are not validated; a deliberate bad-time-content case documents
  that framing success cannot authorize a connection. No issuer signature,
  trust, chain, hostname, TLS scheme or handshake result is claimed.
  Six fresh primary closed checks pass. Native and normal-JIT Bun each pass
  all 31,428 independent cases in 9.991/52.577s: exact fields of four frozen
  public OpenSSL certificates, signed INTEGER aliases, versions/optional
  presence/order/duplicates, all unique-ID and signature unused-bits counts,
  mandatory/validity shape and algorithm binding, every truncation/individual
  bit mutation of all four certificates, seeded mutations, trailing fields
  and large-input boundaries. Every field and original signed byte is compared
  against the independent byte-slicing oracle. Cases stream in batches at most
  32; inputs above 4,096 bytes run alone. Primary native repeats all cases in
  9.350s (guard total 9.448s); input hashes match both generated targets.
  Earlier syntax/ownership/descent failures and packaged C-generation cutoffs
  remain retained. Grouped records alone and a shared mandatory-field walker
  still cross the unchanged 320 MiB individual cutoff with packaged Bend.
  A diagnostic source compiler instead completes C generation at 314.0 MiB.
  Unmodified upstream v2.0.27 source under Bun 1.3.13 then generates byte-identical
  C at 318.1 MiB. All 1,773 source files match the frozen upstream archive;
  SHA-256 `0c763567dc08bd297906a0100df149fb211d936df627882f806fa88a98feff68`.
  Apple clang 21 builds that C at -O3, and the packaged compiler emits final JS;
  source generation also reproduces the previous SPKI packaged-compiler C
  byte for byte at 292.9 MiB, providing a separate known-output comparison.
  the sequential clang/JS job peaks at 297.3 MiB. No compiler/kernel changes
  are adopted; this does not establish the cause of the memory difference or
  a passing packaged-native build. Primary closed checking peaks at 212.3 MiB;
  native/Bun evaluator peaks are 29.4/92.0 MiB aggregate (Bun individual 64.0).
  Primary native peak is 30.8 MiB. Source provenance checking peaks at 24.6 MiB.
  Jobs remain sequential, nice 10, with 120-second deadlines under
  `PYTHONDONTWRITEBYTECODE=1 python3 tools/build_guard.py --memory-mib <384|128>
  --process-memory-mib <320|96> --timeout 120 --report <artifact>/... -- nice
  -n 10 <job>`. Compiler environment: `BEND_NO_TELEMETRY=1 BUN_OPTIONS=--smol
  BUN_JSC_forceRAMSize=134217728 BUN_JSC_useJIT=false`; generated Bun uses normal
  JIT with `BUN_OPTIONS=--smol BUN_JSC_forceRAMSize=67108864`. Every pressure
  sample is normal; cutoffs are sampled and can overshoot, not kernel quotas.
  Exact jobs: unmodified `bun <v2.0.27 source>/bend2/main.ts <certificate_cli>
  -o <artifact>/certificate.c`, `sh <artifact>/build-parser-final-targets.sh`,
  `python3 <checker> --report ... -- <native|bun generated.js>`, primary
  `bend crypto/x509_certificate_test.bend --check-only` and primary native
  checker. Bend 2.0.27, Bun 1.3.13, Python 3.12.8, Apple clang 21; previous
  OpenSSL 3.6.4 public fixtures are reused. Review: RFC 5280 §§4.1–4.1.2,
  RFC 4055/5758; existing verified errata evidence is retained. Remaining
  semantic/path work must apply current 5280 updates, its six verified errata
  and RFC 8813. See `crypto/X509_CERTIFICATE_REVIEW.md` for API and limitations.
  Artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/x509-certificate/`,
  with retained generated targets, complete reports, compiler provenance,
  original/passing drafts, failed attempts, input hashes and `evidence.json`.
  All 435 of 436 previous source/fixture/script inputs except `crypto/check.sh`
  remain unchanged; five added check commands preserve all 128 prior lines.
  Existing Moon globs cover all four new source/check files. No cryptographic
  arithmetic, existing fixture, protocol effect or bounty input changes.
  Full `moon run crypto:check --force`, repository and browser gates remain
  stopped after the memory complaint; all 19 stack boxes remain open. Next:
  bind admitted issuer keys and original signed bytes to Bend mathematical
  signature verification, then implement time/Name/extensions, constraints,
  trust/hostname, TLS scheme admission and handshakes. The unverified signature
  integration draft remains isolated in the artifact checkout, not adopted.

- 2026-10-02 (SPKI public-key admission): `crypto/x509_public_key.bend`
  decodes one bounded, exact SubjectPublicKeyInfo in Bend. Its SEQUENCE must
  contain an admitted AlgorithmIdentifier and one octet-aligned primitive BIT
  STRING, with no trailing fields. RSA/PSS keys contain exactly two minimal,
  positive INTEGERs; normalization removes only necessary sign padding. Public
  modulus/exponent admission matches the existing RSA verification primitive:
  canonical odd 2048–4096-bit modulus, canonical odd exponent greater than one
  and below the modulus. It reuses existing bit-length/canonicality/comparison
  helpers without exponentiation; it does not certify RSA factor structure or
  private-key possession. Public metadata retains unrestricted RSA, PSS-only
  absent parameters or present SHA-256/MGF/trailer/minimum-salt restrictions.
  P-256 uses the existing canonical, non-infinity, on-curve point decoder and
  retains the uncompressed SEC1 encoding. Unsupported compressed/hybrid points,
  other prefixes, coordinate aliases and off-curve points fail closed. Input
  admission retains valid-octet and 65,535-byte bounds. Metadata is public,
  copiable Data; no private material or new secret owner is added.
  Six fresh primary closed checks pass. Native and normal-JIT Bun each pass
  all 11,547 independent cases in 3.617/24.194s: RSA size/parity/exponent and
  INTEGER boundaries, preserved algorithm restrictions, every unused-bits
  count and point prefix, canonical coordinates/curve failures, 50 public
  points from the existing 25 published NIST ECDH vectors, valid negated points,
  every truncation/bit mutation of four SPKIs, seeded mutations, field/length
  failures and input boundaries at/around the cap. Four public OpenSSL SPKIs
  compare against values independently extracted from retained OpenSSL public
  displays. Python supplies a byte-slicing/integer/curve-equation oracle;
  every implementation result comes from one whole Bend evaluator. No private
  NIST field is consumed and synthetic private peer keys remain removed.
  Fresh primary native repeats all cases in 3.932s (guard total 4.079s).
  Source/fixture hashes match both targets and the primary run. All 424 prior
  source/fixture/script inputs remain unchanged except five inserted check
  commands; all 123 previous `crypto/check.sh` lines remain in order. Existing
  Moon globs cover the four new source/check files; published/public fixture
  inputs are reused without alteration. No existing crypto arithmetic changes.
  The first syntax attempt fails during parsing at 53.2 MiB and is retained;
  the corrected standalone closed/C/clang/JS build passes in 15.631s, peak
  288.0 MiB. Primary closed checking peaks at 215.5 MiB. Native/Bun evaluator
  peaks are 36.8/98.3 MiB aggregate, Bun's largest process 63.0 MiB. All jobs
  remain sequential, nice 10, with 120-second deadlines under
  `PYTHONDONTWRITEBYTECODE=1 python3 tools/build_guard.py --memory-mib <384|128>
  --process-memory-mib <320|96> --timeout 120 --report <artifact>/... -- nice
  -n 10 <job>`. Compiler calls use invocation-local `BEND_NO_TELEMETRY=1
  BUN_OPTIONS=--smol BUN_JSC_forceRAMSize=134217728 BUN_JSC_useJIT=false`;
  Bun evaluation uses `BUN_OPTIONS=--smol BUN_JSC_forceRAMSize=67108864` with
  normal JIT. `check.sh` scopes the compiler workaround to its new compiler
  calls. Exact jobs are `sh <artifact>/build.sh`, `python3 <checker> --report
  ... -- <native|bun generated.js>`, primary `bend
  crypto/x509_public_key_test.bend --check-only` and primary native checker.
  Pressure observations are normal; sampled cutoffs can overshoot and are not
  OS memory quotas. Bend 2.0.27/Bun 1.3.13/Python 3.12.8/Apple clang 21/OpenSSL
  3.6.4. RFC 5280 §4.1.2.7, RFC 4055 §1.2 and RFC 5480 §2 were reviewed.
  All six current verified 5280 errata were inspected; none alters this SPKI
  structure. Future EKU/path/name/policy work must apply those corrections,
  current 5280 updates and RFC 8813; held errata remain separate.
  See `crypto/X509_PUBLIC_KEY_REVIEW.md`. Artifacts:
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/x509-public-key/`,
  including retained C/JS, native/Bun/primary/resource reports, input hashes,
  standards/errata snapshots, corrected syntax failure and `evidence.json`.
  Full crypto/repository/browser gates remain stopped after the memory complaint.
  All 19 stack boxes remain open. This does not establish certificate validity,
  trust or TLS/DTLS interoperability; private-owner and timing/erasure findings
  remain unresolved. Next: parse certificates preserving original TBS bytes,
  bind inner/outer signature algorithms and admitted issuer keys to verification,
  implement constraints/trust/hostname checks and TLS scheme/handshake admission.

- 2026-10-02 (certificate algorithm admission; compiler workaround):
  `crypto/x509_algorithm.bend` now parses bounded, exact AlgorithmIdentifiers
  for SHA-256 RSA PSS/v1.5 signatures and named-curve P-256/ECDSA. Public
  copiable metadata retains unrestricted RSA versus PSS-only keys and present
  PSS hash/MGF/trailer/minimum-salt restrictions. PSS signatures require salt
  32; key minima 0–32 are retained, omitted salt defaults to 20. Absent PSS
  key parameters remain PSS-only. NULL/absent hash and v1.5 parameter rules,
  ECDSA absent-only parameters and mandatory EC named-curve parameters follow
  the reviewed RFC profile. Unknown OIDs, unordered/duplicate PSS fields,
  malformed integers, truncation and trailing bytes fail closed. Explicit
  trailer 1 is recognized; this is profile admission, not complete canonical
  ASN.1 schema validation. SHA-1 defaults and other profiles are unsupported,
  never silently interpreted as SHA-256. `compatible` checks certificate
  algorithm compatibility only; it is separate from TLS wire SignatureScheme.
  Seven fresh primary algorithm closed checks pass. Native and normal-JIT Bun
  each pass all 4,563 oracle cases in 6.222/9.951s: PSS parameter matrix and
  defaults, RFC fixtures, every truncation/bit mutation, all PKCS OID suffixes,
  field order, malformed inputs, cross-algorithm binding, DER boundaries and
  four independently prepared public OpenSSL certificate algorithm fixtures.
  Fresh primary native repeats all cases in 4.534s (guard total 4.644s).
  Only the precompiled Bend evaluators implement parsing/classification; Python
  separately supplies a byte-slicing/field-map oracle and routes operation
  groups sequentially. Synthetic private peer keys were removed. Adopted
  runtime sources match native/Bun report hashes; the redundant copied DER
  adapter is byte-identical to existing `der_cli.bend` and is not adopted.
  Five duplicate DER closed witnesses are removed from the new algorithm test;
  the eight committed DER witnesses remain. All 416 prior source/fixture/script
  inputs are preserved except nine inserted `crypto/check.sh` commands; its
  original 114 lines remain in order. Existing Moon input globs cover new files.
  The default-JIT compiler still cuts off for the Data-metadata key adapter
  at 321.6 MiB. Invocation-local `BUN_JSC_useJIT=false` lets the same source
  compile at 242.1 MiB; a full standalone closed/C/clang/JS build of all four
  adapters passes in 31.948s, peak 249.5 MiB. The option is runtime-verified;
  this is a workaround for these inputs, not proof the earlier 18–22 GB
  compiler problem is resolved. `crypto/check.sh` applies it only to the new
  compiler calls, leaving generated Bun execution on normal JIT. Fresh primary
  closed checking peaks at 165.8 MiB. Native/Bun matrices peak at 55.4/121.0 MiB
  aggregate; Bun's largest process is 75.5 MiB. Large DER diagnostics run alone,
  retaining every case. Jobs are sequential, nice 10, with 120-second deadlines
  under `PYTHONDONTWRITEBYTECODE=1 python3 tools/build_guard.py --memory-mib
  <384|128> --process-memory-mib <320|96> --timeout 120 --report <artifact>/...
  -- nice -n 10 <job>`. Compiler invocations use `BEND_NO_TELEMETRY=1
  BUN_OPTIONS=--smol BUN_JSC_forceRAMSize=134217728 BUN_JSC_useJIT=false`;
  Bun evaluators use `BUN_OPTIONS=--smol BUN_JSC_forceRAMSize=67108864`.
  Commands are `sh <artifact>/build.sh`, `python3 <checker> --report ... --
  python3 <fixture> [--bun] --key ... --signature ... --binding ... --der ... --`
  and the primary `bend crypto/x509_algorithm_test.bend --check-only` plus
  primary native checker. Pressure observations are normal; cutoffs are sampled
  and can overshoot. Bend 2.0.27/Bun 1.3.13/Python 3.12.8/Apple clang 21/OpenSSL
  3.6.4. RFC 4055/5756/5480/5758 and refreshed verified errata were inspected;
  RFC 9846 scheme/key distinctions and RFC 8813 future key-usage rules remain
  explicit integration requirements. See `crypto/X509_ALGORITHM_REVIEW.md`.
  Artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/x509-admission/`,
  including `evidence.json`, input manifests, retained C/JS, native/Bun/primary
  reports, compiler-option evidence and unchanged-cutoff failure reports.
  Earlier draft/peer/standards artifacts remain in adjacent `x509-algorithm/`.
  Full crypto/repository/browser gates remain stopped after the memory complaint.
  SPKI bits, signature/chain/constraints/trust/hostname checks, private owners,
  runtime/erasure review and all 19 stack acceptance boxes remain open.
  Next: decode and admit RSA/P-256 SPKI keys using existing public-key validators,
  bind AlgorithmIdentifiers and TLS schemes to verification, then certificate
  constraints/trust and the handshake owner. No certificate/TLS acceptance claim.

- 2026-10-02 (certificate DER framing prerequisite; algorithm draft unverified):
  `crypto/der.bend` adds bounded TLV framing in Bend, with valid-octet and
  65,535-byte total-input admission, single-octet tags, minimal definite lengths,
  truncation rejection and exact consumed-encoding/rest preservation.
  `complete(tag, bytes)` also enforces the selected tag and no trailing bytes.
  It does not validate ASN.1 primitive values, schemas, keys or certificates.
  Eight fresh primary closed checks pass. Isolated native and Bun each pass
  all 1,552 independent byte-slicing oracle cases: length/tag octets, boundaries
  through the cap, aliases, every truncation, header/content bits, seeded
  round trips/rest preservation and four independent public OpenSSL certificates
  plus their SPKIs. Synthetic private peer keys are removed. The original
  batched Bun diagnostics crossed the 96 MiB process cutoff; large inputs now
  run individually with every case retained. Passing Bun takes 2.188s, peak
  105.3 MiB aggregate / 79.6 MiB individual. Original native takes 1.125s,
  35.2 MiB; the fresh primary checker with the final batching passes all 1,552
  in 0.407s. Primary closed/native work totals 0.948s, peak 112.4 MiB.
  Standalone final closed/C/clang/JS compilation passes in 2.311s, peak
  178.8 MiB. Inputs/hashes prove the five adopted DER files match the tested
  isolated copies and all 411 prior source/fixture inputs are preserved, apart
  from five added check-script commands. `crypto/check.sh` retains all 109
  original lines in order; Moon's existing source/Python/vector globs cover
  the five new files. No prior crypto algorithm changes in this milestone.
  All jobs are sequential, nice 10, with 120-second outer deadlines under
  `PYTHONDONTWRITEBYTECODE=1 python3 tools/build_guard.py --memory-mib <384|128>
  --process-memory-mib <320|96> --timeout 120 --report <artifact>/... -- nice
  -n 10 <job>`. Standalone compiles/closed checks use 384/320 MiB and passing
  invocation-local `BUN_OPTIONS=--smol BUN_JSC_forceRAMSize=134217728`;
  evaluators use 128/96 MiB, with Bun's passing invocation using 67108864.
  Exact jobs are `sh <artifact>/build-der.sh`, `python3 <checker> --report
  <artifact>/<target>.json -- <native|bun generated.js>` and
  `sh <artifact>/primary-focused.sh`. All pressure observations are normal;
  cutoffs are sampled and can overshoot. Bend 2.0.27/Bun 1.3.13/Python 3.12.8,
  Apple clang 21/OpenSSL 3.6.4. X.690 2021 length/framing clauses were reviewed.
  The larger algorithm-admission draft remains only in the isolated artifact
  checkout. Initial syntax/order errors were corrected; combined and split
  adapters then crossed the unchanged compiler cutoff (sampled 322–348 MiB).
  A premature driver invocation failed because no evaluator had been produced;
  it is not a successful algorithm matrix. None of that draft is adopted or
  reported as verified. RFC 4055/5756/5480/5758 and refreshed errata were read:
  verified 4055 items 1468/1676 clarify field naming and MGF spelling; 5480
  items 6670/8026 correct key-usage naming and a curve spelling. Key-usage work
  must also follow RFC 8813. Held items are retained separately.
  Artifacts (`<artifact>`):
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/x509-algorithm/`,
  `evidence.json`, `adopted-inputs.json`, public fixtures, retained C/JS,
  `der-final-build.log`, `der-native.json`, `der-bun.json`, primary logs and
  all success/failure resource reports. Full crypto/repository/browser gates
  remain stopped after the memory complaint. DER framing is a prerequisite,
  not certificate acceptance or TLS interop. Next: isolate/reduce the algorithm
  parser's compiler workload, verify both targets, then admit SPKI key bits and
  bind certificate signatures/constraints/trust to the TLS handshake owner.
  Private owners, runtime/erasure review and all 19 stack boxes remain open.

- 2026-10-02 (in-place RSA shift; focused native/Bun signatures):
  `rsa_integer.right.go` now reads the next limb before overwriting the current
  one and clears the vacated high cell in its owned accumulator. This removes
  the fresh 512-cell array per Montgomery limb row. Both high carry cells are
  preserved before the shift; all higher cells remain zero. Public parameter
  admission, arithmetic bounds, final subtraction and exponent scheduling are
  unchanged. Only the integer module and two added closed shift witnesses
  change; the checkers, CLIs, fixtures, `crypto/check.sh` and P-256 are unchanged.
  Thirteen integer and six signature closed checks pass. Fresh uninstrumented
  native and Bun evaluators each pass 725 arithmetic plus 774 full-signature
  cases. All previously defined rows/controls remain: Bun signatures run in
  the existing published/peers/admission/tamper_pss/tamper_v15 sections and
  their combined counts exactly equal native. Native times are 1.670/2.584s;
  Bun 68.097s / 181.024s summed across signature sections. This resolves the
  preceding checkpoint's missing full-signature Bun matrix. Frozen adoption
  hashes preserve all 409 other source/fixture inputs. Fresh primary closed
  checks and both native matrices pass in 4.158s with the tested retained
  binaries, peak 128.8 MiB; all input hashes match.
  Artifact-only profiling of one 2048-bit exponent-65537 public power measures
  9,274 -> 6,260 zero arrays and unchanged 20 clones. Both versions return the
  independent oracle result. The 3,014-array reduction equals 137 limbs times
  22 Montgomery calls; logical slots fall 4,758,528 -> 3,215,360. These are
  array counts, not measured physical bytes or peak RAM. The earlier dense
  4096-bit source model predicts 1,679,072 fewer shift arrays and 18,887,680
  remaining logical slots; that Bun profile is still unmeasured. Release C,
  optimized assembly and line-annotated assembly are retained. The optimized
  release/annotated objects have identical 69,100-byte text and 2,162 relocation
  semantics. Selected inlined `_spin_1` shift instructions preserve read-before-
  write ordering and high-cell clearing. This mapping covers that operation
  only; complete native/runtime/JIT/GC/erasure review remains required.
  All nine native cost profiles pass three repetitions each. Native 65537
  medians are 0.004570/0.005772/0.008671s for 2048/3072/4096 bits; sparse
  0.065100/0.210647/0.508912s; dense 0.095954/0.316718/0.748298s. Bun's single
  2048-bit samples are 0.524899/11.138857/16.849140s. No demonstrated speedup;
  these few samples include startup/file I/O and do not accept handshake latency.
  Every job is sequential and nice 10 under `PYTHONDONTWRITEBYTECODE=1
  python3 tools/build_guard.py --memory-mib <384|128> --process-memory-mib
  <320|96> --timeout 120 --report <artifact>/<job>-resource.json -- nice -n 10
  <job>`. Standalone closed checks/compiles use 384/320 MiB; precompiled
  evaluation/profiling/benchmark jobs use 128/96 MiB. Scripts `build-integer.sh`,
  `build-signature.sh` and `map-native.sh` retain C/assembly; matrix jobs call
  unchanged `rsa_integer_check.py` / `rsa_signature256_check.py [--section ...]`
  with `--report ... -- <native|bun generated.js>`. `run-primary-focused.sh`
  repeats primary closed/native checks without recompilation. Maximum compile
  peak 257.2 MiB; maximum evaluator peak 92.4 MiB; every pressure sample normal.
  These sampled cutoffs can overshoot; they are not kernel allocation quotas.
  Bun 1.3.13 uses invocation-local `BUN_OPTIONS=--smol` and
  `BUN_JSC_forceRAMSize=268435456`; Bend 2.0.27, Python 3.12.8, Apple clang 21.
  All exact commands, terminal results, input/output hashes and limits are in
  `<artifact>/evidence.json` and the retained resource reports; `<artifact>` is
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/rsa-allocation/`.
  Full crypto, repository and integrated browser gates remain stopped after
  the memory complaint. No private operation or timing/erasure approval is
  claimed. Next: certificate AlgorithmIdentifier/public-key admission and
  bounded verification scheduling, then private owners and TLS/DTLS integration.
  Full ECDSA verification and safe package builds also remain outstanding.
  The complete goal stays active with all 19 acceptance boxes open.

- 2026-10-02 (bounded public RSA work and generated-JS review): The new
  `crypto/rsa_integer_bench.py` checks precompiled public powers against Python
  bigint recovery using the frozen public peer modulus/signature operands.
  Native passes all nine 2048/3072/4096-bit exponent profiles, three repetitions
  each; Bun passes all three 2048-bit profiles once and 65537 at 3072/4096 bits
  three times each. Every invocation returns the exact independently computed
  k-byte result. The full-width sparse exponent has two set bits; dense is n-2.
  Alternate exponent/factor relationships are not validated: these are admitted
  arithmetic operands, not additional certified keys or valid signatures.
  Native 65537 medians are 0.004083/0.005730/0.008258s; full-width sparse
  0.066825/0.208241/0.495538s; dense 0.097293/0.316607/0.735184s for increasing
  widths. Bun's 2048-bit 65537/sparse/dense samples are
  0.541224/11.113214/16.753540s. Its 3072/4096-bit 65537 medians are
  0.480855/0.809546s. These times include process startup/file I/O, are only
  one to three samples, and do not establish handshake latency or timing safety.
  No larger full-width Bun job is launched after that 16.75s sample; those
  results remain missing. Public admission is unchanged.
  All six jobs run sequentially, nice 10, through `tools/build_guard.py
  --memory-mib 128 --process-memory-mib 96 --timeout 120 --report <artifact>/...
  -- nice -n 10 python3 crypto/rsa_integer_bench.py --bits <2048|3072|4096>
  [--profile 65537] [--repeats 1] --report <artifact>/... -- <precompiled evaluator>`.
  Native peak is 24.7 MiB, Bun 82.5 MiB; all pressure samples are normal.
  Bun 1.3.13 uses invocation-local `BUN_OPTIONS=--smol` and
  `BUN_JSC_forceRAMSize=268435456`; no compiler runs and heavy builds stay stopped.
  Current RSA source/CLI hashes match the original evaluator adoption record.
  The static generated-JS inventory pins 66 RSA functions and their branch,
  indexed-access and clone sites. Exponent bits select multiply/clone in
  `power.bit`: public in this API, unsuitable for a private exponent. Inspected
  limb indices follow public counters; row bounds and 0/32767 final selection
  are retained. Ordinary arrays, clones, tagged state and trampolines still
  allocate. The source model identifies one fresh 512-cell right-shift array
  per Montgomery limb row and three per R-squared doubling. Dense 4096-bit
  execution statically creates 1,679,072 right-shift arrays and 878,572,544
  logical array slots overall; this is not a measured byte allocation or peak.
  In-place affine shifts and retained public contexts are candidates, not fixes
  already implemented. Current native source-to-optimized-code mapping, Bun
  JIT/GC/erasure approval and all private-owner findings remain unresolved.
  Artifacts (`<artifact>`):
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/rsa-signature/`,
  `cost-native-{2048,3072,4096}.json/log`, `cost-bun-2048.json/log`,
  `cost-bun-{3072,4096}-65537.json/log`, each guard report and
  `rsa-generated-review.json` and `rsa-cost-evidence.json`. Benchmark Python parsing, source hashes,
  fixed deadline/repeat limits and whitespace checks pass. This resolves the
  previous lack of native full-width public-exponent evidence without accepting
  an integrated handshake, full signature scheme on Bun, any private operation
  or package gate. Next: reduce arithmetic allocation under the existing
  admission contract and retain generated code for native mapping; then finish
  the Bun signature matrix, certificate algorithm/key admission and private
  owners. The full goal stays active with all 19 acceptance boxes open.

- 2026-10-02 (native RSA digest-signature checkpoint; heavy builds stopped):
  `rsa_signature256.bend` connects Bend RSAVP1 to strict SHA-256 PSS/v1.5
  verification. PSS binds MGF1-SHA-256 and salt length 32. Its recovered integer
  must fit `ceil((modBits-1)/8)` bytes: when k is one byte larger, a nonzero
  prefix is rejected before shortening; normal-width leading zeros remain.
  Invalid digest bytes/lengths and primitive key/signature admission failures
  return False. Private RSA, key validation/trust, AlgorithmIdentifiers and
  certificate/handshake integration remain required.
  The adopted module/CLI/checker and public fixtures pass 774 full-signature
  cases using the previously compiled isolated native executable: 110 NIST,
  34 OpenSSL peers, 52 parameter/key/range cases and controls, and 289 digest/
  signature tampering cases per scheme. Genuine peer moduli span 2048, 2049,
  2050, 3072 and 4096 bits. The 2049-bit synthetic key combines OpenSSL primes
  with independently formed DER and passes OpenSSL's private-key check; both
  valid shortened PSS and a below-modulus nonzero-prefix rejection are covered.
  A positive full-width zero prefix, wrong salt/MGF profiles, cross-scheme
  signatures and v1.5 DER/padding rejection also pass. Python public recovery
  is an oracle only; all evaluator output is computed by Bend. Temporary
  synthetic private peer keys are deleted; retained fixtures are public.
  An initial peer raw-signing command hit OpenSSL's prehashed input-size limit;
  the no-padding private peer operation plus independent public recovery fixes
  fixture preparation. Published signature integer hex, including odd-nibble
  values, is converted to exactly k bytes after an initial import failure.
  Neither failure changed the Bend verifier. Previously documented two NIST
  exclusions remain explicit; they are not reported as successful tests.
  Six unchanged closed checks and native compilation passed earlier under the
  guard (99.9/248.0 MiB). No compiler was launched during this continuation.
  Native matrices pass in 2.593s isolated and 2.076s from the primary checker;
  both peak at 27.6 MiB. Peer preparation peaks at 30.7 MiB. Execution uses
  `PYTHONDONTWRITEBYTECODE=1 python3 tools/build_guard.py --memory-mib 128
  --process-memory-mib 96 --timeout 120 --report <artifact>/primary-native-resource.json
  -- nice -n 10 python3 crypto/rsa_signature256_check.py --report
  <artifact>/primary-native.json -- <artifact>/rsa-signature-native`.
  All observed system pressure is normal; the primary run records three
  observations. Current read-only inspection finds no Bend/Bun/Moon/compiler
  or Grounds test process; host swap remains about 8.7 GiB. Older ledger
  evidence confirms exploratory 18.0/21.7 GB build footprints; the current
  snapshot cannot attribute accumulated swap to a specific process.
  Evidence root (`<artifact>`):
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/rsa-signature/`, including
  `prepare_peers.py`, both fixed logs/resource reports, `primary-native.json/log`,
  earlier closed/native compilation reports and `adopted-inputs.json`.
  Hashes prove all adopted inputs and all 282 isolated Bend source files match
  the primary checkout. `crypto/check.sh` retains all 104 prior lines in order
  and adds five closed/build/native/Bun commands; existing Moon globs cover the
  new files. Shell syntax, Python parsing and whitespace are checked without
  compilation. Bun full-signature verification, forced crypto/package and
  repository gates are pending; heavy builds remain stopped after the memory
  complaint. This is native focused evidence, not full signature/package/stack
  acceptance or timing/erasure approval. Next: inspect generated verifier code
  and certificate AlgorithmIdentifier/key admission; finish the Bun signature
  matrix when bounded compiler work resumes, then private RSA ownership and
  full TLS/DTLS integration. All 19 complete-stack acceptance boxes stay open.

- 2026-10-02 (experimental RSA public primitive checkpoint): New
  `rsa_integer.bend` supplies unsigned big-endian conversion, negative low-limb
  inverses, variable-size Montgomery arithmetic, R-squared preparation and
  public exponentiation/RSAVP1 in Bend. The public entry admits canonical odd
  2048–4096-bit moduli, canonical odd exponents >1 and <n, and exactly k valid
  signature bytes representing s<n. Public exponents are byte strings, without
  U32 truncation; fixed-width signature leading zeros are preserved. This
  assumes a valid RSA key and does not prove factor structure. Base-2^15 inner
  sums stay <=2^30-1; both high carry cells survive reduction before a masked
  canonical subtraction. Limb loops and affine ownership are explicit. Exponent
  branches are public; this is not a private-key operation.
  In the isolated b30622e archive, the exact adopted arithmetic/CLI/checker
  sources pass 725 cases on native and Bun: byte conversions 58, low inverses
  155, Montgomery products 285, R-squared contexts 57, public powers 39,
  published NIST RSAVP1 representatives 110, parameter/width/range admission 21.
  Arithmetic boundaries reach 4096 bits; public powers include a 65-bit exponent
  beyond U32 and the published 21–24-bit exponents. Near-modulus-width exponents
  have not been benchmarked as a handshake gate. Native/Bun execution took
  1.133s/69.129s, peak 24.5/83.2 MiB. Native/JS compilation peaked at
  238.6/167.7 MiB. All jobs were sequential and nice 10, with 120-second deadlines;
  compilation/Bun caps 384 MiB aggregate / 320 MiB individual, native execution
  128/96 MiB. Every sampled system-pressure observation was normal. Original
  bytes/IO dependencies and existing NIST fixture remain unchanged. Eleven
  final closed checks pass fresh in the primary checkout (peak 128.2 MiB),
  covering four small arithmetic witnesses and seven malformed/key/range cases.
  One extra parenthesis in a newly added test was corrected before that final
  closed run; it did not change arithmetic or either tested runtime input.
  Source hashes prove the primary arithmetic/CLI/checker equal the tested copies.
  Evidence: `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/rsa-integer/`,
  especially `native-all.json/log`, `bun-all.json/log`, their guard reports,
  `primary-closed.log`, `primary-closed-resource.json`, `draft-inputs.json` and
  `adopted-inputs.json`. Bend 2.0.27/Bun 1.3.13; RFC 8017 section 5.2.2 and HAC
  algorithm 14.36 reviewed. `crypto/check.sh` retains all 99 prior lines in
  order and adds five closed/build/native/Bun commands; Moon's existing globs
  cover the new sources and checker. Shell syntax/whitespace checks pass.
  Full crypto/repository gates remain outstanding and were not restarted after
  the memory complaint. Next: connect RSAVP1 with PSS/v1.5 digest verification,
  including the PSS k-versus-emLen boundary, then independent full-signature
  native/Bun/OpenSSL tests. RSASP1, blinding/fault checks, private-key ownership,
  generated timing/erasure approval and certificate/TLS/DTLS integration remain
  required. All 19 complete-stack acceptance boxes remain open.

- 2026-10-02 (experimental RSA encoding checkpoint): `rsa_encoding.bend`
  adds SHA-256 MGF1 and strict PSS/v1.5 encoded-representative APIs in Bend.
  PSS requires SHA-256/MGF1-SHA-256 and a supplied 32-byte salt; unused high bits,
  trailer, exact width, zero PS, delimiter and recomputed hash are checked.
  v1.5 enforces canonical SHA-256 DER DigestInfo including NULL and at least
  eight FF padding bytes. Count bounds precede arithmetic; MGF1 recursion uses
  structurally decreasing public block fuel. Eleven closed checks reject
  non-byte inputs and invalid/minimum/maximum-Nat sizes. Numeric fixture opcodes
  exercise Bend directly; Python/OpenSSL are independent peers only.
  Fresh primary-checkout native and Bun each pass 1,582 cases: MGF1 79, PSS 972,
  v1.5 351, published NIST representative checks 150, OpenSSL peers 30.
  The official NIST archive downloaded with SHA-256
  `8405aeb3572a4f98ed4b1a3ccb3f2f49e725462dd28ec4759d6a15d88855d19c`;
  all selected rows retain source lines and public peer values. Two rows are
  individually excluded for odd-nibble message input or signature >= modulus,
  requiring API/primitive admission outside this component. OpenSSL's 2049-bit
  key request produced an actual 2048-bit modulus; the corrected oracle records
  actual sizes and also checks 2050/3072/4096-bit peers. Initial isolated syntax,
  match-order/affinity and recursion errors were fixed before adoption; original
  primitive dependencies remain byte-identical. The fresh primary focused script
  checks closed terms, compiles both evaluators and runs both complete matrices
  under 384 MiB aggregate / 320 MiB individual caps, niceness 10 and a 120-second
  deadline. It passes in 8.340 seconds, peak 230.4 MiB, with nine normal-pressure
  observations. Source SHA-256s remained unchanged through verification.
  Artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/rsa-encoding/`,
  particularly `run-primary-focused.sh`, `primary-focused.log`,
  `primary-focused-resource.json`, `primary-focused-evidence.json`,
  `primary-native.json`, `primary-bun.json`, `prepare_vectors.py` and the NIST
  archive/fetch report. Bend 2.0.27, Bun 1.3.13, OpenSSL 3.6.4. RFC 8017/TLS
  RFC 9846 reviewed; fresh official 8017 errata confirms all five verified
  corrections, and saved 9846 search lists five Reported, no Verified.
  `crypto/check.sh` retains all 94 previous lines in order and adds all five
  RSA closed/build/native/Bun commands; Moon already covers the new source,
  checker and vector inputs. Shell syntax and whitespace checks pass. The full
  crypto and repository gates were not restarted after the memory complaint;
  this is a focused experimental checkpoint, not package or stack acceptance.
  RSA exponentiation, full signature schemes, key/parameter/range admission,
  generated timing/erasure approval and TLS/DTLS/certificate integration remain
  open. Next: bounded Bend RSA integer/modular arithmetic and RSAVP1/RSASP1,
  followed by full PSS/v1.5 signature owners and independent full-signature
  native/Bun tests. All 19 complete-stack boxes remain open.

- 2026-10-02 (system pressure admission and cutoff): `tools/build_guard.py`
  now reads macOS `kern.memorystatus_vm_pressure_level` before launch and
  once per second while a job runs. Warning/critical pressure refuses a new
  launch (125) or kills only the owned job group (137), independently of its
  existing aggregate/individual memory cutoffs. Unknown observations and read
  failures fail closed. Apple's XNU source confirms this sysctl converts internal
  levels to dispatch flags 1/2/4; no kernel setting was changed. Linux reports
  this added metric unsupported, retaining its existing RSS guard. All 13 guard
  tests passed in 6.893 seconds with
  `PYTHONDONTWRITEBYTECODE=1 python3 tools/build_guard_test.py -v`.
  New cases inject warning/critical observations before and after launch,
  exercise real owned-child cleanup (including a TERM-ignoring child), preserve
  an unrelated process, and verify measurement failure/unknown/short reads.
  They never induce actual system pressure or compile Bend. A live 1.2-second
  Python sleep under 128 MiB aggregate / 64 MiB individual caps exited zero:
  15.6 MiB peak, two actual normal-pressure samples, 1.288 seconds elapsed.
  Evidence is in
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/resource-pressure/normal-live.json`.
  This adds sampled system-pressure protection, not a hard allocation quota or
  a diagnosis of the user's earlier 15 GB / 7 GB peaks. The interrupted crypto
  package gate remains unaccepted and was not restarted. Next: validate the
  isolated RSA encoding draft with short guarded checks, then reduce or partition
  the remaining crypto verification workload before reconsidering a full gate.

- 2026-10-02 (build stopped after memory complaint): Terminated the owned
  guard PID 5213 and its crypto gate process group 5221 after the user reported
  Bend processes using 15 GB / 7 GB. Confirmed the terminal session exited 143
  and no owned guard, Bend compiler or ECDSA evaluator remained. This run's
  sampled peak was 556.8 MiB aggregate and 476.5 MiB individual, at unchanged
  640/512 MiB limits; these measurements do not establish the cause of the
  user's reported earlier peaks. System swap still contained 9847.69 MiB;
  its origin was not attributed. The interrupted gate ran 2027.831 seconds.
  Bun P-256 completed 609 cases, ECDSA published vectors completed 49 cases
  and signing completed 60 additional cases (109 cumulative). Remaining
  ECDSA sections and later package checks did not complete; no full gate is
  accepted. All 589 frozen tracked inputs still matched b4720b9 before this
  ledger update. Reports and logs remain under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/ecdsa-current/`, including
  `crypto-forced-retry-resource.json`, `crypto-forced-retry.log` and
  `crypto-retry-termination.json`. Do not automatically restart the full gate
  after this complaint; first resolve the machine resource impact. No compiler
  limits were raised, unrelated processes were untouched, and the full stack
  remains incomplete.

- 2026-10-02 (forced crypto gate and X25519 evaluator recovery): The first
  fresh ECDSA-expanded `moon --concurrency 1 run crypto:check --force` on
  4953680 (task hash prefix `54beed3a`) passes all closed/type/ownership checks
  and builds every new native ECDSA evaluator, then stops compiling the existing
  X25519 evaluator. Guard exit 137 after 32.164s, peak 593.30 MiB aggregate and
  512.03125 MiB individual at the unchanged 640/512 MiB cutoffs. No complete
  runtime matrix or successful fresh RunReport follows from that stopped run.
  An affine exact-name classifier replaces only X25519 fixture String literal
  patterns; the `public`/`mult`/`shared` CLI and original file/error ordering
  remain. All original X25519 checks are retained. Fresh native/Bun compile
  and full focused matrices pass, including noncanonical aliases, four OpenSSL
  exchanges, all-zero/malformed inputs, 124 added exact-mode/arity failures on
  each target and the native RFC 1,000-iteration vector. The guarded focused
  command exits zero in 47.349s and peaks at
  144.84 MiB, rather than crossing 512 MiB in the prior build.
  Cryptographic core sources, including field, P-256 and X25519 arithmetic,
  remain unchanged. A first classifier draft's forward-reference error was
  corrected with a continuation before this passing check; it is not accepted
  as evidence. Artifacts: `crypto-forced-*`, `primary-forced-inputs.json`,
  `post-forced-input-delta.json` and `x25519-affine-*` under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/ecdsa-current/`.
  Next: fresh forced crypto retry with this source change, inspect all native/Bun
  results and source stability, then the required repository gate. ECDSA's full
  Bun matrix, generated timing/erasure and all 19 stack boxes remain open.

- 2026-10-02 (experimental ECDSA checkpoint under unchanged resource cutoffs):
  Added Bend P-256/SHA-256 raw digest signing/verification, RFC 6979 deterministic
  nonce generation and a strict DER signature boundary. Current accepted
  `p256.bend` and `field256.bend` remain byte-identical. Private/signature/nonce
  scalars require 1..n-1; digest integers reduce modulo n. Verification validates
  the SEC1 point, rejects an infinity sum and compares x modulo n. Signing rejects
  zero r/s, uses the HMAC rejection update and fails closed after 128 candidates.
  The current RFC Editor search confirms verified RFC 6979 erratum 3812 adds
  zero-s retry; held editorial 5963 changes notation only. Exact source/review
  links and unresolved secret-derived branch, runtime/JIT and erasure findings
  are in `crypto/ECDSA_REVIEW.md`. No live TLS/DTLS path consumes this API.
  All 30 selected NIST rows match the previously downloaded official archive,
  and archive/RFC text hashes match the vector manifest. A new NIST fetch returns
  403; this is local re-verification, not a successful current download.
  Five narrower evaluators retain each complete Bend operation; Python only
  routes batches. The discarded combined evaluator crosses the 512 MiB cutoff
  at 526.5 MiB. The long rejection dispatcher also crosses it at 522.3 MiB;
  short fixture opcodes preserve its operations and compile below the limit.
  Initial five native builds peak at 207.2–356.3 MiB; six original closed checks
  and five JavaScript builds pass at 304.4 MiB. Current primary six closed checks,
  all five native builds, all 384 native ECDSA cases, all 1,388 native DER cases
  and all 51 Bun rejection cases pass in the guarded `run-primary-focused.sh`
  command, peak 363.8 MiB. Native ECDSA takes 12.688s, DER 0.562s; Bun rejection
  takes 10.474s, including actual zero/n/n+1 nonce-candidate rejection.
  A slow Bun probe passes all 49 published-vector cases in 376.636s, then is
  deliberately stopped at 511.202s for a runtime comparison (exit 143).
  Clearing BUN_OPTIONS alone retains the reported-RAM heuristic and same cutoff
  but times out at 180.018s, peak 190.7 MiB; it proves no complete matrix or
  improvement and was not adopted. No overlapping compiler/test jobs ran.
  Artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/ecdsa-current/`,
  with `probe-provenance.json`, `tested-inputs.json`,
  `published-vector-provenance.json`, `generated-js-review.json`,
  `gate-coverage-review.json`, `primary-focused-*`, `primary-native/checks.json`,
  `primary-native/bun-rejection.json` and `bun-*-resource.json`/logs.
  The package check retains every previous command and adds the complete native
  and Bun ECDSA/DER matrices. Full Bun sections and forced crypto/repository gates
  are pending at this checkpoint; native vectors alone do not accept the package.
  Next: run fresh guarded `moon --concurrency 1 run crypto:check --force`, inspect
  the complete result and input stability, then the required repository gate.
  Preserve all 19 open full-stack boxes; RSA, generated-runtime/erasure approval,
  Bend cookie/TLS/DTLS and integrated secure browser/relay/data/media remain open.

- 2026-10-02 (unaccepted JSON numeric/value factoring): The compact/pretty
  generator was reduced from 303 transition rows per loop to 187, then 142 by
  sharing numeric decisions and leading nonzero-digit handling. A flat candidate
  still crosses the unchanged 512 MiB cutoff at 560.0 MiB; a grouped numeric
  candidate crosses at 548.2 MiB during source loading. No candidate passes the
  constructor/proof/conformance gate. All five original files, including the
  head template, generator, fast source and two proof sources, are restored
  byte-identically and reverified before this checkpoint. Rejected sources,
  traces, resource reports and `restoration.json` are archived in
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/json-numeric-recovery/`.
  Grouping alone is not an accepted recovery. JSON and signaling compiler
  recovery remain required alongside the signatures/TLS dependency work.

- 2026-10-02 (guarded HTTP core and narrower signaling helpers): Fresh
  `moon --concurrency 1 run http_core:check --force` passes with Bend 2.0.27,
  Bun 1.3.13 and the unchanged 640 MiB aggregate / 512 MiB individual sampled
  cutoffs. Moon task execution is 18s854ms, overall 18s882ms; the enclosing
  guard takes 19.459s, peaking at 564.17 MiB aggregate / 378.88 MiB individual.
  Full hash: `8df08374edcec0b01ba4c06560adacde8f5a25297e27f678bfa39bb6cbe59519`.
  Saved RunReport and task metadata confirm passed execution, exit zero and
  skipped cache hydration. Native and Bun each pass 838 strict canonical
  Base64 cases and 8,320 method classification/unknown-spelling cases.
  Method parsing consumes the selected suffix and reconstructs mismatches
  without sharing Strings; standalone type checking peaks at 134.42 MiB.
  Base64 moves into a narrow Bend module; every existing `Auth.b64_*` interface
  remains, and WebSocket admission uses the same decoder. Boolean padding
  comparisons retain the existing pad-bit/alphabet/tail rejection policy.
  All 93 original unit definitions, all eight public laws, 17 contract
  declarations and 100 proof declarations pass in smaller import scopes.
  `test.bend`, `LAWS.bend` and `PROOF.bend` remain byte-identical to HEAD.
  The runners copy every body verbatim, require complete assignments/public
  law fills and reject unknown units, duplicate assignments, an actual false
  equality and an altered law inventory in four owned negative regressions.
  The full gate also passes existing native cookie HMAC/verification checks
  and cold audits of hello, cookie-signing and runtime-argument method parsing.
  Cookie HMAC still uses the original native OpenSSL compatibility path;
  this does not complete Bend cookie signing or Bun cookie integration.
  Nine copied Base64 bodies and all 28 moved RTC format/entropy bodies match
  their originals exactly. The narrow retained-socket adapter copies 27
  existing operations and the existing Driver fields; transport decisions,
  send acknowledgements and all original fixture scenarios remain present.
  Ten shared/signaling modules type-check at 418.16 MiB aggregate, and 13
  closed exact-command/path/body/method admission regressions pass at 386 MiB.
  HTTP server cache inputs now cover its check script and all 38 transitive
  Bend sources, verified in `http-server-final-import-coverage.json`.
  Recovery commands use local `BUN_OPTIONS=--smol`,
  `BUN_JSC_forceRAMSize=268435456`, `PYTHONDONTWRITEBYTECODE=1`, `nice -n 10`
  and `tools/build_guard.py`; no global compiler setting or budget was changed.
  Artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/resource-recovery/`,
  including `http-core-complete-forced-*`, `partition-runner-regressions-*`,
  `method-affine-*`, `method-runtime-cold-*`, `signaling-token-proofs-*`,
  helper/body reviews and the 369-input manifest/stability reports.

- 2026-10-02 (remaining guarded failures after HTTP core recovery): Fresh
  `moon --concurrency 1 run http_server:check --force` (hash prefix `505681ff`)
  passes hello/request parsing, keep-alive, malformed framing, idle/partial/
  trickle deadlines and 4,000 actual requests with zero failures, then stops
  while building the middleware fixture: exit 137 after 16.366s, peak
  630.42 MiB aggregate / 521.28 MiB individual. Earlier monolithic core unit
  and proof cutoffs are superseded by the complete passing gate above.
  Fresh `moon --concurrency 1 run rtc:check --force` (prefix `45326188`)
  passes the preserved type checks, new closed admission regressions and all
  90 native SDP cases, then stops at signaling C emission: exit 137 after
  131.076s, peak 600.83 MiB aggregate / 513.91 MiB individual.
  Expanded actual HTTP/WS signaling tests and a fresh browser run remain
  unexecuted. The final repository `moon --concurrency 1 run :check` reuses
  the accepted core hash, then stops in JSON's mandatory constructor audit:
  exit 137 after 2.951s, 635.13 MiB aggregate / 545.97 MiB individual.
  JSON regenerates its original files byte-identically. These killed Moon
  runs have terminal guard reports/logs, not fresh successful RunReports.
  An isolated, SHA-verified official
  [Bend 2.0.34](https://github.com/bendlang/bend/releases/tag/v2.0.34) probe
  still crosses 512 MiB for unchanged baseline core units and JSON emission.
  Its standard library also changes TCP/UDP host arguments; signaling fails
  its TCP.listen signature check. It was not installed or adopted, and all
  acceptance evidence above uses the pinned 2.0.27 toolchain. The diagnostic
  GC/tracing copies and shared-String method experiment remain unaccepted.
  Logs and reports are `http-server-inputs-forced-*`,
  `rtc-import-method-forced-*`, `repository-core-complete-*` and
  `*-2.0.34-*` in the recovery directory above. The sampled guard allows brief
  overshoots; it is not a kernel memory quota. Only owned groups were stopped.
  Next: reduce JSON generated transition/emission workload and signaling's
  remaining compiler workload under the same limits, preserving constructor,
  proof, conformance and real-peer gates; resume mandatory signatures and
  generated-code review before Bend TLS/DTLS. All 19 full-stack acceptance
  boxes remain open; no fresh secure browser, TURN, data or media claim follows.

- 2026-10-01 (repository gate after SDP milestone 4777d4a): A fresh sequential
  guarded `moon --concurrency 1 run :check` still stops in JSON's mandatory
  constructor audit, with terminal exit 137 after 1.683s and a sampled peak of
  648.61 MiB aggregate / 534.94 MiB individual (640/512 MiB cutoffs).
  `repository-sdp.log` and
  `repository-sdp-resource.json` in the recovery artifact directory below record
  the cutoff; cached task output is not new package acceptance. JSON experiments
  grouping all 303 transitions per formatter by mode also crossed the unchanged
  512 MiB standalone cutoff. Stderr-only diagnostics locate the nested candidate
  in `fast.gc` type checking, and the helper-based candidate in numeric-helper
  type checking; grouping alone does not solve the workload. Neither candidate
  passed constructor/proof/conformance gates and neither was adopted.
  Original `gen_fast.py`, `fast.bend`, `proof/fast_run.bend` and `PROOF.bend`
  are byte-identical before and after the repository attempt, verified in
  `json-experiment-restoration.json` and `json-post-repository-restoration.json`.
  The unaccepted nested source/generator are saved as `json-unaccepted-fuel-mode-*`
  outside the repository, with `json-*-resource.json` and trace logs. The final
  diagnostic compiler diff/provenance is `trace-compiler-final-provenance.json`;
  it only adds stderr tracing to the owned pinned source copy. No jobs remain.
  Next: separate signaling's format/entropy helpers from imported test CLIs,
  preserving the owner and all current native/Bun/browser tests. For JSON,
  reduce duplicated numeric/whitespace transition work rather than retrying
  grouping; retain cold-type, proof and full conformance gates. The full goal
  remains active with every acceptance box still open.

- 2026-10-01 (SDP compiler workload recovery): Exact consuming text comparisons
  replace nested string-literal patterns in fingerprint/media/candidate parsing;
  line-field dispatch is separate from document-stage admission. Required tokens,
  case/spacing, candidate extensions, defaults, overrides and all bounds remain
  checked. The final `bend rtc/sdp.bend --check-only` and separate native/Bun SDP
  builds pass under the default 512 MiB guard; final type checking peaks at
  230.09 MiB, native compilation at 463.53 MiB and JS emission at 417.14 MiB.
  The expanded independent
  admission/malformed/bound matrix passes all 90 cases on each target, including
  exact-token near misses, wrong header order and optional-field handling.
  `rtc/check.sh` uses the native helper for SDP, and Moon includes that helper.
  A fresh guarded `moon --concurrency 1 run rtc:check --force` passes all 22
  type/proof checks and native SDP, then stops at the signaling fixture frontend:
  exit 137 after 137.555s, 601.83 MiB aggregate / 515.48 MiB individual, using
  unchanged 640/512 MiB cutoffs. A stderr-only copy of the pinned 2.0.27 compiler
  traces that fixture into imported test CLIs (last entered `examples/ice_valid.bend`)
  during loading; the installed compiler is untouched. This is not a successful
  RTC gate or fresh browser run. Logs, terminal resource reports and current input
  hashes are `sdp-*-resource.json`, `rtc-sdp-refactor-*`, `signaling-load-trace-*`
  and `sdp-refactor-evidence.json` under
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/resource-recovery/`.
  Next: reduce JSON generated-loop and signaling fixture import workloads under
  the same cutoff; run their complete existing checks and the missing repository
  gate. All 19 full-stack acceptance boxes remain open.

- 2026-10-01 (standalone cutoff localization after milestone 82fc0c4): With the
  same local recovery settings and `nice -n 10`, the default 512 MiB standalone
  guard stopped `bend rtc/sdp.bend --check-only` at 524.02 MiB after 1.594s,
  and `bend json/main.bend -o .../json-main-probe.c` at 515.44 MiB after 1.290s.
  Both returned 137, independently confirming these source workloads exceed
  the cutoff; neither is a successful type/C-emission acceptance result. No
  source input changed. Reports/logs are `sdp-check-only-*` and
  `json-main-emission-*` in the recovery artifact directory below. A fresh
  scan found no Bend, Moon, Bun or clang jobs after both terminal results.
  Next: reduce SDP pattern-checking and JSON constructor-audit emission workload
  under the same limits, retaining all validation and tests, then rerun the
  missing RTC/repository gates. The full goal remains active and incomplete.

- 2026-10-01 (bounded crypto/wire recovery gates): Fresh sequential guarded
  `moon --concurrency 1 run crypto:check --force` passes (19m50s801ms execution,
  hash `39490f0fb9e68d59734a722c5aa1b133796a069f90abf339c25df3316582af6b`).
  The command used `nice -n 10`, local `BUN_OPTIONS=--smol`,
  `BUN_JSC_forceRAMSize=268435456`, `PYTHONDONTWRITEBYTECODE=1`, a 640 MiB
  aggregate / 512 MiB individual sampled cutoff and a 3600-second timeout.
  Peak owned memory was 590.50 MiB aggregate / 511.59 MiB individual.
  Both targets pass the complete primitive and unchanged 70/72 traffic-owner
  matrices. P-256 passes all 609 cases in 4.340s native / 952.617s Bun. The slow
  Bun matrix is measured under these recovery/priority settings, not an isolated
  performance comparison. The gate now also executes the previously omitted
  Bun SHA-256/HMAC/HKDF matrix: all 29 hashes including million-a, 11 HMAC cases,
  three RFC HKDF vectors and seven output-length boundaries including 8160.
  P-256 reports each successful 16-case batch. Native helper builds, public
  four-word constant groups, the factored field CLI and read/write traffic
  fixtures pass this fresh gate. All 74 preexisting arithmetic definitions
  match the prior source after excluding comments/blank lines, and all 128
  constant bytes match. All 388 frozen code/config/check inputs remained
  unchanged until this gate ended. Current native/JS fixtures and their hashes
  are retained in `resource-recovery/crypto-builds/` below.
  Wire's combined record evaluator then crossed the unchanged individual cutoff
  after 2.051s (517.34 MiB individual). An initial directional split still
  imported the complete crypto command evaluators and was also stopped. The
  accepted fixture split imports only shared formatting and owner diagnostics;
  its complete per-direction record/update/failure/retirement functions remain
  in Bend. The Python launcher only selects and execs a fixture. Protocol
  `tls_record.bend`, `traffic.bend`, their original combined evaluators and the
  existing record checker remain byte-identical. Six directional lifecycle
  functions differ only in helper qualification. Fresh guarded
  `moon --concurrency 1 run wire:check --force` now passes in 1m8s298ms
  (hash `e29a1b805f0298ec9a389d39c796c27b43209a121b0794afecb741e7450971ca`),
  peak 619.33 MiB aggregate / 430.70 MiB individual. Both targets pass 154
  ChaCha and 166 AES record cases, RNG and transport/cleanup/compatibility
  matrices, including the reachable second-IP probe. All 392 frozen inputs
  remained unchanged during wire execution. No compiler budget was raised.
  Logs, terminal resource reports, fresh Moon run/hash reports, frozen manifests,
  source comparisons and draft-review excerpts are in
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/resource-recovery/`.
  Generated P-256 JS selection excerpts show the mask path and public loop/index
  schedule; native assembly/JIT/erasure review remains open. The isolated ECDSA
  draft was compared read-only with RFC 6979 section 3.2 and SEC 1 v2.0 sections
  4.1.3-4.1.4; its current-field full native/Bun acceptance is still pending.
  The RFC Editor errata endpoint returned Internal Error, so no fresh verified
  errata claim follows. An owned compiler copy that only prints existing source
  maps to stderr is prepared for the native audit; it has not been run, and its
  output must match installed-compiler C byte-for-byte before it is used as
  evidence. The installed compiler/user configuration is unchanged.
  Fresh RTC session 35854 is terminal 137: after 19 successful term-check
  messages the guard stopped a process at 517.27 MiB individual / 604.52 MiB
  aggregate, 136.747s elapsed. No fresh RTC integration/browser pass follows.
  The milestone `moon --concurrency 1 run :check` attempt is also terminal 137:
  it reused cached utf8/crypto/io/http-core/wire results, then stopped during
  JSON's constructor audit at 526.36 MiB individual / 632.80 MiB aggregate,
  2.369s elapsed. The temporary PATH wrapper prints Bend source arguments to
  stderr, but that JSON helper captures stderr, so its exact active source was
  not recovered. These failures leave the repository gate incomplete; stale
  `.moon/cache/runReport.json` must not be treated as a new failure/success
  report. Owned process groups were stopped, and no primary code input changed
  during the attempts. Terminal guard reports and logs are retained above.
  The milestone is verified crypto/wire recovery, not full-stack acceptance.
  Next: probe SDP and JSON constructor-audit C emission individually under the
  unchanged 512 MiB cutoff to locate and reduce compiler workload, then rerun
  RTC and repository gates. Continue the ECDSA/current-field matrices and
  timing audit; preserve every other full-stack requirement. All 19 acceptance
  boxes remain open.

- 2026-10-01 (resource safeguard verification): Fresh
  `PYTHONDONTWRITEBYTECODE=1 python3 tools/build_guard_test.py` passes all nine
  real subprocess tests in 3.016s. They exercise default 512 MiB aggregation,
  single Moon worker, command failure, combined and individual child cutoffs,
  timeout/interruption/orphan cleanup, overlap refusal and lock release, missing
  commands, and preservation of an unrelated process. The individual test kills
  a child above 48 MiB while total owned memory stays below 256 MiB. No Bend
  compiler is invoked by these tests. Evidence and source hashes are in
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/resource-recovery/guard-tests.log`
  and `guard-source-sha256.json` in the same directory.
  The CPU build helper runs Bend C emission and native compilation in separate
  processes and atomically creates a new output without replacing an existing
  file/symlink. Its exact current source built every native crypto fixture in
  the interrupted forced run recorded below. That proves the build helper on
  this macOS host, not a complete crypto/package or Linux acceptance result.

- 2026-10-01 (build stopped after renewed memory complaint): On the user's
  report of 15 GB / 7 GB Bend memory use, stopped the verified Grounds guard
  PID 13189 with SIGTERM. It killed owned process group 13194, returned 143,
  and a fresh scan found no remaining members. Unrelated processes were
  untouched. The interrupted forced crypto check is NOT a package pass.
  Its terminal report records 588.153 seconds, 555.14 MiB aggregate peak and
  496.81 MiB largest-process peak, under explicit 640 MiB aggregate / 512 MiB
  per-process sampled cutoffs. These measurements do not establish the
  earlier user-reported multi-gigabyte peaks or system memory recovery.
  No further compilation or package check was started in this response.
  Report and partial log:
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/ecdsa256/field-adapter/primary-crypto-fixtures-resource.json`
  and `primary-crypto-fixtures.log` in the same directory.
  Before interruption, native checks passed through 609 P-256 cases and both
  unchanged traffic matrices (70 ChaCha / 72 AES cases). Bun passed primitives
  through 4,178 field cases and was still evaluating P-256. Bun P-256 and
  subsequent checks, fresh RTC/repository gates and a milestone commit remain
  pending; no stale Moon report may substitute for this interrupted run.
  Pending source changes split public field constants, factor the field CLI,
  build native fixtures in separate Bend/clang phases, and split the traffic
  test fixture by direction while retaining each complete Bend-owned lifecycle.
  The guard adds an optional individual-process cutoff and nine small safety
  tests passed; its default aggregate cutoff remains 512 MiB. Full-stack
  acceptance remains incomplete. Keep future workloads sequential and guarded;
  this complaint response is not authorization to raise resource budgets.

- 2026-10-01 (resource default tightened): Changed the build guard's default
  cutoff from 1024 to 512 MiB and updated its example. The existing successful
  subprocess test now omits the memory option and verifies the actual default;
  all eight real subprocess safety tests pass in 3.057s. No Bend compilation
  or package/repository check was launched for this change. A fresh process
  scan found no Bend, Moon, Bun or clang processes; system swap remained
  10648.50 MB, so absence of compiler processes does not establish that system
  memory pressure has recovered. Logs, source hashes and the scan are in
  `ecdsa256/guard-default512-tests.log`, `guard-default512-verification.json`
  and `resource-current-state.json` under the 2026-10-01 artifact directory.
  All subsequent goal builds must remain sequential under the 512 MiB guard.

- 2026-10-01 (isolated compiler reduction, not transferred): Replaced the four
  public P-256 constant tables with eight-word tables indexed by Nat, preserving
  byte accessors and all arithmetic bodies. Factored the field CLI's argument
  dispatch with explicitly decreasing public Nat fuel, preserving arithmetic
  calls and input guards. Native and Bun each pass all 4178 bigint differential
  cases in 1.436s and 29.048s; 144 closed checks verify every constant byte and
  out-of-range access. Guarded peaks for those checks are 21.5, 125.8 and
  128.9 MiB. A two-phase native helper trial, which makes Bend exit before clang
  starts, built this CLI at 478.9 MiB. Compilation used local
  `BUN_OPTIONS=--smol BUN_JSC_forceRAMSize=268435456`; these runtime settings
  are GC scheduling hints, with the separate physical-memory guard enforcing
  the sampled cutoff. Reports and logs are in `ecdsa256/field-adapter/`.
  These source changes remain isolated and the helper's final atomic output
  publication change is still untested. Next: verify that helper on a tiny
  owned fixture, check the field's existing closed proofs, then transfer the
  validated field/CLI and integrate the helper into crypto native builds.
  Revalidate dependent P-256/ECDSA code and fresh crypto/RTC/repository gates
  under the same cutoff. The full 19-box contract remains unfinished.

- 2026-10-01 (bounded resource and signature progress): Tightened the guard to
  a 0.02-second sample interval. macOS now lists the owned process group with
  `proc_listpids` instead of spawning `ps` on every sample, then reads resident
  size/physical footprint via `proc_pid_rusage`. The same eight subprocess
  safety tests pass in 3.000s; final log and source hashes are in
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/ecdsa256/guard-final-tests.log`
  and `guard-verification.json`. Recovery jobs used a 512 MiB cutoff and ran
  sequentially. Several builds were killed at that cutoff; none count as a
  successful build or gate. Initial 0.1-second sampling briefly overshot to
  719.2 MiB in the split-adapter attempt; the current sampler remains a cutoff,
  not a kernel allocation quota. A minimal Bend native program passes near
  107.8 MiB. Splitting the ECDSA adapter/import graph and Bun's documented
  `BUN_OPTIONS=--smol` did not clear the cutoff; those unverified split adapters
  were removed, and all nine original ECDSA draft source hashes were restored.
  The combined JS adapter built successfully before the incident was frozen
  with its original source bundle and generated-JS hash.

  New isolated `crypto/ecdsa_check.py` contains published SigGen/SigVer/RFC6979,
  independent affine/HMAC deterministic signing, complete signature/digest/key
  byte mutations, strict profile/malformed DER, infinity and rejection controls,
  and direct OpenSSL DER interoperability. Only its interop section has run:
  the actual Bend DER signing API produced four OpenSSL-verified signatures;
  Bend's public DER verifier accepted four OpenSSL signatures and rejected four
  altered digests. Guarded Bun execution passed 12 cases in 57.424s, peak
  140.8 MiB. The independent reference signer matched the actual Bend output.
  Expanded `ecdsa_der_check.py` adds all second-INTEGER length mutations to the
  prior matrix. Existing frozen native/Bun codec builds each pass 1388 cases
  in 0.284s/1.415s, with guarded peaks 20.5/76.8 MiB. Both evaluator scripts
  parse. Full native/Bun signature matrices, native combined scheme, primary
  transfer/registration and fresh package/repository gates remain required.
  Evidence: `interop-bun-evidence.json`, `interop-bun-resource.json`,
  `der-{native,bun}.log`, their resource reports and
  `scheme-source-provenance.json` under the same artifact directory.

  Compiler diagnosis found that the primary original `field256.bend` already
  crosses 512 MiB during `--check-only`, before C compilation. An isolated
  trial replaces four 32-byte-case public constant tables with eight U32 words
  each and bounded byte extraction. All other arithmetic bodies are unchanged.
  That field module now type-checks at 329.8 MiB and 144 closed checks pass
  for all 128 constant bytes plus out-of-range indices, peak 338.7 MiB. Its
  full file adapter still crosses the cutoff even with `--check-only`; native
  adapter builds also stop, with/without low-memory runtime mode. This trial
  is not transferred or accepted: fresh native/Bun bigint differential checks
  and all dependent package/repository gates are still required. Source,
  prefix diagnosis, failed logs, reports and trial hashes are retained in
  `ecdsa256/compiler-profile/`. No full gate was restarted during recovery.
  Exact next action: reduce the field adapter/type-checking workload under
  the unchanged 512 MiB recovery cutoff, then run its full native/Bun 4178-case
  differential evaluator before considering a primary transfer. Revalidate
  point/ECDH/signature sources against whichever field version is accepted,
  finish their native/Bun matrices, then rerun the failed repository/RTC gate
  sequentially under the guard. Preserve the entire 19-box contract: RSA,
  timing/erasure, certificates, Bend TLS/DTLS, secure signaling, IPv6/TURN,
  SCTP/data channels and decoded/rendered direct/relay audio/video remain open.

- 2026-10-01 (resource recovery): Added `tools/build_guard.py` and its usage
  documentation. It refuses concurrent guarded jobs across checkouts and
  pre-existing same-user Bend compilers, forces Moon's default concurrency to
  one, and monitors combined owned process-group memory every 0.1 seconds.
  On macOS it uses the greater of RSS and physical footprint per process, so
  compressed memory is included. Memory measurement errors fail closed. A
  cutoff, timeout, interrupt or leftover child kills only the owned group.
  This is a sampled cutoff with possible brief overshoot, not an allocation
  quota; detached children and unguarded commands are unsupported.
  `PYTHONDONTWRITEBYTECODE=1 python3 tools/build_guard_test.py -v` passed eight
  real subprocess tests in 4.464s: successful/failed commands, aggregate child
  cutoff with an unrelated process left alive, ignored-TERM child cleanup on
  timeout, concurrency refusal and lock reuse, interruption, orphan cleanup
  and missing-command failure. `git diff --check` passed. No Bend build was
  required for guard verification. All subsequent goal builds/checks must use
  this guard and run sequentially. Start the next isolated ECDSA native build
  at 512 MiB; if it crosses the cutoff, reduce the compilation workload before
  retrying. The primary repository/RTC recovery gate remains failed and the
  P-256 point/ECDH milestone remains uncommitted.

- 2026-10-01 (resource incident): The user reported Bend processes using roughly
  15 GB and 7 GB. Two isolated consolidated ECDSA CLI builds (native and JS)
  were launched concurrently while the primary repository check was active.
  This overlap was an unsafe resource scheduling choice. Peak memory was not
  measured, so those figures remain user observations. On inspection both
  builds and the repository runner had exited: native exit 143, JS exit 0,
  repository runner exit 1 with RTC exit 143. The cause of the termination is
  unconfirmed. A fresh process scan found no Bend or Moon processes; current
  swap usage was 8056.69 MB. No additional heavy work was launched. The full
  goal remains incomplete and the pending P-256 milestone is uncommitted.
  Before any compilation or full check resumes, implement and verify an owned
  process-tree memory cutoff and one-job concurrency guard. Run builds and
  checks sequentially; do not overlap draft compilation with repository gates.
  Keep the failed gate evidence and rerun only after that guard is in place.
  Resource evidence: `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/ecdsa256/resource-incident.json`.

- 2026-10-01 (milestone in progress, uncommitted): Added pure Bend `p256.bend`
  point operations and ECDH. Private scalars are exactly 32 big-endian bytes
  in 1..n−1; peers use exactly 65-byte uncompressed SEC1 points with canonical
  coordinates and curve validation. Infinity, aliases, compressed/hybrid and
  off-curve encodings are rejected. Shared output is the fixed 32-byte affine
  x coordinate, preserving leading zero bytes. Internal projective coordinates
  x=X/Z, y=Y/Z use canonical Montgomery byte limbs. The 43 straight-line RCB
  add-2015-rcb-3 assignments cover doubling/inverses/infinity without a secret
  exceptional-case branch; explicit ownership clones preserve required values.
  Raw helpers require validated curve representatives. Every scalar uses 256
  doublings, 256 additions and 256 masked selections; public bit positions
  control indexing. Normalization rejects zero Z. Source fixed schedules and
  bounded arithmetic do not resolve native/runtime/JIT timing or copy erasure.
  Isolated native/Bun runs each pass 609 independent cases: all 25 NIST ECDH
  vectors with public/shared outputs, 121 affine and 121 independently rescaled
  group pairs, 81 zero/order/byte-transition/dense/alternating/random scalars,
  infinity multiplication, canonical peers, private/public malformed/range/
  tampering rejection and eight OpenSSL exchanges in both directions. The
  oracle uses textbook affine slopes/inversions, not the RCB formula. Native
  took 3.778s, Bun 701.563s in these focused runs, with some overlapping ECDSA
  draft checking; this records a substantial target performance gap, not a
  standalone throughput baseline. Four closed malformed/non-byte Bend checks
  pass. Five source/fixture files were transferred with hash checks; imported
  field/byte/IO dependencies match the primary checkout. The primary crypto
  gate registers the proofs, both adapters and both evaluators. Artifacts:
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/p256-points/`, including
  formula/NIST sources and hashes, 420 reference-only planning checks, transfer
  manifest, focused logs and generated C/JS/default Clang arm64 assembly.
  Separate ECDSA verification/signing drafts remain only in the owned isolated
  checkout; native/Bun verification probes pass all 15 published P-256/SHA256
  SigVer cases (12 failures), both RFC6979 P-256/SHA256 deterministic signatures,
  1133 strict DER cases per target, 65 independent signing/repeat/digest-reduction/
  tampering/range/malformed/wrong-key cases per target (with 12 OpenSSL-verifiable
  independent reference signatures), six closed malformed-byte/fuel checks and
  42 rejection/known-nonce controls per target: all 15 NIST SHA256 SigGen cases,
  actual zero-s, injected zero-r, positive control and independently computed
  RFC6979 rejected-candidate/rejected-signature state updates.
  These are not primary package acceptance. Generated JS inventory covers 80
  point functions; native C symbols are anonymous numbered helpers, so complete
  source-to-optimized dependency mapping remains open. The ECDSA draft provenance,
  sources and outstanding gates are in `ecdsa-draft-state.json`.
  Primary forced crypto passes fresh (execution 14m4s128ms, hash
  `c6151b831101af16296095e32ff0e1a7cd12b8f02b6ed8c91243ad3075cb94d0`):
  native/Bun point checks pass 609 cases in 4.026s/608.306s. Forced wire failed
  in the existing address fixture: bind-only second-IP selection chose VPN
  172.16.1.7, but the independent peer's sendto failed EADDRNOTAVAIL (49).
  A plain OS-only roundtrip reproduces the failure and succeeds for the local
  LAN address. The helper now requires exact bidirectional UDP reachability
  from the loopback-bound peer, preserving the actual same-port/two-IP proof;
  it never changes interface configuration or skips that proof. The failed
  report/log are retained. Only this shared test helper changed after the
  crypto gate, so its successful result remains valid; a provenance snapshot
  records the one-file change and updated frozen 518-file manifest. Run the
  distinct forced retry-wire gate and repository gate. Retry-wire now passes
  fresh with exit zero and skipped hydration (execution 100s, hash
  `6dc11d55f1f1ecabad4b9f0b12808ccff6d22d2451d09ab7d8866c1b67a33001`). Recovery session 54512 has exited 1;
  its repository gate failed with RTC exit 143 during the resource incident.
  RTC imports the helper,
  so its changed input hash now requires fresh execution, including the real
  browser/ICE tests; do not reuse the prior RTC result. Exact next action:
  audit these recovery reports/frozen inputs, update this entry and commit the
  verified point/ECDH milestone. Continue ECDSA
  deterministic signing/strict DER and published/independent signature checks,
  then mandatory RSA and full certificate/handshake integration. All 19
  full-stack acceptance boxes remain unchecked.

- 2026-10-01: Added internal pure Bend
  `field256.bend` for the P-256 coordinate prime and scalar order from NIST
  SP 800-186 section 3.2.1.3. Canonical values use 32 little-endian bytes in
  owned 64-cell U32 arrays. Add/subtract use bounded carry/biased borrow and
  0/255 conditional selection. Multiplication performs two byte-limb Montgomery
  products to return the ordinary representation, retaining both high carry
  cells before each canceled-byte shift. Inner product-plus-carry sums are
  at most 65535; the invariant T<2m permits one final masked subtraction.
  A fixed 512-bit reducer and bounded schoolbook product remain independent
  Bend reference paths, with coefficient-plus-carry below 2^21. Inversion
  uses the public modulus-minus-two exponent and rejects zero after a full
  32-byte scan. Strict `decode_canonical` validates exact byte length/values
  and rejects aliases >= the modulus. Reducing/raw helpers have documented
  operand-profile preconditions; protocol point/private-key parsers still need
  byte-order, range and curve-point validation. P-256 point operations, ECDH,
  ECDSA and published curve/signature vectors are not yet implemented.
  Before transfer, isolated native/Bun runs each pass 4178 independent Python
  bigint cases across both moduli: all 256 carry/borrow boundaries, modulus
  aliases, random operands, 512-bit reduction, Montgomery/reference agreement,
  inverses/zero, strict canonical decoding and malformed lengths. Four closed
  Bend checks reject bad lengths and U32 values outside the byte range. The
  primary crypto gate now runs these proofs/adapters/evaluators alongside all
  existing suites. The initial binary-only draft was replaced with Montgomery
  multiplication after a correctness-baseline check; no acceptance gate was
  interrupted. Draft compiler binder/IO issues were corrected before transfer.
  Artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/p256-foundation/`,
  including the four-file transfer manifest, SP 800-186/source hash and parameter
  snapshot, focused logs, frozen 378-file primary source/config/fixture manifest,
  generated C/JS/default Clang arm64 assembly, an 80-function static inventory
  and arithmetic range/invariant arguments. The current SP 800-186 planning
  correction concerns section 3.2.2.1; this slice uses section 3.2.1.3.
  Public loop/index/exponent control and bounded byte arithmetic do not resolve
  optimized runtime/JIT timing, allocation/scheduling or secret-copy erasure.
  `PYTHONDONTWRITEBYTECODE=1 moon run crypto:check --force` passes fresh
  (execution 6m12s415ms, hash
  `ad4ae771746d6e26bc3964b975a7fe6af9c598f78158e4cc1064aa5da2685b1f`).
  Native and Bun each pass all 4178 cases in 2.417s and 31.878s respectively.
  `PYTHONDONTWRITEBYTECODE=1 moon run wire:check --force` passes fresh
  (execution 1m23s234ms, hash
  `e85d70cbdcb93b19e6399ed1cdc298f70925844e303e92c737f823c2ce78379f`).
  Both reports show exit-zero execution and skipped cache hydration.
  Final `PYTHONDONTWRITEBYTECODE=1 moon run :check` passes all 13 tasks in
  6m29s759ms: 12 cached and JSON fresh with 706/706 independent cases.
  Crypto/wire cached hashes match their forced checks; RTC reuses the saved
  fresh browser/ICE gate with exact hash
  `a1dca40ee0e2b21637190a491be4cc785bf4eb1afb4de2c243f3694d20246102`.
  RTC's guarded import closure still includes exactly its five existing crypto
  modules; the unused arithmetic addition does not require a new RTC run.
  All 378 frozen source/config/fixture files remain unchanged through the gates.
  Reports distinguish actual execution from replayed cached logs; RTC/browser
  and optional live Redis tests were cached, not freshly rerun in this milestone.
  Exact next action: implement complete P-256 point operations with published/
  independent ECDH/ECDSA checks, followed by mandatory RSA/certificate signatures
  and the full TLS handshake. All 19 full-stack acceptance boxes remain unchecked.

- 2026-10-01: Extended the affine TLS
  traffic owners and protected-record evaluator to TLS_AES_128_GCM_SHA256.
  Explicit `new_aes128_write/read` factories derive 16-byte keys and 12-byte
  IVs, retain AES through traffic-secret updates, and use the existing
  64-bit record counter/nonce construction. Authentication never falls back
  to another suite. AES sending epochs permit 2^24 records, below RFC 9846
  section 5.5's approximately 2^24.5 full-record bound; an attempted excess
  returns UsageLimit and retires the owner. Raw AAD/inner-size bounds of
  5/16385 bytes preserve the full-record assumptions. Receiving epochs retain
  size/sequence/authentication bounds but do not enforce sending usage limits.
  The last permitted old-key record can carry KeyUpdate before explicit rekey
  resets sequence/usage; phase, message ordering and connection-secret uniqueness
  remain the future handshake owner's responsibilities. Physical erasure and
  complete optimized native/JIT/runtime timing review remain unresolved.
  Native and Bun each pass 72 independent AES owner scenarios and 166 AES
  record scenarios, while retaining the original 70 ChaCha owner/154 record
  scenarios. All seven encrypted records in RFC 8448 section 3 match published
  bytes in continuous handshake/application direction groups: both handshake
  flights, server ticket, both application records and both closing alerts.
  A fixture pins the downloaded RFC source hash and participates in the wire
  input hash. Independent Python HKDF, OpenSSL AES and bigint GHASH cover
  payload/bounds, every tag position, tampering, replay/reordering, usage/counter
  and update-generation boundaries, retirement and algorithm confusion. The
  record codec's production source/API is unchanged; it uses the supplied
  Bend traffic owner. Compiler probes still reject owner copies/direction mixing.
  RTC now declares the five crypto modules in its actual local import closure
  instead of all crypto modules. A guard follows transitive/nested imports and
  fails if the declaration omits required crypto; regressions cover missing
  transitive dependencies, flat/nested glob scope and unused modules. Every
  existing native/Bun/browser RTC check remains. A disposable checkout using
  the identical RTC config and a clearly marked no-op check script verifies
  actual Moon behavior: an unused GCM edit remains cached with the same hash,
  while an imported HMAC edit executes with a changed hash. This cache probe
  is not protocol acceptance evidence; its owned sources were restored.
  Artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/aes-traffic/`,
  including the 17-file hash-checked transfer manifest, a frozen 374-file source/
  config/fixture manifest, standards/vector sources, package logs/reports/hashes,
  cache-probe evidence and generated C/JS/default Clang arm64 assembly. Static
  inventory covers 43 traffic and 24 protected-record functions; public
  count/size/suite dispatch and logical retirement do not establish complete
  timing/erasure safety. The running RTC task hash covers 163 inputs, including
  exactly its five imported crypto modules and both new guard scripts.
  `PYTHONDONTWRITEBYTECODE=1 moon run crypto:check --force` passes fresh
  (execution 2m43s543ms, hash
  `bc3c850b28d5cf540472746760ccb67a42f2e221caa2e64577cdfd0cb2873ef7`).
  `PYTHONDONTWRITEBYTECODE=1 moon run wire:check --force` passes fresh
  (execution 58s035ms, hash
  `4d5a8fa07eb445a86d1261175d08a6a3e2c73463e129362a0577b6338ee81efa`).
  Both reports confirm exit-zero execution and skipped cache hydration.
  `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passes fresh
  (execution 29m17s580ms, hash
  `a1dca40ee0e2b21637190a491be4cc785bf4eb1afb4de2c243f3694d20246102`).
  Fresh Chrome 154.0.8037.92 native/Bun checks pass actual nominated ICE,
  independently authenticated consent in both credential generations, restart,
  denied auth/Origin, reconnect, malformed signaling and cleanup. Browser/server
  shutdowns exit zero without forced termination; copied raw browser artifacts
  and independent packet checks are retained. This proves local plaintext
  WS/ICE only; DTLS/data/media remain absent. The artifact runner's browser-loop
  variable shadowed its gate label; original report/hash/profile files were
  retained and copied to the correct forced-rtc names, with provenance in
  `artifact-label-correction.json`. The runner is corrected for later runs;
  no gate was restarted or interrupted for this artifact-label issue.
  Final `PYTHONDONTWRITEBYTECODE=1 moon run :check` passes all 13 tasks in
  3m39s872ms: 12 cached, JSON fresh with 706/706 independent cases. Crypto,
  wire and RTC cached hashes exactly match the saved forced checks. All
  374 frozen source/config/fixture inputs remain unchanged through the gates.
  Saved reports/hashes distinguish fresh exit-zero execution from cached
  hydration; no required native/Bun/Chrome checks skipped. Optional live Redis
  checks were cached and not rerun. Exact next action: implement mandatory
  P-256/RSA/ECDSA and the full handshake/transcript/certificate path, before
  DTLS/secure signaling and IPv6/TURN/data/media. All 19 full-stack acceptance
  boxes remain unchecked.

- 2026-10-01: Added pure Bend
  `aes128.bend` and `gcm.bend`. AES encryption uses arithmetic GF(2^8)
  inversion/affine S-boxes, column-major state, ten rounds and prepared-key
  reuse for GCM. GCM fixes the profile to a 16-byte key, 12-byte nonce and
  full 16-byte tag, authenticates before decryption, uses eight 16-bit GHASH
  limbs and fixed 128-bit multiplication, and hashes AAD/ciphertext separately
  with independently padded final blocks. Its big-endian bit-length serializer
  splits before multiplying to avoid Bend Nat overflow; the SP 800-38D
  2^36-32-byte plaintext bound prevents CTR reuse. These primitives do not yet
  extend the existing ChaCha TLS traffic/record owners.
  Native and Bun each pass the FIPS 197 cipher example and all 256 S-box bytes,
  all 284 NIST AESAVS AES-128 ECB encryption KATs, 40 OpenSSL differentials and
  malformed lengths. GCM passes 150 selected NIST CAVP vectors covering all
  supported IV/tag PT/AAD length groups, including 32 published authentication
  failures; independent OpenSSL AES/Python bigint GHASH agrees through 64 KiB,
  all 16 tag mutations, AAD/ciphertext/key/nonce tampering, 166 field products
  and 16 compiled length/counter boundaries through the largest Nat. Closed
  Bend checks cover invalid bytes. Vector JSON fixtures pin source URLs and
  downloaded archive hashes and are included in Moon's crypto input hash.
  Poly1305 now uses thirteen base-2^10 limbs and 0/1023 canonical-selection
  masks. The independent coefficient/carry calculation bounds every product
  sum plus incoming carry below 2^26 (maximum bound 63838269); fixed
  normalization produces ten-bit digits and canonical carry 0/1. Native and
  Bun each pass nine RFC vectors and 250 differential cases, including
  extreme patterns and both sides of final prime selection. This mitigates
  the former wide-product/negative-mask source forms; complete optimized
  runtime, allocator/scheduler, Bun JIT/GC and physical erasure remain open.
  Artifacts under `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/aes-gcm/`
  retain generated C/JS/default Clang arm64 assembly, source hashes, 73
  AES/GCM and 45 Poly1305 generated JS function inventories, numeric-range
  arguments, downloaded NIST vectors/specifications, RFC 5116/errata snapshots,
  versions and focused logs. RFC 5116 verified errata 4008/4268 are consistent
  with this interface; reported 5219 proposes the NIST plaintext bound and is
  not treated as verified. FIPS 197's 2023 update and final SP 800-38D were
  reviewed; the latter has a planned revision. A stopped exploratory large-Nat
  type-level evaluation was replaced with compiled boundary checks, before
  the final forced gates; no forced gate was interrupted.
  `PYTHONDONTWRITEBYTECODE=1 moon run crypto:check --force` passed fresh
  (execution 2m49s875ms, hash
  `496af64ce11f2c334df6f16b05d146cb57b01cc296cf9a87dd8a6e2dd935beb0`).
  The subsequent forced `wire:check` passed fresh (36s519ms, hash
  `dc84b356f69c6c8bdff40cd1c727f55a34b503800b24d481bb77691eb3e31bf6`),
  including existing TLS traffic/protected-record regressions. Saved reports
  show passed exit-zero execution and skipped cache hydration. All 53 frozen
  source/config inputs remain unchanged; crypto hashes cover both vector
  fixtures. `PYTHONDONTWRITEBYTECODE=1 moon run :check` passes all 13 tasks
  in 48m19s096ms: 11 cached, RTC and JSON fresh. JSON passes 706/706 cases
  (execution 11m7s889ms). RTC passes fresh (execution 48m18s948ms, hash
  `8e2d39b96af3b67c0e0f6765795ba46de2776b5905f0e20617457b9e2f7f6390`),
  with skipped cache hydration and exit-zero execution. Cached crypto/wire
  hashes match the saved forced checks; all 53 frozen inputs remain unchanged.
  Fresh Chrome 154.0.8037.92 native/Bun runs pass nominated ICE, signed consent,
  credential restart, denied auth/Origin, reconnect and malformed signaling;
  independent packet checks pass. Raw browser artifacts were copied before
  fixture cleanup; browser/server shutdowns exit zero without forced termination.
  This is plaintext local WS/ICE evidence, without DTLS/data/media. Saved full
  report, all 13 hash files and per-task execution/cache metadata distinguish
  fresh checks from cached results; optional live Redis checks were not rerun.
  A one-second process profile observes signaling native building for 934.5s,
  including a Bend generation span of 867.6s. These are sampled spans, not
  exact command runtimes; the long monolithic RTC gate remains a development
  cost. No forced or repository gate was interrupted. Next: extend the TLS
  owners/record evaluator to AES-128-GCM with sending usage limits and real
  RFC 8448 AES records; guard RTC's imported crypto closure so unused TLS
  module changes do not rerun it, then mandatory signatures/key agreement and
  complete TLS/DTLS. All 19 full-stack acceptance boxes remain unchecked.

- 2026-10-01: Added pure Bend `crypto/traffic.bend` and
  `wire/tls_record.bend`, providing TLS_CHACHA20_POLY1305_SHA256 traffic/key
  lifecycle and protected records. HKDF-Expand-Label validates TLS vector/HKDF
  bounds, derives 32-byte keys/12-byte IVs, and derives updates with `traffic upd`.
  Distinct affine read/write owners carry two-word 64-bit record counters;
  big-endian sequence bytes are left-padded and XORed with the static IV.
  Sequence zero starts each new epoch, the final 64-bit value is used once,
  and an attempted wrap retires the owner. Invalid seal input, failed
  authentication and explicit close retire it; closed owners cannot update.
  Sending updates stop at 2^48-1 while preserving the current key and sequence;
  receive updates have no sending-generation cap. Compiler probes reject
  copying either owner or mixing directions. Native and Bun each pass 70
  published/differential/counter/cap/update/replay/tampering/retirement scenarios,
  including three RFC 8448 section 3 HKDF vectors and independent Python HKDF
  plus OpenSSL-ChaCha20/bigint-Poly1305 references. Initial secret uniqueness and
  KeyUpdate/Finished phase and old-key message ordering remain caller/handshake
  responsibilities; visible constructors/helpers permit deliberate owner
  reconstruction. Logical key retirement does not establish physical scrub of
  runtime copies or timing-safe execution.
  The protected-record codec authenticates the actual five-byte received header,
  encodes content/type/zero padding, preserves content trailing zeros, and handles
  incomplete/coalesced frame classification without consuming a key. Writers use
  0x0303; receivers ignore legacy version as a protocol selector while
  authenticating those bytes. Suite bounds are 16384 content bytes, 16385 inner
  bytes and 16401 encrypted body bytes; padding guards precede arithmetic and
  allocation. Empty application data is supported, handshake content must be
  nonempty, and alerts must contain exactly two bytes. Encrypted CCS, unknown
  inner types and authenticated all-zero/empty inner plaintext are rejected.
  Every record failure retires the owner. Each target passes 154 independent
  cases covering all split points of a small frame, maximum and coalesced frames,
  padding/bounds, header/body/tag changes, replay/retirement, and actual old-key
  KeyUpdate bytes followed by an explicitly updated sequence-zero record.
  Closed Bend checks reject invalid bytes and the largest representable Nat
  padding argument before overflow. Wire declares its crypto dependency and
  hashes crypto/IO sources and reference checkers for this path.
  RFC 9846 (July 2026) supersedes RFC 8446. Sections 4.7.3, 5.1-5.5, 7.1-7.3,
  9.1/9.2 and current errata were reviewed: five reported records, none verified,
  with no change to these implemented operations. RFC 8448's two held errata
  address scalar clamping/signature lists, not the selected HKDF vectors.
  Mandatory remaining TLS algorithms include AES-128-GCM/SHA-256, P-256 key
  agreement/ECDSA, RSA PKCS1 SHA-256 certificates and RSA-PSS SHA-256 certificates/
  CertificateVerify; the ChaCha path does not discharge those requirements.
  Generated C, Bun JS and default Clang -O3 arm64 assembly are retained, with
  static inventories of 32 traffic functions and 24 record functions. Record
  padding/type processing inspects authenticated plaintext structure; no timing
  or traffic-analysis guarantee is claimed. Production record/traffic logic
  calls Bend crypto; OpenSSL is only the independent test oracle in this path.
  Full optimized native/JIT/runtime/erasure review remains open, including the
  previously identified Poly1305 mask/range and signaling ABI/stack questions.
  Artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/tls-traffic/`.
  Source manifests freeze 42 crypto and 32 wire/IO check/configuration files,
  all unchanged through the gates. `PYTHONDONTWRITEBYTECODE=1 moon run
  crypto:check --force` passes fresh: execution 1m 31s 055ms, overall 1m 31s 095ms,
  hash `980bacca00243467bc44cb69db04f2b335c4bf0b8e59c221eb20c7e3c337a335`.
  The intermediate repository gate reruns RTC fresh: execution 25m 56s 459ms,
  hash `00986831edd5a87aa93fb5c3e18d6fabdd32debc2b934f6d980edb13a640e2fd`.
  Both fresh Chrome 154.0.8037.92 targets pass actual nominated ICE, signed consent
  in both credential generations, restart, denied auth/Origin, reconnect and
  malformed signaling; independent packet checks pass and browser/server exit
  zero without forced termination. Raw browser directories were copied before
  fixture cleanup. This remains local plaintext WS/ICE, without DTLS/data/media.
  The wire record addition was made during that run after wire's cached action;
  it is checked separately. `PYTHONDONTWRITEBYTECODE=1 moon run wire:check
  --force` passes fresh: execution 34s 198ms, overall 34s 221ms, hash
  `921e4ff5dd49a71a761ae8178318ae9107f2867db70cfafe8242a8c8f9e8719d`.
  The existing RNG, byte UDP/TCP, signals/cleanup and OpenSSL compatibility tests
  also pass. Saved report/hash metadata confirms fresh exit-zero execution and
  skipped output hydration for both changed-package checks and RTC.
  A 1-second descendant-process profile observes about 910.6s (15m 11s) in
  Bend checking/generation and C compilation, using the union of sampled spans
  to avoid overlap double-counting; short processes may be missed. This explains
  much of the monolithic RTC gate's cost without asserting exact per-command
  timings. The longest observed Bend generation is signaling_server at 158.7s;
  its entire native builder spans about 212.4s. Profiling/report artifacts are
  retained. Final `PYTHONDONTWRITEBYTECODE=1 moon run :check` passes all 13 tasks
  in 1m 50s 923ms: 12 cached, JSON fresh with 706/706 independent integration
  cases passed. Cached crypto/wire/RTC hashes match the saved fresh checks;
  all 74 frozen inputs remain unchanged. Redis was cached and not rerun; its
  recorded optional live 6379/password-AUTH 6380 checks skip unavailable services.
  Final repository log, full report and per-task cache/execution metadata are saved.
  Next: resolve the remaining Poly1305 selection/range finding with proven limb
  bounds, add AES-128-GCM and P-256/RSA/ECDSA for mandatory TLS interop, and build
  the handshake/transcript/certificate owner over these records. TCP buffering,
  plaintext/compatibility records, alerts, fragmentation/key-boundary rules and
  live authenticated TLS client/server interop remain open. DTLS, secure browser
  signaling, IPv6/TURN, SCTP and SRTP/media/full integrated sessions remain open.
  All 19 full-stack acceptance gates remain unchecked; the full goal stays active.

- 2026-10-01: Mitigated the inspected X25519/field numeric-range finding in
  Bend. Ladder swaps and canonical selection now use 0/255 masks, with XOR 255
  for the inverse selection mask. Canonical subtraction biases each byte by
  256, keeping the difference in 0..511 and the borrow in 0/1 instead of wrapping
  a negative U32. Canonical byte digits and scalar control bits establish the
  required bounds; public APIs and the RFC ladder remain unchanged. Field checks
  now compare 319 operand pairs across three operations on native and Bun,
  covering every byte carry/borrow boundary, all 19 noncanonical coordinates
  with their high-bit aliases, and p..p+18 addition results. X25519 checks add
  every one of those 38 coordinate aliases and four public constant/alternating
  scalar patterns, retaining RFC vectors, four independent OpenSSL exchanges,
  malformed-input/all-zero rejection and native 1,000 iterations. Both focused
  targets pass. The crypto task now includes check.sh in its cache inputs.
  RFC 7748 sections 5/5.1/5.2 and the current errata records were reviewed:
  verified 7625 clarifies XOR (already used), 5028 clarifies decoded coordinates,
  4730 changes the unused Montgomery v sign, and 7095 clarifies Appendix A
  notation. The full errata page, including held/rejected records, is retained.
  Regenerated native C, Bun JavaScript and default Apple Clang -O3 arm64 assembly
  show the revised mask/subtraction forms at the inspected sites. This resolves
  those source-range forms; it does not approve complete runtime/JIT timing,
  secret-copy erasure or the signaling ABI/stack workaround. No timing leak or
  constant-time guarantee is claimed. Artifacts:
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/x25519-ranges/`, including
  focused logs, build logs, generated sources/assembly, standards/errata records,
  versions and generated-review.json. All 37 crypto check/configuration inputs
  are frozen in source-sha256.json. The source/generated static control/memory
  map covers 73 core function locations, fixed public counters/indices and the
  field product-plus-carry bound below 2^21. Native U32 buffer copying does not
  dispatch on each digit's term tag/refcount; shared-secret zero rejection scans
  all output bytes before its final observable decision. The map records the
  remaining allocator/scheduler, optimized native/JIT and erasure questions in
  control-memory-review.json. Default Clang -O3 -fstack-usage reports 784 static
  function frames in the generated X25519 CLI, largest 2176 bytes in io_exec;
  raw .su and stack-usage-evidence.json are saved. This does not bound total call
  depth or approve the larger signaling fixture. `PYTHONDONTWRITEBYTECODE=1 moon run crypto:check
  --force` passes fresh: execution 1m 18s 022ms, overall 1m 18s 038ms, full hash
  `fded508dce8877a673fd6bdeacbd3eac532944eb5ac167f5936b624a29a94662`.
  Saved metadata confirms exit zero/skipped hydration, all 36 source/check files
  covered by the task hash and unchanged, with configuration frozen separately.
  `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passes fresh: execution
  24m 48s 491ms, overall 24m 48s 562ms, full hash
  `756c98ff6c88915e86ac6bc736058e6fc53736449b50a86d2c6f77faa82037f6`.
  Saved execution metadata confirms exit zero/skipped hydration; all 37 frozen
  inputs remain unchanged. Fresh raw browser directories are retained. Both
  Chrome 154.0.8037.92 targets select actual ICE pairs, authenticate signed
  consent in both generations, restart credentials, and pass independent packet
  checks plus denied auth/Origin, reconnect and malformed-message scenarios.
  Browser/server processes exit zero without forced termination. All prior
  native/Bun RTC regressions pass. `PYTHONDONTWRITEBYTECODE=1 moon run :check`
  passes all 13 tasks in 1m 48s 158ms: 12 cached, JSON fresh with 706 independent
  integration cases passed. Cached Redis live 6379/password-AUTH 6380 checks
  were not rerun; their recorded result skips unavailable local services. Full
  repository log/report and per-task cache/execution evidence are saved.
  Next: inspect Poly1305 canonical selection's remaining full-width mask and
  verify 13-bit digit/carry bounds before changing it; continue optimized native,
  Bun/JSC lowering and secret ownership/erasure review across the primitives,
  then nonce/key lifecycle, signatures and Bend TLS/DTLS. All 19 full-stack
  acceptance gates remain open.

- 2026-10-01: Added `wire_random_bytes` for 0–1048576
  host RNG bytes, retaining the byte-list OS boundary. Darwin uses
  `arc4random_buf`; Linux uses nonblocking `getrandom`, short-read completion and
  bounded consecutive-EINTR retries; Bun chunks WebCrypto at 65536 bytes. Zero
  avoids the RNG, oversized requests fail before allocation, and failure never
  returns partial output or weaker random fallback. Temporary OS buffers are
  cleared on success/failure; returned Bend/runtime copies are not thereby erased.
  Native/Bun each pass 20 real size/boundary cases. Nine controlled native OS
  completion cases cover short reads, interruption exhaustion, zero/invalid reads
  and errors; the Linux syscall itself is simulated on this Darwin host. Twelve
  Bun effect cases verify guards, chunk sizes/order, failure rejection and buffer
  cleanup. The signaling fixture now obtains its 64-bit fragment, 128-bit password
  and 64-bit tie-breaker in one 32-byte request, with byte-to-word conversion in
  Bend. Native and Bun each pass all 28 focused signaling scenarios. Fresh
  `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passes in 24m 27s 729ms
  (overall 24m 27s 771ms), full hash
  `5220562c214c9bff620317bec0515fef7f9ef354a0802f2dc931df634dcb12d4`.
  Exit-zero execution/skipped hydration metadata, full hash/report and fresh raw
  browser directories `forced-browser-native/` / `forced-browser-bun/` are saved.
  Both Chrome 154.0.8037.92 runs verify actual selected pairs, fresh signed consent
  in both generations, credential restart and independent packet authentication;
  browser and server processes exit zero without forced termination. All prior
  RTC regressions pass on both targets. All 12 changed check-input SHA digests
  remain unchanged and are covered by the fresh wire/RTC hash union; configuration
  digests also remain unchanged. Integrated consent expiry measures 30.072s
  native / 30.084s Bun. `PYTHONDONTWRITEBYTECODE=1 moon run :check` passes all
  13 tasks in 1m 47s 777ms: 12 cached, JSON fresh with 706 independent integration
  cases passed. Cached Redis optional live 6379/password-AUTH 6380 checks were
  not rerun; their recorded result skips unavailable local services. Repository
  log, full run report and per-task fresh/cache evidence are saved.
  `bench.bend`/`measure.py` record 102 RNG/storage samples (three per workload)
  and 24 real UDP samples/rejections. Eighteen independent public-pattern cases
  and four argument rejections pass on both targets before timings are trusted.
  For 1 MiB generation plus count/range/checksum traversal, median bulk RNG is
  3 ms native (3–4) / 58 ms Bun (58–59), versus word-at-a-time 1212 ms native
  (1198–1214) / 348 ms Bun (345–359). Eight 1 MiB public pattern construction/
  scan rounds take 15/779 ms native/Bun for `List<U32>`, 15/765 ms for dedicated
  byte constructors, and 72/1595 ms for arrays plus list serialization. Retain
  lists at the sequential OS boundary from these measured workloads; this does
  not compare indexed access or replace crypto limb arrays. All measurements
  include their validators. Whole-process Bun peak RSS is about 815/830/592 MiB
  for these list/dedicated/array workloads, including runtime and temporary
  allocations; packed storage and long-session allocation remain open.
  Median aggregate retained-socket UDP echo throughput at 256/1200/8192 bytes
  is 8.43/57.21/342.86 MiB/s native and 6.51/27.33/121.98 MiB/s Bun. The peer
  independently checks every octet and actual port rebinding. This includes peer,
  OS and byte conversions and does not establish network capacity. This Mac's
  unchanged UDP maxdgram is 9216: 16384-byte peer sends fail EMSGSIZE, the
  Grounds receive deadline closes its socket, and its actual port rebinds.
  The first measurement failure is retained alongside explicit final rejection
  records. No machine network settings were changed.
  The first native RNG build failed because Bend copies effect C into a temporary
  translation unit and a relative helper include was unresolved. The final OS
  helper is self-contained and native/Bun builds pass. The first forced wire gate
  passed but cache review found the new C test excluded by the root `*.c` ignore;
  a specific source exception fixes tracking. The repeated
  `PYTHONDONTWRITEBYTECODE=1 moon run wire:check --force` passes fresh in 22s 099ms
  overall, full hash
  `e295775e559eb2d709044157a54ac2f632485aa7a62a33b71e5ea1fa816c07c9`.
  Exit-zero task execution and skipped cache hydration are saved; all 11 wire
  frozen check inputs, including the C and JS host tests, are included. A twelfth
  digest freezes the signaling integration. No forced gate was interrupted.
  Versions: Bend 2.0.27, Bun 1.3.13, Python 3.12.8, moon 2.5.5, Apple Clang
  21.0.0, macOS 26.2 arm64. Artifacts:
  `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/foundations/`, including
  builds, focused checks, exact benchmark commands/samples/source digests,
  `measurements.json`, `source-sha256.json`, configuration digests, versions,
  first-build/measurement/cache-input diagnostics and final forced-wire reports.
  Initial static crypto review retains generated X25519/AEAD/HMAC-SHA1 C,
  X25519 JavaScript and default Clang -O3 arm64 assembly. `generated-review.json`
  pins all crypto source/generated digests and evidence lines. Inspected native
  selection helpers use bit masks without mask-dependent branch/index, but that
  does not approve the full runtime. X25519 JS produces secret-derived zero/
  4294967295 masks and wrapped canonical subtraction; JIT numeric representation
  and lowering are unverified, with no measured timing leak claimed. The inspected
  native allocator free path has no dedicated complete payload scrub; clearing
  host RNG buffers does not erase all Bend key/field copies. These findings remain
  open and package docs name them. Next: evaluate byte-sized masks and biased 0..511
  canonical subtraction with 0/1 borrow, rerun native/Bun field/X25519 checks and
  inspect regenerated code. Continue full control/memory/JIT, ABI/stack and key
  ownership/erasure review before Bend TLS/DTLS or live-secret use.
  RNG sampling and public-pattern timings prove neither entropy quality nor
  constant-time operation. IPv6, cancellation coverage, packed storage, nonce/key
  lifecycle, signatures, secure signaling, DTLS/data/TURN/media and all 19 full
  stack acceptance boxes remain open.

- 2026-10-01: Added bounded single-application SDP
  decoding, connection-owned signaling revisions/credential restart, exact
  Host/Origin and synthetic-cookie admission, and a retained-socket local WS/ICE
  evaluator. Native and Bun each pass 65 SDP cases and 28 actual HTTP/WS/UDP
  admission, malformed, restart/reconnect, revision/connection-limit and
  port-release scenarios. Final focused isolated Chrome 154.0.8037.92 runs on
  both targets reach actual selected direct ICE pairs, fresh signed consent in
  generations zero and one, and restart on the same Grounds UDP base. Independent
  Python verifies HMAC-SHA1/FINGERPRINT/USERNAME, nomination and transaction
  ownership. Browser denied authentication/Origin, reconnect, malformed signaling
  and clean shutdown also pass; the data channel remains unopened. Packet checks
  also reject success for Chrome's transitional old-local/new-remote credential
  namespace. The final frozen source has 15 check-input SHA-256 digests.
  Bun's synchronous Bend runtime cannot dispatch JS `process.on` signals. An
  OS-only C11 lock-free atomic signal bridge fixes actual SIGTERM/SIGINT shutdown,
  retains its loaded mapping while handlers exist, and removes private build
  files after loading. Four real signal/listener-rebinding scenarios pass on
  each target; Bun additionally passes explicit compiler-failure/temporary-file
  cleanup. `PYTHONDONTWRITEBYTECODE=1 moon run wire:check --force` passed fresh in
  11s 909ms (overall 11s 910ms), full hash
  `d9118597a152e2684d4aadba8c0683d083460512244598a9d15a8f3561d17222`.
  Saved task metadata records exit zero and skipped cache hydration.
  A deep debug snapshot on closure caused 18.0 GB Bun / 21.7 GB native compile
  footprints; those exploratory builds were terminated (exit 143), samples
  retained, and the snapshot removed. No forced gate was interrupted. Apple
  Clang 21 arm64 then failed its generated `preserve_none` `WL_FID_ENTER` stack
  prologue at `-O3`, `-O1`, `-O0` and with shrink wrapping disabled. The scoped
  `examples/build_signaling.sh` helper compiles the identical Bend C using
  `-O3 -fno-stack-check` only for that compiler/platform; native focused server
  and Chrome checks pass. All other native checks retain Bend defaults. The
  generated-runtime ABI, stack and timing review remains open; compilation and
  vectors do not resolve those findings before live-secret use.
  Artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/signaling/`,
  including final focused native/Bun builds and logs, `browser-native/`,
  `browser-bun-final/`, independently verified `packets.json`, signal tests,
  compiler failure diagnostics, source digests, versions and forced-wire report.
  Pilot artifacts and failed exploratory builds are not final passing evidence.
  `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passed fresh: task
  execution 24m 49s 723ms, overall 24m 49s 790ms, full hash
  `a2eca3de3de40c33205987b7155f1571c435721cce3cf55274e21b69e10f00ea`.
  Saved task metadata confirms exit zero and skipped cache hydration. All 15
  frozen check inputs were unchanged at gate completion: 13 are included in the RTC hash and
  the two wire checker files in the fresh wire hash. Both targets pass all
  prior RTC checks, the new 65 SDP/28 signaling cases, and fresh real Chrome
  nomination/consent/restart with independent packet checks. Native/Bun live
  integrated consent expiry measured 30.076s/30.073s; both browser servers and
  isolated Chrome processes exit zero without forced termination. Fresh raw
  browser artifacts are retained in `forced-browser-native/` and
  `forced-browser-bun/`; complete forced task/hash/operation reports are saved
  alongside the logs. `PYTHONDONTWRITEBYTECODE=1 moon run :check` passed all
  13 tasks in 1m 48s 958ms: 12 cached, JSON fresh (706 independent integration
  cases passed). Cached Redis optional live 6379/password-AUTH 6380 checks were
  not rerun; their recorded result skips unavailable local services. Repository
  log, full run report and per-task fresh/cache evidence are saved. Versions:
  Bend 2.0.27, Bun 1.3.13, Python 3.12.8, moon 2.5.5, macOS 26.2 arm64 and
  Chrome 154.0.8037.92. Final staging normalized exactly one extra EOF newline
  in `signaling.bend`; byte comparison confirms no other source change. Original
  gate digests and final commit digests are retained separately with
  `final-whitespace-evidence.json`. No protocol behavior changed, so the suites
  were not repeated for whitespace. This completes the local signaling milestone.
  The public fixture cookie, all-interface HTTP listener, plaintext HTTP/WS,
  placeholder answer fingerprint, IPv4 single media section and unfragmented
  signaling are explicit limits. Production auth/Bend HMAC, HTTPS/WSS, DTLS,
  TURN, data, media and all 19 full-stack acceptance gates remain open.
  Next dependency slice: audit generated-runtime ABI/stack and secret-dependent
  crypto operations, establish measured byte/bulk-RNG foundations, and implement
  required Bend signatures/TLS/DTLS before secure browser signaling and data.

- 2026-10-01: `ice_transport.bend` adds an outer pure transport owner around Agent selection, consent and full/full credential restart. It derives the actual selected base and exchanged credential/integrity context, shares one consent slot across logical aliases on the same physical transport, and requires a fresh selected-base round trip before application data. `ice_consent_server.bend` serves authenticated consent-only Binding requests without mandatory PRIORITY/role attributes; protected ICE usage passes to ICE, while unprotected trailing attributes cannot mutate roles or nominate. `Consent.start_binding` emits role-free authenticated requests while preserving the existing `start` API. One authoritative request directive, private host-generated nonces/callbacks, actual-send acknowledgement, a shared 5-ms pacer and bounded IO leases coordinate ICE and consent. Admission retains active/listening records, consent IDs and 64 recently issued IDs per generation. Incoming consent never grants outgoing data consent. Response IDs resolve original ICE logical attempts without replacing observed base/source metadata; physical consent aliases resolve to their one retained owner.
  Restart reconstructs all ICE layers, clears old queues/flights/deferred/valid/nomination/pending state, preserves the current full/full role and actual pacing, and requires both local credential fields and both remote fields to change. All retained credentials are protected against reuse across a bounded 64-generation history. Only selected old consent/server slots survive, with their original clocks/probes and the role actually reached before restart. Old data requires continuing consent; replacement stream selection retires old aliases immediately and awaits fresh new consent. Old requests are reply-only and cannot change replacement roles/queues; retired namespaces are ignored. Lost contexts remain sealed. Current and retained slots share a configurable 1–256 total limit (default 256); exhaustion/core failure/fault closes the owner. Local close drops pending requests and closes consent states; the IO owner disposes state and retained sockets.
  Final native and Bun focused runs each pass 46 independently signed nomination/consent/restart scenarios and seven real retained-socket UDP scenarios. The pure suite covers ordinary check plus regular nomination handoff, fresh application denial/grant, role-free packet/service authentication and actual-source mapping, malformed/protected/unprotected attributes, exact identity/deadlines, lease expiry, shared pacing and completed-ID admission, mapped B versus generating A, physical aliases, credential changes/reuse/history bounds, old/new overlap, expiry/revocation, stale issued callbacks, role repair and post-selection role preservation, exhaustion/closed cleanup. The UDP peer verifies all integrity modes, incoming consent-only service, wrong source/transaction/forged 403, first-probe loss without retransmission, randomized unique one-shot requests, actual synthetic application datagrams, protected revocation, default 30-second expiry and port release/rebinding. During same-socket restart the replacement nomination retransmits unchanged while an old consent round trip renews and gates old data; new selection rejects old credentials before a fresh new round trip gates new data. Final focused expiry was 30.045 s native / 30.089 s Bun.
  Three preserved pre-fix Bun builds fail the final independent regressions: pending IO suppressed retries indefinitely (`pre-lease.js` / `pre-lease-regression.log`); a reused completed ICE ID let its old authenticated response manufacture fresh consent (`pre-issued-history.js` / `pre-issued-history-regression.log`); and an old server slot retained its selection-time role after a later role conflict (`pre-role-context.js` / `pre-role-context-regression.log`). The fixes enforce IO lease expiry even before a timer turn, remember issued IDs after records retire, and refresh current slot roles before retention. Two initial checker expectations were corrected: tie 2 legitimately switches local controlling tie 1 rather than returning 487, and round-robin ordinary checks in a two-stream/two-base fixture require each actual receiving base. These corrections did not change protocol implementation. No forced gate was interrupted.
  `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passed fresh in 20m 48s 938ms (overall 20m 48s 972ms, full hash `9c651fc1d930815aec1fb255b453c91df25de1e8504ac8994083147dad42624b`). Saved metadata confirms passed exit-zero task execution and skipped cache hydration; all 15 changed check inputs are covered and their SHA-256 digests remain unchanged. Both targets pass the new 46 packet / seven UDP scenarios and all prior RTC checks, including real 39.5-second/seven-identical-send regression runs. Fresh integrated expiry was 30.052 s native / 30.047 s Bun. `PYTHONDONTWRITEBYTECODE=1 moon run :check` passed all 13 tasks (12 cached, JSON fresh, overall 1m 44s 688ms). Cached optional Redis 6379/AUTH 6380 live checks were not rerun. Versions: Bend 2.0.27, Bun 1.3.13, Python 3.12.8, moon 2.5.5, macOS 26.2 arm64. Durable artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/transport/`, including final native/JS/C transport and UDP builds, focused/build/regression logs, `source-sha256.json`, `versions.json`, `focused-evidence.json`, `generated-size.json`, `forced-check.log`, `forced-run-report.json`, `forced-hash.json`, `forced-evidence.json`, `repository-check.log`, `repository-run-report.json` and `repository-evidence.json`. Generated C sizes are 439761 pure-fixture lines and 434794 UDP-fixture lines; these are size evidence only, not timing-safety evidence. Current RFC 8445 section 9 and RFC 7675 section 5.1 were read; both official verified-errata refresh forms returned Internal Error, so no new correction was inferred.
  Scope and exact next action: the owner supports registered UDP/IPv4 full/full sessions and local independent peers; it does not establish browser/NAT/TURN/data/media acceptance. Implement authenticated local HTTP/WebSocket signaling in Bend with explicit Origin policy, synthetic session authentication, bounded SDP/candidate/credential/session binding and restart/lifecycle handling. Connect the transport owner to retained actual bases, then add a fresh real-browser ICE evaluator covering direct negotiation, consent, credential restart and released resources, retaining raw protocol evidence. Preserve the full 19-item contract through that work: gathering/adaptive checklist Ta/RTO, lite/full role redetermination, IPv6/TURN, wire bulk RNG/byte throughput/cancellation, crypto timing review and key lifecycle before live-secret use, Bend TLS/DTLS/certificate/fingerprint/exporter/SRTP integration, secure signaling, SCTP/data channels and decoded/rendered native/browser audio/video with integrated direct/relay proofs remain open. All 19 complete-stack acceptance boxes remain unchecked and the full goal remains active.

- 2026-10-01: `ice_consent.bend` adds a separate pure bounded owner for one trusted selected UDP/IPv4 route. Selection starts Awaiting and cannot manufacture a new consent timestamp from an old nomination or a mapping produced by another base. A fresh authenticated round trip on the actual selected receiving base grants application consent. The owner retains at most 16 one-shot probes and 64 recent IDs, rejects recent reuse, uses trusted host-generated 96-bit IDs and randomized 4–6-second periods, and accounts for actual-send acknowledgement before starting response windows and future intervals. Outstanding probes retain their original signed bytes and integrity policies; the first authenticated success pins future requests without an older dual-policy reply overwriting it. Initial estimated RTO is bounded at 500–60000 ms and updated by integer SRTT/RTTVAR samples. Exact receiving base, peer IP/port, stream/component and generation guard response/application use. Other errors and malformed protected replies consume only their request; protected 403 immediately revokes. At 30000 ms from the last valid receipt, expiry discards all probes before processing a response. Expired/revoked states cannot restart or accept late success. Every synthetic application send in the UDP fixture goes through the exact transport/generation/time gate. Existing public ICE constructors and C/JS effects remain unchanged.
  Final native and Bun focused runs each pass 40 independent signed packet/lifecycle scenarios and six actual retained-socket UDP scenarios. They cover initial application denial, exact deadlines, 4/6-second limits and shared admission, delayed/duplicate/expired acknowledgements, no retransmissions, older outstanding replies, policy retention/pinning, malformed/tampered/errors/403/replay, wrong receiving base/source/generation, full application identity gates, transport failure/local close, RTT sampling, uptime-sized clocks and bounded history. Real UDP peers verify all integrity modes, wrong-source/transaction/forged revocation, first-probe loss, fresh random IDs and measured spacing, two renewals with observed synthetic application packets, immediate protected 403, actual default 30-second expiry and port release/rebinding. Final focused expiry measured 30.057 s native and 30.074 s Bun. Review reproduced an older dual-policy response overwriting the already-pinned SHA-256 policy; the preserved pre-fix Bun build fails the new regression in `pre-policy-baseline.log` / `pre-policy.js`. The final fix permits that outstanding reply to renew without downgrading future requests. One initial test expectation was corrected from 5135 to the independently computed 5130 ms RTO. No forced gate was interrupted. The artifact parser initially assumed Moon's overall status was `passed`; its actual `completed` report was saved before replacement and verified against the passed exit-zero task operation.
  `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passed fresh in 17m 21s 78ms (overall 17m 21s 112ms, full hash `9acc0cb4169e51ffdcca49e038c2004d91e598241bc82acbf2f4968f7b07c6d7`). The saved report confirms actual task execution and skipped cache hydration; all six changed check inputs are covered and match their saved SHA-256 digests. Both targets pass the new 40 packet/6 UDP cases and all prior RTC checks, including the actual 39.5-second/seven-identical-send regressions. Fresh gate expiry measured 30.061 s native and 30.091 s Bun. `PYTHONDONTWRITEBYTECODE=1 moon run :check` passed 13 tasks (12 cached, JSON fresh, overall 1m 49s 336ms); cached optional Redis 6379/AUTH 6380 live checks were not rerun. Versions: Bend 2.0.27, Bun 1.3.13, Python 3.12.8, moon 2.5.5, Darwin arm64. Durable artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/consent/`, including final `ice-consent[.c/.js]` and `ice-consent-udp[.c/.js]`, build/focused logs, `source-sha256.json`, `versions.json`, `focused-evidence.json`, `forced-check.log`, `forced-run-report.json`, `forced-hash.json`, `forced-evidence.json`, `repository-check.log`, `repository-run-report.json` and `repository-evidence.json`. Generated C sizes (77825 pure-fixture lines, 44307 UDP-fixture lines) are recorded without a timing-safety claim. Current [RFC 7675 sections 5.1/5.2](https://www.rfc-editor.org/rfc/rfc7675.html#section-5.1) and [RFC 8445 section 9](https://www.rfc-editor.org/rfc/rfc8445.html#section-9) were read. Both official RFC 7675 errata search forms returned Internal Error; no verified correction was inferred.
  Scope and exact next action: the fixture directly supplies a trusted selected route and does not exercise automatic Agent-to-consent handoff or restart. Add an outer transport owner that derives routes from `Agent.selected`, registered actual bases, exchanged credentials and endpoint integrity policies; retain consent loss so old credentials cannot be reused. Add authenticated incoming consent-only Binding service without mandatory ICE PRIORITY/role attributes; outgoing probes currently use ordinary non-nominating ICE Binding requests. Aggregate actual-send pacing and fresh transaction identity admission across ongoing ICE and consent, and share consent for logical streams using the same physical transport. Then implement atomic credential/generation restart: require both ufrag and password changes, flush old ICE queues/flights/pending/nomination state, preserve roles except the RFC's redetermination cases, keep only the old selected consent/server context while old data is allowed, and isolate late old responses from replacement state. Test actual nomination-to-consent loss/renewal, two-path overlap/shared pacing, old/new credential routing, expiry during restart, stale directives and released sockets on native and Bun. Authenticated DTLS closure, gathering/browser ICE, IPv6/TURN, Bend TLS/DTLS, SCTP/data/media, bulk RNG/byte throughput and generated-code timing review remain open. The full goal remains active and all 19 complete-stack acceptance items remain unchecked.

- 2026-10-01: `ice_agent.bend` adds a lifecycle owner around the compatible nomination-evidence/valid/session APIs. It resolves current generating references, schedules all eligible component nominations, applies actual sent/received authenticated intent, marks returned mapped valid identities, exposes highest-ranked selected paths only when a stream's required components complete, removes nominated component checks/pending/queues and retains original transaction response windows. It continues Binding service after conclusion/protocol failure and rejects new nomination paths with protected 400 before success. Current unrecoverable nomination failures remove chosen valid paths and related Succeeded mapped counterparts; late errors preserve replacements and 487 remains repairable. PAC starts once after actual local credential signaling and remote credential receipt in either order, defaults to 39500 ms, guards protocol failure even without remote candidates, and resumes normal criteria at expiry. A failed stream fails the session and stops remaining checks. Quarantined core faults have a separate explicit `Faulted` owner status, terminal notice and retry cleanup; the IO owner must release that aborted state/socket.
  Focused final native and Bun builds each pass 48 independently signed lifecycle scenarios and ten real retained UDP scenarios. Coverage includes actual mapped-path nomination, latest generating references and mapped counterparts, already-Succeeded/pre-answer controlled intent, exact signed request flags, pacing rollback, selected paths across components/streams, current errors/timeout/non-symmetric failure, 487 repair, stale listeners and legacy parallel nomination, Binding service after conclusion/failure, both PAC signaling orders and exact expiry, all-stream cleanup and fault quarantine. The UDP fixture explicitly uses a 1200 ms PAC policy and 800 ms terminal server grace; pure clocks cover the default 39500 ms PAC boundary. Both targets query/reuse/rebind the same actual bound port. Mapped addresses remain synthetic authenticated peer claims, not a physical NAT/browser proof.
  Review reproduced premature `failed` owner status on valid-list exhaustion while PAC was running and no terminal notice (`ice-agent-capacity-baseline.log`). The earlier compiled Bun build fails the new regression (`ice-agent-fault-status-baseline.log`); final cases additionally prove invalid-mapping fault handling and unrelated-flight retry cleanup. The first forced gate was deliberately interrupted after 10m 13s 514ms (overall 10m 13s 549ms, hash `8177573f`) to fix it; its `ice-agent-pre-fault-status-check.log`/report/hash/source manifest are excluded from final evidence. No owned compiler remained after interruption. An earlier compiled Bun build also fails the separate all-stream session-failure cleanup regression (`ice-agent-session-failure-baseline.log`). Two initial checker assertions were corrected to use the actual negotiated response algorithm and computed local peer-reflexive priority; an authenticated response from another endpoint is a current non-symmetric failure, not ignorable traffic.
  `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passed fresh in 15m 24s 314ms (overall 15m 24s 348ms, full hash `25ca8c0dfd1ef23ffa1e93a2d37e0f6fc01abbc5772394fba6be619aa27002d8`). The saved report records actual exit-zero task execution and skipped cache hydration. All nine changed check inputs are covered and match their recorded SHA-256 digests. Both targets passed all 48 new lifecycle/10 new UDP scenarios and prior ownership, request, valid-list, session, scheduler, shared-socket, clock, incoming, duplex, authentication, format and actual 39.5-second/seven-identical-send regressions. `PYTHONDONTWRITEBYTECODE=1 moon run :check` passed all 13 tasks (12 cached, JSON fresh, 1m 44s 479ms); cached optional live Redis 6379/AUTH 6380 checks remain skipped. The saved repository log/report are `ice-agent-repository-check.log` and `ice-agent-repository-run-report.json`. Versions: Bend 2.0.27, Bun 1.3.13, Python 3.12.8, moon 2.5.5, Darwin arm64. Artifacts under `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/`: `ice-agent-forced-check.log`, `ice-agent-forced-run-report.json`, `ice-agent-forced-hash.json`, `ice-agent-forced-evidence.json`, `ice-agent-source-sha256.json`, `ice-agent-versions.json`, final `ice-agent[.c/.js]` and `ice-agent-udp[.c/.js]` builds/logs and focused logs. Generated C sizes (381585 pure-fixture lines, 275389 UDP-fixture lines) are recorded in `ice-agent-generated-size.json`; they are not timing-safety evidence.
  Current RFC 8445 nomination/conclusion and RFC 8863 PAC text were read; both official errata refresh endpoints returned Internal Error, so the prior successful RFC 8445 snapshot remains the last available evidence. The owner currently requires registered UDP/IPv4 local candidates to identify required components; empty local gathering/explicit required-component configuration remains open. Exact next action: add consent freshness on selected transport tuples and observe authenticated response timestamps, with host-only random transaction IDs/4–6 second intervals, one send per probe, 30-second expiry, immediate authenticated 403 revocation, and no revival by old/expired responses; then implement credential/generation restart preserving roles and keeping consent on any old data path until replacement. RFC 7675 consent and RFC 8445 section 9 restart requirements were read during the gate. Dynamic pair pruning, pending expiry, gathering, IPv6/TURN, browser ICE, Bend TLS/DTLS, signaling, data/media and timing safety remain unfinished. The full-stack goal remains active with all 19 complete-stack acceptance gates open.

- 2026-10-01: `ice_nomination.bend` adds a bounded nomination-evidence owner around a fresh unbound valid-list/session generation, preserving existing state and record constructors. Current authenticated successes associate original and unique mapped Succeeded references with the path and generating attempt they proved; late paths cannot replace those associations. Lookup returns the latest current generating record even when the stored duplicate path retains an older origin. Qualified controlled-side USE-CANDIDATE intent survives actual pending materialization, using the actual session merge and bound remote fragment. Fresh triggered sends bind the request to exact generation/reference/sent-role/token/transaction; ordinary replacement requests do not inherit old intent. Response-only listeners retain their own bindings. Outcomes and non-symmetric notices carry the original request before retirement; recoverable 487 remains owned until repair, and generation replacement drops old evidence. Creation rejects bound/running sessions and faulted valid owners cannot supply a path proof.
  Focused Bun checks pass 46 independent signed packet cases. A source review reproduced retained old-generation binding metadata when the synthetic core changed its generation without removing old records; explicit current-generation comparison now drops it. The pre-correction Bun binary fails the new regression, saved as `ice-nomination-evidence-generation-baseline.log`. The first forced gate was deliberately interrupted at 4m 31s 586ms (overall 4m 31s 624ms); its `pre-generation-guard` log/report are excluded from final evidence. The first native fixture build spent over 19 minutes optimizing generated C, then was cancelled because it began before the fault and generation guards; its `ice-nomination-evidence-obsolete-native-build.json` cancellation record is excluded from final evidence. Fresh native verification comes from the restarted forced gate. Two initial assertions incorrectly expected a dual-integrity request's selected algorithm to remain Dual and an illegal controlled USE-CANDIDATE to reach pending state; they now assert SHA-256 selection and authenticated 400 rejection. The native checker was initially invoked before compilation finished, then deferred to the running build. New pure cases cover all integrity modes, host/reflexive/counterpart mapping, duplicate origins, current/late isolation, pre-answer merge and wrong fragments, qualified intent, ordinary and nominated replacement, pacing/capacity, listener expiry, 487 repair, non-symmetric failure, synthetic generation replacement and fresh creation. Existing UDP checks remain separate; no live nomination-owner, nominated/selected, terminal, NAT/browser or complete-stack proof is claimed. Every path still has `nominated=False`.
  The second forced gate was deliberately interrupted at 12m 54s 461ms (overall 12m 54s 533ms, hash `4af97286`) while an expanded native fixture compiled. Its `pre-dispatch-simplification` log/report are excluded from final evidence. Generated C measurements located 3,529 continuations in the fixture's combined recursive JSON/owner-state action match; splitting those matches reduces the group to 12 and generated C from 2,733,862 to 270,839 lines (existing valid-list baseline: 198,399 lines). All 46 Bun cases still pass; the change preserves action semantics and protocol/state constructors. Native baseline generation and the size comparison are saved as `ice-valid-native-size-baseline.c` and `ice-nomination-evidence-generated-size.json`. Cancelling moon orphaned its Bend/clang subtree, which retained output pipes; those exact obsolete owned processes were stopped before restart.
  Focused final native and Bun builds each pass all 46 cases (`ice-nomination-evidence-native-focused.log` and `ice-nomination-evidence-bun-focused.log`). `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passed fresh in 13m 34s 160ms (overall 13m 34s 194ms, full hash `ca4cf36d1835e1ddc30c3219d257ed9d1e52831d6cbfb22d276bd9543bf8a231`). The saved report confirms actual exit-zero task execution and skipped cache hydration; all four changed check inputs are covered by the hash and their recorded digests remain unchanged. Both targets passed the 46 ownership, 121 builder, 117 scheduler, 129 session, 70 valid-list and 23 request cases, plus the real nomination/session/valid-list UDP, clock, shared-socket, incoming, duplex and 39.5-second/seven-identical-send regressions. `PYTHONDONTWRITEBYTECODE=1 moon run :check` passed all 13 tasks (12 cached, JSON fresh, 1m 44s 696ms); cached optional Redis 6379/AUTH 6380 checks remain skipped. Versions: Bend 2.0.27, Bun 1.3.13, Python 3.12.8, moon 2.5.5, Darwin arm64. Durable artifacts under `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/`: `ice-nomination-evidence-forced-check.log`, `ice-nomination-evidence-forced-run-report.json`, `ice-nomination-evidence-forced-hash.json`, `ice-nomination-evidence-repository-check.log`, `ice-nomination-evidence-repository-run-report.json`, `ice-nomination-evidence-source-sha256.json`, `ice-nomination-evidence-versions.json`, final compiled `ice-nomination-evidence[.c/.js]` fixtures and focused logs; regression/size artifacts and excluded interrupted runs are identified above. Current RFC 8445 nomination sections and RFC 8863 were consulted; prior successful errata evidence remains the last available snapshot while the official refresh service errors. Exact next action: continue in `ice_nomination.bend` with controlling plans and controlled/outgoing nomination outcome application from retained requests and original records. Add a session intent-selection API that accepts all eligible nomination references; one caller-supplied target would send another queued nomination as an ordinary check. Resolve the current generating record from associations instead of an older duplicate stored-path origin. Apply already-Succeeded incoming counterpart intent through its associated path, and triggered intent through its actually bound flight. Enforce one controlling choice per stream/component, unrecoverable failure path removal and pair/checklist failure, role changes and response-only listeners without failing replacements. Add nominated/selected state, related cancellation and terminal/PAC handling, then finish the remaining complete-stack queue. The full goal remains active and all 19 acceptance items remain unchecked.

- 2026-10-01: Additive nomination request/repeat primitives are verified on native and Bun. `Ice.intent_request` adds one empty protected USE-CANDIDATE only for controlling senders; False intent preserves ordinary bytes and the existing two-field `Check` and original request API. `Tx.start_intent` signs once and retains exact intent through existing pacing, retries and response-only listeners. `A.start_intent` retains speculative selection rollback and endpoint integrity negotiation. `S.nominate` repeats the original sending pair even when Succeeded, deduplicates its triggered FIFO, guards current generation/controlling role and returns any interrupted token. `A.queue_nomination` retains response-only interruption and rejects outstanding authenticated 487 repair. `Session.start_intent` computes the flag from the actual selected reference after deferred work drains, so unrelated selected pairs remain ordinary. `V.queue_nomination` resolves owned stored path metadata rather than trusting a caller's copied origin; `V.start_intent` preserves existing fault and metadata handling. No original state/record constructor changes or C/JS effects changes were made.
  Focused native and Bun checks pass 121 byte-exact builders, 117 independent scheduler cases, 23 new pure nomination-request cases and ten new real UDP transaction cases; all 70 existing valid-list cases also pass. New cases cover original-pair repetition for mapped/reflexive/counterpart paths, exact protected intent and negotiated integrity, generation/role gates, FIFO deduplication, stale-target ordinary checks, pacing/capacity rollback, pending 487 repair, interrupted intent listeners, bad MAC/source, loss/retry, late outcomes, original timeout and released-port rebinding. This is request/scheduling integration: successful intent replies STILL produce `nominated=False`. The live fixture exercises retained transactions, not complete regular nomination or physical NAT/browser connectivity. No complete-stack acceptance checkbox is claimed.
  `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passed fresh in 12m 47s 570ms (overall 12m 47s 614ms, hash `c99cc4d9665f375a932fdb75c4314d6bfa25f897b7045476989c97ec686aa9bf`). The saved report confirms actual exit-zero execution and skipped cache hydration; all 15 changed check inputs are covered by the hash and their recorded source digests remain unchanged. Both targets also passed the previous session, valid-list, shared-socket, incoming, duplex and real 39.5-second/seven-identical-send regressions. `PYTHONDONTWRITEBYTECODE=1 moon run :check` passed all 13 tasks (12 cached, JSON fresh, 1m 52s 190ms). Cached optional Redis 6379/AUTH 6380 checks remain skipped. Versions: Bend 2.0.27, Bun 1.3.13, Python 3.12.8, moon 2.5.5, Darwin arm64. Durable artifacts under `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/`: `ice-nomination-request-forced-check.log`, `ice-nomination-request-forced-run-report.json`, `ice-nomination-request-forced-hash.json`, `ice-nomination-request-repository-check.log`, `ice-nomination-request-repository-run-report.json`, `ice-nomination-request-source-sha256.json`, `ice-nomination-request-versions.json` and final compiled `ice-nomination-build[.js]`, `ice-nomination-scheduler[.js]`, `ice-nomination-request[.js]` and `ice-nomination-udp[.js]` fixtures. Current RFC 8445 sections 7.1.2, 7.2.4, 7.2.5.3.4, 7.3.1.5 and 8.1.1 were read. The official errata refresh again returns Internal Error; the previous successful 2026-10-01 snapshot remains the last available errata evidence.
  Exact next action: retain authenticated controlled-side USE-CANDIDATE requests after pending materialization, with generation/fragment/reference and actual request role bound to the outgoing triggered flight. Track the successful path associated with both original and counterpart Succeeded references, so an incoming nomination chooses the mapped path generated by the correct current check, not an unrelated late mapping. Apply successful outgoing/controlled nomination using actual signed request metadata and original attempt ownership; unrecoverable nomination failure must remove its valid path and fail the pair/checklist without failing a replacement or unrelated intent. Preserve recoverable 487 role repair. Implement one controlling choice per stream/component, nominated/selected paths, related response-retaining cancellation and terminal/PAC handling. Then finish consent/restart, gathering/browser ICE, IPv6/TURN, Bend TLS/DTLS, data/media, required wire/RNG/performance and generated-code timing review. The full goal remains active and all 19 acceptance items remain unchecked.
- 2026-10-01: Authenticated current valid-path construction now completes any unique existing checklist counterpart under [RFC 8445 section 7.2.5.3.3](https://www.rfc-editor.org/rfc/rfc8445.html#section-7.2.5.3.3). Matching compares the mapped local address against the candidate actually checked after reflexive base substitution, scoped by stream/component and remote endpoint; a mapped reflexive address never aliases its base pair. The counterpart becomes Succeeded from any prior state, leaves its triggered FIFO and current flights, and thaws its matching Frozen foundations across the checklist set. Redundant active retries stop through the existing response-only listener API, preserving the signed request, generation/reference/sent role/transaction and original deadline. A counterpart awaiting 487 repair has no network transaction left: its obsolete repair record is retired, while unrelated repair work remains intact. Additional Stopped notices are returned to the IO owner, whose stale send check suppresses invalidated directives. Counterpart late success/error and listener retirement cannot fail a Succeeded pair. A late original success may still learn a valid path, but cannot apply any checklist counterpart transition or stop a distinct active pair. Existing public records and state constructors remain unchanged; protocol logic stays in Bend and C/JS effects are unchanged.
  Focused native and Bun checks each pass 70 pure signed packet/bigint cases and nine real UDP cases. The 15 added pure cases cover all five counterpart states, queue removal while preserving unrelated work, pending-send suppression, cross-checklist foundation thawing, reflexive/base separation and late-result isolation for both original and distinct current flights. Four new UDP cases cover counterpart late success/error, full original listener expiry, no redundant retransmission and a distinct active pair's byte-exact retry after a late mapped response; both explicitly bound socket ports are released and rebound. The previous milestone binary fails the new Waiting-counterpart regression (original Succeeded, represented counterpart still Waiting), saved as `ice-counterpart-baseline-regression.log`. Initial live-fixture assertions exposed reply ordering and used too short an expiry window: the fixture now waits for the actual Stopped event before delivering the late reply, and runs beyond its three-request policy's two-second final deadline. These were test corrections. A source review during the first forced gate then reproduced an obsolete 487 repair record after counterpart success; an added pure regression covers its retirement and unrelated repair preservation. That gate was deliberately interrupted at 10m 12s 83ms (overall 10m 12s 118ms); `ice-counterpart-pre-conflict-cleanup-check.log` and its interrupted report are excluded from final evidence. Mapped responses remain synthetic authenticated peer claims, not physical NAT or browser evidence.
  `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passed fresh in 12m 20s 15ms (overall 12m 20s 50ms, hash `0af9f689`). The saved report confirms actual task execution, exit 0 and skipped cache hydration; both targets passed the real 39.5-second/seven-identical-send regression and all previous RTC checks. The hash covers every changed module/fixture and imported wire effects/helper, and the recorded source digests remain unchanged. `PYTHONDONTWRITEBYTECODE=1 moon run :check` passed all 13 tasks (12 cached, JSON fresh, 1m 54s 482ms). Cached optional Redis 6379/AUTH 6380 tests remain skipped. Versions: Bend 2.0.27, Bun 1.3.13, Python 3.12.8, moon 2.5.5, Darwin arm64. Durable artifacts under `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/`: `ice-counterpart-forced-check.log`, `ice-counterpart-forced-run-report.json`, `ice-counterpart-forced-hash.json`, `ice-counterpart-repository-check.log`, `ice-counterpart-repository-run-report.json`, `ice-counterpart-versions.json`, `ice-counterpart-source-sha256.json` and final compiled pure `ice-counterpart[.js]` fixtures. Pre-correction UDP binaries and the interrupted gate are marked `pre-conflict-cleanup` and excluded from final evidence. The current RFC text was read; attempts to refresh the official RFC 8445 errata endpoint returned Internal Error, so the successful prior 2026-10-01 errata snapshot remains the last available evidence (reported editorial 7526 only). This refresh failure does not prevent the specified pair-state implementation.
  Exact next action: add an additive USE-CANDIDATE builder/transaction API while preserving two-field `Ice.Check` and ordinary requests. Regular nomination must repeat the check that produced the chosen valid path, using its original generation and sending reference, through the paced triggered queue even when that original pair is already Succeeded. Retain authenticated controlled-side nomination requests beyond pending materialization; bind success/failure to actual signed sent intent and the original generation/reference/sent role, including role changes, delayed credentials and old listeners. Implement nominated/selected paths, one nomination per stream/component, related cancellation and terminal/PAC handling. Adaptive Ta/RTO, dynamic pair-cap pruning, deferred expiry, consent/restart, gathering/browser ICE, IPv6/TURN, Bend TLS/DTLS, data/media, bulk RNG/byte throughput and generated-code timing review remain open. The full goal stays active; all 19 complete-stack acceptance items remain unchecked.
- 2026-10-01: `ice_valid.bend` adds a pure bounded owner around the existing session; `Session.State`, `A.Record`, transaction APIs and old callers remain compatible. Before response processing removes the retained entry, typed attempt metadata reads the original signed request's PRIORITY and USE-CANDIDATE flag, guarded by token, generation, transport reference, sent role and transaction. Known mapped candidates, including omitted bases, retain advertised priority/foundation/type. A new authenticated symmetric mapping learns one local peer-reflexive candidate with the exact sent priority and original base; it creates no remote cross-products. Locally learned UDP peer-reflexive foundations use base IP and responding peer/server IP, ignoring ports/components/streams, and skip existing local names. Valid paths are separate from checklist transport references, retain mapped candidate/base/remote and original attempt, partition by stream, sort by current-role bigint-equivalent ranks and rerank after role changes. Duplicate outcomes preserve the existing path even at capacity. A late success can add its original mapped path without completing/failing the active replacement. Invalid late mappings likewise leave that replacement active. Paths start with `nominated=False`.
  The limit is 1–256 valid paths and independently 1–256 learned local candidates. Failed admission commits no new candidate/foundation. Current-attempt capacity/invalid-mapping faults explicitly suppress later starts/sends and require IO cleanup; rejected old-listener mappings report their notice without faulting a replacement. The actual two-socket driver now runs this owner and closes both sockets on owner fault. Native and Bun each pass 55 independent signed packet/bigint cases and five new live UDP cases, plus all 129 previous logical session and 13 previous two-IP UDP cases. New cases cover exact sent PRIORITY, known reflexive candidates and omitted host bases, foundation sharing/separation/collisions, current-role ranks, old versus replacement mappings, duplicate full-list outcomes, admission rollback, invalid/error/non-symmetric/wrong-ID/expired traffic, pre-answer triggered remote learning, loss/retry with exact bytes/source IP/port and released-port rebinding. Live mapped addresses are synthetic authenticated peer claims; they do not prove a physical NAT, nomination or browser connectivity. Protocol/crypto logic remains in Bend, with C/JS effect sources unchanged.
  `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passed fresh in 11m 55s 464ms (overall 11m 55s 499ms, hash `c5981400`). Its report confirms actual task execution, exit 0 and skipped cache hydration; both targets passed the real 39.5-second/seven-identical-send regression. Saved hash inputs include every new module/fixture and imported wire effects/helper. `PYTHONDONTWRITEBYTECODE=1 moon run :check` passed all 13 tasks (12 cached, JSON fresh, 2m 1s 24ms); cached optional Redis 6379/AUTH 6380 tests remain skipped. Versions: Bend 2.0.27, Bun 1.3.13, Python 3.12.8, moon 2.5.5, Darwin arm64. Durable artifacts under `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/`: `ice-valid-forced-check.log`, `ice-valid-forced-run-report.json`, `ice-valid-forced-hash.json`, `ice-valid-repository-check.log`, `ice-valid-repository-run-report.json`, `ice-valid-versions.json` and final native/Bun `ice_valid[.js]` / `ice_valid_udp[.js]` fixtures with their compile logs. Exploratory type/fixture corrections preceded the final gate; no final gate was interrupted. [RFC 8445 sections 5.1.1.3 and 7.2.5.3](https://www.rfc-editor.org/rfc/rfc8445.html#section-7.2.5.3) and the [current errata listing](https://errata.rfc-editor.org/search/?rfc_number=8445) were checked; the listing contains only reported editorial erratum 7526, with no verified protocol correction.
  Exact next action: finish RFC 8445 section 7.2.5.3.3 when a constructed valid path represents a different existing checklist pair: mark that counterpart Succeeded, stop any redundant active retries while retaining response correlation, thaw its foundations, and preserve replacement isolation for late outcomes. Then add an additive regular USE-CANDIDATE request/transaction interface, retain authenticated controlled-side nomination intent beyond pending materialization, and bind nomination outcomes to the actual sent request and original generation/reference. Implement nominated/selected paths and checklist/agent terminal transitions with RFC 8863 PAC timing. Adaptive Ta/RTO, dynamic pair-cap pruning, deferred expiry, consent/restart, gathering/browser ICE, IPv6/TURN, Bend TLS/DTLS, data/media, bulk RNG/byte throughput and generated-code timing review remain open. The full goal stays active; all 19 complete-stack acceptance items remain unchecked.
- 2026-10-01: `wire_udp_bind(host, port)` and `wire_udp_local_address(socket)` add OS-only IPv4 bind/query effects on native and Bun. Binding accepts canonical literals and port 0 for OS assignment, returns actual errno, adds no reuse/DNS/fallback behavior, and closes allocated sockets on bind or nonblocking-setup failure. Querying preserves socket ownership on all paths and reports wildcard `0.0.0.0` truthfully. Existing APIs remain available. The independent Python peer passes 22 cases per target: malformed/NUL/port rejection, ephemeral/wildcard reporting, address-unavailable/in-use errno, all 256 octets and empty datagrams, two distinct IPs sharing a port without reuse options, wrong-destination isolation, port rebinding, and 1,500 failed binds in one living process with exactly one retained UDP descriptor. The Mac's bindable second local address was `192.168.50.99`, independently enumerated through `getifaddrs` and verified by bidirectional Python sockets at one port; fixtures select it dynamically and do not change interface configuration. Linux branches are implemented but not verified on this Darwin host.
  `ice_session_udp.bend` now binds explicit unicast IPs and queries both actual bound addresses/ports before constructing session candidates. It rejects wildcard inputs before allocation, supports port-zero binding, retains the original seven-argument fixture interface, and closes first/both sockets when later setup fails. Native and Bun each pass all 129 signed logical session cases and 13 live UDP cases. Added live cases prove IP-only non-symmetric failure at the same port, independent second-pair success, distinct-IP loss/retry with exact bytes and source IP/port, queried ephemeral candidate identity, and wildcard rejection; previous pre-answer, interruption/late-response, role, capacity and cleanup cases remain passing. Protocol and crypto logic stay in Bend; C/JS additions only call OS socket operations. This remains a synthetic IPv4 owner fixture, not gathering, signaling or a nominated/browser path.
  `PYTHONDONTWRITEBYTECODE=1 moon run wire:check rtc:check --force` passed both tasks fresh (wire 12s 717ms, hash `f928773a`; RTC 11m 12s 822ms, hash `58c2eea7`; overall 11m 12s 858ms). The report confirms actual task execution, exit 0 and skipped cache hydration, and both targets passed the real 39.5-second/seven-identical-send regression. Wire's cache inputs now include its check script and Python fixtures; RTC's include imported crypto/wire/io/utf8/json sources and the shared helper, with required paths verified in the saved input hashes. `PYTHONDONTWRITEBYTECODE=1 moon run :check` passed all 13 tasks (12 cached, JSON fresh, 1m 51s 938ms). Cached optional Redis 6379/AUTH 6380 tests remain skipped. Versions: Bend 2.0.27, Bun 1.3.13, Python 3.12.8, moon 2.5.5, Darwin arm64. Durable artifacts under `/Users/ozeron/.codex/artifacts/grounds/2026-10-01/`: `udp-address-forced-check.log`, `udp-address-forced-run-report.json`, `udp-address-wire-hash.json`, `udp-address-rtc-hash.json`, `udp-address-repository-check.log`, `udp-address-repository-run-report.json` and `udp-address-independent-os-proof.json`; compiled native/Bun wire and ICE address fixtures are retained there as `udp_address[.js]` and `ice_address_udp[.js]`. No final gate was interrupted.
  Exact next action: retain the actual sent PRIORITY and nomination intent in attempt records; learn mapped local peer-reflexive candidates with foundations derived from candidate type, base IP, protocol and applicable server identity under [RFC 8445 sections 5.1.1.3 and 7.2.5.3](https://www.rfc-editor.org/rfc/rfc8445.html#section-7.2.5.3); construct separate per-checklist valid pairs keyed by mapped local candidate and remote endpoint, with role-correct ranking and original reference/generation guards. Preserve existing APIs while adding regular controlling USE-CANDIDATE requests, and retain authenticated controlled-side nomination intent after pending work materializes and through triggered checks. Late attempt outcomes must not complete/fail replacements. Adaptive Ta/RTO, dynamic pair-cap pruning, deferred expiry, consent/restart, PAC terminal-state handling, gathering/browser ICE, IPv6/TURN, Bend TLS/DTLS, data/media, bulk RNG/byte throughput and generated-code timing review remain open. The full goal remains active and all 19 complete-stack acceptance items remain unchecked.
- 2026-09-30: `ice_attempts.bend` now correlates Binding responses by transaction before checking endpoint symmetry. It authenticates a mismatch using the original retained key, allowed algorithm and FINGERPRINT. An authenticated response at another registered base or peer IP/port emits `NonSymmetric{record, observed, failed}`: a current flight immediately becomes Failed, its transaction/record are removed and stale/queued sends cannot execute. The transition never authorizes 487 role repair or thaws other Frozen pairs. An interrupted old listener retires with `failed=False` without affecting its replacement or another active pair. Bad MAC/CRC, unsigned, opposite-mode, wrong-ID/method and unrelated input remain raw; they cannot alter policy/deadlines or cancel a flight. Final timeout/retirement takes precedence at its exact boundary. An authenticated reply from the original peer IP/port still selects that endpoint's first integrity algorithm even when its receiving base differs, as required by RFC 8489 section 9.1.5; a different peer cannot select the original endpoint's mode. Previously signed retries keep their bytes/mode, and late responses cannot overwrite an established policy. Existing low-level STUN/reliable/transaction APIs and source-filtering behavior are unchanged. Native and Bun each pass 129 independent signed Python session cases and nine actual two-socket UDP cases, covering authenticated endpoint failure versus untrusted raw traffic, both response algorithms and success/487/500, IP/port/base gates, stale sends, exact deadlines, independent/frozen pairs, old replies after replacement, completed/pending conflict records, policy selection/non-overwrite and interrupted listener retirement. Live mismatches send no further original retries, preserve independent and triggered retries, and release/rebind both ports. `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passed fresh in 11m 10s (actual task execution, exit 0, hash `85523dfc`), including both real 39.5-second retry regressions and all prior RTC cases. `PYTHONDONTWRITEBYTECODE=1 moon run :check` passed all 13 tasks (12 cached, JSON fresh, 1m 53s); cached optional Redis 6379/AUTH 6380 checks remain skipped. Versions: Bend 2.0.27, Bun 1.3.13, Python 3.12.8, moon 2.5.5, Darwin arm64. Durable artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-09-30/rtc-symmetry-forced-check.log`, `rtc-symmetry-forced-run-report.json`, `symmetry-repository-check.log` and `symmetry-repository-run-report.json`. A preceding gate was deliberately interrupted at 9m 58s to correct the interaction with endpoint algorithm selection; `rtc-symmetry-pre-policy-interrupted-check.log` is excluded from final evidence. C/JS effect sources are unchanged. Inspecting generated `ice_symmetric_udp.c` and `ice_symmetric_udp.js` confirms Base's `UDP.bind(port)` binds `0.0.0.0` on both targets; the receive API supplies only the peer address. Thus the live fixture verifies receiving socket/port identity, not arbitrary local destination-IP identity. The pure owner requires the actual receiving base from its effects owner. Exact next action: add address-specific IPv4 UDP binding and bound-address/port discovery as OS-only effects while preserving existing APIs; prove byte preservation, explicit-address/same-port socket isolation, errors and cleanup on native and Bun, then use it in the two-base RTC fixture to establish actual receiving-IP identity. After that, retain sent PRIORITY/nomination intent, learn local peer-reflexive candidates with correct foundations, construct separate per-checklist valid pairs and implement regular controlling/controlled nomination. Adaptive Ta/RTO, dynamic pair-cap pruning, deferred expiry, consent/restart, PAC terminal-state handling, gathering/browser ICE, IPv6/TURN, Bend TLS/DTLS, data/media and generated-code timing review remain open. The full goal is active and unfinished; no complete-stack acceptance box was checked.
- 2026-09-30: `ice_session.bend`, `ice_attempts.bend` and `ice_registry.bend` join incoming authentication, scheduling and retained transactions for one bounded UDP/IPv4 peer generation. The session validates registered local bases and endpoint metadata even when checklist pruning hides them, keeps local and remote passwords separate, answers before an answer arrives, binds immutable signaled credentials and drains only matching remote fragments. Bounded FIFO pending requests retain authenticated nomination intent; observed peer-reflexive learning and one-pair insertion commit atomically with unique foundations. Selection remains speculative under pacing/capacity pressure. Active/listening records retain generation, stable reference, transaction and sent role; interrupted retries stop while late responses remain bound to the original attempt and cannot complete/fail its replacement. Current authenticated 487 repair uses fresh host RNG and flips the recorded sent role despite intervening server-side changes. The first authenticated response pins the integrity algorithm per remote IP/port without overwriting signed in-flight retries. Raw datagrams preserve actual receiving-base and source metadata. The two-socket fixture routes commands from registered bases, acknowledges actual send time, alternates receives and closes/rebinds ports on completion and failure. Native and Bun each pass 80 independent signed Python session cases and six actual UDP lifecycle cases, including pre-answer/deferred binding, fragment mismatch, deduplication, registry/cap rollback, hidden aliases, source/stream/component/base/transaction gates, stale directive suppression, interruption/late reply isolation, role repair after another role switch, per-endpoint algorithm policy, two-base loss/retry, retained capacity/retirement and bind/session cleanup. `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passed fresh in 10m 59s (actual task execution, exit 0, hash `5450d8c7`), including both actual 39.5-second active retry regressions and all prior RTC checks. `PYTHONDONTWRITEBYTECODE=1 moon run :check` passed all 13 tasks (12 cached, JSON fresh, 1m 51s); cached optional live Redis 6379/AUTH 6380 checks remain skipped. Versions: Bend 2.0.27, Bun 1.3.13, Python 3.12.8, moon 2.5.5, Darwin arm64. Durable artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-09-30/rtc-session-forced-check.log`, `rtc-session-forced-run-report.json`, `session-repository-check.log` and `session-repository-run-report.json`. An earlier exploratory gate was deliberately interrupted before the final receiving-base metadata change; it is excluded from final evidence. C/JS effect sources are unchanged. Exact next action: authenticate transaction-correlated responses received at non-symmetric endpoints and immediately fail only their original current pair under RFC 8445 section 7.2.5.2.1. Current source guards leave such packets raw and the original attempt active, so the milestone does not yet satisfy that mandatory ICE failure transition. Preserve raw unauthenticated traffic and late-attempt isolation; then retain sent PRIORITY/nomination intent, construct valid pairs and implement regular controlling/controlled nomination. Adaptive Ta/RTO, dynamic pair-cap pruning, deferred expiry, consent/restart, PAC terminal-state handling, gathering/browser ICE, IPv6/TURN, Bend TLS/DTLS, data/media and generated-code timing review remain open. The full goal is active and unfinished; no complete-stack acceptance box was checked.
- 2026-09-30: `ice_scheduler.bend` adds pure bounded IPv4 scheduling with stable transport references, deduplicated per-checklist FIFO triggered queues, round-robin ordinary selection, global Waiting/In-Progress foundation blocking and sequential thawing, idle-stream skipping and highest Waiting rank selection. Triggered In-Progress work returns the interrupted token, removes its current flight and requeues Waiting; Succeeded incoming pairs stay unchanged. Selections are speculative: an owner commits only after `Tx.Ready`, preserving queue/pair/cursor/token state under pacing or retained-response capacity pressure. U32 tokens never repeat within a generation; completion requires its current flight and matching generation, so an interrupted token cannot complete or fail a replacement. Role reordering retains queue references and sent roles. Current authenticated client-side 487 repair flips the role recorded by that attempt, requires a new host-generated tie-breaker, reorders and requeues; actual response dispatch remains owner work. Observed-pair insertion validates Host/Relay locals and matching remote components, adds only one pair, preserves existing endpoint metadata and rejects malformed/missing-stream/capacity inputs atomically. Native and Bun each pass 106 independent Python full-sort/bigint fixtures comparing every pair, queue, cursor, allocator and flight snapshot, including 60 seeded schedules of 55 interleaved turns, speculative selection without commit, FIFO priority/deduplication, global foundation thaw/blocking, old-token and generation rejection, U32 exhaustion, sent-role 487 repair after another role switch, reflexive advertised ranks, observed peer-reflexive insertion and alias/bounds/capacity rejection. `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passed fresh in 10m 13s (actual execution, exit 0, hash `ee7799c6`), including both actual 39.5-second active retry regressions and all prior incoming, duplex, response-retention and shared-socket checks. `PYTHONDONTWRITEBYTECODE=1 moon run :check` passed all 13 tasks (12 cached, JSON fresh, 2m 7s); cached optional live Redis 6379/AUTH 6380 checks remain skipped. Versions: Bend 2.0.27, Bun 1.3.13, Python 3.12.8, moon 2.5.5, Darwin arm64. Durable artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-09-30/rtc-scheduler-forced-check.log`, `rtc-scheduler-forced-run-report.json`, `scheduler-repository-check.log` and `scheduler-repository-run-report.json`. C/JS effect sources are unchanged. Exact next action: build a bounded socket/session owner joining `Incoming`, `Scheduler` and `Tx`; retain a registered local-base/remote-candidate registry even for empty or pruned checklists, bind accepted remote fragments to signaled credentials, retain bounded pre-answer/capacity-deferred work, learn uniquely founded peer-reflexive remote candidates and insert only the observed pair. Map active and listening transactions to stable reference, generation, sent role and original transaction; stop interrupted retries without discarding that metadata, commit scheduler selection only when a paced transaction is accepted, route sends from its registered base and reject responses received on a different local base. Dispatch current authenticated 487 with host RNG, and keep late notices tied to the original attempt without completing/failing its replacement. Add independent real-UDP incoming/triggered/ordinary/loss/role/capacity/late-response and cleanup fixtures on both targets before claiming owner integration. Ta/RTO policy, valid pairs, nomination, consent/restart, PAC terminal-state handling, browser ICE, IPv6/TURN, Bend TLS/DTLS, data/media and generated-code timing review remain open. The goal tracker currently reports active; no technical blocker was encountered. The full-stack contract remains unfinished and no complete-stack acceptance box was checked.
- 2026-09-30: `ice_transactions.bend` adds `stop_retries(state, token)` for RFC 8445 section 7.3.1.4 interruption. `Listening` retains original source/transaction/key/algorithm correlation through a frozen final deadline computed from the current scheduled wait and remaining retry waits. `Stopped` is emitted once; repeated interruption cannot extend the window. Listening entries reserve identity and capacity but cannot emit or execute retries, including already queued initial/retry commands. Authenticated replies before the deadline produce separate `LateResponse` notices; expiry and transport failure produce `Retired`, never active-check failure. Invalid traffic stays raw and cannot reset deadlines or convert an earlier integrity violation into interrupted pair failure. Socket-wide failure retires listeners while retaining existing active transport-error behavior. Explicit `cancel` remains destructive cleanup. Native and Bun each pass 296 clock/response fixtures (264 added to the previous 32), including large timestamps, default 39.5-second retention, delayed retry deadlines, idempotence, identity/capacity pressure, initial/retry suppression, success/error/malformed authenticated replies, invalid credentials/CRC/source/transaction/class, exact deadline boundaries, cancellation and mixed socket failure. Default retention uses logical clock fixtures; five new independent live UDP cases use a two-second window. Both targets pass all 15 shared-socket cases: interrupted checks send no retries, valid late replies remain authenticated, invalid traffic cannot postpone retirement, a second check still loses/retries/completes independently, wrong-source traffic stays raw, late errors/expiry do not fail the interrupted pair, and bound ports are released and rebound. `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passed fresh in 9m 54s (actual task execution, exit 0, hash `a1f45985`), including both actual 39.5-second active retry regressions and all prior RTC checks. `PYTHONDONTWRITEBYTECODE=1 moon run :check` passed all 13 tasks (12 cached, JSON fresh, 2m 14s); cached optional live Redis 6379/AUTH 6380 checks remain skipped. Versions: Bend 2.0.27, Bun 1.3.13, Python 3.12.8, moon 2.5.5, Darwin arm64. Durable artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-09-30/rtc-listening-forced-check.log`, `rtc-listening-forced-run-report.json`, `listening-repository-check.log` and `listening-repository-run-report.json`. Exact next action: integrate a bounded ICE agent that maps each transaction to its stable pair reference, generation and sent role; apply accepted incoming requests to deduplicated per-checklist FIFO triggered queues, use response-only interruption for In-Progress pairs and keep work queued under capacity pressure. Implement ordinary Ta/round-robin/foundation scheduling, observed-source peer-reflexive pairs and credential binding before outgoing triggered checks; then client-side 487 role/tie-breaker repair, valid pairs and nomination. Late notices must remain bound to the original attempt rather than completing or failing a newer one. Consent/restart, PAC terminal-state handling, browser ICE, IPv6/TURN, Bend TLS/DTLS, data/media and generated-code timing review remain open. The full-stack contract remains unfinished, and no complete-stack acceptance box was checked. The automatic goal continuation resumed work after the preceding tracker-status note; no technical blocker was encountered.
- 2026-09-30: `ice_pairs.bend` adds transport references keyed by stream, component, local base and remote endpoint for formed checklists. Unique lookup, beginning and finishing checks resolve current positions at use time; missing or ambiguous endpoint matches are rejected. Reordering recomputes all ranks from advertised candidate priorities for the current role, preserving candidate metadata, pair state and stream order, with no pruning or initial-state reset. References survive priority/order changes but belong to one ICE generation; the owner must discard them on restart and resolve aliased remote endpoints before use. Native and Bun each pass 64 independent Python bigint/full-sort fixtures, including mirror priorities that change positions, completion through a saved reference after reversal, repeated role changes, state guards, reflexive advertised priorities versus bases, cross-stream foundation thawing, missing/ambiguous identities and randomized candidate sets. `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passed fresh in 9m 30s (actual execution, exit 0, hash `1e11a799`), including all incoming/duplex and earlier RTC checks on both targets. `PYTHONDONTWRITEBYTECODE=1 moon run :check` passed all 13 tasks (12 cached, JSON fresh, 2m 5s); optional live Redis 6379/AUTH 6380 checks remain skipped in cached evidence. Versions: Bend 2.0.27, Bun 1.3.13, Python 3.12.8, moon 2.5.5, Darwin arm64. Durable artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-09-30/rtc-pair-refs-forced-check.log`, `rtc-pair-refs-forced-run-report.json`, `pair-refs-repository-check.log` and `pair-refs-repository-run-report.json`. Exact next action: add a response-only transaction state that suppresses retransmissions and queued sends while retaining source/transaction/authentication correlation until the original timeout, with retirement that cannot report pair failure. Test late authenticated responses, invalid traffic, deadline boundaries, cancellation, capacity and shared-socket interleaving on both targets; then integrate deduplicated per-checklist triggered queues using the stable references. Ordinary scheduling, dynamic/valid pairs, applying role changes, client-side 487 retries, nomination, consent/restart, PAC handling, browser ICE, IPv6/TURN, Bend TLS/DTLS and data/media remain open. Generated-code timing safety remains unproven. The full-stack acceptance contract remains unfinished. Operational note: the goal tracker still reports `blocked` from the preceding run despite this continuation making progress; the available goal status tool cannot set active/resume. No new technical blocker was encountered and no acceptance checkbox was marked complete.
- 2026-09-30: `ice_incoming.bend` authenticates incoming IPv4 ICE Binding requests with local session credentials before exposing metadata or authorizing role changes. It answers before remote credentials arrive, requires FINGERPRINT, applies the protected-attribute boundary and SHA-256 precedence without fallback, and constructs byte-exact signed success or 400/420/487 responses and unsigned credential-failure 400/401 responses. Responses omit USERNAME and select one integrity algorithm; unknown required attributes are reported in wire order, including repeats. `ice_roles.bend` resolves server-side role conflicts using all 64 tie-breaker bits and retains the local tie-breaker on switches; the caller still must apply switches and recompute pair priorities. Canonical observed IPv4 source parsing is in `ice_candidates.bend`. Native and Bun each pass 308 independent compiled authentication/response/field/role/boundary cases, including maximum-size protected payloads, equality and extreme tie-breakers. The independent duplex UDP fixture handles invalid requests, signed conflicts, pre-answer requests, retransmissions and both role switches on the same bound socket while an outgoing check retries; wrong-source responses cannot complete it, retry bytes and port stay unchanged, and the bound port is released. `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passed fresh in 8m 54s (actual execution, exit 0, hash `560a9794`), including all prior RTC checks on both targets. `PYTHONDONTWRITEBYTECODE=1 moon run :check` passed all 13 tasks (12 cached, JSON fresh, 1m 49s); cached Redis evidence continues to skip optional live 6379/AUTH 6380 checks. Versions: Bend 2.0.27, Bun 1.3.13, Python 3.12.8, moon 2.5.5, Darwin arm64. Durable artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-09-30/rtc-incoming-forced-check.log`, `rtc-incoming-forced-run-report.json` and `incoming-repository-check.log`. Limits: the stateless receiver and role decisions do not implement a complete agent, valid pairs, nomination, session expiry/restart or timing safety. Full-stack acceptance remains unfinished. Exact next action: add stable pair identities and role-driven reordering, then connect incoming requests to deduplicated per-checklist triggered queues and transaction tracking. RFC 8445 section 7.3.1.4 requires stopping retransmissions of an interrupted check while retaining response correlation through its timeout; the existing destructive `Tx.cancel` alone does not satisfy this behavior and needs a separate response-only transaction state before integration. Client-side 487 retries, dynamic/valid pairs, nomination, consent/restart, PAC terminal-state handling, browser ICE, IPv6/TURN, Bend TLS/DTLS, data/media and generated-code timing review remain open.
- 2026-09-30: `ice_candidates.bend` and `ice_checklist.bend` add UDP/IPv4 candidate validation, two-word 64-bit pair ranks, advertised-priority sorting, reflexive base substitution, redundancy pruning, configurable global pair limits, foundation-aware initial unfreezing and guarded check-state transitions. Successful checks thaw matching foundations across streams; they do not establish valid/nominated pairs or agent completion. Inputs are bounded at 16 streams, 64 candidates per side/stream and 1–256 retained pairs globally. An independent full-sort Python reference found that early per-stream truncation changed global discard quotas; formation now counts all unique pairs while retaining bounded top lists, and matches 132 compiled fixtures per target, including 53 candidate-priority and 100 bigint pair-rank vectors, randomized/malformed/state cases and 16×64×64 candidate combinations. `ice_transactions.bend` supplies a pure multi-transaction engine with Ta/default 50 ms and shared 5 ms send spacing, cached authenticated retry bytes, exact source/transaction response correlation, monotonic deadlines, per-transaction cancellation/transport errors and byte-exact untrusted datagram notices. `ice_socket.bend` executes OS UDP effects on one retained socket, acknowledges actual send time, suppresses cancelled queued sends and returns ownership on every turn. The first native live fixture reproduced a stack overflow in Base Nat.max at host uptime-sized timestamps; comparison-and-selection deadline helpers now pass large-clock regressions. Native and Bun each pass 32 exact pacing/deadline/duplicate/acknowledgement/cancellation/transport cases and ten independent real-UDP overlap/loss/reordering/raw-delivery/error/timeout/cancellation cases, with checklist transitions tied to the two live transactions. The raw UDP fixture uses 8 KiB because this macOS host's default UDP send cap is 9216 bytes; maximum STUN format checks remain covered separately. `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passed fresh in 8m 8s, including all existing authentication, builder, exchange and actual 39.5-second retry regressions on both targets. The forced report and task logs were recovered from moon's retained cache after temporary logs disappeared at a turn boundary; the report records actual task execution, exit 0 and hash `f19c8a21`, not cache hydration. The first repository-check handle also disappeared and no live process remained, so it was restarted. `PYTHONDONTWRITEBYTECODE=1 moon run :check` then passed all 13 tasks (12 cached, JSON fresh, 3m 39s); cached Redis results still skip optional live 6379/AUTH 6380 checks. Versions: Bend 2.0.27, Bun 1.3.13, Python 3.12.8, moon 2.5.5, Darwin arm64. Artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-09-30/rtc-checklist-forced-run-report.json`, `rtc-checklist-forced-stdout.log`, `rtc-checklist-forced-stderr.log`, `rtc-checklist-forced-hash.json` and `checklist-repository-check.log` in the same directory. Current RFC 8445 errata list only a reported editorial broken-reference correction; RFC 8863 PAC timing was added to the acceptance plan for later agent failure handling. Limits: IPv4 candidate bookkeeping and transaction dispatch are foundation APIs, not a complete ICE agent. Local-credential incoming authentication, ordinary/triggered selection, dynamic/valid pairs, role switching/priority recomputation, nomination, consent/restart, gathering, PAC terminal-state handling, browser ICE, IPv6/TURN, Bend TLS/DTLS, data/media and timing safety remain open. Exact next action: authenticate incoming ICE Binding requests against local session credentials, build protected success/error replies, then connect incoming requests to stable pair identities, triggered checks, role-conflict handling and nomination. The full-stack goal remains active; no complete-stack acceptance checkbox is claimed from this milestone.
- 2026-09-30: `stun_retry.bend` and `ice_reliable.bend` add bounded retained-socket retransmissions without changing the existing single-send API. The request is signed once; retries preserve its exact bytes, transaction ID and bound port. The RFC 8489 default sends seven requests at 0/500/1500/3500/7500/15500/31500 ms and expires after the final 8000 ms wait (39500 ms total). Invalid traffic cannot reset monotonic attempt deadlines. Explicit outcomes distinguish timeout, transport error, invalid input, flood limit, authenticated success/error and integrity violation at exhaustion; wrong source/transaction/class or invalid envelope/CRC cannot manufacture an integrity violation. `ice_response.bend` processes only protected attributes, validates ERROR-CODE and UTF-8 reason limits, and returns the authenticated response algorithm for subsequent requests to the same peer. Native and Bun each pass 154 compiled schedule/boundary cases and 50 independent Python UDP loss/timer/error/lifecycle cases, including the actual 39.5-second default timeout, repeated invalid traffic, immediate authenticated 487 errors, unauthenticated-error rejection, late-response isolation, socket reuse after timeout and negotiated legacy/SHA-256 follow-up requests. `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passed fresh in 6m 49s with existing 139 authentication, 51 builder and 29 exchange cases plus retained-socket/legacy regressions on both targets. `PYTHONDONTWRITEBYTECODE=1 moon run :check` passed all 13 tasks (12 cached, JSON fresh, 3m 32s); cached Redis evidence still skips optional live 6379 and AUTH 6380 checks. Versions: Bend 2.0.27, Bun 1.3.13, Python 3.12.8, moon 2.5.5, Darwin arm64. Verification logs: `/tmp/grounds-rtc-retry-verified-check.log` and `/tmp/grounds-retry-repository-check.log`; earlier exploratory/interrupted logs are not the final gate. Limits: one synchronous IPv4 transaction owns receives and discards other traffic; caller-calculated ICE RTO, shared-socket demultiplexing/cancellation, checklist pacing, triggered checks, role-conflict resolution, nomination, consent/restart, browser ICE, IPv6/TURN, Bend TLS/DTLS and media remain open. Timing safety remains unproven; fixtures use synthetic local credentials. Exact next action: implement candidate/pair priorities and checklist state with a shared-socket event dispatcher that retains incoming Binding requests and interleaved transactions, then integrate authenticated triggered checks, role conflicts and nomination. The full-stack goal remains active and every complete-stack acceptance gate in STACK_PLAN.md still applies.
- 2026-09-30: Bend `ice_binding.bend` constructs USERNAME (`remote:local`), PRIORITY and exactly one ICE role attribute with all 64 tie-breaker bits preserved as two U32 words, then signs with the selected integrity mode and final FINGERPRINT. Credentials follow the RFC 8839 ASCII grammar and send/receive limits. `ice_client.bend` checks source, transaction, success class, response algorithm, HMAC and required CRC before returning a protected IPv4 mapping; invalid packets do not reset its deadline. Its exchange interface retains the caller's bound socket; the convenience request supplies a random transaction and closes its socket. Native and Bun each pass 51 byte-exact builder cases and 29 independent Python UDP success/rejection/recovery cases, plus two authenticated checks reusing one bound port. Cases cover both roles, extreme tie-breakers, legacy/SHA-256/dual requests, response selection, bad/missing authentication, wrong source/transaction, unsigned mappings, malformed packets and continued waiting after invalid traffic. `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passed fresh (4m 29s), including all 139 authentication checks per target and existing legacy/discovery regressions. `PYTHONDONTWRITEBYTECODE=1 moon run :check` passed all 13 tasks (12 cached, 2m 52s); Redis was cached and its recorded result skips optional live/AUTH checks. RTC cache inputs now include its check script, with io/utf8 declared as dependencies. This proves synthetic local authenticated ICE Binding exchanges, not retries, candidate-pair/checklist management, role conflicts, nomination, browser interop, timing safety, Bend TLS/DTLS or full WebRTC.
- 2026-09-30: Bend `stun_auth.bend` adds full-length MESSAGE-INTEGRITY-SHA256 and dual SHA-1/SHA-256 signing, algorithm selection without fallback after failed SHA-256, response-policy checks and filtering of ordinary attributes after the first integrity field. Closed Bend proofs and compiled native/Bun checks reproduce RFC 8489 Appendix B.1 corrected by verified erratum 6268; the originally published header length is malformed. Each target passes 139 independent Python RFC/differential/malformed/policy checks, including padding, duplicate/order errors, ignored attributes and maximum 65,532-byte STUN bodies. A first Bun run reproduced a stack overflow in SHA-256's Base list traversal; SHA-256/HMAC now use the existing tail-recursive byte helpers and both targets pass the maximum-size cases. `PYTHONDONTWRITEBYTECODE=1 moon run crypto:check rtc:check --force` passed both tasks fresh (4m 11s), including the existing crypto and unauthenticated UDP/legacy STUN regressions. These synthetic correctness checks do not establish timing safety or complete an authenticated ICE transaction; request construction and live authentication are the next milestone.
- 2026-09-28: Bend legacy STUN signer adds MESSAGE-INTEGRITY and final FINGERPRINT, with the RFC 8489 header-length adjustments for each. A closed proof constructs the RFC 5769 request byte for byte from its unsigned prefix; compiled native and Bun JS executables also check the resulting HMAC and CRC. The signer rejects already signed packets, malformed input, and invalid key bytes. `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passed (3m 27s), and `PYTHONDONTWRITEBYTECODE=1 moon run :check` passed all 13 tasks (12 cached, 2m 6s). The caller still must provide credential and ICE attributes; this does not complete an authenticated network transaction.
- 2026-09-28: Bend STUN FINGERPRINT verification matches the RFC 5769 request and IPv4 response CRC values. Closed Bend proofs reject changes to header, content, CRC, attribute size, attributes after FINGERPRINT, and duplicate FINGERPRINT. `PYTHONDONTWRITEBYTECODE=1 moon run rtc:check --force` passed compiled native and Bun JS examples, RFC vectors and CRC tampering, plus the existing UDP checks (2m 11s). `PYTHONDONTWRITEBYTECODE=1 moon run :check` passed all 13 tasks (12 cached, 2m 5s). This CRC is packet classification, not authentication; the UDP discovery client does not currently require it.
- 2026-09-28: `PYTHONDONTWRITEBYTECODE=1 moon run crypto:check rtc:check --force` passed. Bend HMAC-SHA1 matched all seven RFC 2202 vectors and eight Python differential cases on native and Bun JS. The STUN verifier matched RFC 5769 request and IPv4 response MESSAGE-INTEGRITY values with the RFC 8489 adjusted header length on both targets; changed content, MAC, and key failed, a SHA-256 attribute could not be downgraded to SHA-1, and the later FINGERPRINT was correctly outside the HMAC input. `PYTHONDONTWRITEBYTECODE=1 moon run :check --force` passed all 13 packages (6m 51s); optional Redis live checks were skipped because no local server ran. `json/scripts/cold.py` reports hot constructors (`SNIL`, `SCON`, `WCON`, `FALSE`, `TRUE`, `NIL`, `CON`, `CHR`) in the HMAC-SHA1 CLI, so no timing-safety claim follows. The verifier is not yet used by the one-shot discovery client and does not validate FINGERPRINT or SHA-256 integrity.
- 2026-09-28: New `rtc` package parses the RFC 5769 IPv4 Binding response and obtains `192.0.2.1:32853`; Bend checks reject bad cookie, declared length, top bits, out-of-range bytes, truncated attributes and invalid transaction IDs. `moon run rtc:check --force` passed on native and Bun JS: a separate Python UDP responder received two distinct random 96-bit transaction IDs from each target, returned each sender's address through XOR-MAPPED-ADDRESS, and confirmed that wrong transaction IDs and response sources are rejected. Both targets parsed a maximum 65,532-byte STUN attribute section without a JS stack overflow. `PYTHONDONTWRITEBYTECODE=1 moon run :check --force` passed all 13 packages (5m 38s); optional Redis live tests were skipped because no local server ran. This proves a one-shot unauthenticated STUN discovery transaction, not ICE or peer authentication.
- 2026-09-28: Bend SHA-1 matched 16 native and 15 Bun JS standard/differential cases against Python `hashlib`, including 64 KiB on both and a million `a` bytes on native. The Bend WebSocket handshake produced the RFC 6455 example accept value. Pure frame checks cover masked example text, partial input, unmasked rejection, fragmented control rejection, nonminimal and oversized lengths, and unmasked server output. A native echo server passed raw socket tests for coalesced upgrade and first frame, fragmented text with interleaved ping, UTF-8 text, binary including 64 KiB, close, and malformed frames; `websockets` 15 and Bun WebSocket clients exchanged text and closed cleanly. `wss://` text echo also passed through the existing OpenSSL socket effects. A first full run exposed a 64 KiB writer crash from constructing a Nat above Bend's 2^48-1 immediate limit; the corrected extended-length writer has a Bend check and passed the live exchange. `PYTHONDONTWRITEBYTECODE=1 moon run :check --force` then passed all 12 packages (6m 18s); optional Redis live checks were skipped because no local server ran. This proves a transport slice, not signaling, native Bend TLS, or WebRTC.
- 2026-09-28: `PYTHONDONTWRITEBYTECODE=1 moon run crypto:check --force` passed with Bend X25519 on native and Bun JS. Field arithmetic passed 181 operand pairs across add/subtract/multiply against Python bigint modulo 2^255-19. X25519 matched the RFC 7748 function vectors, Alice/Bob exchange and one-iteration vector; four fresh key exchanges matched OpenSSL; noncanonical coordinates, high-bit masking, malformed lengths and all-zero shared-secret rejection passed on both targets. Native also matched the RFC 1,000 iteration chain. `json/scripts/cold.py` reports hot constructors (`SNIL`, `SCON`, `WCON`, `FALSE`, `TRUE`, `NIL`, `CON`, `CHR`, `WNIL`) in the X25519 CLI. No timing-safety claim follows from these results; generated-code review remains required before using it with live secrets.
- 2026-09-28: After X25519, `PYTHONDONTWRITEBYTECODE=1 moon run :check --force` passed all 12 packages (5m 28s). Optional Redis live tests were skipped because no local Redis server was running; its fault and fuzz checks passed.
- 2026-09-28: `moon run crypto:check --force` passed with pure Bend Poly1305 and ChaCha20-Poly1305 AEAD on native and Bun JS. Poly1305 passed nine RFC 8439 vectors and 34 bigint differential cases. AEAD matched the RFC ciphertext/tag and 12 differential records, including 64 KiB seal/open; modified tag, AAD, ciphertext, key, and nonce were rejected. A native executable encoded the 2^32 byte length as `0000000001000000` in the RFC 64-bit length field. Bend Base's non-tail list helpers overflowed the JS stack at 64 KiB; tail-recursive byte helpers now pass that case. These are tested-input correctness results, not timing safety or live integration evidence.
- 2026-09-28: After this crypto addition, `PYTHONDONTWRITEBYTECODE=1 moon run :check --force` passed all 12 packages (3m 18s). Optional Redis live tests were skipped because no local Redis server was running; its fault and fuzz checks passed.
- 2026-09-28: `moon run crypto:check --force` passed with pure Bend ChaCha20 on native and Bun JS targets. Both match the RFC 8439 block and cipher examples. `chacha_check.py` compares eight further block cases and ten stream lengths (including 0, 63/64/65 and 127/128/129) with OpenSSL, verifies decrypt symmetry, and rejects bad key/nonce lengths and counter wrap. A Bend proof checks the RFC quarter-round example and rejects out-of-range bytes. Authentication and timing safety remain unproven; `json/scripts/cold.py` still reports hot constructors in the CLI.
- 2026-09-28: `moon run wire:check --force` passed, including `udp.bend` on native and Bun JS targets. Both tested all 256 octets, a zero-byte datagram, timeout, oversize rejection and consumption, and invalid-byte rejection. UDP uses Base's socket bind/close and OS `sendto`/`recvfrom` effects, with `List<U32>` as the Bend byte representation.
- 2026-09-28: Bend Base 2.0.27 already has `IO.random_u32` (macOS `arc4random_buf`, Linux `getrandom`, JS `crypto.getRandomValues`) and `IO.now` (`io_tick` or `performance.now`). A wrapper is only needed for bulk byte output and protocol-facing error handling.
- 2026-09-28: After the UDP addition, `moon run :check --force` passed all 12 packages (4m 16s). Optional Redis live tests were skipped locally because no Redis server was running; fault and fuzz checks passed.
- 2026-09-28: `moon run crypto:check --force` passed: 29 SHA-256 standard/differential cases, 11 HMAC-SHA-256 cases, three RFC 5869 HKDF cases and seven HKDF length boundaries. SHA includes the million-`a` vector; HMAC includes a 131-byte key. `bend test.bend` passed invalid-byte, bad-PRK, overlong-output and rotate checks.
- 2026-09-28: A native file hash of one million `a` bytes matched the published digest in about 0.39 seconds on this machine. `json/scripts/cold.py` on `crypto/cli.bend` reports hot constructors (`SNIL`, `SCON`, `WCON`, `FALSE`, `TRUE`, `NIL`, `CON`, `CHR`); this is a performance gap, not a failed correctness vector.
- 2026-09-28: `crypto/PROOF.bend` proves SHA-256 state output is 32 bytes. Replacing its last four-byte word with an empty list made the proof fail; the restored source passed `moon run crypto:check --force`.
- 2026-09-28: `moon run :check --force` passed all 12 packages, including crypto (4m 44s). Optional Redis live tests were skipped because no local Redis server was running; their fault and fuzz tests passed.
- Remaining before live crypto use: independent code review, generated-code timing audit, benchmark against the existing OpenSSL path, and proof obligations. The current vector results do not establish those properties.
