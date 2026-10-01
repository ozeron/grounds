# Full Bend stack progress

Target: a native, browser-interoperable network stack with crypto, TLS/DTLS and RTC protocols authored in Bend. C/JS should only implement OS and device effects. `bounty/` is unrelated and must never be staged.

The full completion checklist and continuation order are in [STACK_PLAN.md](STACK_PLAN.md). Completed RTC milestones do not complete the five-layer stack.

| Layer | Current state | Next proof of progress |
|---|---|---|
| `wire` | Byte TCP and IPv4 UDP effects, explicit local-IP binding and OS bound-address/ephemeral-port discovery; OpenSSL TLS effects. UDP handles all octets, zero datagrams, timeout and oversize errors, with same-port/two-IP isolation and failed-bind descriptor checks. Actual SIGTERM/SIGINT stop parked native/Bun loops and release the listener; Bun uses an OS-only C11 atomic signal bridge because its synchronous runtime cannot dispatch JS signal callbacks. Bounded bulk host RNG bytes now pass native/Bun guard/error tests and supply signaling credentials. Public-pattern byte/RNG and retained UDP measurements are recorded; Bend Base supplies monotonic `IO.now`. | Verify IPv6/cancellation and packed storage/long-session allocation, retaining measured baselines; complete crypto/runtime review before secure transport. |
| `crypto` | Bend SHA-1 for WebSocket challenge, HMAC-SHA1 for legacy STUN integrity, SHA-256, HMAC-SHA256, HKDF-SHA-256, ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD, AES-128 encryption, AES-128-GCM and X25519; P-256 prime/order arithmetic and uncompressed-point ECDH, plus TLS HKDF labels and distinct affine ChaCha/AES-GCM traffic owners with 64-bit nonces/key updates and AES sending usage limits. Poly1305 products now stay below 2^26; OpenSSL remains in live cookie/TLS paths. | Resolve remaining runtime/erasure review, add mandatory P-256/RSA/ECDSA, then cookie and full handshake integration. |
| `tls` | Bend protected TLS 1.3 ChaCha20-Poly1305 and AES-128-GCM records and traffic/key lifecycle pass synthetic native/Bun differential tests; AES also reproduces RFC 8448 encrypted records. Live TLS client/server still use OpenSSL C effects; JS TLS effects return `ENOSYS`. | Complete mandatory TLS algorithms, handshake/transcripts, certificates/signatures/trust/hostname checks and real client/server interop; DTLS 1.2 for RTC. |
| `http` | Bend HTTP/1.1 client/server, routing, JSON, cookies, auth, CORS, multipart, SSE, and server WebSocket handshake/framing/session. Native echo interops with a third-party Python client and Bun's WebSocket API. A bounded local signaling fixture admits exact Host/Origin and a public synthetic cookie before upgrade/UDP allocation; native and Bun exchange SDP with real Chrome and clean up connection-owned ICE state/sockets. | Replace the fixture selector with Bend cookie/HMAC authentication and integrate Bend TLS for browser HTTPS/WSS. |
| `rtc` | Bend STUN parsing, IPv4 XOR-MAPPED-ADDRESS, SHA-1/SHA-256/dual integrity, FINGERPRINT, authenticated incoming/outgoing ICE Binding exchanges, retained-socket retransmissions and explicit error/integrity outcomes. IPv4 candidate/pair priorities, bounded checklist formation, stable transport references and guarded state transitions, role-driven priority reordering, a paced shared-socket transaction engine with response-only interruption, protected incoming replies and server-side role decisions, FIFO triggered queues, ordinary round-robin/foundation scheduling and generation/sent-role attempt ownership. A bounded session now binds signaled credentials, registered receiving/sending bases, observed peer-reflexive candidates, deferred incoming work, retained attempts and endpoint integrity policies. Authenticated non-symmetric responses fail only their original current pair; interrupted old listeners retire independently. The live owner fixture explicitly binds unicast IPv4 bases and queries actual local ports before candidate formation. An additive valid-list owner resolves authenticated mappings, learns locally peer-reflexive candidates from retained signed-request priority, allocates IP-keyed foundations, reranks by role and keeps late paths separate from replacement flights. A nomination-evidence owner associates current successful checks with their valid paths and retains qualified incoming intent through materialization, exact triggered flights and response-only listeners; already-Succeeded counterparts resolve their actual generating record. A generation lifecycle owner now applies regular controlling/controlled nomination, selects completed stream paths, removes nominated component checks while retaining response listeners, continues authenticated Binding service, and defers failure through PAC. An outer transport owner derives selected physical consent routes, serves authenticated consent-only Binding requests, shares actual-send pacing and recent transaction identity admission, gates logical application routes, and preserves sealed consent loss. Full/full credential restart rebuilds ICE state while retaining only selected old consent/server contexts until replacement selection. Bounded SDP/signaling now binds connection-owned credentials and the actual retained UDP base; real Chrome verifies direct selected pairs, fresh consent, restart and cleanup on native and Bun. Separate unauthenticated discovery remains available. | Complete crypto/runtime foundations and secure signaling, then gathering, IPv6/TURN, DTLS/SCTP and SRTP/media. |

## Evidence ledger

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
