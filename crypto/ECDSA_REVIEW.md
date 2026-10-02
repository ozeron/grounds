# P-256 ECDSA review

Reviewed 2026-10-02 against the pinned Bend 2.0.27/Bun 1.3.13 toolchain. The new
modules use the current accepted P-256 and prime/order arithmetic. This is an
experimental digest/signature boundary, not a complete TLS or certificate owner.

## Algorithm and input boundary

[SEC 1 v2.0](https://www.secg.org/sec1-v2.pdf), sections 4.1.3 and 4.1.4, define
r = x(kG) mod n, s = k^-1(z + rd) mod n and verification via z/s G + r/s Q.
The verifier checks the strict SEC1 public key and canonical nonzero r/s, rejects
an infinity sum and compares the normalized x modulo n. P-256's cofactor is one;
the existing validated curve point API supplies the selected public-key profile.
The digest API restricts input to exactly 32 valid SHA-256 bytes. Its full integer
can exceed n; scalar arithmetic reduces it without accepting private/signature
aliases. DER is a strict two-positive-integer boundary with only short lengths.

[RFC 6979](https://www.rfc-editor.org/rfc/rfc6979.html), section 3.2, supplies
HMAC-SHA256 deterministic candidate generation. Initialization uses BE32(private)
and bits2octets(digest), V = 32 bytes of 1 and K = 32 bytes of 0. Rejected nonce
or signature candidates update K = HMAC_K(V || 0), then V = HMAC_K(V). Candidates
outside 1..n-1 are rejected rather than reduced. The bounded search performs at
most 128 attempts and returns None on exhaustion.

The current [RFC Editor errata search](https://errata.rfc-editor.org/search/?rfc_number=6979)
was inspected on 2026-10-02. Verified technical erratum 3812 adds s = 0 rejection;
`finish.scanned`, `search.signature` and `rejected` implement it. Held editorial
erratum 5963 changes hex notation for V/K, not their byte values. The older
www.rfc-editor.org errata endpoints returned errors; the RFC information page
links to the working errata.rfc-editor.org search above.

## Evidence and pending gate

Current-dependency isolated evidence is in
`/Users/ozeron/.codex/artifacts/grounds/2026-10-02/ecdsa-current/`.
`probe-provenance.json` pins the base 7a27a9a, original draft hashes and current
field/P-256 hashes. `tested-inputs.json` pins the later probe inputs. The previously
downloaded official NIST archive and RFC text match the source hashes recorded
in `ecdsa_vectors.json`; all 30 selected NIST rows match the archive exactly.
The current NIST HTTP fetch returned 403; `published-vector-provenance.json`
records the locally reverified official artifact instead of claiming a new fetch.

The current primary native matrix passes all 384 cases in 12.688 seconds and
all 1,388 DER cases in 0.562 seconds. Six closed checks and all five current
native evaluators pass, and Bun passes the complete 51-case rejection section
in 10.474 seconds, including actual 0/n/n+1 nonce-candidate rejection. This whole
focused command peaks at 363.8 MiB and exits zero; its report/log are
`primary-focused-resource.json` and `primary-focused.log`.
The combined evaluator crossed the unchanged 512 MiB cutoff at 526.5 MiB.
Five narrow native evaluators compile at 207.2–356.3 MiB; the six initial closed
checks and five JavaScript builds pass at 304.4 MiB. The rejection evaluator uses
short opcodes after its original long literal dispatcher crossed the same cutoff.
The slow Bun probe passes all 49 published-vector cases in 376.636 seconds,
then was deliberately stopped after 511.202 seconds for a runtime comparison
(exit 143; the remaining sections are not accepted). The comparison clears only
BUN_OPTIONS, retains the reported-RAM setting and the 512 MiB cutoff, and times
out after 180.018 seconds at 190.7 MiB; it has no complete matrix result and was
not adopted. `generated-js-review.json` pins the signer JavaScript digest and
five exact retry/nonzero function bodies; it records unresolved branches and
allocation/erasure findings rather than granting timing approval. Complete Bun
runtime verification and forced crypto/repository gates remain pending at this
checkpoint. The first forced package gate on 4953680 stops in the existing X25519 evaluator
at the 512 MiB process cutoff after compiling every new native ECDSA evaluator;
it is not a package acceptance result. X25519's subsequent consuming exact-name
fixture recovery passes native/Bun at 144.8 MiB, with its full original matrix,
124 admission cases per target and the native 1,000-iteration vector intact.
See STACK_PROGRESS.md for subsequent gate results;
these focused results alone do not establish full package or stack acceptance.

## Unresolved timing and erasure findings

1. Nonce range, zero-r/zero-s and retry decisions depend on secret-derived
   values. The bounded search can perform a variable number of HMAC and point
   operations. Rejection is required by the algorithm; passing vectors does not
   establish a constant-time generated implementation.
2. The point/field schedules use the existing fixed 256-bit multiplication and
   public counters. The JavaScript signer still uses tagged objects, trampoline
   allocation and garbage collection for key, nonce and arithmetic state.
   Native optimized code, the full runtime and Bun JIT need current review;
   source-level masks and fixed schedules are insufficient evidence.
3. Private scalars, nonce K/V and intermediate values remain ordinary Bend
   lists/arrays. Releasing references or returning None does not demonstrate
   physical erasure of every heap/stack/compressed-memory copy. There is no
   demonstrated key-retirement owner or wiping guarantee in this API.

These findings remain open. No live-secret approval, whole-runtime timing claim,
TLS/DTLS authentication claim or full-stack acceptance follows from this milestone.
