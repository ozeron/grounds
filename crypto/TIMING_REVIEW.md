# Server secret timing review (2026-11-09)

This review covers every secret-dependent operation of the native Bend
HTTPS **server**. It is the timing item on the STACK_PLAN Crypto checklist.
Secret erasure is out of scope, and [ERASURE.md](ERASURE.md) still blocks
live secrets on its own. Bun is synthetic-only and was not reviewed.

- Toolchain: Bend 2.0.38 and Apple clang 21.0.0 (`-std=c11 -O3
  -fno-stack-check`, as in `tools/bend_native.sh`).
- Machine: macwork, Apple M4 Pro, macOS.

**Verdict: the server is not yet timing-safe for a real private key.**

- **Source level.** After the fixes below, every server private-key and
  session-secret path is constant-time. Two exceptions remain, both
  dispositioned below: the RFC 6979 retry, which is inherent, and the
  one-time private-key import at startup.
- **Emitted code.** It adds no secret-dependent branch.
- **CPU.** The Bend runtime runs with Arm DIT (data-independent timing)
  turned off. With DIT off, P-256 scalar multiplication still showed a
  reproducible, data-dependent difference in cycle counts, even though the
  instruction stream was identical. Turning DIT on removed it.

The STACK_PLAN box therefore stays unticked until the runtime sets DIT on
every thread (upstream ask 1).

## Method

1. **Static review of the Bend source.** We looked for `match`,
   `Bool.pick` and `if` on secrets; loop counts and list lengths that depend
   on secrets; secret `Array.get`/`set` indices; and secret shift amounts or
   divisions. The operations reviewed are:
   - RSA-PSS signing, including the validation it repeats on every
     signature;
   - private-key PEM/DER import;
   - ECDSA P-256 signing;
   - P-256 and X25519 ECDH and key generation;
   - AES-128/256-GCM and ChaCha20-Poly1305;
   - HMAC/HKDF with SHA-256 and SHA-384;
   - Finished and tag comparisons;
   - TLS 1.3 record open.
2. **Review of the emitted C and the arm64 machine code.** How Bend 2.0.38
   lowers each construct, as checked in the emitted C:
   - U32 arithmetic, bitwise operations and comparisons become branch-free
     C expressions (`U32_BIN`). `shrn`/`shln` guard the shift amount with
     `n >= 32 ?`.
   - `Bool.pick` and every `match` become a C `if`/`else`.
   - Nat is a u64 with an overflow check. `Nat.div`/`mod` and
     `U32.div`/`mod` become hardware division.
   - `Array.get`/`set` index directly at `index & (size-1)`.
   - The runtime adds a poll every 4096 loop iterations, block-location
     caches that compare array handles (heap identity, not values),
     free-list allocation by size class, and reference counting by
     structure.

   None of these runtime additions depend on data values. Every server path
   above uses public indices, shift amounts and divisors. `asm_lines.py`
   maps `clang -O3 -g -S` output back to lines of emitted C. It checked all
   56 masked-select and mask lines of the harness program and found no
   conditional branch. Those lines compile to ALU operations, plus `csel`
   where clang folded masks such as `255*(b&1)`. The only `b.eq` on those
   call lines come from the array-handle caches and the yield check.
3. **Empirical leakage detection** (`crypto/timing/`):
   - The harness calls the server entry points in-process with
     BENDRTS=`--threads 1`, interleaving the two classes at random.
   - Each sample records per-thread **cycles** and **instructions
     retired** (`thread_selfcounts`).
   - Cycles get a Welch t-test over six crops; instruction counts per class
     are compared the same way. |t| > 4.5 counts as a leak indication.
   - Inputs are copied just before measurement (b84bdc2), so the class does
     not also choose a memory placement. Without that copy, the earlier run
     gave spurious indications of 5 to 16 for RSA, AES-256 and HMAC. They
     were placement artifacts and vanished with fresh inputs.
   - Controls: the empty operation gave |t| = 1.7–3.1. The positive control
     (a loop that runs as many times as a secret nibble, about 40 cycles)
     gave t = 632 on cycles and t = 242 on instructions.

A pass does not prove constant-time execution. It covers only the sampled
inputs, this core and this build. Instruction counts also miss
secret-dependent memory addresses and if/else branches whose two arms are
the same length.

## Per-operation results

Each t cell gives the largest |t| across the cycle crops, then the
instruction t, then N. "run2" is the harness with fresh inputs. "run1"
copied constant inputs less carefully, so it can only produce false
positives, never hide a leak. "DIT" means PSTATE.DIT was set on the
measuring thread (`GROUNDS_TIMING_DIT=1`).

| Operation (server use) | Static | Emitted code | t, DIT off | t, DIT on | Fix / residual | Upstream ask |
|---|---|---|---|---|---|---|
| RSA-PSS sign 2048 (CertificateVerify) | **Leak, now fixed (3740ffc).** The CRT product q·h ran `bit_length(h)` limbs, and h = ⌊s/q⌋, which leaks q. The `r < n` blinder check exited at the first differing byte. `bit_length` looped over the top byte. | Fixed-window exponentiation, full 16-entry masked scan and masked final subtraction kept; no branches on masks | run2: 1.7 / 0.9 (19,800; fixed key vs random pool key) | run2: 1.0 / 2.5 (19,800) | Residual: byte lengths of d, dp, dq and qi, and the bit lengths of p and q (≈ \|n\|/2), are still visible through per-signature `validate` and loop widths. One pool key has a 255-byte d, and its instruction count is lower by 181k. | 1, 2 |
| RSA CRT product q·h (component) | as above | — | before fix: 73.9 / −694; after: 2.7 / −0.7 (1M) | 1.9 / 1.1 | Fixed | — |
| RSA blinder `r < n` (component) | as above | — | before fix: 731 / −22,510; after (run2): 1.4 / −1.2 (1M) | 1.1 / −1.5 | Fixed | — |
| RSA key import (PEM/DER/validate, once at startup) | base64 digits branched on character class: fixed (5a14aa7). DER lengths and the `positive` top-byte checks are inherent. | not measured (startup only) | — | — | Accepted: integer lengths and top bytes are visible to anyone who can time server start | 2 |
| ECDSA P-256 sign (RFC 6979) | Constant-time apart from the RFC 6979 retry, r=0 and s=0 branches (≈ 2⁻³²; these reveal only a discarded candidate) | Fixed 256-step double-and-add with masked select; Fermat inverses with a public exponent | run1: 2.0 / 1.5 (39,800; d=1 and digest 0 vs random) | run1: 1.3 / 1.0 | The retry is accepted as inherent to RFC 6979 | 1 |
| P-256 ECDH and keygen (d·Q, d·G) | Constant-time (complete formulas, masked select, public bit positions) | as above | **d=1 vs random: run2 16.1 / −1.5 (ECDH), 31.3 / −0.2 (keygen); run1 19.2 / 9.0.** 16 leading zero bits vs full width: 1.2 / 1.2. Fixed random-looking d vs random: 1.1 / 1.5 | **run2 2.4 / 0.5 (ECDH), 1.0 / 0.1 (keygen); run1 2.1 / 1.0.** Leading zeros 0.5; fixed random-looking 0.4 | **Residual: data-dependent CPU timing with DIT off.** The instruction stream is identical, but the class distributions differ by about 0.1–0.5% depending on quantile. Gone with DIT. No Minerva-style nonce-length leak was seen at 30k samples, though that test has low power for small effects | 1 |
| X25519 shared | Constant-time (255-step ladder, XOR-mask cswap, fixed inversion chain) | Masked cswap has no branches | run1: 0.2 / −0.5 (99,800; scalar 0 vs random) | run1: 0.8 / −0.2 | — | 1 |
| AES-128/256-GCM seal | Constant-time: arithmetic GF(2⁸) S-box with no table, masked GHASH | `255*(b&1)` becomes `csel`; GHASH mask has no branches | run2: 2.0 / 0.2 (128-bit), 3.6 / 0.1 (256-bit); 1M each | run2: 2.8 / −0.9, 0.9 / −0.1 | — | 1 |
| ChaCha20-Poly1305 seal | Constant-time (ARX; masked Poly1305 final subtraction) | The `1023` mask has no branches | run1: 1.2 / −0.3 (1M) | run1: 1.6 / −1.0 | — | 1 |
| AEAD open tag compare (GCM / ChaCha) | XOR/OR over all 16 bytes, then a single decision | — | run1: 2.2 / 0.8 and 2.6 / −1.1 (1M; first vs last tag byte wrong) | run1: 2.2 / 1.9 and 1.6 / −1.1 | — | — |
| HMAC-SHA256 (HKDF, Finished, RFC 6979) | Constant-time (U32 ARX; key-length branches depend only on public lengths) | — | run2: 3.9 / 0.4 (1M; zero key vs random) | run2: 2.2 / 0.1 | — | 1 |
| Finished verify | XOR/OR over all 32 or 48 bytes | — | run1: 2.1 / 0.1 (1M; first vs last byte wrong) | run1: 1.7 / 0.0 | — | — |
| TLS 1.3 record open: inner plaintext | Trailing-zero scan branches once per padding byte (RFC 8446 §5.4) | — | not measured | — | Accepted: it reveals the peer's padding length, which the peer chose. The server sends no padding. | — |
| TLS 1.2 PRF and records | Client only; the server never builds TLS 1.2 epochs | — | — | — | Out of scope | — |

Why we read the P-256 result as CPU timing rather than a control-flow leak:

- The instruction counts are identical in both classes.
- The source and the machine code select by masks.
- The effect reproduced in two independent runs with fresh inputs.
- It was absent under DIT with the same seeds.

Apple guarantees data-independent timing only while DIT is set, and that
includes disabling the data memory-dependent prefetcher (the GoFetch class)
on M3 and later. d=1 is a deliberately extreme input. Random,
random-looking and 16-leading-zero scalars showed no indication. Even so, a
server holding a real key should not rely on timing with DIT off.

## Fixes in this review

- `3740ffc` (rsa_private/rsa_integer):
  - `product` widths now come from operand byte lengths. Before this, the
    CRT term h = ⌊s/q⌋ set a loop count.
  - `bit_length` is a fixed sum of eight `nonzero` bits.
  - The equal-width `less` records the first differing byte with a mask
    instead of exiting early. This covers blinder admission in the signer
    and in `tls_server_flight`, and the private-key range checks.
  - The CRT exponents are widened to the factor width.
  - Outputs are bit-identical, and the full RSA integer, private, PEM and
    private-key corpora pass. Gates are listed in STACK_PROGRESS.md.
- `5a14aa7` (pem): the base64 digit is selected by masks instead of
  branches.

## Residual risks

1. **DIT is off in the Bend runtime.** Without it, P-256 scalar
   multiplication showed data-dependent cycle timing on M4 Pro; with it
   there was none.
   - On macOS, new threads do not inherit DIT (tested). A Grounds effect
     therefore cannot set it for the runtime's worker threads.
   - Linux/x86 and other cores were not measured. Intel and AMD need
     DOITM-style kernel support.
2. **RSA key shape is visible.** The visible parts are the byte lengths of
   d, dp, dq and qi, the bit lengths of p and q, and the startup DER and
   `positive` checks. They reveal nothing secret beyond what DER import and
   the public modulus already expose.
3. **The RFC 6979 retry** and the zero-r/zero-s branches (≈ 2⁻³²).
4. **The TLS 1.3 padding scan** reveals the peer's chosen padding length.
5. **Coverage limits:**
   - Only RSA-2048 was measured, not 3072 or 4096.
   - The measurements ran single-threaded, but the server runs on the
     multi-threaded scheduler.
   - Allocation and refcounting do not depend on values in any path we
     reviewed, but this is not proven for all inputs.
   - The machine code has no formal constant-time verification (that would
     need ctgrind, Binsec/Rel or a verified compiler).
6. **Erasure** is separate and still blocking (ERASURE.md).

## Upstream asks (Bend runtime/compiler)

1. **Data-independent timing mode.**
   - On arm64 with FEAT_DIT, set PSTATE.DIT (`msr DIT, #1`) on every thread
     that runs Bend code: worker threads, the IO thread and spawned threads.
     This can be always on or behind a flag such as `--dit`.
   - Document that the x86 equivalent (DOITM) depends on the kernel.
   - The harness's `GROUNDS_TIMING_DIT` switch demonstrates this on one
     thread. With DIT on, cycles changed by −1% to +9%, depending on the operation.
2. **Constant-time primitives.**
   - Guaranteed branch-free `U32.select(mask, a, b)` and `Bool.to_u32`
     intrinsics. Today `Bool.pick` becomes `if`/`else`, and only clang's
     heuristics turn it into `csel`.
   - A way to mark values as secret, so the checker rejects any `match`,
     loop count, `Array` index, shift amount or divisor derived from them.
     The `bit_length(h)` leak was exactly this kind of bug.
   - This fits alongside the erasure ask in ERASURE.md: secret-typed
     storage with wiping.

## Evidence

All on macwork, under `~/grounds-artifacts/2026-11-09/timing/`:

- `run2/` contains the fresh-input harness from b84bdc2 (emitted C SHA-256
  `72bb318f…a2a0`), with `o*` and `dit-o*` for kinds 1, 2, 4, 5, 6, 10
  and 15.
- `run1/` covers kinds 0–15:
  - Main harness emitted C SHA-256 `f4519a3f…b825`. `prefix/` holds the
    same harness built against `a51b65f`, for the before-fix kinds 14 and
    15.
  - `ecc/` holds kinds 16 and 17.
  - `dit/` holds every kind with DIT on, using the 7b72bd7 harness.
  - `repeat/` holds the reruns.
  - `asm/asm_masks.txt` is the assembly scan; asm SHA-256 `868668c4…c6c5`.
- `ns-clock-partial/` and `pre-fix/` hold the first nanosecond-clock runs.
  Before the fixes, the RSA product gave t=24.5 and the compare t=175.8;
  after, 1.5 and 1.9.
- `pool.bin` (in each run directory) is the synthetic key pool.

To rerun, see [timing/README.md](timing/README.md).
