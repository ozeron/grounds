# Secret erasure: status and plan

Status: **blocker for live secrets.** Grounds cryptography is accepted for
synthetic keys only (see `RUNTIME_REVIEW.md`, "Physical erasure"). This note
records why, what other runtimes do, and what would lift the blocker.

## Why Grounds cannot erase secrets today

Bend values are immutable and owned by the runtime, so a Bend library cannot
overwrite a key in place. Erasure has to happen in the Bend runtime and its C/JS
effects. Bend 2 source checked at `aee1b1f2` (tag v2.0.38):

| Location | Behavior |
| --- | --- |
| `bend2/comp.ts` `heap_free` (~L3907) | Pushes the block onto a size-class free list. Contents stay until reuse. |
| `bend2/comp.ts` `BEND_POISON` (~L3911) | Optional, enabled with `CCC_OVERRIDE_OPTIONS=+-DBEND_POISON`. Overwrites every freed heap block. Intended for use-after-free debugging, not security: plain stores, no guarantee for copies elsewhere. Grounds does not enable it. |
| `heap_hand` / banks | Freed blocks are recycled inside one mapped corpus; memory is never returned to the OS. |
| `bend2/effs/file_read.c` | PEM/private key bytes land in a `malloc` buffer that is `free`d without wiping. |
| `bend2/effs/tcp_recv.c` | Receive buffer freed without wiping (mostly ciphertext). |
| `io_cbuf` in `comp.ts` | Outgoing bytes built with `realloc`; old blocks are freed without wiping. |
| Stack, registers | No scrubbing anywhere. |
| Bun/JS lane | No erasure API. Strings are immutable and shared; the runtime may copy buffers internally. |

Upstream: no Bend issue covers secret erasure (searched 2026-10-23). Issue #846
(stdlib crypto) was answered WONTFIX: crypto lives in hub packages such as Grounds.

## What other runtimes do

| Runtime | Mechanism | Documented gaps |
| --- | --- | --- |
| Go 1.26 | `runtime/secret.Do(f)` (experimental, `GOEXPERIMENT=runtimesecret`, Linux amd64/arm64): zeroes registers and stack used by `f` on return; heap allocations made by `f` are zeroed when the GC frees them. | Globals; heap until the next GC; no-op on other platforms. |
| Haskell | `ScrubbedBytes` (memory/ram): finalizer memsets the buffer; constant-time `Eq`, opaque `Show`. crypton #266 fixed memsets the compiler could drop before `free`. | GC evacuation copies (GHC #13241 open); hash contexts left unscrubbed for speed. |
| Rust | `zeroize`: volatile writes plus a compiler fence. | Moves, `Vec` reallocation and stack spills leave copies; drop-zeroing alone is not guaranteed zeroization. |
| Node.js | `--secure-heap` for OpenSSL private-key BIGNUMs. | Symmetric and some imported keys bypass it (nodejs#57750); wrapper objects and buffers remain GC-managed. |
| Bun | `--zero-fill-buffers` for new allocations; `fill(0)` on typed arrays. JSC's GC is non-moving, so `fill(0)` clears that backing store. | Strings cannot be wiped; internal copies (e.g. pbkdf2/scrypt inputs since #40554); freed allocator memory is not cleared. |

No runtime offers complete erasure. The strongest model is Go's: scoped,
runtime-owned erasure of registers, stack and heap.

## Plan to lift the blocker (native only)

1. **Wipe on free that the optimizer cannot drop.** A runtime mode (or a
   secret-marked allocation class) whose `heap_free` clears the block with
   `explicit_bzero`/`memset_s` or volatile stores, generalizing `BEND_POISON`.
2. **Wipe effect buffers.** `file_read.c`, `tcp_recv.c` and `io_cbuf` clear
   before `free`, and grow without `realloc` leaving stale copies.
3. **Scoped stack/register scrub,** like `runtime/secret.Do`, around handshake
   and signing.
4. **Acceptance test:** run the Bend TLS server with a synthetic key, force a
   core dump (or read process memory) after handshakes and after shutdown, and
   search for private-key and traffic-secret bytes. Record before/after.
5. **Upstream:** propose 1–3 to bendlang/bend with this evidence.

Bun stays **synthetic keys only** permanently: JS gives no erasure guarantee.
Even after native work, record residual risk (hardware side channels, copies
before erasure, crash before free) in `RUNTIME_REVIEW.md`.

## References

- Go: https://go.dev/doc/go1.26, https://antonz.org/accepted/runtime-secret/
- Haskell: https://github.com/kazu-yamamoto/crypton/pull/266, https://gitlab.haskell.org/ghc/ghc/-/issues/13241
- Rust: https://docs.rs/zeroize/latest/zeroize/, https://appsec.guide/docs/languages/rust/memory-zeroization/
- Node: https://github.com/nodejs/node/pull/36779, https://github.com/nodejs/node/issues/57750
- Bun: https://github.com/oven-sh/bun/pull/40554, https://bun.sh/blog/bun-v1.2.1
