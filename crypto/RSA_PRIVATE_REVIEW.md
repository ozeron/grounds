# RSA-PSS private operation review — M2, 2026-10-23

**Synthetic keys only.** This implementation provides RSA-PSS-RSAE/SHA-256
signing for interoperability work. It does not approve live TLS secrets,
constant-time execution, physical erasure, or arbitrary untrusted RSA key
creation. The repository's broader runtime decision is in RUNTIME_REVIEW.md.

## API and admitted keys

`rsa_private.Private{n,e,d,p,q,dp,dq,qi}` is an affine `Type`. Each integer is a
canonical unsigned big-endian byte list, with no redundant leading zero.
`validate(key) -> Maybe<&1, Private>` checks the complete product `n=p*q`
without truncation, distinct odd factors, all ranges, `d mod (p-1)=dp`,
`d mod (q-1)=dq`, `e*dp mod (p-1)=1`, `e*dq mod (q-1)=1`, and `q*qi mod p=1`.
The selected bounded credential policy admits 2048–4096-bit moduli,
1024–2048-bit factors, and odd public exponents `3 <= e <= 2^32-1`.

**Factor provenance is a prerequisite:** this checks CRT consistency, not
primality. Imported factors must come from trusted RSA key generation. The
Fermat inverse used for base blinding assumes prime factors; an explicit
multiplicative inverse check and the final public-operation check fail closed
on unsuccessful arithmetic. Those checks do not turn arbitrary composite
factors into an approved RSA key. Supporting untrusted key generation needs a
separate prime-generation/validation owner.

`sign_digest(key, digest, salt, blind) -> Maybe<&1, List<&2,U32>>` consumes the
private owner even on rejection. SHA-256 digest and PSS salt must each contain
exactly 32 valid bytes. The signature is exactly `k=ceil(bit_length(n)/8)`
bytes. PSS uses SHA-256, MGF1-SHA256, 32-byte salt, and `emBits=bit_length(n)-1`.
There is no PKCS#1 v1.5 signing API and no RSA key generation.

## Randomness and private operation

For every attempt the host must obtain a fresh, independent 32-byte salt and a
fresh `k`-byte blinder from the host RNG effect. RNG failure aborts before
calling the pure signer; a zero-filled replacement, deterministic fallback,
or reuse is forbidden. This pure API cannot attest entropy provenance. Salt
bytes, including an all-zero test salt, are valid PSS values; an entropy test
cannot distinguish a legitimate draw from a failed host RNG.

The blinder candidate is an exactly-`k`-byte unsigned integer and is rejected
unless `1 < r < n`. It is never reduced modulo `n`. Callers may mask unused
high bits above `bit_length(n)` on fresh uniform RNG output before this
rejection test; that gives uniform candidates with at least approximately
one-half range acceptance even for non-byte-aligned moduli. Each rejected
candidate requires fresh bytes. Abort on exhausted host retries. For each CRT
factor the signer reduces the admitted blinder, computes `r^-1` by Fermat,
and checks `r*r^-1 mod factor = 1`; candidates divisible by either factor are
rejected. Base blinding computes `(EM*r^e)^dp * r^-1 mod p` and its `q`
counterpart, then recombines `m2 + q*((m1-m2)*qi mod p)`.

Before releasing any signature, an RSA public operation must recover the
**entire exact PSS representative**, including the leading zero when `emLen`
is shorter than `k`. A failed inverse or public-operation fault returns
`None`. The test CLI additionally verifies every successful signature using
the pre-existing `rsa_signature256.verify_pss_digest` API.

## Source and generated runtime findings

| Finding | Disposition | Evidence / limit |
|---|---|---|
| Branching on private exponent bits | fixed | New exponentiation always squares and multiplies, then selects limbs with a `0/32767` mask. Both generated targets preserve this structure. |
| Early exit on subtraction borrow | fixed | `minus_small.go` scans the complete admitted limb width even when borrow becomes zero; borrow-zero and borrow-propagation cases are covered. |
| Unblinded private input and CRT faults | mitigated | Fresh base blinding, per-factor inverse validation, exact final public-operation check, and existing Bend PSS verification in the test CLI. This is not a timing or fault-resistance proof. |
| Private factor/exponent lengths, key/blinder comparisons and validation branches | accepted-for-synthetic-keys-only | `rsa_integer.bit_length`, `less`/`compare.go` (also blinder admission), range/congruence outcomes, factor/exponent byte widths and allocation shape remain observable. Base blinding does not hide key-validation leakage. |
| Secret-indexed tables / arbitrary-precision host arithmetic | mitigated | The new arithmetic uses bounded base-2^15 `U32` arrays and public loop indices; private exponents use masks. Generated JS uses `Math.imul`, shifts and arrays, rather than host `BigInt` arithmetic on RSA integers. No secret-indexed lookup table was introduced. This is source/generated inspection, not a constant-time guarantee. |
| Allocation, copying, runtime scheduling, JIT and physical erasure | accepted-for-synthetic-keys-only | Native heap objects/array clones and JS `.slice()`/GC retain copies; compiler/runtime/JIT behavior is not a live-secret guarantee. |
| Untrusted or composite-factor key creation | accepted-for-synthetic-keys-only | Trusted prime-generation provenance is required; no primality checker or key generator is supplied. |

`Private` ownership prevents implicit reuse of the affine wrapper. Its
`List<&2,U32>` fields remain duplicable data; validation and exponentiation
intentionally retain temporary copies. Callers can explicitly construct
another owner from such data. Returning `None` consumes/drops the supplied
owner and temporaries semantically; it does not clear registers, stacks,
heaps, GC copies, swap, crash dumps, or other aliases. Never interpret an
affine type as a physical secret-storage or erasure guarantee.

## Independent evidence

The frozen `rsa_private_fixture.json` contains **public synthetic private
keys**, generated from Python `cryptography` 50.0.2 prime factors, plus
independently verified PSS signatures. Widths are 2048, 2049, 3072 and 4096
bits, with public exponents 65537 and 3. The exact 2049-bit key is composed
from independently generated 1025/1024-bit prime factors and validated by
`cryptography`; this host rounds an odd key-generation size request down,
as the earlier RSA_REVIEW.md also records. The failed direct odd-size
fixture-generation call is retained, and no unverified fixture was written. Generation scripts and command receipts live under
`~/.codex/artifacts/grounds/2026-10-23/m2/rsa/`. The gate uses only Python
stdlib plus OpenSSL 3 as an external verifier. It has no installed
`cryptography` dependency and Grounds never invokes an external crypto
implementation.

`rsa_private_check.py` checks arithmetic against Python integers, key/range
rejections, exact RFC 8017 PSS encoding plus Python private exponentiation,
and OpenSSL PSS verification. Test sections are `arithmetic`, `keys`, `sign`,
and `reject`; each complete case can be independently guarded using
`--case-index`, and `--phase-prefix` declares resource phases without dropping
cases. The production signer performs the public fault check; the CLI checks
every released signature with the existing Bend verifier before emitting it.

Published specification/design references: [RFC 8017 §§5.1.2, 8.1, 9.1](https://www.rfc-editor.org/rfc/rfc8017)
(CRT RSASP1, PSS and MGF1), [RFC 9846 §§4.3.3, 4.5.2](https://www.rfc-editor.org/rfc/rfc9846)
(TLS signature-scheme binding; successor of RFC 8446 §§4.2.3, 4.4.3), and the repository's existing base-2^15
Montgomery implementation (`rsa_integer.bend`, HAC algorithm 14.36). No
external library code was linked or called by Grounds; no external source
implementation was ported for this module.

## Final focused receipt

All source/CLI/fixture inputs were frozen for the final runs. Bend **2.0.38**,
Bun **1.3.14**, Apple Clang **21.0.0** (arm64), Python **3.13.12**, OpenSSL
**3.6.3**, and the unchanged aggregate/individual **4096 MiB / 120 s** guard
were used. The CLI frontend and all **13 proof declarations** pass; proofs
take 13.000 s. Native compilation peaks at 831.4 MiB and takes 15.619 s.

| Complete corpus section | Native cases / seconds | Bun cases / seconds |
|---|---:|---:|
| Arithmetic, including fixed-loop subtraction | 63 / 0.661 | 63 / 3.095 |
| Key validation and malformed keys | 45 / 0.227 | 45 / 3.142 |
| PSS signing and all independent verifiers | 9 / 1.771 | 9 / 10.520 |
| Entropy/input/key rejection | 28 / 0.305 | 28 / 3.766 |
| **Total per target** | **145** | **145** |

Every one of the nine successful signing cases on each target agrees with
independent RFC 8017 encoding/Python exponentiation, passes OpenSSL PSS
verification, and is accepted by the existing Bend verifier. The 2049-bit
case exercises `emLen < k`. Zero cases were removed or skipped. These are
focused component results; full crypto/wire/root acceptance is recorded by
the parent milestone ledger.

Final generated inputs inspected (SHA-256):

- `~/.codex/artifacts/grounds/2026-10-23/m2/rsa/rsa_private_cli-final.c`:
  `9cf3ca53965ce20ae0c33f88d521b5ed564c502e747450b427872741bbb08fdd`.
- `~/.codex/artifacts/grounds/2026-10-23/m2/rsa/rsa_private_cli-final.js`:
  `012d0884032a597e79e903b01224d633a8c8c930a5292924a926941ef7215731`.

In final C, `FID_rsa_private_power_bytes` at line 13879 always calls the square
and masked multiply/select paths for each bit; `FID_rsa_private_minus_small_go`
at line 15641 branches on its loop count, with no borrow-zero early return.
`FID_rsa_integer_compare_go` at line 11153 remains value-dependent. In final JS,
`rsa_private_power_bits` at line 12593 and `power_selected` at line 13347 retain
the masked schedule; `minus_small_go` at line 12072 has no borrow branch.
`rsa_integer_byte_bits_go` at line 12299 and `compare_go` at line 12924 remain
observable, while `rsa_encoding_equal_go` at line 12712 accumulates all byte
differences. This inspection does not prove constant-time machine execution.

`m2/rsa/receipt.json` records all source/generated hashes and report paths;
`m2/rsa/{native,bun}-{arithmetic,keys,sign,reject}.json` holds complete case
counts and bindings. `m2/rsa/receipts/` preserves exact commands, guards,
source bindings and failed attempts. Compiler executable hashes and resolved
paths are in the shared `m2/versions.json`; final local metadata is in
`m2/rsa/final-toolchain.json`. The metadata-only failed `bend --version`
probe is retained; the successful retry uses Bend's `bend version` command.
