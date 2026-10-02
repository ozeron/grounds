# Experimental RSA signature encoding

`rsa_encoding.bend` implements SHA-256 MGF1, EMSA-PSS encoding/admission and
EMSA-PKCS1-v1_5 encoding/admission in Bend. It is a component of the required
RSA signature path. `rsa_integer.bend` now supplies the public RSA primitive.
RSA signing/verification as a complete scheme, TLS
certificate handling and live-secret approval remain incomplete.

## Interface and boundaries

| Call | Inputs | Result and limits |
|---|---|---|
| `mgf1(length, seed)` | Valid byte list; counts are bytes | `Maybe` byte list; seed/output each at most 512 bytes |
| `pss_encode_digest(emBits, digest, salt)` | 32-byte SHA-256 digest and 32-byte salt | `Maybe` encoded representative; 521–4096 encoded bits |
| `pss_verify_digest(emBits, digest, encoded)` | Exact representative width and valid bytes | `Bool`; SHA-256/MGF1-SHA-256, exactly 32 salt bytes |
| `v15_encode_digest(length, digest)` | Encoded length and 32-byte SHA-256 digest | `Maybe` representative; 62–512 bytes, at least eight FF padding bytes |
| `v15_verify_digest(digest, encoded)` | Valid bytes and 32-byte SHA-256 digest | `Bool`; exact canonical SHA-256 DER DigestInfo with NULL parameters |

The encoding functions do not accept messages or signatures. The PSS caller supplies
`emBits = modulusBits - 1`; it must generate a fresh salt using a trusted RNG.
The v1.5 verifier derives its expected padding width from the supplied encoded
representative. `rsa_integer.public_operation` enforces public parameter
admission, signature width and representative range; future scheme/key owners
still need full parameter validation and protocol policy. The 521-bit minimum is a padding
boundary, not permission to use a 522-bit RSA key in TLS.

MGF1 emits SHA-256(seed || four-byte big-endian counter) blocks and truncates
the last block. PSS enforces the unused high bits, exact trailer, zero PS,
delimiter, fixed salt length and full recomputed hash. v1.5 compares the entire
canonical encoding and rejects absent NULL/BER alternatives. Length checks
precede count arithmetic; a closed check supplies Bend's maximum Nat count.

## Standards and independent evidence

The implementation follows [RFC 8017 sections 9.1, 9.2 and B.2.1](https://www.rfc-editor.org/rfc/rfc8017.html).
The chosen PSS profile matches SHA-256's digest/MGF/salt requirements in
[RFC 9846 section 4.3.3](https://datatracker.ietf.org/doc/html/rfc9846#section-4.3.3).
The official RFC 8017 errata refresh succeeded on 2026-10-02. Verified items
5111, 5154, 5235, 5577 and 7405 do not change this SHA-256 encoding; they correct
scheme terminology, a SHA-224 label and editorial notation/references.
The official RFC 9846 errata page downloaded on 2026-10-02 lists five Reported
items, no Verified items. Source snapshots and fetch evidence are retained in
the artifact directory named below.

Eleven closed Bend checks cover non-byte digest/salt/representative/seed input,
maximum Nat overflow admission and minimum padding widths. The native and Bun
oracle each executes 1,582 cases:

- 79 MGF1 counter/truncation/size cases.
- 972 PSS boundary, malformed, every-byte/digest tampering, PS/delimiter,
  trailer, high-bit, salt-profile and wrong-MGF-hash cases.
- 351 v1.5 padding, canonical DigestInfo, malformed and every-byte cases.
- 150 published representative-encoding checks from NIST vectors.
- 30 OpenSSL peer encoding/profile checks.

The [official NIST RSA archive](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3rsatestvectors.zip)
was downloaded successfully, SHA-256
`8405aeb3572a4f98ed4b1a3ccb3f2f49e725462dd28ec4759d6a15d88855d19c`.
`rsa_encoding_vectors.json` records every selected row and its source line,
including published SHA-256 PSS salt profiles that the selected TLS profile
rejects. Two SHA-256 rows are individually excluded: an odd-nibble message
outside the digest API and an out-of-range signature requiring RSA primitive
admission. They are not reported as successful signature verification.

Python bigint exponentiation recovers representatives only in the independent
oracle. OpenSSL produces peer signatures; neither is used by the Bend module
or fixture evaluator. The checker records actual modulus sizes rather than
assuming requested key sizes: this OpenSSL rounds a 2049-bit request to 2048.
Actual peers cover 2048, 2050, 3072 and 4096 bits. These tests establish encoding
behavior only; they cannot establish Grounds RSA exponentiation or TLS interop.

Artifacts, prepared vectors and extraction script:
`/Users/ozeron/.codex/artifacts/grounds/2026-10-02/rsa-encoding/`.
The complete crypto package and repository gates remain outstanding after the
memory complaint. Focused results do not accept those larger gates.

## Runtime review and remaining implementation

The byte comparator accumulates every byte difference before deciding equality.
PSS structural validation has early exits on public encoded input. MGF1 bounds
its loop by the public output length. This source inspection does not prove
generated-code constant-time behavior or secure erasure. No private key is
handled by this component; supplied salt/digest lists may still be copied by
the generated runtime. Synthetic fixtures only until the complete review passes.

Next finish native/Bun verification of the public PSS/v1.5 scheme owner, then
implement RSASP1 with private-key admission. Private operations need blinding, fault checks, key ownership/retirement and
generated-code review. Certificate AlgorithmIdentifiers must bind hash/MGF/salt,
SPKI restrictions, trust and hostname policy before handshake integration.
All required native/Bun vectors, malformed cases and independent full-signature
interop still apply to those future owners.

## Public RSA integer primitive

`rsa_integer.public_operation(modulus, exponent, signature)` implements
[RFC 8017 RSAVP1](https://www.rfc-editor.org/rfc/rfc8017.html#section-5.2.2)
in Bend, returning `Maybe` of exactly `k` big-endian bytes. Moduli must be
canonical unsigned byte strings representing odd 2048–4096-bit integers.
The public exponent must be canonical, odd, greater than one and below the
modulus. Signature bytes must be valid, exactly `k` bytes and represent a value
below the modulus. Zero signature representatives are permitted by the
primitive; the signature encoding layer determines whether the recovered value
is admissible. Leading zeros in fixed-width signatures are permitted; aliases
of the modulus/exponent are rejected.

This assumes a valid RSA public key; parity/size/range admission cannot prove
the modulus's factor structure or its relationship to the exponent. Public
exponents are scanned as byte strings, without U32 truncation. Published cases
cover 21–24-bit exponents, synthetic cases include 65537/U32 maximum and a
65-bit exponent. Exponents approaching the modulus's full bit length have not
been benchmarked or accepted as an integrated handshake performance gate.

Integers use 15-bit little-endian limbs in affine 512-cell U32 arrays, at most
274 limbs plus two carry cells. Coarsely integrated Montgomery multiplication
follows [HAC algorithm 14.36](https://cacr.uwaterloo.ca/hac/about/chap14.pdf).
Every inner sum is at most `32767^2 + 2*32767 = 2^30-1`; cancellation preserves
both high carry cells before division by the radix. A final biased subtraction
and 0/32767 masks select the canonical result. Four Newton steps compute the
negative low-limb inverse modulo 32768. R-squared setup starts at the public
modulus's highest power of two, avoiding its initial trivial doublings.

The public exponent controls multiply branches. This is explicitly a public
operation; it must not be used as private exponentiation. Arrays are threaded
through owned states; public operand clones are explicit. Fixed limb loops
and masked subtraction alone do not prove generated-code timing safety or
erasure. Those findings remain unresolved for live private-key use.

The exact adopted arithmetic/CLI/checker sources passed 725 independent cases
on native and Bun: byte conversion 58, negative inverses 155, Montgomery
products 285, R-squared contexts 57, public powers 39, published RSAVP1
representatives 110 and parameter/width/range admission 21. Tests span limb
boundaries through 4096 bits and preserve independently recovered NIST values;
both outputs are computed by Bend. Eleven closed checks additionally cover
small arithmetic witnesses and malformed-byte/key/range admission. Full
PSS/v1.5 signature scheme acceptance on both targets and private RSA acceptance
still remain outstanding.

Artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/rsa-integer/`.
Native/Bun matrices took 1.133s/69.129s and peaked at 24.5/83.2 MiB respectively.
Native/JS compilation peaked at 238.6/167.7 MiB. All jobs were sequential,
guarded, nice 10, with a 120-second deadline; compilation/Bun caps were
384 MiB aggregate / 320 MiB individual. All observed system pressure was normal.

## Full digest-signature verification checkpoint

`rsa_signature256.verify_pss_digest(n, e, digest, signature)` and
`verify_v15_digest(n, e, digest, signature)` perform public exponentiation and
strict SHA-256 encoding verification entirely in Bend. Invalid digest byte
values or lengths return `False` before public exponentiation. Public key and
signature admission delegates to `rsa_integer.public_operation`; verification
does not reduce or truncate signature aliases. These APIs assume a valid RSA
key and a protocol owner that selects and binds the algorithm profile.

[RFC 8017 section 8.1.2](https://www.rfc-editor.org/rfc/rfc8017.html#section-8.1.2)
requires PSS's recovered integer to fit exactly `ceil((modBits-1)/8)` bytes.
When `modBits % 8 == 1`, this is one byte shorter than the primitive's `k`-byte
output: the owner rejects a nonzero leading byte before removing it. Otherwise
the complete output is retained, including a valid leading zero. v1.5 checks
the complete `k`-byte canonical SHA-256 encoding with NULL parameters.

The unchanged isolated native executable passes 774 full-signature cases:
110 published NIST signatures, 34 independently prepared OpenSSL peers,
52 parameter/range/key rejection cases and controls, and 289 tampering cases
for each scheme. Every digest byte and every 2048-bit signature byte is
individually changed. Peer keys are actually 2048, 2049, 2050, 3072 and 4096
bits; the exact 2049-bit peer uses OpenSSL-generated primes, independent DER
construction and OpenSSL's private-key check. Tests include the positive
shortened PSS encoding, a below-modulus representative with an illegal nonzero
shortening prefix, a valid full-width zero prefix, wrong MGF/hash/salt profiles,
cross-scheme signatures and noncanonical v1.5 DigestInfo/padding.

The peer generator originally used `pkeyutl -sign` for raw representatives.
OpenSSL's prehashed signing CLI limits input size, so it was corrected to the
peer's no-padding private operation (`-decrypt`); public bigint recovery
independently confirms the exact representative. This is fixture preparation
only. All retained fixtures contain public values; temporary private keys were
deleted. NIST integer hex signatures are converted to exactly `k` bytes,
including published odd-nibble/leading-zero integer representations. The two
previously documented excluded NIST rows remain excluded.

Six closed checks cover required-prefix handling and non-byte digest rejection.
They and native compilation passed before the latest resource inspection.
This continuation reused that binary and started no compiler. The complete
native matrix took 2.593 seconds and peaked at 27.6 MiB under a 128 MiB aggregate
/ 96 MiB individual cutoff and 120-second deadline, nice 10. Peer preparation
peaked at 30.7 MiB; all observed macOS pressure levels were normal. Source hashes
prove adoption preserves the tested module/CLI/checker/fixtures and all 282
Bend source files in the isolated checkout. The checker also passes from the
primary checkout using the existing binary: 774 cases in 2.076 seconds,
peak 27.6 MiB, three normal-pressure observations.

Artifacts: `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/rsa-signature/`,
especially `native-all-fixed.json/log`, its guard report,
`prepare-peers-fixed.log`, `prepare_peers.py`, `adopted-inputs.json` and the
earlier closed/native compilation logs. Bun full-signature verification,
forced crypto/package checks and repository acceptance remain pending; heavy
builds were not restarted after the latest memory inspection. The check script
includes both targets for later verification. No private signing, salt owner,
key retirement, timing/erasure approval, certificate trust or TLS/DTLS interop
is established by this checkpoint.

## Public-power cost and generated-JavaScript review

`rsa_integer_bench.py` measures the precompiled public-power evaluator against
Python bigint recovery. It uses frozen public signature/modulus operands and
tests exponent 65537, a full-width sparse exponent with two set bits, and a
full-width dense exponent `n-2`. The alternate exponents are admitted arithmetic
inputs; their relationship to the peer's private factors is not validated, so
they are not presented as additional valid RSA keys or certificate signatures.
Every recorded invocation returns the independently computed exactly-k-byte
result. Measurements include process startup and fixture file I/O; they are
not isolated operation timings or integrated handshake latency.

| Modulus bits | Exponent | Native seconds, median of 3 | Bun seconds (samples) |
|---|---|---:|---:|
| 2048 | 65537 | 0.004083 | 0.541224 (1) |
| 2048 | full-width sparse | 0.066825 | 11.113214 (1) |
| 2048 | full-width dense | 0.097293 | 16.753540 (1) |
| 3072 | 65537 | 0.005730 | 0.480855 (median of 3) |
| 3072 | full-width sparse | 0.208241 | not run |
| 3072 | full-width dense | 0.316607 | not run |
| 4096 | 65537 | 0.008258 | 0.809546 (median of 3) |
| 4096 | full-width sparse | 0.495538 | not run |
| 4096 | full-width dense | 0.735184 | not run |

This supplies the previously missing native near-modulus-width exponent
evidence and a Bun 2048-bit boundary sample. It does not accept a certificate
owner or handshake performance gate. Larger full-width Bun jobs were not
launched after the 16.75-second sample; their results remain missing. Native
checks peak at 24.7 MiB, Bun at 82.5 MiB. All six jobs run sequentially under
128 MiB aggregate / 96 MiB individual cutoffs, nice 10, with 120-second outer
deadlines and 90-second evaluator deadlines. Every pressure observation is
normal. No compiler runs. Bun is 1.3.13 with invocation-local `--smol` and
`BUN_JSC_forceRAMSize=268435456`. The benchmark repeats range from one to three;
these few samples do not establish statistical or constant-time guarantees.

`rsa-generated-review.json` pins the current source, native evaluator and
previously generated JavaScript hashes and inventories all 66 generated RSA
functions with branch, indexed-access and clone sites. The exponent-bit branch
selects multiplication and an array clone. In the current API that bit is
public; this generated path must not become private exponentiation. The
inspected digit accesses use public counter-derived indices. Inner row sums
stay at most `2^30-1`; biased subtraction stays in 0..65535, and masked final
selection uses 0/32767. These observations concern the inspected sites and
source invariants; native optimized code and Bun JIT/GC remain unapproved.

The generated program allocates ordinary 512-element JavaScript arrays,
`.slice()` copies, tagged intermediate state and trampoline argument objects.
The CIOS right shift creates a fresh zero array for every limb row, and
R-squared setup creates three zero arrays for every modular doubling. For the
sampled dense 4096-bit input, the source operation model counts 6,128 Montgomery
calls and 1,679,072 right-shift arrays. Including setup, canonicalization and
clones gives 878,572,544 logical array slots created. This is a static execution
count, not a measured allocation-byte total or a memory peak. The bounded
resident-memory samples must not be confused with cumulative allocation churn.

An in-place affine right shift and a retained public Montgomery context are
concrete reduction candidates. They are not implemented or accepted by these
measurements. Certificate work also needs bounded verification scheduling and
key/AlgorithmIdentifier admission; changing generic RSA admission merely to
make a benchmark pass is not an approved substitute. The temporary emitted C
was not retained, so a current native source-to-optimized-code map remains
missing. No finding here approves private-key timing or erasure.

Evidence: `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/rsa-signature/`,
`cost-native-{2048,3072,4096}.json/log`, `cost-bun-2048.json/log`,
`cost-bun-{3072,4096}-65537.json/log`, each accompanying guard report and
`rsa-generated-review.json` and `rsa-cost-evidence.json`. The evaluator artifacts and original adoption
hashes are in the neighboring `rsa-integer/` directory. Native/Bun full
signature acceptance, all package/repository gates and the complete stack
contract remain open.
