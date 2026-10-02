# Experimental RSA signature encoding

`rsa_encoding.bend` implements SHA-256 MGF1, EMSA-PSS encoding/admission and
EMSA-PKCS1-v1_5 encoding/admission in Bend. It is a component of the required
RSA signature path. RSA signing/verification as a complete scheme, TLS
certificate handling and live-secret approval remain incomplete.

## Interface and boundaries

| Call | Inputs | Result and limits |
|---|---|---|
| `mgf1(length, seed)` | Valid byte list; counts are bytes | `Maybe` byte list; seed/output each at most 512 bytes |
| `pss_encode_digest(emBits, digest, salt)` | 32-byte SHA-256 digest and 32-byte salt | `Maybe` encoded representative; 521–4096 encoded bits |
| `pss_verify_digest(emBits, digest, encoded)` | Exact representative width and valid bytes | `Bool`; SHA-256/MGF1-SHA-256, exactly 32 salt bytes |
| `v15_encode_digest(length, digest)` | Encoded length and 32-byte SHA-256 digest | `Maybe` representative; 62–512 bytes, at least eight FF padding bytes |
| `v15_verify_digest(digest, encoded)` | Valid bytes and 32-byte SHA-256 digest | `Bool`; exact canonical SHA-256 DER DigestInfo with NULL parameters |

These functions do not accept messages or signatures. The PSS caller supplies
`emBits = modulusBits - 1`; it must generate a fresh salt using a trusted RNG.
The v1.5 verifier derives its expected padding width from the supplied encoded
representative. A future RSA owner must separately enforce the modulus's
signature/representative width, representative range, valid public/private
parameters and protocol key-size policy. The 521-bit minimum is a padding
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

Next implement Bend RSA integer conversion, modular exponentiation and
RSAVP1/RSASP1 with strict primitive admission; connect PSS/v1.5 scheme owners.
Private operations need blinding, fault checks, key ownership/retirement and
generated-code review. Certificate AlgorithmIdentifiers must bind hash/MGF/salt,
SPKI restrictions, trust and hostname policy before handshake integration.
All required native/Bun vectors, malformed cases and independent full-signature
interop still apply to those future owners.
