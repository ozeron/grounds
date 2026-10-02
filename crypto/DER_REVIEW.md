# Certificate DER framing prerequisite

`der.bend` provides bounded TLV framing in Bend for the upcoming certificate
schema owner. It does not validate a complete ASN.1 value or certificate.

`decode(bytes)` admits valid octets and at most 65,535 input bytes. It returns
`Maybe<Element>` containing `tag`, `body`, `rest` and `encoded`: the exact
consumed prefix, including the received header. It consumes one element; the
remaining bytes need not themselves be valid DER. `complete(tag, bytes)` returns
only the body and requires the requested tag and no trailing bytes. Internal
`read` expects previously admitted octets; schema owners must use the public
admission boundary before reading nested bodies.

Supported tags use one octet. End-of-contents and high-tag-number encodings are
rejected. Lengths use short form or one/two long-form octets. Indefinite lengths,
long-form aliases below 128, leading-zero lengths and truncated headers/bodies
are rejected. A maximum-width four-octet header leaves at most 65,531 content
bytes under the total-input bound. No untrusted count controls unbounded
allocation: body extraction uses decreasing fuel bounded by those lengths and
also stops at end of input. Body/encoding copies remain ordinary public byte
lists; this is not a packed-storage or allocation-performance approval.

Schema owners still need primitive-value validation, field order, nesting,
SET ordering, defaults, OIDs, BIT STRING padding, integer canonicality and
certificate-specific constraints. A successfully framed certificate or SPKI
does not establish valid key bits, a valid signature, trust or a valid hostname.

The length rules follow [ITU-T X.690 (2021), sections 8.1.3 and 10.1](https://www.itu.int/rec/T-REC-X.690-202102-I/en),
reviewed on 2026-10-02. Eight closed checks cover non-byte input, indefinite/
nonminimal/truncated framing, exact consumed bytes, complete-body extraction,
wrong tags and trailing-byte rejection. Fresh native and Bun evaluators each
pass 1,552 independent byte-slicing oracle cases: all length-octet values and
single-octet tags, length boundaries through the input cap, every truncation of
three fixtures, header/content bit changes, seeded round trips/rest preservation,
and four independent OpenSSL certificates and their SPKIs. These public fixtures
include RSA/v1.5, RSA/PSS, restricted PSS and P-256/ECDSA, but only their outer
framing is tested here. Temporary private peer keys were removed.

Standalone final compilation peaks at 178.8 MiB under sampled 384 MiB aggregate
/ 320 MiB individual cutoffs. Native evaluation peaks at 35.2 MiB; Bun at
105.3 MiB aggregate / 79.6 MiB individual under 128/96 MiB cutoffs. Large inputs
run individually after the original batched Bun diagnostics crossed the
individual cutoff; every case remains. All jobs are sequential, nice 10, with
120-second outer deadlines and normal macOS pressure observations. Cutoffs are
sampled and can overshoot; they are not kernel allocation quotas. Bun 1.3.13
uses invocation-local `--smol` / `BUN_JSC_forceRAMSize=67108864` during the passing
matrix; the compiler uses the 134217728 setting. Bend 2.0.27, Python 3.12.8,
Apple clang 21 and OpenSSL 3.6.4 are used.

Evidence: `/Users/ozeron/.codex/artifacts/grounds/2026-10-02/x509-algorithm/`,
including `evidence.json`, `der-final-build.log`, `der-native.json`,
`der-bun.json`, fresh primary checks, public fixtures, retained C/JS and resource
reports. That checkpoint's unverified algorithm draft crossed the compiler
cutoff. A later standalone compiler workaround and both-target verification
support the now-adopted [algorithm admission module](X509_ALGORITHM_REVIEW.md);
its separate evidence is in `../x509-admission/` beside this artifact root.
Complete crypto/repository gates remain stopped after the memory complaint;
the full stack is unfinished.
