# Canonical OIDs and certificate extension envelopes

`oid.decode(bytes)` admits one exact primitive DER OBJECT IDENTIFIER and returns
its canonical contents octets. Each base-128 group must terminate and use a
minimal encoding; empty contents and a group beginning with 0x80 are rejected.
Encoded contents retain arbitrarily large arc values without narrowing them to
U32. The first group combines the first two arcs. Internal `contents` assumes
its parent has already admitted octets. Root inputs are limited to octets 0–255
and 65,535 bytes, using the existing DER owner.

`x509_extensions.decode(bytes)` admits one exact nonempty Extensions SEQUENCE.
Each Extension contains a canonical primitive OID, an optional one-octet TRUE
BOOLEAN encoded as FF, and a primitive OCTET STRING, with no other fields.
Omitted critical means FALSE. Explicit FALSE, noncanonical TRUE, constructed
payloads, trailing fields and malformed DER are rejected. `optional(None)`
returns an empty list; a present empty sequence is invalid. Entries preserve
wire order, OID contents, the critical flag and unchanged opaque payload bytes,
including empty payloads.

Duplicate detection uses an affine Base Map with fixed eight-character keys.
FNV-1a selects a bucket; tail-recursive comparisons of the complete canonical
OID bytes decide identity. Hash equality never establishes OID equality.
Buckets retain colliding distinct identifiers, and an exact duplicate fails
even when its critical flag or payload differs. The short map keys avoid Base's
recursive string operations on arbitrarily long OIDs. Collision buckets can
require linear scans; worst-case aggregate comparisons can be quadratic. This
is not an adversarial-work or constant-time guarantee. The parser adds no
extension-count limit below the existing byte bound. Its decoded-record/state
helpers assume admitted records; untrusted input must enter through `decode`
or `optional`. The fixture printer uses tail-recursive field/row accumulation.

This owner checks envelopes, not the DER structure or meaning inside a payload.
Known extension decoding, mandatory-extension policy, CA/key/EKU/SAN/Name
constraints, issuer selection and chain/trust/hostname decisions remain
required. A policy owner must reject unknown or unprocessable critical
extensions; structural success cannot authorize a connection. Callers must
apply this owner to the certificate's optional extension field. Existing
certificate framing and mathematical signature verification retain their
behavior and original signed bytes.

The rules were inspected on 2026-10-02 in
[RFC 5280 §4.2](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2) and
[ITU-T X.690 (02/2021), §§8.19, 10.2, 11.1 and 11.5](https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I!!PDF-E&lang=e&type=items).
X.690's published {2,999,3} value encodes as 06 03 88 37 03. The retained
2026-10-02 RFC 5280 errata snapshot is bound in the evidence manifest; its six
verified records concern EKU, path processing, operational protocols, policies
and Name processing. Current updates and semantic/path errata still need
implementation by those pending owners; this slice claims no full PKIX
conformance.

Native and baseline-JIT Bun each pass 67,731 independent oracle cases and four
CLI errors. The Python reference numerically decodes arbitrary-size OID
subidentifiers, re-encodes them canonically and parses exact extension fields.
Coverage includes every one/two-octet OID, large numeric arcs, all critical
BOOLEAN values, truncations/bit tampering, field count/tag/default/shape errors,
duplicate positions, 128–8,000 distinct extensions, late duplicates, long shared
OID prefixes, exact 65,535/65,536-byte bounds and eight frozen OpenSSL certificate
fields. Distinct `costarring` and `liquid` OID contents share FNV-1a 5e4daa9d;
both orders and exact duplicates exercise the collision buckets. Payload
interpretation and trust are explicitly outside the oracle. No peer fixtures
or keys change.

Native/Bun matrices take 11.205/30.059s and peak at 34.6/112.9 MiB aggregate;
Bun's largest individual process is 76.5 MiB. Six closed OID/default/collision
checks pass compiler checking at 77.4 MiB; BendTT `--verdict` was not run.
The primary-source native repeat takes 9.509s, peak 40.4 MiB, using the
retained executable; all 12 input hashes match both matrices. All 443 prior
code/fixture/script inputs are unchanged except check.sh additions, and all 74
extracted compiler files still match the previously verified official archive. Original native draft results predate the final implementation and
are not used as final-source evidence.

Default optimizing-JIT Bun remains an unresolved resource gate. The original
8,000-entry run crosses the 96 MiB process cutoff; printer changes, a reused
map lookup and a smaller GC hint do not clear it. Admission without printing
also crosses it. With DFG disabled, the first whole matrix exposes a stack
overflow on an 8,192-octet shared OID prefix; fixed keys and exact collision
buckets resolve that failure. The final default-JIT large-input diagnostic
still crosses the cutoff at 4,096 entries. Failed reports and generated/source
snapshots remain retained. The passing complete Bun matrix explicitly uses
`BUN_OPTIONS=--smol BUN_JSC_forceRAMSize=67108864 BUN_JSC_useJIT=true
BUN_JSC_useDFGJIT=false`. It retains baseline JIT and is not default
optimizing-JIT acceptance. The package checker keeps its ordinary Bun command.
JavaScriptCore exposes the DFG switch in its
[option definitions](https://github.com/WebKit/WebKit/blob/main/Source/JavaScriptCore/runtime/OptionsList.h).

Scoped official unmodified Bend 2.0.34 C/JS generation and Apple clang 21 `-O3`
pass at 169.7 MiB aggregate peak. The repository remains pinned to 2.0.27 and
broader compiler compatibility remains pending. Compiler jobs use nice 10,
120 seconds, sampled 384/320 MiB aggregate/individual cutoffs, and
`BEND_NO_TELEMETRY=1 BUN_OPTIONS=--smol BUN_JSC_forceRAMSize=134217728
BUN_JSC_useJIT=false`. Evaluation/provenance jobs use 128/96 MiB and 120 seconds.
Warning pressure refused several jobs before launch; those reports are
preserved. Thirteen guard safety tests passed in 6.852s. No limits or guard
source are changed. Sampled cutoffs can overshoot; GC hints are not OS quotas.

Exact commands, generated targets, source/compiler binding, successful/failed
reports and `evidence.json` are in
`/Users/ozeron/.codex/artifacts/grounds/2026-10-02/x509-extensions/`.
`build.sh` resolves the scoped compiler and native target; the checker command
is `python3 crypto/x509_extensions_check.py --report <report> -- <native|bun js>`
under the resource guard and stated environment. `check.sh` retains all 143
prior lines and adds five commands. Full forced crypto, repository and browser
gates remain pending; no complete-stack acceptance box closes.

Fresh bounded `moon --concurrency 1 run crypto:check --force` is stopped at the
pinned Bend 2.0.27 field256 CPU frontend after 62.383s: exit 137, sampled
386.6/327.7 MiB aggregate/individual. The subsequent `moon --concurrency 1 run
:check` hydrates cached io:check, then stops during crypto after 22.953s:
exit 137, 371.7/327.3 MiB. Both use the same compiler environment above and
384/320 MiB, 120 seconds. Neither is a successful package/repository gate;
cached outputs do not replace fresh acceptance. Reports are `package-resource.json`
and `repository-resource.json`, with retained task logs. Resolve compiler/runtime
resource and compatibility gates before treating the full stack as verified.
