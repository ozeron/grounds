# Certificate civil-time validation

`x509_validity.decode_time(bytes)` admits one exact DER UTCTime or
GeneralizedTime and returns integral civil UTC seconds since
`0001-01-01T00:00:00Z`. `decode(bytes)` admits one Validity SEQUENCE containing
exactly two such times and returns `Validity{not_before, not_after}` only when
the interval is ordered. `valid_at(bytes, now)` checks both inclusive endpoints.
Malformed input returns `None` or `False`; original signed bytes are unchanged.
The decoded-record helpers assume admitted public records.

Times require ASCII decimal digits, complete seconds and a final uppercase Z.
Calendar admission uses the proleptic Gregorian calendar, years 1–9999, real
month/day bounds, century/400-year leap rules, hours 0–23 and minutes/seconds
0–59. Year zero, offsets, fractions, omitted seconds, wrong/constructed tags,
trailing data and malformed/nonminimal DER are rejected. UTCTime maps 50–99 to
1950–1999 and 00–49 to 2000–2049. GeneralizedTime parsing also admits earlier
years; CA issuance-profile checks belong to the future policy owner.
The maximum timestamp is 315,537,897,599; Nat arithmetic keeps seconds beyond
32 bits exact. DER retains its 65,535-byte input limit. Leap-second encodings
are unsupported, rather than normalized into another civil time.

The caller supplies a trusted civil UTC clock. `IO.now` is monotonic and must
not be supplied here. For post-1970 Unix seconds, the epoch offset is
62,135,596,800 seconds; the host clock effect and its conversion/uncertainty
policy still need integration. No implicit clock skew allowance is applied.
The fixture CLI parses an explicit encoded reference time and can extract a
certificate's existing validity field before applying this owner. It performs
no signature, issuer selection, Name/extension, chain/trust/hostname or handshake
decision. The signature module continues to report mathematical validity only.

The time rules and published examples were inspected on 2026-10-02 in
[RFC 5280 §4.1.2.5 and Appendix C](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.5).
The fresh official errata fetch failed. The retained 2026-10-02 snapshot was
re-inspected: its six verified records concern EKU, path processing, operational
protocols, policies and Name processing, and do not revise these time rules.
Its exact hash is recorded in `evidence.json`. Broader current RFC 5280 updates
and errata remain requirements for the pending semantic/path owners.

Native and normal-JIT Bun each pass 31,545 independent Python-datetime cases
and four CLI error checks. Coverage includes Appendix C's three certificate
validity examples, the year-9999 expiry sentinel, February 29 and the final
second of every year 1–9999, every UTCTime year, month/day grids across leap
centuries, all octet substitutions in representative time bodies, every tag and
truncation, clock ranges and DER/time aliases, randomized ordered/reversed
intervals, inclusive edges/equal endpoints, mixed 2049/2050 encoding, field
count/tag/shape, input bounds, and eight frozen OpenSSL certificate fields.
The previously signed invalid-time-content certificate fails this time owner;
its mathematical signature still succeeds. No peer keys or fixtures change.

Native/Bun matrices take 5.823/17.586s, peak 30.0/64.0 MiB aggregate (Bun
individual 39.1 MiB). A fresh primary-source native repeat using the retained
executable takes 5.520s, peak 28.5 MiB; all 11 input hashes match. Four closed
epoch/calendar/input-admission checks pass compiler checking at 74.9 MiB;
BendTT `--verdict` validation was not run. An earlier closed proof file with
large timestamp cases reported compiler stack overflow at 87.1 MiB. That
failure is retained; runtime upper-bound cases pass on both targets. Earlier
32-bit literal and forward-definition errors are also retained as failures.

Official unmodified Bend 2.0.34 C/JS generation plus Apple clang 21 `-O3` passes
in 12.057s, peak 174.0/172.0 MiB aggregate/individual. All 74 extracted compiler
files still match the previously verified release archive; provenance is shared
with the [signature milestone](X509_SIGNATURE_REVIEW.md). The repository remains
pinned to 2.0.27 and its broader upgrade/compatibility checks remain pending.
The explicit fixture command supports both IO.args conventions. Versions are
Bun 1.3.13 and Python 3.12.8; existing OpenSSL 3.6.4 public fixtures are reused.

Every job is sequential, nice 10, with a 120-second deadline, sampled 384/320
MiB compiler or 128/96 MiB evaluator/provenance cutoffs, and normal pressure
samples. Compiler environment is `BEND_NO_TELEMETRY=1 BUN_OPTIONS=--smol
BUN_JSC_forceRAMSize=134217728 BUN_JSC_useJIT=false`; generated Bun uses normal
JIT with `BUN_OPTIONS=--smol BUN_JSC_forceRAMSize=67108864`. These GC hints and
sampled cutoffs are not OS allocation quotas. Full-stack builds remain stopped.

Exact commands, generated targets, source hashes, successful/failed reports
and `evidence.json` are in
`/Users/ozeron/.codex/artifacts/grounds/2026-10-02/x509-validity/`.
`build.sh` resolves the scoped compiler and native build; the checker command is
`python3 crypto/x509_validity_check.py --report <report> -- <native|bun js>`,
inside `tools/build_guard.py` with the stated environment and cutoffs.
`check.sh` preserves all 138 prior lines and adds five commands. Full forced
crypto, repository and browser gates remain pending; no stack box closes.
