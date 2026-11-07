# HTTP client build memory

The guard is unchanged: 4096 MiB per phase, aggregate and per process, and
120 s. The target is a compile-phase peak of at most 3.3 GiB, which leaves
about 20% headroom. The runtime memory of the client is small (10–100 MiB).
This note covers the Bend 2.0.38 compiler only.

## Diagnosis (2026-11-07)

Before the fix, the root and package gates on macwork (Apple M4 Pro, 24 GiB)
peaked as follows.

| Phase | Peak |
| --- | --- |
| `http_client/bend_public_frontend` | 4009 MiB |
| `http_client/bend_frontend_native` | 4007 MiB |
| `http_client/bend_public_chain_build` | 3869 MiB |
| `http_client/bend_bundle_build` | 3717 MiB |
| `crypto/native/build/pem_bundle_cli` | 3238 MiB |

The HTTP server frontends peak at about 1.8 GiB. `x509_chain_cli`, which
imports more of the X.509 code than `pem_bundle_cli`, peaks at only 528 MiB.

The checker stage dominates. `bend crypto/pem_bundle_cli.bend --check-only`
alone peaked at 3039 MiB. The full `-o .c` build peaked at 3138 MiB.

To find the cause, a copy of the v2.0.38 checker was instrumented to log time
and RSS per definition (`book_valid` → `def_check`). Every client entry has
the same two outliers, both in `crypto/pem_bundle.bend`, which
`bend_transport.bend` imports:

| Definition | Check time | RSS growth |
| --- | --- | --- |
| `pem_bundle:body.line` | 1.3–3.1 s | ~700–790 MiB |
| `pem_bundle:start.line` | 0.7–1.9 s | ~460–500 MiB |
| next largest (`pem:header`) | — | ≤ 96 MiB |

Both definitions matched a line against a string-literal pattern
(`"-----END CERTIFICATE-----"`, `"-----BEGIN CERTIFICATE-----"`). Each also had
a large default row that threads a linear continuation.

In 2.0.38, `parse_patt` fully unfolds a literal pattern through `lit_step`. A
string becomes `SCon`, `Chr` and `U32`, and every `U32` becomes 32 `WCon`/bit
constructors. `match_flatten` then copies the remaining rows into a
fall-through branch at each constructor level. A 25–27 character delimiter
therefore turns into roughly 1,800 nested matches, each with its own copy of
the default branch, and every copy is checked. `pem:header` has five such
literals, but its default is `Fail{Malformed{}}`, so it stays cheap.

## Fix

Commit `2bd395d` makes `crypto/pem_bundle.bend` compare the two delimiters
with `String.eq`. The comparison sits in a one-line helper, and the old match
bodies move into helpers that match on the `Bool`. The admitted and rejected
lines are the same, and the bounds and errors are unchanged. No guard, test,
entry program or compiler setting changed.

The same commands, with the guard raised to 9000 MiB for measurement only,
gave these peaks:

| Phase | Before | After |
| --- | --- | --- |
| `pem_bundle_cli` native build | 3238 | 736 |
| `bend_bundle_build` | 3717 | 1276 |
| `bend_frontend_native` | 3950–4045 | 1727 |
| `bend_public_chain_build` | 3869 | 1286 |
| `bend_public_frontend` (the public client users build) | 4009 | 1458 |

The figures from the gates themselves are in STACK_PROGRESS.md (2026-11-07,
M6). The public client entry, `examples/public_https.bend`, compiles well
under target without changes, so no entry needed to be split.

## Guidance and upstream note

In Bend 2.0.38, a string or `U32` literal pattern costs work proportional to
the size of the literal's whole constructor tree, multiplied by the size of
the default rows. Hot modules that every program imports should compare
long literals with `String.eq` or `U32.is_eq` in a helper, especially when the
default branch is large.

Nothing upstream is needed for the target. A worthwhile fix in Bend would be
to compile a literal row as one equality test with one shared default (a
join point) instead of unfolding it bit by bit.
