# Local build resource guard

Run compilation and package/repository checks through `build_guard.py` after
the 2026-10-01 resource incident. The lock is shared across Grounds checkouts.
The guard refuses a second guarded job or an existing same-user Bend process,
sets `MOON_CONCURRENCY=1`, and samples the entire spawned process group every
0.02 seconds. macOS uses `proc_listpids` to avoid spawning `ps` on each sample,
and takes the greater of RSS and `proc_pid_rusage` physical
footprint per process, including compressed memory. Linux measures RSS.
Measurement errors fail closed. A memory cutoff, timeout, interruption or
leftover child kills the owned process group; unrelated processes are untouched.
The default aggregate cutoff is 512 MiB. For Moon, use a 640 MiB aggregate
budget and `--process-memory-mib 512`: every compiler, test or runner process
still has a 512 MiB cutoff, with 128 MiB aggregate headroom for orchestration.
The reports retain both the combined peak and the largest individual process.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/build_guard.py \
  --memory-mib 640 --process-memory-mib 512 --timeout 3600 \
  --report /tmp/grounds-check-resource.json \
  -- moon --concurrency 1 run :check
```

For Bend 2.0.27 recovery builds, use the locally tested Bun runtime settings:

```sh
BUN_OPTIONS=--smol BUN_JSC_forceRAMSize=268435456 \
  PYTHONDONTWRITEBYTECODE=1 python3 tools/build_guard.py \
  --memory-mib 640 --process-memory-mib 512 --timeout 3600 \
  --report /tmp/grounds-crypto-resource.json \
  -- moon --concurrency 1 run crypto:check --force
```

Bend's executable embeds Bun. Standalone executables accept runtime flags
through [BUN_OPTIONS](https://bun.com/docs/bundler/executables#runtime-arguments-via-bun_options);
[`--smol`](https://bun.com/docs/runtime#bun-run---smol) trades throughput for memory usage.
`BUN_JSC_forceRAMSize` supplies a smaller reported RAM size to the GC's
[scheduling heuristic](https://github.com/oven-sh/bun/issues/3628#issuecomment-1633847478).
Neither setting is a memory quota; the separate guard measures the owned
process group and stops it at the sampled cutoff. These settings are local to
the invocation and do not alter the installed compiler or user configuration.

This is a sampled cutoff, not a kernel-enforced allocation quota: a fast
allocation can overshoot between samples. Commands must keep children in their
inherited process group; detached/daemonized jobs are unsupported. It does not
limit other applications or unguarded commands. Keep build and test jobs
sequential and preserve each report. If a build crosses the cutoff, split or
reduce its compilation workload before retrying; do not raise the individual
compiler limit to mask the failure. Standalone recovery builds use the default
512 MiB aggregate cutoff; Moon jobs use the two budgets above.

Verify guard behavior without compiling Bend:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/build_guard_test.py
```

`bend_native.sh source.bend new-output` builds CPU fixtures in two steps:
Bend first emits checked C and exits; clang then compiles with the same C11,
`-O3`, pthread/math and platform-library flags as
[Bend 2.0.27](https://github.com/bendlang/bend/blob/v2.0.27/bend2/main.ts). This releases
the frontend's memory before clang starts. It refuses existing outputs and
GPU programs and publishes a completed executable atomically. Run it under
the resource guard, like other build commands. The crypto check uses this
helper for its native adapters; JS generation and the arithmetic checks remain
unchanged.
