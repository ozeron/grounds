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

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/build_guard.py \
  --memory-mib 512 --timeout 3600 --report /tmp/grounds-check-resource.json \
  -- moon --concurrency 1 run :check
```

This is a sampled cutoff, not a kernel-enforced allocation quota: a fast
allocation can overshoot between samples. Commands must keep children in their
inherited process group; detached/daemonized jobs are unsupported. It does not
limit other applications or unguarded commands. Keep build and test jobs
sequential and preserve each report. If a build crosses the cutoff, split or
reduce its compilation workload before retrying; do not raise the limit to
mask the failure. The default cutoff is 512 MiB; keep recovery builds at that
cutoff.

Verify guard behavior without compiling Bend:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/build_guard_test.py
```
