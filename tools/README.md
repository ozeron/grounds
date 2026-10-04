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
On 2026-10-03 the user requested a 1 GiB RAM limit. Defaults are now
1024 MiB aggregate and 1024 MiB per process, with the existing 120-second
deadline. The aggregate cutoff caps the complete owned process tree, rather
than granting a separate 1 GiB allowance to each child. The aggregate
budget includes compiler, test and runner processes; it is not added per child.
The reports retain both the combined peak and the largest individual process.

On macOS the guard also reads `kern.memorystatus_vm_pressure_level` before
launch and once per second during the job. Warning or critical pressure refuses
the launch (exit 125), or stops an already running owned process group (exit
137), even when that group's memory stays below its cutoff. Read errors and
unknown values fail closed. The sysctl returns dispatch flags, as shown in
[Apple's XNU implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_memorystatus_notify.c);
it is read only. Reports record the last observed level and sample count.
Linux does not currently have this additional system-pressure check; its report
marks that metric unsupported while retaining process-group RSS monitoring.

```sh
PYTHONDONTWRITEBYTECODE=1 nice -n 10 python3 tools/build_guard.py \
  --memory-mib 1024 --process-memory-mib 1024 --timeout 120 \
  --report /tmp/grounds-check-resource.json \
  -- moon --concurrency 1 run :check
```

Recent isolated compiler diagnostics also use `BUN_OPTIONS=--smol`,
`BUN_JSC_forceRAMSize=134217728` and `BUN_JSC_useJIT=false`. These are
invocation-local diagnostic settings. Generated-program tests must record
their own actual runtime configuration; changing JIT settings does not prove
default optimizing-JIT acceptance.

Bend's executable embeds Bun. Standalone executables accept runtime flags
through [BUN_OPTIONS](https://bun.com/docs/bundler/executables#runtime-arguments-via-bun_options);
[`--smol`](https://bun.com/docs/runtime#bun-run---smol) trades throughput for memory usage.
`BUN_JSC_forceRAMSize` supplies a smaller reported RAM size to the GC's
[scheduling heuristic](https://github.com/oven-sh/bun/issues/3628#issuecomment-1633847478).
Neither setting is a memory quota; the separate guard measures the owned
process tree and stops it at the sampled cutoff. These settings are local to
the invocation and do not alter the installed compiler or user configuration.

This is a sampled cutoff, not a kernel-enforced allocation quota: a fast
allocation can overshoot between samples. The guard includes descendants in
separate process groups and retains observed ownership after reparenting, using
process birth identities to exclude reused PIDs. A daemon that detaches and loses
its parent before any sample is unsupported. It does not
limit other applications or unguarded commands. The macOS pressure check can
stop work because of pressure caused by another application; it does not
identify the source of pressure or reset accumulated swap. Keep build and test jobs
sequential and preserve each report. If a build crosses the cutoff, split or
reduce its compilation workload before retrying; do not raise the current
limits without another explicit user request. A timed-out package/repository check remains
incomplete; do not omit cases or raise budgets to produce a passing report.

Verify guard behavior without compiling Bend:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/build_guard_test.py
PYTHONDONTWRITEBYTECODE=1 python3 tools/check_phase_test.py
```

Each small test workload has its own guard and private test lock. An outer guard
can now also monitor the whole test tree, including detached test children.
Darwin enumeration and exit/identity checks use in-process `libproc` metadata
instead of launching the setuid-root `/bin/ps`. Public short BSD metadata
discovers ancestry across UIDs; full identity and memory reads apply only to
owned candidates. Only absent or zombie observations permit zero live memory;
unreadable live processes still fail closed and record identity diagnostics.
Cleanup attempts every independently verified owner even after another read
fails. The ABI follows the installed macOS SDK and
[Apple's proc_info implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/proc_info.c).

For an enumerated package check, `--phases` retains one lock, aggregate memory
monitor and pressure check for the entire Moon process tree. Each ordered phase
has the existing 120-second deadline. Startup, transitions and final cleanup
have a ten-second idle bound. Missing, repeated, overlapping, out-of-order or
failed phases fail the run; only explicitly optional phases permit a recorded
skip. A zero child exit cannot hide incomplete phases. Announcements are
acknowledged over a private local socket and use the guard's clock; no heartbeat
or client timestamp extends a deadline. Ordinary jobs still have one total
120-second timeout.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/build_guard.py \
  --phases http/server/check_phases.json --report /tmp/http-server-phases.json \
  -- nice -n 10 moon --concurrency 1 run http_server:check --force
```

The HTTP script preserves all check bodies and arguments, shares its temporary
outputs and stops/waits for each fixture before ending that phase. Its manifest
and announcement helper are Moon cache inputs. A full fresh run must finish the
entire declared sequence; passing a subset does not satisfy the package gate.
Crypto and RTC also declare their complete existing check sequences. Crypto's
long Bun P-256/ECDSA oracles announce the existing batches individually without
reducing their corpora. A combined root manifest is not yet implemented.
Migration alone does not complete a package gate: historical failed runs and
the latest actual check results are in `STACK_PROGRESS.md`.

Evaluators use the current 1 GiB aggregate/process cap, a 120-second deadline
and nice 10. Historical reports retain their older explicit budgets. Keep the
full package/repository gates pending when these budgets or system pressure
prevent verification. Do not present a different Bun JIT configuration as
default optimizing-JIT acceptance; record the actual runtime flags and failed
attempts with the results.

Compiler upgrades must cover consumers of the changed runtime interfaces:
program-name handling in `IO.args`, explicit socket bind addresses, namespaced
effect IDs/JS registration and native parked deadlines. Verify actual Bun
binary versions with `--version`; a mise directory label may differ from the
binary inside it. For a generated JS program, Bun consumes its own `--`
delimiter before Bend sees arguments. Supply that host delimiter separately
when checking Bend's delimiter and literal runtime-option names. Record the
exact launch command and retain the failing invocation as evidence.

The current isolated 2.0.34 compatibility draft and remaining validation gates
are referenced in `STACK_PROGRESS.md`. A successful focused arithmetic or
socket fixture does not justify changing the repository pin or marking a
package/repository check complete. Keep unsuccessful printer experiments out
of the draft; preserve all RNG sizes and the original output contract while
investigating the large-byte-list allocation gate.

`bend_native.sh source.bend new-output` builds CPU fixtures in two steps:
Bend first emits checked C and exits; clang then compiles with the same C11,
`-O3`, pthread/math and platform-library flags as
[Bend 2.0.27](https://github.com/bendlang/bend/blob/v2.0.27/bend2/main.ts). This releases
the frontend's memory before clang starts. It refuses existing outputs and
GPU programs and publishes a completed executable atomically. Run it under
the resource guard, like other build commands. The crypto check uses this
helper for its native adapters; JS generation and the arithmetic checks remain
unchanged.

For CPU C files of at least 4 MiB, the helper uses `bend_native_parts.py`
to compile separate translation units sequentially without LTO. It preserves
each generated segment body, signature and calling-convention attribute.
The allocator, other mutable runtime globals and dispatch table have one
definition. Unknown layouts, unexpected code between segments, local static
storage in the shared prefix and device backends fail explicitly. Function-local
storage in the runtime suffix stays in its single owner. Objective-C builds retain the
original monolithic compiler path. The splitter records source/body hashes
and compiler commands in its build directory; `bend_native.sh` removes that
temporary directory after publication. The signaling builder retains its C
and `.parts` directory beside the new output for inspection.

Run the splitter's storage, cross-unit direct/dynamic calls and atomic output
publication regressions with `python3 tools/bend_native_parts_test.py` under
the guard. Splitting addresses Clang's memory footprint; it does not resolve
Bend frontend resource failures or certify generated-code timing safety.
