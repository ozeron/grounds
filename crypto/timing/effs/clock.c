// Timing-harness counters. No secret crosses these effects; the argument only
// orders the read after the value it depends on. On Apple silicon the
// per-thread fixed counters give core cycles and instructions retired
// (thread_selfcounts, unprivileged). Elsewhere, and if the call fails,
// cycles fall back to raw nanoseconds and instructions to 0. Values are
// reduced modulo 2^47 (Bend's immediate Nat bound). Run with
// BENDRTS="--threads 1" so the measured continuation stays on the thread
// that read the counters.
//
// GROUNDS_TIMING_DIT=1 sets PSTATE.DIT (Arm data-independent timing) on the
// measuring thread at the first read, and GROUNDS_TIMING_DIT_REPORT prints
// the DIT bit to stderr: an experiment for the runtime ask in
// TIMING_REVIEW.md, not something the server does today.
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#ifdef __APPLE__
extern int thread_selfcounts(int type, void* buf, size_t nbytes);
#endif
static void grounds_timing_dit(void) {
#if defined(__aarch64__)
  static int done = 0;
  if (done) return;
  done = 1;
  const char* want = getenv("GROUNDS_TIMING_DIT");
  if (want != NULL && want[0] == '1') {
    __asm__ volatile(".inst 0xd503415f" ::: "memory");  // msr DIT, #1
  }
  if (getenv("GROUNDS_TIMING_DIT_REPORT") != NULL) {
    uint64_t v;
    __asm__ volatile("mrs %0, s3_3_c4_c2_5" : "=r"(v));  // mrs DIT
    fprintf(stderr, "DIT=%d\n", (int)((v >> 24) & 1));
  }
#endif
}
static uint64_t grounds_timing_read(int which) {
  const uint64_t m = (1ull << 47) - 1;
  grounds_timing_dit();
#ifdef __APPLE__
  uint64_t c[2] = {0, 0};
  if (thread_selfcounts(1, c, sizeof c) == 0) {
    return (which ? c[0] : c[1]) & m;
  }
  return which ? 0 : clock_gettime_nsec_np(CLOCK_UPTIME_RAW) & m;
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  return which ? 0 : ((uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec) & m;
#endif
}
static Term grounds_timing_cycles_run(Env e, Term* f, IoWork* w) {
  return (Term)grounds_timing_read(0);
}
static Term grounds_timing_instructions_run(Env e, Term* f, IoWork* w) {
  return (Term)grounds_timing_read(1);
}
static void __attribute__((constructor)) grounds_timing_use(void) {
  io_eff(CID(grounds_timing_cycles), grounds_timing_cycles_run);
  io_eff(CID(grounds_timing_instructions), grounds_timing_instructions_run);
}
