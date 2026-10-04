// CPU ABI fixture: a mutation must survive calls between separate units.
#include <stdint.h>
#include <stdio.h>
typedef uint64_t Term;
typedef uint64_t u64;
typedef uint32_t u32;
typedef struct { u64 unused; } Env;
#define DEVICE 0
#define BEND_METAL 0
#define BEND_CUDA 0
#define BANGS 0
#define PRESERVE(x) __attribute__((x))
#define WL_FN static PRESERVE(preserve_none) __attribute__((noinline)) Term
#define WL_CASE(F) WL_FN WL_##F(WL_SIG)
#define WL_SIG Term r0
#define WL_ALL r0
#define WL_BANK
#define WL_OPEN { WL_BANK u32 rn;
#define WL_JMP(F) __attribute__((musttail)) return WL_##F(WL_ALL)
#define WL_DYN(F) __attribute__((musttail)) return wl_tab[F](WL_ALL)
#define WL_TABLE WL_X(FID_COUNT) WL_X(FID_EXIT)
enum { FID_COUNT, FID_EXIT };
static u64 ALC[1];
static Term f32_show(Env e, Term x);
static Term f32_read(Env e, Term x);
static int corpus_grow(u64* words, u64 need);

// Work
typedef Term (PRESERVE(preserve_none) *WlFn)(WL_SIG);
#define WL_X(F) WL_FN WL_##F(WL_SIG);
WL_TABLE WL_X(FID_ENTER)
#undef WL_X
#define WL_X(F) WL_##F,
static const WlFn wl_tab[] = { WL_TABLE };
#undef WL_X
static Term work_loop(Term r0) {
  return WL_FID_ENTER(WL_ALL);
}

// Segments
  WL_CASE(FID_ENTER)
  {
    WL_OPEN
    ALC[0] = 10;
    WL_JMP(FID_COUNT);
  }}
  WL_CASE(FID_COUNT)
  {
    WL_OPEN
    ALC[0] += 1;
    WL_DYN(FID_EXIT);
  }}
  WL_CASE(FID_EXIT)
  {
    WL_OPEN
    return ALC[0];
  }}
static Term f32_show(Env e, Term x) { return x; }
static Term f32_read(Env e, Term x) { return x; }
static int corpus_grow(u64* words, u64 need) { return 0; }
int main(void) {
  printf("%llu\n", (unsigned long long)work_loop(0));
  return 0;
}
