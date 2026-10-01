#ifndef GROUNDS_RANDOM_FILL
#define GROUNDS_RANDOM_FILL
#include <errno.h>
#include <stddef.h>
#include <sys/types.h>

// OS read completion only. A platform adapter supplies the entropy syscall;
// tests can exercise interruption/short-read behavior without a Linux kernel.
typedef ssize_t (*GwRandomRead)(void*, size_t);
static int gw_random_fill(unsigned char* bytes, size_t count, GwRandomRead read) {
  size_t at = 0;
  unsigned interrupted = 0;
  while (at < count) {
    ssize_t n = read(bytes + at, count - at);
    if (n < 0) {
      int code = errno;
      if (code == EINTR && ++interrupted < 64) continue;
      return code ? code : EIO;
    }
    if (n == 0 || (size_t)n > count - at) return EIO;
    at += (size_t)n;
    interrupted = 0;
  }
  return 0;
}
#endif

#ifdef CID_WIRE_RANDOM_BYTES
#ifdef __linux__
#include <sys/random.h>
static ssize_t gw_random_read(void* bytes, size_t count) {
  // Fail explicitly if the kernel pool is not ready. Never substitute a PRNG.
  return getrandom(bytes, count, GRND_NONBLOCK);
}
#endif

static void gw_random_call(IoWork* w) {
#ifdef __APPLE__
  arc4random_buf(w->data, w->size);
  w->code = 0;
#elif defined(__linux__)
  w->code = gw_random_fill((unsigned char*)w->data, w->size, gw_random_read);
#else
  w->code = ENOSYS;
#endif
}

static Term gw_random_pack(Env e, IoWork* w) {
  Term result = term_pak(CID_NIL, 0);
  if (!w->code) {
    for (size_t i = w->size; i > 0; --i) {
      result = io_node(e, CID_CON, (unsigned char)w->data[i - 1], result);
    }
  }
  // The temporary OS buffer is no longer needed. The returned Bend list still
  // owns its byte values; this does not claim erasure of Bend heap copies.
  volatile unsigned char* bytes = (volatile unsigned char*)w->data;
  for (size_t i = 0; i < w->size; ++i) bytes[i] = 0;
  free(w->data);
  return w->code ? io_fail(e, w->code, NULL) : io_done(e, result);
}

Term gw_random_run(Env e, Term* f, IoWork* w) {
  if (f[0] > 1048576) return io_fail(e, EINVAL, NULL);
  if (f[0] == 0) return io_done(e, term_pak(CID_NIL, 0));
  w->size = (size_t)f[0];
  w->data = malloc(w->size);
  if (!w->data) return io_fail(e, ENOMEM, NULL);
  return io_work(w, gw_random_call, gw_random_pack);
}

static void __attribute__((constructor)) gw_random_use(void) {
  io_eff(CID_WIRE_RANDOM_BYTES, gw_random_run, 0);
}
#endif
