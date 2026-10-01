#include "effs/random.c"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int scenario, calls;
static unsigned char* origin;
static ssize_t read_fixture(void* buf, size_t count) {
  ++calls;
  if (scenario == 1 || (scenario == 2 && calls == 1)) {
    errno = EINTR;
    return -1;
  }
  if (scenario == 3) return 0;
  if (scenario == 4) { errno = EAGAIN; return -1; }
  if (scenario == 5) return (ssize_t)count + 1;
  if (scenario == 6) { errno = 0; return -1; }
  if (scenario == 7 && calls == 2) { errno = ENOSYS; return -1; }
  size_t n = count < 3 ? count : 3;
  for (size_t i = 0; i < n; ++i) ((unsigned char*)buf)[i] = (unsigned char)(((unsigned char*)buf - origin) + i);
  return (ssize_t)n;
}

int main(void) {
  unsigned char bytes[17];
  origin = bytes;
  calls = 0;
  assert(gw_random_fill(bytes, 0, read_fixture) == 0 && calls == 0);
  const int expected[] = {0, EINTR, 0, EIO, EAGAIN, EIO, EIO, ENOSYS};
  for (scenario = 0; scenario < 8; ++scenario) {
    memset(bytes, 255, sizeof(bytes));
    calls = 0;
    assert(gw_random_fill(bytes, sizeof(bytes), read_fixture) == expected[scenario]);
    if (expected[scenario] == 0) {
      for (size_t i = 0; i < sizeof(bytes); ++i) assert(bytes[i] == i);
      assert(calls == (scenario == 2 ? 7 : 6));
    }
    if (scenario == 1) assert(calls == 64);
    if (scenario == 7) assert(bytes[0] == 0 && bytes[3] == 255);
  }
  puts("RNG OS read completion: nine zero/short/interrupted/error/bound scenarios passed (Linux syscall simulated)");
}
