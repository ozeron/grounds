// Native cookie signatures: HMAC-SHA256 through OpenSSL 3, loaded at run
// time, and constant-time comparison of well-formed 32-byte MACs.

#if defined(CID_SIGN) || defined(CID_VERIFY)
#ifndef GROUNDS_COOKIE_CRYPTO
#define GROUNDS_COOKIE_CRYPTO

#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  int state;
  const void* (*sha256)(void);
  unsigned char* (*hmac)(const void*, const void*, int, const unsigned char*, size_t, unsigned char*, unsigned int*);
  int (*memcmp)(const void*, const void*, size_t);
} CookieCrypto;

static CookieCrypto ck_crypto;

static void* ck_open(void) {
  const char* paths[] = { getenv("BEND_LIBCRYPTO"),
    "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib",
    "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib", "libcrypto.3.dylib", "libcrypto.so.3" };
  for (u64 i = 0; i < sizeof(paths) / sizeof(paths[0]); i += 1) {
    void* h = paths[i] != NULL ? dlopen(paths[i], RTLD_NOW | RTLD_LOCAL) : NULL;
    if (h != NULL) {
      return h;
    }
  }
  return NULL;
}

static bool ck_load(void) {
  if (ck_crypto.state != 0) {
    return ck_crypto.state > 0;
  }
  ck_crypto.state = -1;
  void* h = ck_open();
  if (h == NULL) {
    return false;
  }
  ck_crypto.sha256 = dlsym(h, "EVP_sha256");
  ck_crypto.hmac = dlsym(h, "HMAC");
  ck_crypto.memcmp = dlsym(h, "CRYPTO_memcmp");
  if (ck_crypto.sha256 == NULL || ck_crypto.hmac == NULL || ck_crypto.memcmp == NULL) {
    return false;
  }
  ck_crypto.state = 1;
  return true;
}

static bool ck_mac(const char* key, u64 kn, const char* data, u64 dn, unsigned char out[32]) {
  unsigned int len = 0;
  return kn <= INT_MAX
    && ck_crypto.hmac(ck_crypto.sha256(), key, (int)kn, (const unsigned char*)data,
         (size_t)dn, out, &len) != NULL
    && len == 32;
}

static int ck_unhex(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

#endif
#endif

#ifdef CID_SIGN

Term ck_sign_run(Env e, Term* f, IoWork* w) {
  u64 kn = 0;
  u64 vn = 0;
  char* key = io_cstr(e, f[0], &kn);
  char* value = io_cstr(e, f[1], &vn);
  if (!ck_load()) {
    free(key);
    free(value);
    return io_fail(e, ENOENT, "cookie signing needs OpenSSL 3 (libcrypto.3)");
  }
  if (vn > SIZE_MAX - 65) {
    free(key);
    free(value);
    return io_fail(e, EINVAL, "cookie value is too long");
  }
  unsigned char mac[32];
  if (!ck_mac(key, kn, value, vn, mac)) {
    free(key);
    free(value);
    return io_fail(e, EINVAL, "HMAC-SHA256 failed");
  }
  free(key);
  static const char hex[] = "0123456789abcdef";
  char* out = io_mem(malloc((size_t)vn + 65));
  memcpy(out, value, (size_t)vn);
  free(value);
  out[vn] = '.';
  for (u64 i = 0; i < 32; i += 1) {
    out[vn + 1 + 2 * i] = hex[mac[i] >> 4];
    out[vn + 2 + 2 * i] = hex[mac[i] & 15];
  }
  Term result = io_done(e, io_str(e, out, vn + 65));
  free(out);
  return result;
}

static void __attribute__((constructor)) ck_sign_use(void) {
  io_eff(CID_SIGN, ck_sign_run, 0);
}

#endif

#ifdef CID_VERIFY

Term ck_verify_run(Env e, Term* f, IoWork* w) {
  u64 kn = 0;
  u64 sn = 0;
  char* key = io_cstr(e, f[0], &kn);
  char* signed_value = io_cstr(e, f[1], &sn);
  if (!ck_load()) {
    free(key);
    free(signed_value);
    return io_fail(e, ENOENT, "cookie verification needs OpenSSL 3 (libcrypto.3)");
  }
  if (sn < 65 || signed_value[sn - 65] != '.') {
    free(key);
    free(signed_value);
    return io_done(e, term_pak(CID_NONE, 0));
  }
  unsigned char supplied[32];
  for (u64 i = 0; i < 32; i += 1) {
    int hi = ck_unhex(signed_value[sn - 64 + 2 * i]);
    int lo = ck_unhex(signed_value[sn - 63 + 2 * i]);
    if (hi < 0 || lo < 0) {
      free(key);
      free(signed_value);
      return io_done(e, term_pak(CID_NONE, 0));
    }
    supplied[i] = (unsigned char)((hi << 4) | lo);
  }
  unsigned char actual[32];
  bool ok = ck_mac(key, kn, signed_value, sn - 65, actual);
  free(key);
  if (!ok) {
    free(signed_value);
    return io_fail(e, EINVAL, "HMAC-SHA256 failed");
  }
  Term result = ck_crypto.memcmp(actual, supplied, 32) == 0
    ? io_done(e, io_box(e, CID_SOME, io_str(e, signed_value, sn - 65)))
    : io_done(e, term_pak(CID_NONE, 0));
  free(signed_value);
  return result;
}

static void __attribute__((constructor)) ck_verify_use(void) {
  io_eff(CID_VERIFY, ck_verify_run, 0);
}

#endif
