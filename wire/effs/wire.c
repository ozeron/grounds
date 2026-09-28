// Wire
// ====
// TCP on bytes: a List<U32> of octets in and out, where Base's socket
// effects decode and encode UTF-8. After bend-kit-wire (MIT-0).

#if !defined(GROUNDS_WIRE) && defined(CID_CON)
#define GROUNDS_WIRE

static Term gw_list(Env e, const char* p, u64 n) {
  Term xs = term_pak(CID_NIL, 0);
  for (u64 i = n; i > 0; i -= 1) {
    xs = io_node(e, CID_CON, ((uint8_t*)p)[i - 1], xs);
  }
  return xs;
}

// A value past 255 is not an octet: bad is set, and the send fails.
static char* gw_octets(Env e, Term xs, u64* len, bool* bad) {
  u64   cap = 64;
  u64   n   = 0;
  char* buf = io_mem(malloc(cap));
  *bad = false;
  while (term_aux(xs) == CID_CON) {
    Term fb[2];
    spare_free(e, cls_fit(2), ctr_take(e, xs, 2, fb));
    if (n + 1 > cap) {
      cap *= 2;
      buf = io_mem(realloc(buf, cap));
    }
    *bad = *bad || (u64)fb[0] > 255;
    buf[n++] = (char)(fb[0] & 0xFF);
    xs = fb[1];
  }
  *len = n;
  return buf;
}

// Set when the program links TLS: a socket with a TLS session (a server's
// after wire_tls_accept) moves its bytes through the session, even by the
// plain effects, and wire_close ends the session first.
static void* (*gw_tls_sess)(int) = NULL;
static Term (*gw_tls_recv_hook)(Env, Term*, IoWork*) = NULL;
static Term (*gw_tls_send_hook)(Env, Term*, IoWork*) = NULL;
static void (*gw_tls_end_hook)(int) = NULL;

static bool gw_tls_on(Term sock) {
  return gw_tls_sess != NULL && gw_tls_sess((int)io_hand_v(sock)) != NULL;
}

#endif

#ifdef CID_WIRE_RECV

// The loop parked the request until the socket was readable; a recv that
// still finds nothing (the socket is non-blocking) parks again.
static Term gw_recv_more(Env e, IoWork* w) {
  int     fd = (int)w->hand;
  ssize_t n  = io_sys_end(w, recv(fd, w->data, (size_t)w->made, 0));
  if (w->code == EAGAIN) {
    return io_wait_on(w, fd, POLLIN, 0, gw_recv_more);
  }
  Term r = w->code ? io_fail(e, w->code, NULL) : io_done(e, gw_list(e, w->data, (u64)n));
  free(w->data);
  return io_tup(e, io_hand(w->hand), r);
}

Term gw_recv_run(Env e, Term* f, IoWork* w) {
  w->hand = (intptr_t)io_hand_v(f[0]);
  w->made = f[1] < INT32_MAX ? (intptr_t)f[1] : INT32_MAX;
  w->data = io_mem(malloc((size_t)w->made + 1));
  return gw_recv_more(e, w);
}

static void __attribute__((constructor)) gw_recv_use(void) {
  io_eff(CID_WIRE_RECV, gw_recv_run, IO_READ);
}

#endif

#ifdef CID_WIRE_RECV_TIMEOUT

// wire_recv with a deadline, as Base's TCP.poll: parks on the socket and
// the clock, whichever fires first; None{} past the deadline.
static Term gw_poll_end(Env e, IoWork* w, Term r) {
  free(w->data);
  return io_tup(e, io_hand(w->hand), r);
}

static Term gw_poll_more(Env e, IoWork* w) {
  int     fd = (int)w->hand;
  u64     at = io_wait_time(w);
  ssize_t n  = io_sys_end(w, recv(fd, w->data, (size_t)w->made, 0));
  if (w->code == EAGAIN) {
    return io_tick() < at ? io_wait_on(w, fd, POLLIN, at, gw_poll_more)
      : gw_poll_end(e, w, io_done(e, term_pak(CID_NONE, 0)));
  }
  return gw_poll_end(e, w, w->code ? io_fail(e, w->code, NULL) : io_done(e,
    io_box(e, CID_SOME, gw_list(e, w->data, (u64)n))));
}

Term gw_poll_run(Env e, Term* f, IoWork* w) {
  if (gw_tls_on(f[0]) && gw_tls_recv_hook != NULL) {
    return gw_tls_recv_hook(e, f, w);
  }
  w->hand = (intptr_t)io_hand_v(f[0]);
  w->made = f[1] < INT32_MAX ? (intptr_t)f[1] : INT32_MAX;
  w->data = io_mem(malloc((size_t)w->made + 1));
  return io_wait_on(w, (int)w->hand, POLLIN,
    io_tick() + (u64)f[2] * 1000000ull, gw_poll_more);
}

static void __attribute__((constructor)) gw_poll_use(void) {
  io_eff(CID_WIRE_RECV_TIMEOUT, gw_poll_run, 0);
}

#endif

#ifdef CID_WIRE_SEND

// Sends what is left; a full socket parks until it is writable.
static Term gw_send_more(Env e, IoWork* w) {
  int fd = (int)w->hand;
  while (w->code == 0 && (u64)w->made < w->size) {
    ssize_t n = send(fd, w->data + w->made, w->size - (u64)w->made, 0);
    if (n < 0 && errno == EAGAIN) {
      return io_wait_on(w, fd, POLLOUT, 0, gw_send_more);
    }
    w->made += io_sys_end(w, n);
  }
  Term r = w->code != 0 ? io_fail(e, w->code, NULL) : io_done(e, term_pak(CID_UNIT, 0));
  free(w->data);
  return io_tup(e, io_hand(w->hand), r);
}

Term gw_send_run(Env e, Term* f, IoWork* w) {
  bool bad;
  w->hand = (intptr_t)io_hand_v(f[0]);
  w->data = gw_octets(e, f[1], &w->size, &bad);
  w->made = 0;
  w->code = bad ? EINVAL : 0;
  return gw_send_more(e, w);
}

static void __attribute__((constructor)) gw_send_use(void) {
  io_eff(CID_WIRE_SEND, gw_send_run, 0);
}

#endif

#ifdef CID_WIRE_SEND_TIMEOUT

// wire_send with a deadline: a full socket parks on POLLOUT and the clock,
// whichever fires first; past the deadline the send fails ETIMEDOUT. The
// first park sets the deadline (the socket is almost always writable).
static Term gw_sendt_more(Env e, IoWork* w) {
  int fd = (int)w->hand;
  u64 at = io_wait_time(w);
  while (w->code == 0 && (u64)w->made < w->size) {
    ssize_t n = send(fd, w->data + w->made, w->size - (u64)w->made, 0);
    if (n < 0 && errno == EAGAIN) {
      if (io_tick() < at) {
        return io_wait_on(w, fd, POLLOUT, at, gw_sendt_more);
      }
      w->code = ETIMEDOUT;
      break;
    }
    w->made += io_sys_end(w, n);
  }
  Term r = w->code != 0 ? io_fail(e, w->code, NULL) : io_done(e, term_pak(CID_UNIT, 0));
  free(w->data);
  return io_tup(e, io_hand(w->hand), r);
}

Term gw_sendt_run(Env e, Term* f, IoWork* w) {
  if (gw_tls_on(f[0]) && gw_tls_send_hook != NULL) {
    return gw_tls_send_hook(e, f, w);
  }
  bool bad;
  w->hand = (intptr_t)io_hand_v(f[0]);
  w->data = gw_octets(e, f[1], &w->size, &bad);
  w->made = 0;
  w->code = bad ? EINVAL : 0;
  return io_wait_on(w, (int)w->hand, POLLOUT, io_tick() + (u64)f[2] * 1000000ull, gw_sendt_more);
}

static void __attribute__((constructor)) gw_sendt_use(void) {
  io_eff(CID_WIRE_SEND_TIMEOUT, gw_sendt_run, 0);
}

#endif

#ifdef CID_WIRE_UDP_SEND_TO

static Term gw_udp_send_more(Env e, IoWork* w) {
  struct sockaddr_in at;
  int fd = (int)w->hand;
  u64 deadline = io_wait_time(w);
  ssize_t n = -1;
  errno = EINVAL;
  if (io_sys_addr(w->text, (u32)w->made, &at) == 0) {
    n = sendto(fd, w->data, w->size, 0, (struct sockaddr*)&at, sizeof(at));
  }
  io_sys_end(w, n);
  if (w->code == EAGAIN) {
    if (io_tick() < deadline) {
      return io_wait_on(w, fd, POLLOUT, deadline, gw_udp_send_more);
    }
    w->code = ETIMEDOUT;
  }
  if (w->code == 0 && (u64)n != w->size) {
    w->code = EIO;
  }
  Term r = w->code ? io_fail(e, w->code, NULL)
    : io_done(e, term_pak(CID_UNIT, 0));
  free(w->text);
  free(w->data);
  return io_tup(e, io_hand(w->hand), r);
}

Term gw_udp_send_run(Env e, Term* f, IoWork* w) {
  u64 host_len;
  bool bad;
  w->hand = (intptr_t)io_hand_v(f[0]);
  w->text = io_cstr(e, f[1], &host_len);
  w->made = (intptr_t)f[2];
  w->data = gw_octets(e, f[3], &w->size, &bad);
  if (bad || io_nul(w->text, host_len)) {
    free(w->text);
    free(w->data);
    return io_tup(e, io_hand(w->hand), io_fail(e, EINVAL, NULL));
  }
  return io_wait_on(w, (int)w->hand, POLLOUT,
    io_tick() + (u64)f[4] * 1000000ull, gw_udp_send_more);
}

static void __attribute__((constructor)) gw_udp_send_use(void) {
  io_eff(CID_WIRE_UDP_SEND_TO, gw_udp_send_run, 0);
}

#endif

#ifdef CID_WIRE_UDP_RECV_FROM_TIMEOUT

static Term gw_udp_recv_more(Env e, IoWork* w) {
  struct sockaddr_in at = { 0 };
  socklen_t at_len = sizeof(at);
  char host[16];
  int fd = (int)w->hand;
  u64 deadline = io_wait_time(w);
  ssize_t n = io_sys_end(w, recvfrom(fd, w->data, (size_t)w->made, 0,
    (struct sockaddr*)&at, &at_len));
  if (w->code == EAGAIN) {
    if (io_tick() < deadline) {
      return io_wait_on(w, fd, POLLIN, deadline, gw_udp_recv_more);
    }
    free(w->data);
    return io_tup(e, io_hand(w->hand), io_done(e, term_pak(CID_NONE, 0)));
  }
  Term r;
  if (w->code) {
    r = io_fail(e, w->code, NULL);
  } else if ((u64)n > w->size) {
    r = io_fail(e, EMSGSIZE, NULL);
  } else if (!inet_ntop(AF_INET, &at.sin_addr, host, sizeof(host))) {
    r = io_fail(e, errno, NULL);
  } else {
    Term peer = io_tup(e, io_str(e, host, strlen(host)),
      io_tup(e, ntohs(at.sin_port), gw_list(e, w->data, (u64)n)));
    r = io_done(e, io_box(e, CID_SOME, peer));
  }
  free(w->data);
  return io_tup(e, io_hand(w->hand), r);
}

Term gw_udp_recv_run(Env e, Term* f, IoWork* w) {
  w->hand = (intptr_t)io_hand_v(f[0]);
  w->size = (u64)f[1];
  w->made = w->size < 65535 ? (intptr_t)w->size + 1 : 65535;
  w->data = io_mem(malloc((size_t)w->made));
  return io_wait_on(w, (int)w->hand, POLLIN,
    io_tick() + (u64)f[2] * 1000000ull, gw_udp_recv_more);
}

static void __attribute__((constructor)) gw_udp_recv_use(void) {
  io_eff(CID_WIRE_UDP_RECV_FROM_TIMEOUT, gw_udp_recv_run, 0);
}

#endif

#ifdef CID_WIRE_CONNECT_TIMEOUT

// TCP.connect with a deadline: the connect parks on POLLOUT and the clock;
// a socket still not writable at the deadline is closed, ETIMEDOUT.
static Term gw_conn_more(Env e, IoWork* w) {
  int fd  = (int)w->made;
  int err = (int)w->code;
  if (err == EINPROGRESS) {
    struct pollfd p = { fd, POLLOUT, 0 };
    if (poll(&p, 1, 0) == 0) {
      u64 at = io_wait_time(w);
      if (io_tick() < at) {
        return io_wait_on(w, fd, POLLOUT, at, gw_conn_more);
      }
      err = ETIMEDOUT;
    } else {
      socklen_t len = sizeof(err);
      if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len)) {
        err = errno;
      }
    }
  }
  if (err != 0 && fd >= 0) {
    close(fd);
  }
  free(w->data);
  return err != 0 ? io_fail(e, (u32)err, NULL) : io_done(e, io_hand(fd));
}

Term gw_conn_run(Env e, Term* f, IoWork* w) {
  struct sockaddr_in at;
  w->data = io_cstr(e, f[0], &w->size);
  int fd  = -1;
  errno   = EINVAL;
  if (!io_nul(w->data, w->size) && io_sys_addr(w->data, (u32)f[1], &at) == 0) {
    fd = socket(AF_INET, SOCK_STREAM, 0);
  }
  if (fd >= 0 && fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0) {
    close(fd);
    fd = -1;
  }
  w->made = fd;
  io_sys_end(w, fd < 0 ? fd : connect(fd, (struct sockaddr*)&at, sizeof(at)));
  return w->code == EINPROGRESS
    ? io_wait_on(w, fd, POLLOUT, io_tick() + (u64)f[2] * 1000000ull, gw_conn_more) : gw_conn_more(e, w);
}

static void __attribute__((constructor)) gw_conn_use(void) {
  io_eff(CID_WIRE_CONNECT_TIMEOUT, gw_conn_run, 0);
}

#endif

#ifdef CID_WIRE_ACCEPT_TIMEOUT

// TCP.accept with a deadline: accepts at once when a connection waits,
// else parks on the listener and the clock; None{} when none comes by then.
static Term gw_acc_more(Env e, IoWork* w) {
  int fd  = (int)w->hand;
  u64 at  = w->size;
  int got = accept(fd, NULL, NULL);
  if (got >= 0 && fcntl(got, F_SETFL, fcntl(got, F_GETFL) | O_NONBLOCK) < 0) {
    close(got);
    got = -1;
  }
  io_sys_end(w, got);
  if (w->code == EAGAIN) {
    return io_tick() < at ? io_wait_on(w, fd, POLLIN, at, gw_acc_more)
      : io_tup(e, io_hand(fd), io_done(e, term_pak(CID_NONE, 0)));
  }
  Term r = w->code != 0 ? io_fail(e, w->code, NULL) : io_done(e, io_box(e, CID_SOME, io_hand(got)));
  return io_tup(e, io_hand(fd), r);
}

Term gw_acc_run(Env e, Term* f, IoWork* w) {
  w->hand = (intptr_t)io_hand_v(f[0]);
  w->size = io_tick() + (u64)f[1] * 1000000ull;
  return gw_acc_more(e, w);
}

static void __attribute__((constructor)) gw_acc_use(void) {
  io_eff(CID_WIRE_ACCEPT_TIMEOUT, gw_acc_run, 0);
}

#endif

// SIGTERM and SIGINT set a flag the program polls; the live count is the
// connections a server is still serving. Both are process-wide.
#if defined(CID_WIRE_ON_STOP) || defined(CID_WIRE_STOPPING)
static volatile sig_atomic_t gw_stop = 0;

static void gw_on_signal(int sig) {
  (void)sig;
  gw_stop = 1;
}
#endif

#ifdef CID_WIRE_ON_STOP

Term gw_on_stop_run(Env e, Term* f, IoWork* w) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = gw_on_signal;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  return term_pak(CID_UNIT, 0);
}

static void __attribute__((constructor)) gw_on_stop_use(void) {
  io_eff(CID_WIRE_ON_STOP, gw_on_stop_run, 0);
}

#endif

#ifdef CID_WIRE_STOPPING

Term gw_stopping_run(Env e, Term* f, IoWork* w) {
  return (Term)(u32)(gw_stop ? 1 : 0);
}

static void __attribute__((constructor)) gw_stopping_use(void) {
  io_eff(CID_WIRE_STOPPING, gw_stopping_run, 0);
}

#endif

#ifdef CID_WIRE_LIVE

static u32 gw_live = 0;

// adds d (1, or 0xFFFFFFFF for -1, or 0 to read) and gives the new count
Term gw_live_run(Env e, Term* f, IoWork* w) {
  gw_live += (u32)f[0];
  return (Term)gw_live;
}

static void __attribute__((constructor)) gw_live_use(void) {
  io_eff(CID_WIRE_LIVE, gw_live_run, 0);
}

#endif

#ifdef CID_WIRE_RESOLVE

#include <netdb.h>

// A host name to its first IPv4 address, dotted, on a helper thread:
// getaddrinfo blocks. An address already dotted comes back as it is.
static void gw_resolve_call(IoWork* w) {
  struct addrinfo hint;
  struct addrinfo* got = NULL;
  memset(&hint, 0, sizeof(hint));
  hint.ai_family   = AF_INET;
  hint.ai_socktype = SOCK_STREAM;
  int r = getaddrinfo(w->data, NULL, &hint, &got);
  if (r != 0 || got == NULL) {
    w->code = r == EAI_SYSTEM ? (u32)errno : EHOSTUNREACH;
    return;
  }
  char* out = io_mem(malloc(INET_ADDRSTRLEN));
  inet_ntop(AF_INET, &((struct sockaddr_in*)got->ai_addr)->sin_addr, out, INET_ADDRSTRLEN);
  freeaddrinfo(got);
  free(w->data);
  w->data = out;
  w->code = 0;
}

static Term gw_resolve_pack(Env e, IoWork* w) {
  Term r = w->code ? io_fail(e, w->code, NULL) : io_done(e, io_str(e, w->data, strlen(w->data)));
  free(w->data);
  return r;
}

Term gw_resolve_run(Env e, Term* f, IoWork* w) {
  w->data = io_cstr(e, f[0], &w->size);
  if (io_nul(w->data, w->size) || w->size == 0) {
    free(w->data);
    return io_fail(e, EINVAL, NULL);
  }
  return io_work(w, gw_resolve_call, gw_resolve_pack);
}

static void __attribute__((constructor)) gw_resolve_use(void) {
  io_eff(CID_WIRE_RESOLVE, gw_resolve_run, 0);
}

#endif

// TLS
// ===
// OpenSSL 3, loaded at run time (bend links no extra libraries), after
// bend-kit-wire's tls (MIT-0). The SSL object of a socket lives in a table
// keyed by its fd. The client verifies the peer's chain and host name; TLS
// 1.2 is the floor. GROUNDS_TLS_CA names a PEM file to trust as well as
// the system's roots; BEND_LIBSSL overrides libssl's path.

#if defined(CID_WIRE_TLS_CONNECT) || defined(CID_WIRE_TLS_SEND_TIMEOUT) || defined(CID_WIRE_TLS_RECV_TIMEOUT) || defined(CID_WIRE_TLS_CLOSE) || defined(CID_WIRE_TLS_LISTEN_CTX) || defined(CID_WIRE_TLS_ACCEPT)
#define GW_TLS_ANY
#endif

#ifdef GW_TLS_ANY
#ifndef GROUNDS_TLS
#define GROUNDS_TLS
#include <dlfcn.h>

typedef struct {
  int   lib;
  int   state;
  void* ctx;
  void* srv;
  void* (*ctx_new)(void*);
  void  (*ctx_free)(void*);
  long  (*ctx_ctrl)(void*, int, long, void*);
  void* (*server_method)(void);
  int   (*use_chain)(void*, const char*);
  int   (*use_key)(void*, const char*, int);
  int   (*check_key)(const void*);
  u64   (*set_options)(void*, u64);
  int   (*set_ciphers)(void*, const char*);
  void  (*set_level)(void*, int);
  int   (*set_early)(void*, u32);
  void  (*set_alpn)(void*, int (*)(void*, const unsigned char**, unsigned char*, const unsigned char*, unsigned int, void*), void*);
  int   (*accept)(void*);
  void* (*ssl_new)(void*);
  int   (*set_fd)(void*, int);
  long  (*ctrl)(void*, int, long, void*);
  int   (*set1_host)(void*, const char*);
  int   (*connect)(void*);
  int   (*read)(void*, void*, int);
  int   (*write)(void*, const void*, int);
  int   (*get_error)(const void*, int);
  int   (*shutdown)(void*);
  void  (*ssl_free)(void*);
  long  (*verify_result)(const void*);
  const char* (*verify_text)(long);
} GwTls;

#define GW_TLS_FDS 65536
static GwTls gw_tls;
static void* gw_tls_ssl[GW_TLS_FDS];

static void* gw_tls_open(void) {
  const char* paths[] = { getenv("BEND_LIBSSL"),
    "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib",
    "/usr/local/opt/openssl@3/lib/libssl.3.dylib", "libssl.3.dylib", "libssl.so.3" };
  for (u64 i = 0; i < sizeof(paths) / sizeof(paths[0]); i += 1) {
    void* h = paths[i] != NULL ? dlopen(paths[i], RTLD_NOW | RTLD_LOCAL) : NULL;
    if (h != NULL) {
      return h;
    }
  }
  return NULL;
}

// libssl and its functions, once
static bool gw_tls_lib(void) {
  if (gw_tls.lib != 0) {
    return gw_tls.lib > 0;
  }
  gw_tls.lib = -1;
  void* h = gw_tls_open();
  if (h == NULL) {
    return false;
  }
  gw_tls.ctx_new       = dlsym(h, "SSL_CTX_new");
  gw_tls.ctx_free      = dlsym(h, "SSL_CTX_free");
  gw_tls.ctx_ctrl      = dlsym(h, "SSL_CTX_ctrl");
  gw_tls.server_method = dlsym(h, "TLS_server_method");
  gw_tls.use_chain     = dlsym(h, "SSL_CTX_use_certificate_chain_file");
  gw_tls.use_key       = dlsym(h, "SSL_CTX_use_PrivateKey_file");
  gw_tls.check_key     = dlsym(h, "SSL_CTX_check_private_key");
  gw_tls.set_options   = dlsym(h, "SSL_CTX_set_options");
  gw_tls.set_ciphers   = dlsym(h, "SSL_CTX_set_cipher_list");
  gw_tls.set_level     = dlsym(h, "SSL_CTX_set_security_level");
  gw_tls.set_early     = dlsym(h, "SSL_CTX_set_max_early_data");
  gw_tls.set_alpn      = dlsym(h, "SSL_CTX_set_alpn_select_cb");
  gw_tls.accept        = dlsym(h, "SSL_accept");
  gw_tls.ssl_new       = dlsym(h, "SSL_new");
  gw_tls.set_fd        = dlsym(h, "SSL_set_fd");
  gw_tls.ctrl          = dlsym(h, "SSL_ctrl");
  gw_tls.set1_host     = dlsym(h, "SSL_set1_host");
  gw_tls.connect       = dlsym(h, "SSL_connect");
  gw_tls.read          = dlsym(h, "SSL_read");
  gw_tls.write         = dlsym(h, "SSL_write");
  gw_tls.get_error     = dlsym(h, "SSL_get_error");
  gw_tls.shutdown      = dlsym(h, "SSL_shutdown");
  gw_tls.ssl_free      = dlsym(h, "SSL_free");
  gw_tls.verify_result = dlsym(h, "SSL_get_verify_result");
  gw_tls.verify_text   = dlsym(h, "X509_verify_cert_error_string");
  if (!gw_tls.ctx_new || !gw_tls.ctx_free || !gw_tls.ctx_ctrl || !gw_tls.server_method || !gw_tls.use_chain
    || !gw_tls.use_key || !gw_tls.check_key || !gw_tls.set_options || !gw_tls.set_ciphers
    || !gw_tls.set_level || !gw_tls.set_early || !gw_tls.set_alpn || !gw_tls.accept
    || !gw_tls.ssl_new || !gw_tls.set_fd || !gw_tls.ctrl || !gw_tls.set1_host
    || !gw_tls.connect || !gw_tls.read || !gw_tls.write || !gw_tls.get_error
    || !gw_tls.shutdown || !gw_tls.ssl_free || !gw_tls.verify_result || !gw_tls.verify_text) {
    return false;
  }
  gw_tls.lib = 1;
  return true;
}

// the client context, once: the system's roots, GROUNDS_TLS_CA, the peer
// verified, TLS 1.2 the floor
static bool gw_tls_load(void) {
  if (gw_tls.state != 0) {
    return gw_tls.state > 0;
  }
  gw_tls.state = -1;
  if (!gw_tls_lib()) {
    return false;
  }
  void* h = gw_tls_open();
  void* (*method)(void)                      = dlsym(h, "TLS_client_method");
  int   (*paths)(void*)                      = dlsym(h, "SSL_CTX_set_default_verify_paths");
  int   (*load)(void*, const char*, const char*) = dlsym(h, "SSL_CTX_load_verify_locations");
  void  (*verify)(void*, int, void*)         = dlsym(h, "SSL_CTX_set_verify");
  if (!method || !paths || !load || !verify) {
    return false;
  }
  void* ctx = gw_tls.ctx_new(method());
  if (ctx == NULL || paths(ctx) != 1) {
    return false;
  }
  const char* ca = getenv("GROUNDS_TLS_CA");
  if (ca != NULL && ca[0] != 0 && load(ctx, ca, NULL) != 1) {
    return false;
  }
  verify(ctx, 1, NULL);                     // SSL_VERIFY_PEER
  gw_tls.ctx_ctrl(ctx, 123, 0x0303, NULL);  // SSL_CTRL_SET_MIN_PROTO_VERSION: TLS 1.2
  gw_tls.ctx   = ctx;
  gw_tls.state = 1;
  return true;
}

static void* gw_tls_of(int fd) {
  return fd >= 0 && fd < GW_TLS_FDS ? gw_tls_ssl[fd] : NULL;
}

static void gw_tls_drop(int fd) {
  void* ssl = gw_tls_of(fd);
  if (ssl != NULL) {
    gw_tls.ssl_free(ssl);
    gw_tls_ssl[fd] = NULL;
  }
}

// one close_notify, not waiting for the peer's, then the session is freed
static void gw_tls_end(int fd) {
  void* ssl = gw_tls_of(fd);
  if (ssl != NULL) {
    gw_tls.shutdown(ssl);
    gw_tls_drop(fd);
  }
}

static void __attribute__((constructor)) gw_tls_hooks(void) {
  gw_tls_sess     = gw_tls_of;
  gw_tls_end_hook = gw_tls_end;
}

#endif
#endif

#ifdef CID_WIRE_TLS_CONNECT

// The handshake, over a connected socket, by the deadline in w->size.
static Term gw_tlsc_end(Env e, IoWork* w, Term r) {
  free(w->text);
  return io_tup(e, io_hand(w->hand), r);
}

static Term gw_tlsc_fail(Env e, IoWork* w, u32 code, const char* why) {
  gw_tls_drop((int)w->hand);
  return gw_tlsc_end(e, w, io_fail(e, code, why));
}

static Term gw_tlsc_more(Env e, IoWork* w) {
  int   fd  = (int)w->hand;
  void* ssl = gw_tls_of(fd);
  int   r   = gw_tls.connect(ssl);
  if (r == 1) {
    return gw_tlsc_end(e, w, io_done(e, term_pak(CID_UNIT, 0)));
  }
  int err = gw_tls.get_error(ssl, r);
  if (err == 2 || err == 3) {  // SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE
    if (io_tick() < w->size) {
      return io_wait_on(w, fd, err == 2 ? POLLIN : POLLOUT, w->size, gw_tlsc_more);
    }
    return gw_tlsc_fail(e, w, ETIMEDOUT, NULL);
  }
  long v = gw_tls.verify_result(ssl);
  return gw_tlsc_fail(e, w, EPROTO, v != 0 ? gw_tls.verify_text(v) : "TLS handshake failed");
}

Term gw_tlsc_run(Env e, Term* f, IoWork* w) {
  uint64_t hn = 0;
  w->hand = (intptr_t)io_hand_v(f[0]);
  w->text = io_cstr(e, f[1], &hn);
  w->size = io_tick() + (u64)f[2] * 1000000ull;
  int fd  = (int)w->hand;
  if (!gw_tls_load()) {
    return gw_tlsc_end(e, w, io_fail(e, ENOENT, "TLS needs OpenSSL 3 (libssl.3); set BEND_LIBSSL to its path"));
  }
  if (fd < 0 || fd >= GW_TLS_FDS || io_nul(w->text, hn)) {
    return gw_tlsc_end(e, w, io_fail(e, EINVAL, NULL));
  }
  void* ssl = gw_tls.ssl_new(gw_tls.ctx);
  if (ssl == NULL) {
    return gw_tlsc_end(e, w, io_fail(e, ENOMEM, NULL));
  }
  gw_tls_ssl[fd] = ssl;
  // SNI (SSL_CTRL_SET_TLSEXT_HOSTNAME) and the host name to verify
  if (gw_tls.set_fd(ssl, fd) != 1 || gw_tls.ctrl(ssl, 55, 0, w->text) != 1
    || gw_tls.set1_host(ssl, w->text) != 1) {
    return gw_tlsc_fail(e, w, EPROTO, "TLS setup failed");
  }
  return gw_tlsc_more(e, w);
}

static void __attribute__((constructor)) gw_tlsc_use(void) {
  io_eff(CID_WIRE_TLS_CONNECT, gw_tlsc_run, 0);
}

#endif

#if defined(GW_TLS_ANY) && !defined(GW_TLS_SEND)
#define GW_TLS_SEND

// SSL_write is retried with the same buffer, as OpenSSL requires.
static Term gw_tlss_more(Env e, IoWork* w) {
  int   fd  = (int)w->hand;
  void* ssl = gw_tls_of(fd);
  while (w->code == 0 && (u64)w->made < w->size) {
    if (ssl == NULL) {
      w->code = EBADF;
      break;
    }
    u64 left = w->size - (u64)w->made;
    int n    = gw_tls.write(ssl, w->data + w->made, left > INT32_MAX ? INT32_MAX : (int)left);
    if (n > 0) {
      w->made += n;
      continue;
    }
    int err = gw_tls.get_error(ssl, n);
    if (err == 2 || err == 3) {
      u64 at = *(u64*)w->text;
      if (io_tick() < at) {
        return io_wait_on(w, fd, err == 2 ? POLLIN : POLLOUT, at, gw_tlss_more);
      }
      w->code = ETIMEDOUT;
      break;
    }
    w->code = EPIPE;
  }
  Term r = w->code != 0 ? io_fail(e, w->code, NULL) : io_done(e, term_pak(CID_UNIT, 0));
  free(w->data);
  free(w->text);
  return io_tup(e, io_hand(w->hand), r);
}

Term gw_tlss_run(Env e, Term* f, IoWork* w) {
  bool bad;
  w->hand = (intptr_t)io_hand_v(f[0]);
  w->data = gw_octets(e, f[1], &w->size, &bad);
  w->made = 0;
  w->text = io_mem(malloc(sizeof(u64)));
  *(u64*)w->text = io_tick() + (u64)f[2] * 1000000ull;
  w->code = bad ? EINVAL : 0;
  return gw_tlss_more(e, w);
}

static void __attribute__((constructor)) gw_tlss_use(void) {
  gw_tls_send_hook = gw_tlss_run;
#ifdef CID_WIRE_TLS_SEND_TIMEOUT
  io_eff(CID_WIRE_TLS_SEND_TIMEOUT, gw_tlss_run, 0);
#endif
}

#endif

#if defined(GW_TLS_ANY) && !defined(GW_TLS_RECV)
#define GW_TLS_RECV

// Some{bytes}; Some{[]} once the peer sends close_notify; None{} past the
// deadline. A bare EOF, without close_notify, fails ECONNRESET: a body
// read to the close could have been cut.
static Term gw_tlsr_more(Env e, IoWork* w) {
  int   fd  = (int)w->hand;
  void* ssl = gw_tls_of(fd);
  int   n   = ssl != NULL ? gw_tls.read(ssl, w->data, (int)w->made) : -1;
  Term  r;
  if (n > 0) {
    r = io_done(e, io_box(e, CID_SOME, gw_list(e, w->data, (u64)n)));
  } else {
    int err = ssl != NULL ? gw_tls.get_error(ssl, n) : 1;
    if (err == 2 || err == 3) {
      if (io_tick() < w->size) {
        return io_wait_on(w, fd, err == 2 ? POLLIN : POLLOUT, w->size, gw_tlsr_more);
      }
      r = io_done(e, term_pak(CID_NONE, 0));
    } else if (err == 6) {  // SSL_ERROR_ZERO_RETURN: close_notify
      r = io_done(e, io_box(e, CID_SOME, term_pak(CID_NIL, 0)));
    } else {
      r = io_fail(e, ssl != NULL ? ECONNRESET : EBADF, NULL);
    }
  }
  free(w->data);
  return io_tup(e, io_hand(w->hand), r);
}

Term gw_tlsr_run(Env e, Term* f, IoWork* w) {
  w->hand = (intptr_t)io_hand_v(f[0]);
  w->made = f[1] < INT32_MAX ? (intptr_t)f[1] : INT32_MAX;
  w->data = io_mem(malloc((size_t)w->made + 1));
  w->size = io_tick() + (u64)f[2] * 1000000ull;
  return gw_tlsr_more(e, w);
}

static void __attribute__((constructor)) gw_tlsr_use(void) {
  gw_tls_recv_hook = gw_tlsr_run;
#ifdef CID_WIRE_TLS_RECV_TIMEOUT
  io_eff(CID_WIRE_TLS_RECV_TIMEOUT, gw_tlsr_run, 0);
#endif
}

#endif

#ifdef CID_WIRE_TLS_CLOSE

// one close_notify, not waiting for the peer's, then the socket
Term gw_tlsx_run(Env e, Term* f, IoWork* w) {
  int fd = (int)io_hand_v(f[0]);
  gw_tls_end(fd);
  close(fd);
  return term_pak(CID_UNIT, 0);
}

static void __attribute__((constructor)) gw_tlsx_use(void) {
  io_eff(CID_WIRE_TLS_CLOSE, gw_tlsx_run, 0);
}

#endif

#ifdef CID_WIRE_TLS_LISTEN_CTX

// ALPN (RFC 7301): http/1.1 or nothing. A client that offers protocols but
// not http/1.1 gets no_application_protocol
static int gw_alpn(void* ssl, const unsigned char** out, unsigned char* outlen,
  const unsigned char* in, unsigned int inlen, void* arg) {
  unsigned int i = 0;
  while (i < inlen) {
    unsigned int n = in[i];
    if (i + 1 + n > inlen) {
      break;
    }
    if (n == 8 && memcmp(in + i + 1, "http/1.1", 8) == 0) {
      *out    = in + i + 1;
      *outlen = 8;
      return 0;  // SSL_TLSEXT_ERR_OK
    }
    i += 1 + n;
  }
  return 2;  // SSL_TLSEXT_ERR_ALERT_FATAL
}

static Term gw_tlsl_end(Env e, char* cert, char* key, void* ctx, u32 code, const char* why) {
  free(cert);
  free(key);
  if (code != 0) {
    if (ctx != NULL) {
      gw_tls.ctx_free(ctx);
    }
    return io_fail(e, code, why);
  }
  if (gw_tls.srv != NULL) {
    gw_tls.ctx_free(gw_tls.srv);
  }
  gw_tls.srv = ctx;
  return io_done(e, term_pak(CID_UNIT, 0));
}

// The server's context (RFC 9325): TLS 1.2 the floor, ECDHE with AES-GCM or
// ChaCha20 for 1.2, OpenSSL's 1.3 suites, security level 2, no compression,
// no renegotiation, no 0-RTT, ALPN http/1.1. The chain and key are loaded
// and matched now, so a bad pair stops the server before it listens
Term gw_tlsl_run(Env e, Term* f, IoWork* w) {
  uint64_t cn = 0;
  uint64_t kn = 0;
  char* cert = io_cstr(e, f[0], &cn);
  char* key  = io_cstr(e, f[1], &kn);
  if (!gw_tls_lib()) {
    return gw_tlsl_end(e, cert, key, NULL, ENOENT, "TLS needs OpenSSL 3 (libssl.3); set BEND_LIBSSL to its path");
  }
  if (io_nul(cert, cn) || io_nul(key, kn) || cn == 0 || kn == 0) {
    return gw_tlsl_end(e, cert, key, NULL, EINVAL, "TLS: no certificate or key file named");
  }
  void* ctx = gw_tls.ctx_new(gw_tls.server_method());
  if (ctx == NULL) {
    return gw_tlsl_end(e, cert, key, NULL, ENOMEM, NULL);
  }
  if (gw_tls.ctx_ctrl(ctx, 123, 0x0303, NULL) != 1) {  // SSL_CTRL_SET_MIN_PROTO_VERSION
    return gw_tlsl_end(e, cert, key, ctx, EPROTO, "TLS: cannot require TLS 1.2");
  }
  // SSL_OP_NO_COMPRESSION, SSL_OP_CIPHER_SERVER_PREFERENCE, SSL_OP_NO_RENEGOTIATION
  u64 options = (1ull << 17) | (1ull << 22) | (1ull << 30);
  if ((gw_tls.set_options(ctx, options) & options) != options) {
    return gw_tlsl_end(e, cert, key, ctx, EPROTO, "TLS: cannot set server options");
  }
  gw_tls.set_level(ctx, 2);
  if (gw_tls.set_early(ctx, 0) != 1) {
    return gw_tlsl_end(e, cert, key, ctx, EPROTO, "TLS: cannot disable early data");
  }
  gw_tls.set_alpn(ctx, gw_alpn, NULL);
  if (gw_tls.set_ciphers(ctx, "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL") != 1) {
    return gw_tlsl_end(e, cert, key, ctx, EPROTO, "TLS: no cipher suite left");
  }
  if (gw_tls.use_chain(ctx, cert) != 1) {
    return gw_tlsl_end(e, cert, key, ctx, ENOENT, "TLS: cannot load the certificate chain (PEM)");
  }
  if (gw_tls.use_key(ctx, key, 1) != 1) {  // SSL_FILETYPE_PEM
    return gw_tlsl_end(e, cert, key, ctx, ENOENT, "TLS: cannot load the private key (PEM)");
  }
  if (gw_tls.check_key(ctx) != 1) {
    return gw_tlsl_end(e, cert, key, ctx, EINVAL, "TLS: the private key does not match the certificate");
  }
  return gw_tlsl_end(e, cert, key, ctx, 0, NULL);
}

static void __attribute__((constructor)) gw_tlsl_use(void) {
  io_eff(CID_WIRE_TLS_LISTEN_CTX, gw_tlsl_run, 0);
}

#endif

#ifdef CID_WIRE_TLS_ACCEPT

// The server's handshake on an accepted socket, by the deadline in w->size
static Term gw_tlsa_end(Env e, IoWork* w, Term r) {
  return io_tup(e, io_hand(w->hand), r);
}

static Term gw_tlsa_more(Env e, IoWork* w) {
  int   fd  = (int)w->hand;
  void* ssl = gw_tls_of(fd);
  int   r   = gw_tls.accept(ssl);
  if (r == 1) {
    return gw_tlsa_end(e, w, io_done(e, term_pak(CID_UNIT, 0)));
  }
  int err = gw_tls.get_error(ssl, r);
  if ((err == 2 || err == 3) && io_tick() < w->size) {
    return io_wait_on(w, fd, err == 2 ? POLLIN : POLLOUT, w->size, gw_tlsa_more);
  }
  gw_tls_drop(fd);
  return gw_tlsa_end(e, w, io_fail(e, err == 2 || err == 3 ? ETIMEDOUT : EPROTO, err == 2 || err == 3 ? NULL : "TLS handshake failed"));
}

Term gw_tlsa_run(Env e, Term* f, IoWork* w) {
  w->hand = (intptr_t)io_hand_v(f[0]);
  w->size = io_tick() + (u64)f[1] * 1000000ull;
  int fd  = (int)w->hand;
  if (gw_tls.srv == NULL) {
    return gw_tlsa_end(e, w, io_fail(e, EINVAL, "TLS: no server context; call wire_tls_listen_ctx first"));
  }
  if (fd < 0 || fd >= GW_TLS_FDS) {
    return gw_tlsa_end(e, w, io_fail(e, EBADF, NULL));
  }
  void* ssl = gw_tls.ssl_new(gw_tls.srv);
  if (ssl == NULL) {
    return gw_tlsa_end(e, w, io_fail(e, ENOMEM, NULL));
  }
  gw_tls_ssl[fd] = ssl;
  if (gw_tls.set_fd(ssl, fd) != 1) {
    gw_tls_drop(fd);
    return gw_tlsa_end(e, w, io_fail(e, EPROTO, "TLS setup failed"));
  }
  return gw_tlsa_more(e, w);
}

static void __attribute__((constructor)) gw_tlsa_use(void) {
  io_eff(CID_WIRE_TLS_ACCEPT, gw_tlsa_run, 0);
}

#endif

#ifdef CID_WIRE_CLOSE

// a socket's close: its TLS session first, if it has one
Term gw_close_run(Env e, Term* f, IoWork* w) {
  int fd = (int)io_hand_v(f[0]);
  if (gw_tls_end_hook != NULL) {
    gw_tls_end_hook(fd);
  }
  close(fd);
  return term_pak(CID_UNIT, 0);
}

static void __attribute__((constructor)) gw_close_use(void) {
  io_eff(CID_WIRE_CLOSE, gw_close_run, 0);
}

#endif
