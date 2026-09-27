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
