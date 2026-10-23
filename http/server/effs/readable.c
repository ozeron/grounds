// Non-consuming byte-socket readiness. All TLS framing remains in Bend.
#ifdef CID(http_readable)
static Term gh_readable_more(Env e, IoWork* w) {
  unsigned char byte;
  int fd = (int)w->hand;
  ssize_t n = io_sys_end(w, recv(fd, &byte, 1, MSG_PEEK));
  if (w->code == EAGAIN) {
    if (io_tick() < w->time) return io_wait_on(w, fd, POLLIN, w->time, gh_readable_more);
    return io_tup(e, io_hand(w->hand), io_done(e, term_pak(CID(False), 0)));
  }
  return io_tup(e, io_hand(w->hand), w->code ? io_fail(e, w->code, NULL)
    : io_done(e, term_pak(CID(True), 0)));
}
static Term gh_readable_run(Env e, Term* f, IoWork* w) {
  w->hand = (intptr_t)io_hand_v(f[0]);
  w->time = io_tick() + (u64)f[1] * 1000000ull;
  return gh_readable_more(e, w);
}
static void __attribute__((constructor)) gh_readable_use(void) {
  io_eff(CID(http_readable), gh_readable_run);
}
#endif
