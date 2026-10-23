// Backend identity; no credential or cryptographic work crosses this effect.
static Term gh_native_target_run(Env e, Term* f, IoWork* w) {
  return 1;
}
static void __attribute__((constructor)) gh_native_target_use(void) {
  io_eff(CID(http_native_target), gh_native_target_run);
}
