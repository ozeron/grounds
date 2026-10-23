function http_readable(socket, ms, k) {
  const sys = io_sys();
  const byte = new Uint8Array(1);
  const at = performance.now() + Number(ms);
  const go = () => {
    const n = Number(sys.recv(socket, sys.ptr(byte), 1, 2)); // MSG_PEEK
    // Bend 2's JS backend lowers Bool to primitive booleans. Constructor
    // objects are always truthy, including a boxed False after a timeout.
    if (n >= 0) return io_tup(socket, io_done(true));
    const code = sys.errno();
    if (code !== (sys.mac ? 35 : 11)) return io_tup(socket, io_fail(code));
    if (performance.now() >= at) return io_tup(socket, io_done(false));
    io_park_on(socket, false, k, go, at);
    return undefined;
  };
  return go();
}
io_eff(CID(http_readable), http_readable);
