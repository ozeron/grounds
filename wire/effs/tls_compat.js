// Legacy OpenSSL-compatible API stubs, isolated from byte TCP imports.
// TLS is native only: the JS target fails ENOSYS (78 on macOS, 38 on Linux)
function gw_nosys() {
  return io_sys().mac ? 78 : 38;
}

function wire_tls_connect(socket, host, ms) {
  return io_tup(socket, io_fail(gw_nosys()));
}

function wire_tls_send_timeout(socket, data, ms) {
  return io_tup(socket, io_fail(gw_nosys()));
}

function wire_tls_recv_timeout(socket, max, ms) {
  return io_tup(socket, io_fail(gw_nosys()));
}

function wire_tls_listen_ctx(cert, key) {
  return io_fail(gw_nosys());
}

function wire_tls_accept(socket, ms) {
  return io_tup(socket, io_fail(gw_nosys()));
}

function wire_tls_close(socket) {
  io_sys().close(socket);
  return { $: CID(Unit) };
}


io_eff(CID(wire_tls_connect), wire_tls_connect);
io_eff(CID(wire_tls_send_timeout), wire_tls_send_timeout);
io_eff(CID(wire_tls_recv_timeout), wire_tls_recv_timeout);
io_eff(CID(wire_tls_close), wire_tls_close);
io_eff(CID(wire_tls_listen_ctx), wire_tls_listen_ctx);
io_eff(CID(wire_tls_accept), wire_tls_accept);
