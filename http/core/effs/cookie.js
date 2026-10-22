// Native OpenSSL cookie signing is not available on the JS target.
function sign(key, value) {
  return io_fail(io_sys().mac ? 78 : 38);
}

function verify(key, signed) {
  return io_fail(io_sys().mac ? 78 : 38);
}

io_eff(CID(sign), sign);
io_eff(CID(verify), verify);
