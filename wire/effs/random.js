function wire_random_bytes(count) {
  const n = Number(count);
  if (!Number.isInteger(n) || n < 0 || n > 1048576) return io_fail(22);
  if (n === 0) return io_done({ $: "Nil" });
  let bytes;
  try {
    bytes = new Uint8Array(n);
  } catch (_) {
    return io_fail(12);
  }
  try {
    for (let at = 0; at < n; at += 65536) {
      crypto.getRandomValues(bytes.subarray(at, Math.min(n, at + 65536)));
    }
  } catch (_) {
    bytes.fill(0);
    return io_fail(5);
  }
  let result = { $: "Nil" };
  for (let i = n; i > 0; --i) {
    result = { $: "Con", head: bytes[i - 1], tail: result };
  }
  bytes.fill(0);
  return io_done(result);
}
