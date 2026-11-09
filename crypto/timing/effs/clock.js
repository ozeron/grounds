// Timing-harness counters (Bun is synthetic-only; native is the measured target).
function grounds_timing_cycles(dep) {
  return Number(process.hrtime.bigint() & 0x7fffffffffffn);
}
function grounds_timing_instructions(dep) {
  return 0;
}
io_eff(CID(grounds_timing_cycles), grounds_timing_cycles);
io_eff(CID(grounds_timing_instructions), grounds_timing_instructions);
