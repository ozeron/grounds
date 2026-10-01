// Test the actual JS effect with controlled OS entropy outcomes. The compiled
// Bend evaluator separately exercises real Bun WebCrypto; neither is an entropy audit.
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
const code = readFileSync(new URL('./effs/random.js', import.meta.url), 'utf8');
const run = entropy => {
  const ctx = vm.createContext({crypto: {getRandomValues: entropy}, io_fail: code => ({fail: code}), io_done: value => ({done: value})});
  vm.runInContext(code, ctx);
  return n => ctx.wire_random_bytes(n);
};
const forbidden = run(() => {throw new Error('RNG must not run');});
assert.equal(forbidden(0).done.$, 'Nil');
for (const n of [-1, 1.5, NaN, 1048577, 4294967295]) assert.equal(forbidden(n).fail, 22);
for (const n of [1, 65535, 65536, 65537, 1048576]) {
  let calls = 0, at = 0;
  const refs = [];
  const result = run(view => {
    assert(view.length <= 65536); refs.push(view); ++calls;
    for (let i = 0; i < view.length; ++i) view[i] = at++ & 255;
    return view;
  })(n);
  assert.equal(calls, Math.ceil(n / 65536));
  let count = 0;
  for (let xs = result.done; xs.$ === 'Con'; xs = xs.tail) assert.equal(xs.head, count++ & 255);
  assert.equal(count, n);
  for (const ref of refs) assert(ref.every(x => x === 0), 'temporary entropy buffer retained');
}
let calls = 0, ref;
const failed = run(view => {
  ++calls;
  if (calls === 2) throw new Error('synthetic host entropy failure');
  ref = view; view.fill(123); return view;
})(65537);
assert.equal(failed.fail, 5);
assert.equal(calls, 2);
assert(new Uint8Array(ref.buffer).every(x => x === 0));
console.log('Bun RNG OS adapter: 12 guard/chunk/order/failure/temporary-buffer cleanup cases passed');
