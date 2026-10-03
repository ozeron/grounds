import Base
import ./unicode32_nfkc_buffer.bend as B

# Stable four-byte radix ordering by (starter segment, combining class).
# This keeps equal classes in source order and avoids quadratic mark insertion.
type Arrays is Type:
  Arrays{values: Array<U32>, keys: Array<U32>, scratch_values: Array<U32>, scratch_keys: Array<U32>}

type Pass is Type:
  Pass{values: Array<U32>, keys: Array<U32>, scratch_values: Array<U32>, scratch_keys: Array<U32>, counts: Array<U32>}

def histogram.count(values: Array<U32>, keys: Array<U32>, scratch_values: Array<U32>, scratch_keys: Array<U32>, +bucket: U32, result: Array<U32> & U32) -> Pass:
  (counts, count) = result
  Pass{values, keys, scratch_values, scratch_keys, Array.set(U32, counts, bucket, U32.inc(count))}

def histogram.key(values: Array<U32>, scratch_values: Array<U32>, scratch_keys: Array<U32>, counts: Array<U32>, shift: Nat, result: Array<U32> & U32) -> Pass:
  (keys, key) = result
  +bucket = U32.and(U32.shrn(key, shift), 255)
  histogram.count(values, keys, scratch_values, scratch_keys, bucket, Array.get(U32, counts, bucket))

def histogram.step(at: U32, shift: Nat, state: Pass) -> Pass:
  match state:
    case Pass{values, keys, scratch_values, scratch_keys, counts}:
      histogram.key(values, scratch_values, scratch_keys, counts, shift, Array.get(U32, keys, at))

def histogram(left: Nat, +at: U32, +shift: Nat, state: Pass) -> Pass:
  match left:
    case 0n: state
    case 1n+p: histogram(p, U32.inc(at), shift, histogram.step(at, shift, state))

def prefix.step(at: U32, +total: U32, values: Array<U32>, keys: Array<U32>, scratch_values: Array<U32>, scratch_keys: Array<U32>, result: Array<U32> & U32) -> Pass & U32:
  (counts, count) = result
  (Pass{values, keys, scratch_values, scratch_keys, Array.set(U32, counts, at, total)}, U32.add(total, count))

def prefix.next(result: Pass & U32, next: Pass -> U32 -> Pass) -> Pass:
  (state, total) = result
  next(state, total)

def prefix(left: Nat, +at: U32, total: U32, state: Pass) -> Pass:
  match left state:
    case 0n state: state
    case 1n+p Pass{values, keys, scratch_values, scratch_keys, counts}:
      prefix.next(prefix.step(at, total, values, keys, scratch_values, scratch_keys, Array.get(U32, counts, at)),
        s => n => prefix(p, U32.inc(at), n, s))

def scatter.value(keys: Array<U32>, scratch_values: Array<U32>, scratch_keys: Array<U32>, counts: Array<U32>, bucket: U32, +position: U32, key: U32, result: Array<U32> & U32) -> Pass:
  (values, value) = result
  Pass{values, keys, Array.set(U32, scratch_values, position, value), Array.set(U32, scratch_keys, position, key), Array.set(U32, counts, bucket, U32.inc(position))}

def scatter.position(values: Array<U32>, keys: Array<U32>, scratch_values: Array<U32>, scratch_keys: Array<U32>, at: U32, bucket: U32, key: U32, result: Array<U32> & U32) -> Pass:
  (counts, position) = result
  scatter.value(keys, scratch_values, scratch_keys, counts, bucket, position, key, Array.get(U32, values, at))

def scatter.key(values: Array<U32>, scratch_values: Array<U32>, scratch_keys: Array<U32>, counts: Array<U32>, at: U32, shift: Nat, result: Array<U32> & U32) -> Pass:
  (keys, +key) = result
  +bucket = U32.and(U32.shrn(key, shift), 255)
  scatter.position(values, keys, scratch_values, scratch_keys, at, bucket, key, Array.get(U32, counts, bucket))

def scatter.step(+at: U32, shift: Nat, state: Pass) -> Pass:
  match state:
    case Pass{values, keys, scratch_values, scratch_keys, counts}:
      scatter.key(values, scratch_values, scratch_keys, counts, at, shift, Array.get(U32, keys, at))

def scatter(left: Nat, +at: U32, +shift: Nat, state: Pass) -> Pass:
  match left:
    case 0n: state
    case 1n+p: scatter(p, U32.inc(at), shift, scatter.step(at, shift, state))

def swapped(state: Pass) -> Arrays:
  match state:
    case Pass{values, keys, scratch_values, scratch_keys, _}: Arrays{scratch_values, scratch_keys, values, keys}

def pass(+length: U32, +shift: Nat, state: Arrays) -> Arrays:
  match state:
    case Arrays{values, keys, scratch_values, scratch_keys}:
      swapped(scatter(U32.to_nat(length), 0, shift,
        prefix(256n, 0, 0,
          histogram(U32.to_nat(length), 0, shift, Pass{values, keys, scratch_values, scratch_keys, Array.new(U32, 8n, 0)}))))

def run(left: Nat, +length: U32, +shift: Nat, state: Arrays) -> Array<U32>:
  match left state:
    case 0n Arrays{values, _, _, _}: values
    case 1n+p state: run(p, length, Nat.add(shift, 8n), pass(length, shift, state))

def keys.point(keys: Array<U32>, +at: U32, +segment: U32, result: Array<U32> & U32) -> Array<U32> & Array<U32> & U32:
  (values, +point) = result
  +current = U32.add(segment, Bool.pick(U32, U32.is_eq(U32.and(point, 255), 0), 1, 0))
  key = U32.or(U32.shln(current, 8n), U32.and(point, 255))
  (values, Array.set(U32, keys, at, key), current)

def keys.next(result: Array<U32> & Array<U32> & U32, next: Array<U32> -> Array<U32> -> U32 -> Arrays) -> Arrays:
  (values, keys, segment) = result
  next(values, keys, segment)

def keys(left: Nat, +at: U32, segment: U32, values: Array<U32>, array: Array<U32>, scratch_values: Array<U32>, scratch_keys: Array<U32>) -> Arrays:
  match left:
    case 0n: Arrays{values, array, scratch_values, scratch_keys}
    case 1n+p:
      keys.next(keys.point(array, at, segment, Array.get(U32, values, at)),
        v => k => s => keys(p, U32.inc(at), s, v, k, scratch_values, scratch_keys))

def ordered(buffer: B.Buffer) -> Array<U32> & U32:
  match buffer:
    case B.Buffer{values, length, _, _, _, _, True{}}: (values, length)
    case B.Buffer{values, +length, _, +exponent, _, _, False{}}:
      (run(4n, length, 0n,
        keys(U32.to_nat(length), 0, 0, values, Array.new(U32, exponent, 0), Array.new(U32, exponent, 0), Array.new(U32, exponent, 0))), length)
