import Base
import ./bytes.bend as B

# Internal variable-size base-2^15 Montgomery arithmetic for RSA.
# At most 274 limbs for 4096 bits, plus two carry limbs, in 512 cells.
# Inner sum <= 32767^2 + 32767 + 32767 = 2^30-1.
# Public verification first; private-key timing/erasure approval is outstanding.

def zero() -> Array<U32>:
  Array.new(U32, 9n, 0)

def one() -> Array<U32>:
  Array.set(U32, zero(), 0, 1)

def pack.step(flush: Bool, +i: U32, +value: U32, bits: Nat, out: Array<U32>, next: U32 -> U32 -> Nat -> Array<U32> -> Array<U32>) -> Array<U32>:
  match flush:
    case False{}:
      next(i, value, bits, out)
    case True{}:
      next(U32.inc(i), U32.shrn(value, 15n), Nat.sub(bits, 15n), Array.set(U32, out, i, U32.and(value, 32767)))

def pack.go(bytes: List<&2, U32>, +i: U32, value: U32, +bits: Nat, out: Array<U32>) -> Array<U32>:
  match bytes:
    case Nil{}:
      Array.set(U32, out, i, value)
    case Con{byte, tail}:
      +count = Nat.add(bits, 8n)
      pack.step(Nat.is_ge(count, 15n), i, U32.or(value, U32.shln(byte, bits)), count, out,
        at => v => used => a => pack.go(tail, at, v, used, a))

# Internal: caller validates valid bytes and size <= 512 first.
def decode(bytes: List<&2, U32>) -> Array<U32>:
  pack.go(List.reverse(&2, U32, bytes), 0, 0, 0n, zero())

type Unpack is Type:
  Unpack{digits: Array<U32>, i: U32, value: U32, bits: Nat}

def unpack.digit(+bits: Nat, value: U32, +i: U32, pair: Array<U32> & U32) -> Unpack:
  (digits, digit) = pair
  Unpack{digits, U32.inc(i), U32.or(value, U32.shln(digit, bits)), Nat.add(bits, 15n)}

def unpack.fill(enough: Bool, digits: Array<U32>, +i: U32, value: U32, bits: Nat) -> Unpack:
  match enough:
    case True{}:
      Unpack{digits, i, value, bits}
    case False{}:
      unpack.digit(bits, value, i, Array.get(U32, digits, i))

def unpack.got(reversed: List<&2, U32>, state: Unpack, next: Unpack -> List<&2, U32> -> List<&2, U32>) -> List<&2, U32>:
  match state:
    case Unpack{digits, i, +value, bits}:
      next(Unpack{digits, i, U32.shrn(value, 8n), Nat.sub(bits, 8n)}, Con{U32.and(value, 255), reversed})

def unpack.go(left: Nat, state: Unpack, reversed: List<&2, U32>) -> List<&2, U32>:
  match left state:
    case 0n Unpack{_, _, _, _}:
      reversed
    case 1n+p Unpack{digits, i, value, +bits}:
      unpack.got(reversed, unpack.fill(Nat.is_ge(bits, 8n), digits, i, value, bits),
        s => r => unpack.go(p, s, r))

# Internal: exact requested big-endian width; caller proves value fits.
def encode(length: Nat, value: Array<U32>) -> List<&2, U32>:
  unpack.go(length, Unpack{value, 0, 0, 0n}, [])

def byte_bits.go(left: Nat, value: U32, used: Nat) -> Nat:
  match left value:
    case _ 0:
      used
    case 0n _:
      used
    case 1n+p value:
      byte_bits.go(p, U32.shrn(value, 1n), Nat.add(used, 1n))

def bit_length(bytes: List<&2, U32>) -> Nat:
  match bytes:
    case Nil{}:
      0n
    case Con{first, tail}:
      Nat.add(Nat.mul(B.length(tail), 8n), byte_bits.go(8n, first, 0n))

def inverse.step(+low: U32, +value: U32) -> U32:
  U32.and(U32.mul(value, U32.sub(2, U32.mul(low, value))), 32767)

def inverse_low(+low: U32) -> U32:
  U32.and(U32.sub(0, inverse.step(low, inverse.step(low, inverse.step(low, inverse.step(low, 1))))), 32767)

type ModResult is Type:
  ModResult{modulus: Array<U32>, value: Array<U32>}

type Subtract is Type:
  Subtract{modulus: Array<U32>, original: Array<U32>, candidate: Array<U32>, borrow: U32}

def subtract.value(+i: U32, modulus: Array<U32>, digit: U32, candidate: Array<U32>, borrow: U32, pair: Array<U32> & U32) -> Subtract:
  (original, value) = pair
  +difference = U32.sub(U32.add(value, 32768), U32.add(digit, borrow))
  Subtract{modulus, original, Array.set(U32, candidate, i, U32.and(difference, 32767)), U32.sub(1, U32.shrn(difference, 15n))}

def subtract.modulus(+i: U32, original: Array<U32>, candidate: Array<U32>, borrow: U32, pair: Array<U32> & U32) -> Subtract:
  (modulus, digit) = pair
  subtract.value(i, modulus, digit, candidate, borrow, Array.get(U32, original, i))

def subtract.go(left: Nat, +i: U32, state: Subtract) -> Subtract:
  match left state:
    case 0n Subtract{modulus, original, candidate, borrow}:
      Subtract{modulus, original, candidate, borrow}
    case 1n+p Subtract{modulus, original, candidate, borrow}:
      subtract.go(p, U32.inc(i), subtract.modulus(i, original, candidate, borrow, Array.get(U32, modulus, i)))

type Select is Type:
  Select{original: Array<U32>, candidate: Array<U32>, out: Array<U32>}

def select.candidate(+i: U32, +mask: U32, original: Array<U32>, a: U32, out: Array<U32>, pair: Array<U32> & U32) -> Select:
  (candidate, b) = pair
  Select{original, candidate, Array.set(U32, out, i, U32.or(U32.and(a, U32.xor(mask, 32767)), U32.and(b, mask)))}

def select.original(+i: U32, mask: U32, candidate: Array<U32>, out: Array<U32>, pair: Array<U32> & U32) -> Select:
  (original, a) = pair
  select.candidate(i, mask, original, a, out, Array.get(U32, candidate, i))

def select.go(left: Nat, +i: U32, +mask: U32, state: Select) -> Array<U32>:
  match left state:
    case 0n Select{_, _, out}:
      out
    case 1n+p Select{original, candidate, out}:
      select.go(p, U32.inc(i), mask, select.original(i, mask, candidate, out, Array.get(U32, original, i)))

def canonical.choose(count: Nat, state: Subtract) -> ModResult:
  match state:
    case Subtract{modulus, original, candidate, borrow}:
      ModResult{modulus, select.go(count, 0, U32.mul(32767, U32.sub(1, borrow)), Select{original, candidate, zero()})}

# Internal precondition: value < 2*modulus, modulus odd and canonical.
def canonical(+limbs: Nat, modulus: Array<U32>, value: Array<U32>) -> ModResult:
  canonical.choose(Nat.add(limbs, 1n), subtract.go(Nat.add(limbs, 1n), 0, Subtract{modulus, value, zero(), 0}))

type Shift is Type:
  Shift{source: Array<U32>, out: Array<U32>, carry: U32}

def double.step(+i: U32, out: Array<U32>, carry: U32, pair: Array<U32> & U32) -> Shift:
  (source, value) = pair
  +sum = U32.add(U32.mul(value, 2), carry)
  Shift{source, Array.set(U32, out, i, U32.and(sum, 32767)), U32.shrn(sum, 15n)}

def double.go(left: Nat, +i: U32, state: Shift) -> Array<U32>:
  match left state:
    case 0n Shift{_, out, _}:
      out
    case 1n+p Shift{source, out, carry}:
      double.go(p, U32.inc(i), double.step(i, out, carry, Array.get(U32, source, i)))

def double_mod(+limbs: Nat, modulus: Array<U32>, value: Array<U32>) -> ModResult:
  canonical(limbs, modulus, double.go(Nat.add(limbs, 1n), 0, Shift{value, zero(), 0}))

def r2.go(left: Nat, +limbs: Nat, state: ModResult) -> ModResult:
  match left state:
    case 0n ModResult{modulus, value}:
      ModResult{modulus, value}
    case 1n+p ModResult{modulus, value}:
      r2.go(p, limbs, double_mod(limbs, modulus, value))

# Start at 2^(bits-1) < an admitted odd modulus; skip initial trivial doublings.
def r2(+bits: Nat, +limbs: Nat, modulus: Array<U32>) -> ModResult:
  +at = Nat.sub(bits, 1n)
  r2.go(Nat.sub(Nat.mul(limbs, 30n), at), limbs,
    ModResult{modulus, Array.set(U32, zero(), U32.from_nat(Nat.div(at, 15n)), U32.shln(1, Nat.mod(at, 15n)))})

type Row is Type:
  Row{operand: Array<U32>, t: Array<U32>, carry: U32}

def row.t(+i: U32, operand: Array<U32>, av: U32, bv: U32, carry: U32, pair: Array<U32> & U32) -> Row:
  (t, value) = pair
  +sum = U32.add(U32.add(value, U32.mul(av, bv)), carry)
  Row{operand, Array.set(U32, t, i, U32.and(sum, 32767)), U32.shrn(sum, 15n)}

def row.operand(+i: U32, av: U32, t: Array<U32>, carry: U32, pair: Array<U32> & U32) -> Row:
  (operand, bv) = pair
  row.t(i, operand, av, bv, carry, Array.get(U32, t, i))

def row.go(left: Nat, +i: U32, +av: U32, state: Row) -> Row:
  match left state:
    case 0n Row{operand, t, carry}:
      Row{operand, t, carry}
    case 1n+p Row{operand, t, carry}:
      row.go(p, U32.inc(i), av, row.operand(i, av, t, carry, Array.get(U32, operand, i)))

def high.extra(+at: U32, digit: U32, carry: U32, pair: Array<U32> & U32) -> Array<U32>:
  (t, high) = pair
  Array.set(U32, Array.set(U32, t, at, digit), U32.inc(at), U32.add(high, carry))

def high.digit(+at: U32, carry: U32, pair: Array<U32> & U32) -> Array<U32>:
  (t, digit) = pair
  +sum = U32.add(digit, carry)
  high.extra(at, U32.and(sum, 32767), U32.shrn(sum, 15n), Array.get(U32, t, U32.inc(at)))

def high(+at: U32, carry: U32, t: Array<U32>) -> Array<U32>:
  high.digit(at, carry, Array.get(U32, t, at))

def right.step(i: U32, pair: Array<U32> & U32) -> Array<U32>:
  (t, value) = pair
  Array.set(U32, t, i, value)

# Internal: shift the admitted live prefix low-to-high, reading i+1 before
# overwriting i. Clear the vacated high cell; all later cells are already zero.
def right.go(left: Nat, +i: U32, t: Array<U32>) -> Array<U32>:
  match left:
    case 0n:
      Array.set(U32, t, i, 0)
    case 1n+p:
      right.go(p, U32.inc(i), right.step(i, Array.get(U32, t, U32.inc(i))))

type Montgomery is Type:
  Montgomery{modulus: Array<U32>, a: Array<U32>, b: Array<U32>, t: Array<U32>}

def mont.reduced(+limbs: Nat, a: Array<U32>, b: Array<U32>, state: Row) -> Montgomery:
  match state:
    case Row{modulus, t, carry}:
      Montgomery{modulus, a, b,
        right.go(Nat.add(limbs, 1n), 0, high(U32.from_nat(limbs), carry, t))}

def mont.low(+limbs: Nat, inverse: U32, modulus: Array<U32>, a: Array<U32>, b: Array<U32>, pair: Array<U32> & U32) -> Montgomery:
  (t, low) = pair
  factor = U32.and(U32.mul(low, inverse), 32767)
  mont.reduced(limbs, a, b, row.go(limbs, 0, factor, Row{modulus, t, 0}))

def mont.product(+limbs: Nat, inverse: U32, modulus: Array<U32>, a: Array<U32>, state: Row) -> Montgomery:
  match state:
    case Row{b, t, carry}:
      mont.low(limbs, inverse, modulus, a, b, Array.get(U32, high(U32.from_nat(limbs), carry, t), 0))

def mont.a(+limbs: Nat, inverse: U32, modulus: Array<U32>, b: Array<U32>, t: Array<U32>, pair: Array<U32> & U32) -> Montgomery:
  (a, av) = pair
  mont.product(limbs, inverse, modulus, a, row.go(limbs, 0, av, Row{b, t, 0}))

def mont.go(left: Nat, +limbs: Nat, +inverse: U32, +i: U32, state: Montgomery) -> ModResult:
  match left state:
    case 0n Montgomery{modulus, _, _, t}:
      canonical(limbs, modulus, t)
    case 1n+p Montgomery{modulus, a, b, t}:
      mont.go(p, limbs, inverse, U32.inc(i), mont.a(limbs, inverse, modulus, b, t, Array.get(U32, a, i)))

# Internal: 1 <= limbs <= 274, n odd > 1, a/b canonical < n.
# HAC algorithm 14.36: result = a*b*R^-1 mod n, R=2^(15*limbs).
def mont(+limbs: Nat, inverse: U32, modulus: Array<U32>, a: Array<U32>, b: Array<U32>) -> ModResult:
  mont.go(limbs, limbs, inverse, 0, Montgomery{modulus, a, b, zero()})

def result.encode(length: Nat, state: ModResult) -> List<&2, U32>:
  match state:
    case ModResult{_, value}:
      encode(length, value)

type Power is Type:
  Power{modulus: Array<U32>, base: Array<U32>, acc: Array<U32>}

def power.acc(base: Array<U32>, result: ModResult) -> Power:
  match result:
    case ModResult{modulus, acc}:
      Power{modulus, base, acc}

def power.square_pair(limbs: Nat, inverse: U32, modulus: Array<U32>, base: Array<U32>, pair: Array<U32> & Array<U32>) -> Power:
  (first, second) = pair
  power.acc(base, mont(limbs, inverse, modulus, first, second))

def power.square(limbs: Nat, inverse: U32, state: Power) -> Power:
  match state:
    case Power{modulus, base, acc}:
      power.square_pair(limbs, inverse, modulus, base, Array.clone(U32, acc))

def power.multiply_pair(limbs: Nat, inverse: U32, modulus: Array<U32>, acc: Array<U32>, pair: Array<U32> & Array<U32>) -> Power:
  (base, factor) = pair
  power.acc(base, mont(limbs, inverse, modulus, acc, factor))

def power.bit(set: Bool, limbs: Nat, inverse: U32, state: Power) -> Power:
  match set state:
    case False{} Power{modulus, base, acc}:
      Power{modulus, base, acc}
    case True{} Power{modulus, base, acc}:
      power.multiply_pair(limbs, inverse, modulus, acc, Array.clone(U32, base))

# Branches on the public exponent. This is not a private exponentiation API.
def power.bits(left: Nat, +limbs: Nat, +inverse: U32, +byte: U32, state: Power) -> Power:
  match left:
    case 0n:
      state
    case 1n+ +p:
      power.bits(p, limbs, inverse, byte,
        power.bit(U32.is_eq(U32.and(U32.shrn(byte, p), 1), 1), limbs, inverse,
          power.square(limbs, inverse, state)))

def power.got(state: Power, next: Power -> Power) -> Power:
  next(state)

def power.bytes(exponent: List<&2, U32>, +limbs: Nat, +inverse: U32, state: Power) -> Power:
  match exponent:
    case Nil{}:
      state
    case Con{byte, tail}:
      power.got(power.bits(8n, limbs, inverse, byte, state),
        s => power.bytes(tail, limbs, inverse, s))

def power.first(exponent: List<&2, U32>, +limbs: Nat, +inverse: U32, state: Power) -> Power:
  match exponent:
    case Nil{}:
      state
    case Con{+byte, tail}:
      power.bytes(tail, limbs, inverse,
        power.bits(byte_bits.go(8n, byte, 0n), limbs, inverse, byte, state))

def power.base(acc: Array<U32>, result: ModResult) -> Power:
  match result:
    case ModResult{modulus, base}:
      Power{modulus, base, acc}

def power.one(+limbs: Nat, inverse: U32, base: Array<U32>, r_squared: Array<U32>, result: ModResult) -> Power:
  match result:
    case ModResult{modulus, acc}:
      power.base(acc, mont(limbs, inverse, modulus, base, r_squared))

def power.r_squared_pair(+limbs: Nat, +inverse: U32, modulus: Array<U32>, base: Array<U32>, pair: Array<U32> & Array<U32>) -> Power:
  (first, second) = pair
  power.one(limbs, inverse, base, second, mont(limbs, inverse, modulus, one(), first))

def power.r_squared(limbs: Nat, inverse: U32, base: Array<U32>, result: ModResult) -> Power:
  match result:
    case ModResult{modulus, r_squared}:
      power.r_squared_pair(limbs, inverse, modulus, base, Array.clone(U32, r_squared))

def power.finish(limbs: Nat, inverse: U32, state: Power) -> ModResult:
  match state:
    case Power{modulus, _, acc}:
      mont(limbs, inverse, modulus, acc, one())

def power.low(+bits: Nat, +limbs: Nat, exponent: List<&2, U32>, base: Array<U32>, pair: Array<U32> & U32) -> ModResult:
  (modulus, low) = pair
  +inverse = inverse_low(low)
  power.finish(limbs, inverse, power.first(exponent, limbs, inverse,
    power.r_squared(limbs, inverse, base, r2(bits, limbs, modulus))))

# Internal: admitted odd modulus > 1, canonical base < n and public exponent.
def public_power(+bits: Nat, modulus: Array<U32>, exponent: List<&2, U32>, base: Array<U32>) -> ModResult:
  power.low(bits, Nat.div(Nat.add(bits, 14n), 15n), exponent, base, Array.get(U32, modulus, 0))

def canonical_bytes(bytes: List<&2, U32>) -> Bool:
  match bytes:
    case Nil{}:
      False{}
    case Con{first, _}:
      U32.is_ne(first, 0)

def last_byte(bytes: List<&2, U32>, previous: U32) -> U32:
  match bytes:
    case Nil{}:
      previous
    case Con{first, tail}:
      last_byte(tail, first)

def compare.step(equal: Bool, less: Bool, next: Unit -> Bool) -> Bool:
  match equal:
    case False{}:
      less
    case True{}:
      next(Unit{})

def compare.go(first: List<&2, U32>, second: List<&2, U32>) -> Bool:
  match first second:
    case Con{+a, first} Con{+b, second}:
      compare.step(U32.is_eq(a, b), U32.is_lt(a, b), _ => compare.go(first, second))
    case _ _:
      False{}

def less.checked(equal_length: Bool, shorter: Bool, first: List<&2, U32>, second: List<&2, U32>) -> Bool:
  match equal_length:
    case False{}:
      shorter
    case True{}:
      compare.go(first, second)

# Big-endian, unsigned byte strings; operands may have equal-width leading zeros.
def less(+first: List<&2, U32>, +second: List<&2, U32>) -> Bool:
  +a = B.length(first)
  +b = B.length(second)
  less.checked(Nat.is_eq(a, b), Nat.is_lt(a, b), first, second)

def operation.checked(valid: Bool, +modulus: List<&2, U32>, exponent: List<&2, U32>, representative: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      Some{result.encode(B.length(modulus), public_power(bit_length(modulus), decode(modulus), exponent, decode(representative)))}

def operation(+minimum_bits: Nat, +modulus: List<&2, U32>, +exponent: List<&2, U32>, +representative: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  operation.checked(Bool.and(Bool.and(Bool.and(B.valid(modulus), canonical_bytes(modulus)),
    Bool.and(Bool.and(Nat.is_ge(bit_length(modulus), minimum_bits), Nat.is_le(bit_length(modulus), 4096n)), U32.is_eq(U32.and(last_byte(modulus, 0), 1), 1))),
    Bool.and(Bool.and(Bool.and(B.valid(exponent), canonical_bytes(exponent)),
      Bool.and(Bool.and(less([1], exponent), less(exponent, modulus)), U32.is_eq(U32.and(last_byte(exponent, 0), 1), 1))),
      Bool.and(Bool.and(B.valid(representative), Nat.is_eq(B.length(representative), B.length(modulus))), less(representative, modulus)))),
    modulus, exponent, representative)

# RSA public verification primitive, 2048..4096-bit unsigned canonical modulus.
# Signature input/output are exactly k bytes; no reduction of aliases >= n.
def public_operation(modulus: List<&2, U32>, exponent: List<&2, U32>, representative: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  operation(2048n, modulus, exponent, representative)
