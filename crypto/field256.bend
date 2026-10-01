import Base
import ./bytes.bend as B

# P-256 coordinate prime and scalar order (SP 800-186 section 3.2.1.3).
# Internal canonical values are 32 little-endian bytes in a 64-cell array.
# Fixed binary reduction is an initial correctness baseline, not a speed claim.
# Source control/indices use public counters and mode; conditional subtraction
# selects bytes with 0/255 masks. Runtime/JIT timing and erasure remain open.

type Mode is Data:
  Field{}
  Scalar{}

def zero() -> Array<U32>:
  Array.new(U32, 6n, 0)

def one() -> Array<U32>:
  Array.set(U32, zero(), 0, 1)

# Public constant access uses eight 32-bit words instead of 32 byte cases.
def word_byte(word: U32, i: U32) -> U32:
  U32.and(U32.shrn(word, U32.to_nat(U32.mul(U32.and(i, 3), 8))), 255)

def field_digit.word.low(i: Nat) -> U32:
  match i:
    case 0n:
      4294967295
    case 1n:
      4294967295
    case 2n:
      4294967295
    case 3n:
      0
    case _:
      0

def field_digit.word.high(i: Nat) -> U32:
  match i:
    case 0n:
      0
    case 1n:
      0
    case 2n:
      1
    case 3n:
      4294967295
    case _:
      0

def field_digit.word.group(group: Nat, i: Nat) -> U32:
  match group:
    case 0n:
      field_digit.word.low(i)
    case 1n:
      field_digit.word.high(i)
    case _:
      0

def field_digit.word(+i: U32) -> U32:
  field_digit.word.group(U32.to_nat(U32.shrn(i, 2n)), U32.to_nat(U32.and(i, 3)))

def field_digit(+i: U32) -> U32:
  word_byte(field_digit.word(U32.shrn(i, 2n)), i)

def scalar_digit.word.low(i: Nat) -> U32:
  match i:
    case 0n:
      4234356049
    case 1n:
      4089039554
    case 2n:
      2803342980
    case 3n:
      3169254061
    case _:
      0

def scalar_digit.word.high(i: Nat) -> U32:
  match i:
    case 0n:
      4294967295
    case 1n:
      4294967295
    case 2n:
      0
    case 3n:
      4294967295
    case _:
      0

def scalar_digit.word.group(group: Nat, i: Nat) -> U32:
  match group:
    case 0n:
      scalar_digit.word.low(i)
    case 1n:
      scalar_digit.word.high(i)
    case _:
      0

def scalar_digit.word(+i: U32) -> U32:
  scalar_digit.word.group(U32.to_nat(U32.shrn(i, 2n)), U32.to_nat(U32.and(i, 3)))

def scalar_digit(+i: U32) -> U32:
  word_byte(scalar_digit.word(U32.shrn(i, 2n)), i)

def modulus_digit(mode: Mode, i: U32) -> U32:
  match mode:
    case Field{}:
      field_digit(i)
    case Scalar{}:
      scalar_digit(i)

type Carry is Type:
  Carry{digits: Array<U32>, carry: U32}

def carry_step(+i: U32, carry: U32, r: Array<U32> & U32) -> Carry:
  (digits, value) = r
  +sum = U32.add(value, carry)
  Carry{Array.set(U32, digits, i, U32.and(sum, 255)), U32.shrn(sum, 8n)}

def carry_digits(left: Nat, +i: U32, state: Carry) -> Array<U32>:
  match left state:
    case 0n Carry{digits, _}:
      digits
    case 1n+p Carry{digits, carry}:
      carry_digits(p, U32.inc(i), carry_step(i, carry, Array.get(U32, digits, i)))

def carry(xs: Array<U32>) -> Array<U32>:
  carry_digits(64n, 0, Carry{xs, 0})

type SubMod is Type:
  SubMod{original: Array<U32>, candidate: Array<U32>, borrow: U32}

def subtract_mod.step(+mode: Mode, +i: U32, candidate: Array<U32>, borrow: U32, pair: Array<U32> & U32) -> SubMod:
  (original, value) = pair
  +difference = U32.sub(U32.add(value, 256), U32.add(modulus_digit(mode, i), borrow))
  SubMod{original, Array.set(U32, candidate, i, U32.and(difference, 255)), U32.sub(1, U32.shrn(difference, 8n))}

def subtract_mod.go(left: Nat, +mode: Mode, +i: U32, state: SubMod) -> SubMod:
  match left state:
    case 0n SubMod{original, candidate, borrow}:
      SubMod{original, candidate, borrow}
    case 1n+p SubMod{original, candidate, borrow}:
      subtract_mod.go(p, mode, U32.inc(i), subtract_mod.step(mode, i, candidate, borrow, Array.get(U32, original, i)))

type Select is Type:
  Select{original: Array<U32>, candidate: Array<U32>, out: Array<U32>}

def select_step.candidate(+i: U32, +mask: U32, original: Array<U32>, a: U32,
                          out: Array<U32>, r: Array<U32> & U32) -> Select:
  (candidate, b) = r
  selected = U32.or(U32.and(a, U32.xor(mask, 255)), U32.and(b, mask))
  Select{original, candidate, Array.set(U32, out, i, selected)}

def select_step.original(+i: U32, mask: U32, candidate: Array<U32>, out: Array<U32>,
                         r: Array<U32> & U32) -> Select:
  (original, a) = r
  select_step.candidate(i, mask, original, a, out, Array.get(U32, candidate, i))

def select_bytes(left: Nat, +i: U32, +mask: U32, state: Select) -> Array<U32>:
  match left state:
    case 0n Select{_, _, out}:
      out
    case 1n+p Select{original, candidate, out}:
      select_bytes(p, U32.inc(i), mask,
        select_step.original(i, mask, candidate, out, Array.get(U32, original, i)))

def canonical.choose(state: SubMod) -> Array<U32>:
  match state:
    case SubMod{original, candidate, borrow}:
      select_bytes(33n, 0, U32.mul(255, U32.sub(1, borrow)), Select{original, candidate, zero()})

# Precondition: the represented nonnegative integer is below twice the modulus.
def canonical(mode: Mode, input: Array<U32>) -> Array<U32>:
  canonical.choose(subtract_mod.go(33n, mode, 0, SubMod{input, zero(), 0}))

type Shift is Type:
  Shift{input: Array<U32>, output: Array<U32>, carry: U32}

def shift.step(+i: U32, output: Array<U32>, carry: U32, pair: Array<U32> & U32) -> Shift:
  (input, value) = pair
  +sum = U32.add(U32.mul(2, value), carry)
  Shift{input, Array.set(U32, output, i, U32.and(sum, 255)), U32.shrn(sum, 8n)}

def shift.go(left: Nat, +i: U32, state: Shift) -> Array<U32>:
  match left state:
    case 0n Shift{_, output, _}:
      output
    case 1n+p Shift{input, output, carry}:
      shift.go(p, U32.inc(i), shift.step(i, output, carry, Array.get(U32, input, i)))

type Reduction is Type:
  Reduction{wide: Array<U32>, remainder: Array<U32>}

def reduce.step(+mode: Mode, bit: Nat, remainder: Array<U32>, pair: Array<U32> & U32) -> Reduction:
  (wide, value) = pair
  incoming = U32.and(U32.shrn(value, bit), 1)
  Reduction{wide, canonical(mode, shift.go(33n, 0, Shift{remainder, zero(), incoming}))}

def reduce.go(left: Nat, +mode: Mode, state: Reduction) -> Array<U32>:
  match left state:
    case 0n Reduction{_, remainder}:
      remainder
    case 1n+ +p Reduction{wide, remainder}:
      reduce.go(p, mode, reduce.step(mode, Nat.mod(p, 8n), remainder,
        Array.get(U32, wide, U32.from_nat(Nat.div(p, 8n)))))

# Accept normalized 64-byte integers, returning a canonical 32-byte value.
# Invariant before each bit: remainder < modulus; after shift < 2*modulus.
def reduce(mode: Mode, wide: Array<U32>) -> Array<U32>:
  reduce.go(512n, mode, Reduction{wide, zero()})

type Operands is Type:
  Operands{a: Array<U32>, b: Array<U32>, out: Array<U32>}

type Row is Type:
  Row{b: Array<U32>, out: Array<U32>}

def multiply_row.out(+at: U32, av: U32, bv: U32, b: Array<U32>, r: Array<U32> & U32) -> Row:
  (out, old) = r
  Row{b, Array.set(U32, out, at, U32.add(old, U32.mul(av, bv)))}

def multiply_row.b(+i: U32, +j: U32, av: U32, out: Array<U32>, r: Array<U32> & U32) -> Row:
  (b, bv) = r
  multiply_row.out(U32.add(i, j), av, bv, b, Array.get(U32, out, U32.add(i, j)))

def multiply_row(left: Nat, +i: U32, +j: U32, +av: U32, state: Row) -> Row:
  match left state:
    case 0n Row{b, out}:
      Row{b, out}
    case 1n+p Row{b, out}:
      multiply_row(p, i, U32.inc(j), av,
        multiply_row.b(i, j, av, out, Array.get(U32, b, j)))

def multiply_digits.row(a: Array<U32>, state: Row) -> Operands:
  match state:
    case Row{b, out}:
      Operands{a, b, out}

def multiply_digits.a(+i: U32, b: Array<U32>, out: Array<U32>, r: Array<U32> & U32) -> Operands:
  (a, av) = r
  multiply_digits.row(a, multiply_row(32n, i, 0, av, Row{b, out}))

def multiply_digits(left: Nat, +i: U32, state: Operands) -> Array<U32>:
  match left state:
    case 0n Operands{_, _, out}:
      out
    case 1n+p Operands{a, b, out}:
      multiply_digits(p, U32.inc(i), multiply_digits.a(i, b, out, Array.get(U32, a, i)))

def binary_mul(mode: Mode, a: Array<U32>, b: Array<U32>) -> Array<U32>:
  reduce(mode, carry(multiply_digits(32n, 0, Operands{a, b, zero()})))

type Add is Type:
  Add{a: Array<U32>, b: Array<U32>, out: Array<U32>, carry: U32}

def add.b(+i: U32, a: Array<U32>, av: U32, out: Array<U32>, carry: U32, pair: Array<U32> & U32) -> Add:
  (b, bv) = pair
  +sum = U32.add(U32.add(av, bv), carry)
  Add{a, b, Array.set(U32, out, i, U32.and(sum, 255)), U32.shrn(sum, 8n)}

def add.a(+i: U32, b: Array<U32>, out: Array<U32>, carry: U32, pair: Array<U32> & U32) -> Add:
  (a, av) = pair
  add.b(i, a, av, out, carry, Array.get(U32, b, i))

def add.go(left: Nat, +mode: Mode, +i: U32, state: Add) -> Array<U32>:
  match left state:
    case 0n Add{_, _, out, carry}:
      canonical(mode, Array.set(U32, out, 32, carry))
    case 1n+p Add{a, b, out, carry}:
      add.go(p, mode, U32.inc(i), add.a(i, b, out, carry, Array.get(U32, a, i)))

def add(mode: Mode, a: Array<U32>, b: Array<U32>) -> Array<U32>:
  add.go(32n, mode, 0, Add{a, b, zero(), 0})

type Difference is Type:
  Difference{a: Array<U32>, b: Array<U32>, out: Array<U32>, borrow: U32}

def subtract.b(+i: U32, a: Array<U32>, av: U32, out: Array<U32>, borrow: U32, pair: Array<U32> & U32) -> Difference:
  (b, bv) = pair
  +difference = U32.sub(U32.add(av, 256), U32.add(bv, borrow))
  Difference{a, b, Array.set(U32, out, i, U32.and(difference, 255)), U32.sub(1, U32.shrn(difference, 8n))}

def subtract.a(+i: U32, b: Array<U32>, out: Array<U32>, borrow: U32, pair: Array<U32> & U32) -> Difference:
  (a, av) = pair
  subtract.b(i, a, av, out, borrow, Array.get(U32, b, i))

def subtract.go(left: Nat, +i: U32, state: Difference) -> Array<U32> & U32:
  match left state:
    case 0n Difference{_, _, out, borrow}:
      (out, borrow)
    case 1n+p Difference{a, b, out, borrow}:
      subtract.go(p, U32.inc(i), subtract.a(i, b, out, borrow, Array.get(U32, a, i)))

def repair.step(+mode: Mode, +i: U32, +mask: U32, carry: U32, pair: Array<U32> & U32) -> Carry:
  (digits, value) = pair
  +sum = U32.add(U32.add(value, U32.and(modulus_digit(mode, i), mask)), carry)
  Carry{Array.set(U32, digits, i, U32.and(sum, 255)), U32.shrn(sum, 8n)}

def repair.go(left: Nat, +mode: Mode, +i: U32, +mask: U32, state: Carry) -> Array<U32>:
  match left state:
    case 0n Carry{digits, _}:
      digits
    case 1n+p Carry{digits, carry}:
      repair.go(p, mode, U32.inc(i), mask, repair.step(mode, i, mask, carry, Array.get(U32, digits, i)))

def sub.result(mode: Mode, pair: Array<U32> & U32) -> Array<U32>:
  (digits, borrow) = pair
  repair.go(32n, mode, 0, U32.mul(255, borrow), Carry{digits, 0})

def sub(mode: Mode, a: Array<U32>, b: Array<U32>) -> Array<U32>:
  sub.result(mode, subtract.go(32n, 0, Difference{a, b, zero(), 0}))

def decode_bytes(bytes: List<&2, U32>, +i: U32, out: Array<U32>) -> Array<U32>:
  match bytes:
    case Nil{}:
      out
    case Con{byte, tail}:
      decode_bytes(tail, U32.inc(i), Array.set(U32, out, i, byte))

# Caller validates exact length and byte values first. Protocol encodings need
# their own strict canonical/range checks; these arithmetic helpers reduce.
def decode(mode: Mode, bytes: List<&2, U32>) -> Array<U32>:
  canonical(mode, decode_bytes(bytes, 0, zero()))

def decode_wide(mode: Mode, bytes: List<&2, U32>) -> Array<U32>:
  reduce(mode, decode_bytes(bytes, 0, zero()))

def encode_list(left: Nat, xs: List<&1, U32>) -> List<&2, U32>:
  match left xs:
    case 0n _:
      []
    case 1n+p Con{byte, tail}:
      Con{byte, encode_list(p, tail)}
    case _ _:
      []

def encode(xs: Array<U32>) -> List<&2, U32>:
  encode_list(32n, Array.to_list(U32, xs))

def field_r2_digit.word.low(i: Nat) -> U32:
  match i:
    case 0n:
      3
    case 1n:
      0
    case 2n:
      4294967295
    case 3n:
      4294967291
    case _:
      0

def field_r2_digit.word.high(i: Nat) -> U32:
  match i:
    case 0n:
      4294967294
    case 1n:
      4294967295
    case 2n:
      4294967293
    case 3n:
      4
    case _:
      0

def field_r2_digit.word.group(group: Nat, i: Nat) -> U32:
  match group:
    case 0n:
      field_r2_digit.word.low(i)
    case 1n:
      field_r2_digit.word.high(i)
    case _:
      0

def field_r2_digit.word(+i: U32) -> U32:
  field_r2_digit.word.group(U32.to_nat(U32.shrn(i, 2n)), U32.to_nat(U32.and(i, 3)))

def field_r2_digit(+i: U32) -> U32:
  word_byte(field_r2_digit.word(U32.shrn(i, 2n)), i)

def scalar_r2_digit.word.low(i: Nat) -> U32:
  match i:
    case 0n:
      3195661986
    case 1n:
      2200194197
    case 2n:
      1237151654
    case 3n:
      1184463260
    case _:
      0

def scalar_r2_digit.word.high(i: Nat) -> U32:
  match i:
    case 0n:
      728493145
    case 1n:
      675656249
    case 2n:
      4091106848
    case 3n:
      1726033300
    case _:
      0

def scalar_r2_digit.word.group(group: Nat, i: Nat) -> U32:
  match group:
    case 0n:
      scalar_r2_digit.word.low(i)
    case 1n:
      scalar_r2_digit.word.high(i)
    case _:
      0

def scalar_r2_digit.word(+i: U32) -> U32:
  scalar_r2_digit.word.group(U32.to_nat(U32.shrn(i, 2n)), U32.to_nat(U32.and(i, 3)))

def scalar_r2_digit(+i: U32) -> U32:
  word_byte(scalar_r2_digit.word(U32.shrn(i, 2n)), i)

def r2_digit(mode: Mode, i: U32) -> U32:
  match mode:
    case Field{}:
      field_r2_digit(i)
    case Scalar{}:
      scalar_r2_digit(i)

def r2_go(left: Nat, +mode: Mode, +i: U32, out: Array<U32>) -> Array<U32>:
  match left:
    case 0n:
      out
    case 1n+p:
      r2_go(p, mode, U32.inc(i), Array.set(U32, out, i, r2_digit(mode, i)))

def r2(mode: Mode) -> Array<U32>:
  r2_go(32n, mode, 0, zero())

def inverse_low(mode: Mode) -> U32:
  match mode:
    case Field{}:
      1
    case Scalar{}:
      79

# Coarsely integrated byte-limb Montgomery reduction. Inputs are canonical.
# Every inner product sum is <= 255*255 + 255 + 255 = 65535.
# The 34-byte accumulator retains high carry through both row additions;
# shifting removes the canceled low byte. At each outer step T < 2*modulus.
type MontRow is Type:
  MontRow{b: Array<U32>, t: Array<U32>, carry: U32}

def mont.row_t(+j: U32, b: Array<U32>, av: U32, bv: U32, carry: U32, pair: Array<U32> & U32) -> MontRow:
  (t, old) = pair
  +sum = U32.add(U32.add(old, U32.mul(av, bv)), carry)
  MontRow{b, Array.set(U32, t, j, U32.and(sum, 255)), U32.shrn(sum, 8n)}

def mont.row_b(+j: U32, av: U32, t: Array<U32>, carry: U32, pair: Array<U32> & U32) -> MontRow:
  (b, bv) = pair
  mont.row_t(j, b, av, bv, carry, Array.get(U32, t, j))

def mont.row_go(left: Nat, +j: U32, +av: U32, state: MontRow) -> MontRow:
  match left state:
    case 0n MontRow{b, t, carry}:
      MontRow{b, t, carry}
    case 1n+p MontRow{b, t, carry}:
      mont.row_go(p, U32.inc(j), av, mont.row_b(j, av, t, carry, Array.get(U32, b, j)))

def mont.high33(byte32: U32, high: U32, pair: Array<U32> & U32) -> Array<U32>:
  (t, old33) = pair
  Array.set(U32, Array.set(U32, t, 32, byte32), 33, U32.add(old33, high))

def mont.high32(carry: U32, pair: Array<U32> & U32) -> Array<U32>:
  (t, old32) = pair
  +sum = U32.add(old32, carry)
  mont.high33(U32.and(sum, 255), U32.shrn(sum, 8n), Array.get(U32, t, 33))

def mont.mod_step(+mode: Mode, +j: U32, alpha: U32, carry: U32, pair: Array<U32> & U32) -> Carry:
  (t, old) = pair
  +sum = U32.add(U32.add(old, U32.mul(alpha, modulus_digit(mode, j))), carry)
  Carry{Array.set(U32, t, j, U32.and(sum, 255)), U32.shrn(sum, 8n)}

def mont.mod_go(left: Nat, +mode: Mode, +j: U32, +alpha: U32, state: Carry) -> Array<U32>:
  match left state:
    case 0n Carry{t, carry}:
      mont.high32(carry, Array.get(U32, t, 32))
    case 1n+p Carry{t, carry}:
      mont.mod_go(p, mode, U32.inc(j), alpha, mont.mod_step(mode, j, alpha, carry, Array.get(U32, t, j)))

type RightShift is Type:
  RightShift{t: Array<U32>, output: Array<U32>}

def mont.shift_step(+j: U32, output: Array<U32>, pair: Array<U32> & U32) -> RightShift:
  (t, value) = pair
  RightShift{t, Array.set(U32, output, j, value)}

def mont.shift_go(left: Nat, +j: U32, state: RightShift) -> Array<U32>:
  match left state:
    case 0n RightShift{_, output}:
      output
    case 1n+p RightShift{t, output}:
      mont.shift_go(p, U32.inc(j), mont.shift_step(j, output, Array.get(U32, t, U32.inc(j))))

type Montgomery is Type:
  Montgomery{a: Array<U32>, b: Array<U32>, t: Array<U32>}

def mont.low(+mode: Mode, a: Array<U32>, b: Array<U32>, pair: Array<U32> & U32) -> Montgomery:
  (t, low) = pair
  factor = U32.and(U32.mul(low, inverse_low(mode)), 255)
  Montgomery{a, b, mont.shift_go(33n, 0, RightShift{mont.mod_go(32n, mode, 0, factor, Carry{t, 0}), zero()})}

def mont.row_done(mode: Mode, a: Array<U32>, state: MontRow) -> Montgomery:
  match state:
    case MontRow{b, t, carry}:
      mont.low(mode, a, b, Array.get(U32, mont.high32(carry, Array.get(U32, t, 32)), 0))

def mont.a(mode: Mode, b: Array<U32>, t: Array<U32>, pair: Array<U32> & U32) -> Montgomery:
  (a, av) = pair
  mont.row_done(mode, a, mont.row_go(32n, 0, av, MontRow{b, t, 0}))

def mont.go(left: Nat, +mode: Mode, +i: U32, state: Montgomery) -> Array<U32>:
  match left state:
    case 0n Montgomery{_, _, t}:
      canonical(mode, t)
    case 1n+p Montgomery{a, b, t}:
      mont.go(p, mode, U32.inc(i), mont.a(mode, b, t, Array.get(U32, a, i)))

def mont(mode: Mode, a: Array<U32>, b: Array<U32>) -> Array<U32>:
  mont.go(32n, mode, 0, Montgomery{a, b, zero()})

# Two Montgomery products return the ordinary representation:
# mont(mont(a,b), R^2 mod m) = a*b mod m, with R=2^256.
def mul(+mode: Mode, a: Array<U32>, b: Array<U32>) -> Array<U32>:
  mont(mode, mont(mode, a, b), r2(mode))

def square.cloned(mode: Mode, pair: Array<U32> & Array<U32>) -> Array<U32>:
  (a, b) = pair
  mul(mode, a, b)

def square(mode: Mode, a: Array<U32>) -> Array<U32>:
  square.cloned(mode, Array.clone(U32, a))


type Power is Type:
  Power{base: Array<U32>, acc: Array<U32>}

def power.multiplied(mode: Mode, acc: Array<U32>, pair: Array<U32> & Array<U32>) -> Power:
  (base, factor) = pair
  Power{base, mul(mode, acc, factor)}

def power.bit(set: Bool, mode: Mode, state: Power) -> Power:
  match set state:
    case False{} Power{base, acc}:
      Power{base, acc}
    case True{} Power{base, acc}:
      power.multiplied(mode, acc, Array.clone(U32, base))

# The exponent is the public modulus minus two; both low bytes are >= 2.
def power.exponent(+mode: Mode, +at: Nat) -> U32:
  +index = U32.from_nat(Nat.div(at, 8n))
  byte = U32.sub(modulus_digit(mode, index), Bool.pick(U32, U32.is_eq(index, 0), 2, 0))
  U32.and(U32.shrn(byte, Nat.mod(at, 8n)), 1)

def power.advance(+mode: Mode, bit: U32, state: Power) -> Power:
  match state:
    case Power{base, acc}:
      power.bit(U32.is_eq(bit, 1), mode, Power{base, square(mode, acc)})

def power.go(left: Nat, +mode: Mode, state: Power) -> Array<U32>:
  match left state:
    case 0n Power{_, acc}:
      acc
    case 1n+ +p Power{base, acc}:
      power.go(p, mode, power.advance(mode, power.exponent(mode, p), Power{base, acc}))

type ZeroScan is Type:
  ZeroScan{value: Array<U32>, difference: U32}

def zero.step(+i: U32, difference: U32, pair: Array<U32> & U32) -> ZeroScan:
  (value, byte) = pair
  ZeroScan{value, U32.or(difference, byte)}

def zero.go(left: Nat, +i: U32, state: ZeroScan) -> Array<U32> & U32:
  match left state:
    case 0n ZeroScan{value, difference}:
      (value, difference)
    case 1n+p ZeroScan{value, difference}:
      zero.go(p, U32.inc(i), zero.step(i, difference, Array.get(U32, value, i)))

def invert.checked(nonzero: Bool, mode: Mode, value: Array<U32>) -> Maybe<&1, Array<U32>>:
  match nonzero:
    case False{}:
      None{}
    case True{}:
      Some{power.go(256n, mode, Power{value, one()})}

def invert.scanned(mode: Mode, pair: Array<U32> & U32) -> Maybe<&1, Array<U32>>:
  (value, difference) = pair
  invert.checked(U32.is_ne(difference, 0), mode, value)

# Canonical input; zero is explicitly rejected after scanning all 32 bytes.
def invert(mode: Mode, value: Array<U32>) -> Maybe<&1, Array<U32>>:
  invert.scanned(mode, zero.go(32n, 0, ZeroScan{value, 0}))

def decode_canonical.accept(valid: Bool, value: Array<U32>) -> Maybe<&1, Array<U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      Some{value}

def decode_canonical.subtracted(state: SubMod) -> Maybe<&1, Array<U32>>:
  match state:
    case SubMod{original, _, borrow}:
      decode_canonical.accept(U32.is_eq(borrow, 1), original)

def decode_canonical.checked(valid: Bool, mode: Mode, bytes: List<&2, U32>) -> Maybe<&1, Array<U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      decode_canonical.subtracted(subtract_mod.go(33n, mode, 0,
        SubMod{decode_bytes(bytes, 0, zero()), zero(), 0}))

# Strict 32-byte little-endian profile; reject aliases >= the modulus.
def decode_canonical(mode: Mode, +bytes: List<&2, U32>) -> Maybe<&1, Array<U32>>:
  decode_canonical.checked(Bool.and(Nat.is_eq(B.length(bytes), 32n), B.valid(bytes)), mode, bytes)
