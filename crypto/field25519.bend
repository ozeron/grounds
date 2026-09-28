import Base

# Field GF(2^255 - 19). Values are canonical little-endian bytes in a
# 64-cell U32 array; the upper cells are zero outside reduction. A product
# coefficient is at most 32 * 255 * 255 < 2^21.

def zero() -> Array<U32>:
  Array.new(U32, 6n, 0)

def one() -> Array<U32>:
  Array.set(U32, zero(), 0, 1)

def a24() -> Array<U32>:
  Array.set(U32, Array.set(U32, Array.set(U32, zero(), 0, 65), 1, 219), 2, 1)

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

type Fold is Type:
  Fold{source: Array<U32>, out: Array<U32>}

def fold_step.upper1(+i: U32, +low: U32, upper0: U32, out: Array<U32>, r: Array<U32> & U32) -> Fold:
  (source, upper1) = r
  high = U32.and(U32.or(U32.shrn(upper0, 7n), U32.shln(upper1, 1n)), 255)
  digit = Bool.pick(U32, U32.is_eq(i, 31), U32.and(low, 127), low)
  Fold{source, Array.set(U32, out, i, U32.add(digit, U32.mul(19, high)))}

def fold_step.upper0(+i: U32, low: U32, out: Array<U32>, r: Array<U32> & U32) -> Fold:
  (source, upper0) = r
  fold_step.upper1(i, low, upper0, out, Array.get(U32, source, U32.add(i, 32)))

def fold_step.low(+i: U32, out: Array<U32>, r: Array<U32> & U32) -> Fold:
  (source, low) = r
  fold_step.upper0(i, low, out, Array.get(U32, source, U32.add(i, 31)))

def fold_high(left: Nat, +i: U32, state: Fold) -> Array<U32>:
  match left state:
    case 0n Fold{_, out}:
      out
    case 1n+p Fold{source, out}:
      fold_high(p, U32.inc(i), fold_step.low(i, out, Array.get(U32, source, i)))

def fold(xs: Array<U32>) -> Array<U32>:
  fold_high(32n, 0, Fold{xs, zero()})

type SubPrime is Type:
  SubPrime{original: Array<U32>, candidate: Array<U32>, borrow: U32}

def prime_digit(+i: U32) -> U32:
  Bool.pick(U32, U32.is_eq(i, 0), 237, Bool.pick(U32, U32.is_eq(i, 31), 127, 255))

def subtract_prime_step(+i: U32, candidate: Array<U32>, borrow: U32, r: Array<U32> & U32) -> SubPrime:
  (original, value) = r
  +difference = U32.sub(value, U32.add(prime_digit(i), borrow))
  SubPrime{original, Array.set(U32, candidate, i, U32.and(difference, 255)),
    U32.shrn(difference, 31n)}

def subtract_prime(left: Nat, +i: U32, state: SubPrime) -> SubPrime:
  match left state:
    case 0n SubPrime{original, candidate, borrow}:
      SubPrime{original, candidate, borrow}
    case 1n+p SubPrime{original, candidate, borrow}:
      subtract_prime(p, U32.inc(i),
        subtract_prime_step(i, candidate, borrow, Array.get(U32, original, i)))

type Select is Type:
  Select{original: Array<U32>, candidate: Array<U32>, out: Array<U32>}

def select_step.candidate(+i: U32, +mask: U32, original: Array<U32>, a: U32,
                          out: Array<U32>, r: Array<U32> & U32) -> Select:
  (candidate, b) = r
  selected = U32.or(U32.and(a, U32.not(mask)), U32.and(b, mask))
  Select{original, candidate, Array.set(U32, out, i, selected)}

def select_step.original(+i: U32, mask: U32, candidate: Array<U32>, out: Array<U32>,
                         r: Array<U32> & U32) -> Select:
  (original, a) = r
  select_step.candidate(i, mask, original, a, out, Array.get(U32, candidate, i))

def select_canonical(left: Nat, +i: U32, +mask: U32, state: Select) -> Array<U32>:
  match left state:
    case 0n Select{_, _, out}:
      out
    case 1n+p Select{original, candidate, out}:
      select_canonical(p, U32.inc(i), mask,
        select_step.original(i, mask, candidate, out, Array.get(U32, original, i)))

def canonical.choose(state: SubPrime) -> Array<U32>:
  match state:
    case SubPrime{original, candidate, borrow}:
      mask = U32.sub(0, U32.sub(1, borrow))
      select_canonical(32n, 0, mask, Select{original, candidate, zero()})

def canonical(xs: Array<U32>) -> Array<U32>:
  canonical.choose(subtract_prime(32n, 0, SubPrime{xs, zero(), 0}))

# Three folds suffice: after the first, the value is below 20*2^255;
# after the second, below 2^255+380; after the third, below 2^255+19.
def reduce(xs: Array<U32>) -> Array<U32>:
  canonical(carry(fold(carry(fold(carry(fold(carry(xs))))))))

type Operands is Type:
  Operands{a: Array<U32>, b: Array<U32>, out: Array<U32>}

def add_step.b(+i: U32, a: Array<U32>, av: U32, out: Array<U32>, r: Array<U32> & U32) -> Operands:
  (b, bv) = r
  Operands{a, b, Array.set(U32, out, i, U32.add(av, bv))}

def add_step.a(+i: U32, b: Array<U32>, out: Array<U32>, r: Array<U32> & U32) -> Operands:
  (a, av) = r
  add_step.b(i, a, av, out, Array.get(U32, b, i))

def add_digits(left: Nat, +i: U32, state: Operands) -> Array<U32>:
  match left state:
    case 0n Operands{_, _, out}:
      reduce(out)
    case 1n+p Operands{a, b, out}:
      add_digits(p, U32.inc(i), add_step.a(i, b, out, Array.get(U32, a, i)))

def add(a: Array<U32>, b: Array<U32>) -> Array<U32>:
  add_digits(32n, 0, Operands{a, b, zero()})

def sub_step.b(+i: U32, a: Array<U32>, av: U32, out: Array<U32>, r: Array<U32> & U32) -> Operands:
  (b, bv) = r
  digit = U32.sub(U32.add(av, U32.mul(2, prime_digit(i))), bv)
  Operands{a, b, Array.set(U32, out, i, digit)}

def sub_step.a(+i: U32, b: Array<U32>, out: Array<U32>, r: Array<U32> & U32) -> Operands:
  (a, av) = r
  sub_step.b(i, a, av, out, Array.get(U32, b, i))

def sub_digits(left: Nat, +i: U32, state: Operands) -> Array<U32>:
  match left state:
    case 0n Operands{_, _, out}:
      reduce(out)
    case 1n+p Operands{a, b, out}:
      sub_digits(p, U32.inc(i), sub_step.a(i, b, out, Array.get(U32, a, i)))

def sub(a: Array<U32>, b: Array<U32>) -> Array<U32>:
  sub_digits(32n, 0, Operands{a, b, zero()})

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
      reduce(out)
    case 1n+p Operands{a, b, out}:
      multiply_digits(p, U32.inc(i), multiply_digits.a(i, b, out, Array.get(U32, a, i)))

def mul(a: Array<U32>, b: Array<U32>) -> Array<U32>:
  multiply_digits(32n, 0, Operands{a, b, zero()})

def square.cloned(pair: Array<U32> & Array<U32>) -> Array<U32>:
  (a, b) = pair
  mul(a, b)

def square(a: Array<U32>) -> Array<U32>:
  square.cloned(Array.clone(U32, a))

def decode_bytes(bytes: List<&2, U32>, +i: U32, out: Array<U32>) -> Array<U32>:
  match bytes:
    case Nil{}:
      reduce(out)
    case Con{+byte, tail}:
      digit = Bool.pick(U32, U32.is_eq(i, 31), U32.and(byte, 127), byte)
      decode_bytes(tail, U32.inc(i), Array.set(U32, out, i, digit))

# Callers validate the 32-byte length before decoding.
def decode(bytes: List<&2, U32>) -> Array<U32>:
  decode_bytes(bytes, 0, zero())

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
