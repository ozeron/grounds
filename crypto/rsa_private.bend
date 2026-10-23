import Base
import ./bytes.bend as B
import ./rsa_integer.bend as R
import ./rsa_encoding.bend as E

# RSA-PSS-RSAE/SHA-256 private CRT operation. Synthetic keys only: the
# arithmetic/runtime are not approved for live secrets (RSA_PRIVATE_REVIEW.md).
# Unsigned integers are canonical big endian. Private is affine and consumed
# on success and failure; affine consumption does not physically erase bytes.
type Private is Type:
  Private{n: List<&2, U32>, e: List<&2, U32>, d: List<&2, U32>,
          p: List<&2, U32>, q: List<&2, U32>, dp: List<&2, U32>,
          dq: List<&2, U32>, qi: List<&2, U32>}

def limbs(+modulus: List<&2, U32>) -> Nat:
  Nat.div(Nat.add(R.bit_length(modulus), 14n), 15n)

def value(result: R.ModResult) -> Array<U32>:
  match result:
    case R.ModResult{_, value}:
      value

# Internal fixed-width addition; callers bound the sum below 2^4097.
type Add is Type:
  Add{a: Array<U32>, b: Array<U32>, out: Array<U32>, carry: U32}

def add.b(+i: U32, a: Array<U32>, +av: U32, out: Array<U32>, +carry: U32, pair: Array<U32> & U32) -> Add:
  (b, bv) = pair
  +sum = U32.add(U32.add(av, bv), carry)
  Add{a, b, Array.set(U32, out, i, U32.and(sum, 32767)), U32.shrn(sum, 15n)}

def add.a(+i: U32, b: Array<U32>, out: Array<U32>, +carry: U32, pair: Array<U32> & U32) -> Add:
  (a, av) = pair
  add.b(i, a, av, out, carry, Array.get(U32, b, i))

def add.go(+left: Nat, +i: U32, state: Add) -> Array<U32>:
  match left state:
    case 0n Add{_, _, out, _}:
      out
    case 1n+p Add{a, b, out, carry}:
      add.go(p, U32.inc(i), add.a(i, b, out, carry, Array.get(U32, a, i)))

def add(a: Array<U32>, b: Array<U32>) -> Array<U32>:
  add.go(275n, 0, Add{a, b, R.zero(), 0})

# Schoolbook product. Inputs have at most 137 limbs for p*q and e*dp/dq,
# or at most 274 limbs with a one-limb factor for the internal tests.
type ProductRow is Type:
  ProductRow{b: Array<U32>, out: Array<U32>, carry: U32}

def product.cell(+at: U32, b: Array<U32>, +av: U32, +bv: U32, +carry: U32, pair: Array<U32> & U32) -> ProductRow:
  (out, old) = pair
  +sum = U32.add(U32.add(old, U32.mul(av, bv)), carry)
  ProductRow{b, Array.set(U32, out, at, U32.and(sum, 32767)), U32.shrn(sum, 15n)}

def product.b(+at: U32, +av: U32, out: Array<U32>, +carry: U32, pair: Array<U32> & U32) -> ProductRow:
  (b, bv) = pair
  product.cell(at, b, av, bv, carry, Array.get(U32, out, at))

def product.row(+left: Nat, +at: U32, +j: U32, +av: U32, state: ProductRow) -> ProductRow:
  match left state:
    case 0n ProductRow{b, out, carry}:
      ProductRow{b, R.high(at, carry, out), 0}
    case 1n+p ProductRow{b, out, carry}:
      product.row(p, U32.inc(at), U32.inc(j), av,
        product.b(at, av, out, carry, Array.get(U32, b, j)))

type Product is Type:
  Product{a: Array<U32>, b: Array<U32>, out: Array<U32>}

def product.done(a: Array<U32>, row: ProductRow) -> Product:
  match row:
    case ProductRow{b, out, _}:
      Product{a, b, out}

def product.a(+i: U32, +count: Nat, b: Array<U32>, out: Array<U32>, pair: Array<U32> & U32) -> Product:
  (a, av) = pair
  product.done(a, product.row(count, i, 0, av, ProductRow{b, out, 0}))

def product.finish(state: Product, next: Product -> Array<U32>) -> Array<U32>:
  next(state)

def product.go(+left: Nat, +i: U32, +count: Nat, state: Product) -> Array<U32>:
  match left state:
    case 0n Product{_, _, out}:
      out
    case 1n+p Product{a, b, out}:
      product.finish(product.a(i, count, b, out, Array.get(U32, a, i)),
        s => product.go(p, U32.inc(i), count, s))

def product(+a: List<&2, U32>, +b: List<&2, U32>) -> Array<U32>:
  product.go(limbs(a), 0, limbs(b), Product{R.decode(a), R.decode(b), R.zero()})

# Bitwise reduction also works for even p-1/q-1, unlike Montgomery reduction.
def reduce.increment(+count: Nat, +bit: U32, state: R.ModResult) -> R.ModResult:
  match state:
    case R.ModResult{modulus, value}:
      R.canonical(count, modulus, add.go(Nat.add(count, 1n), 0, Add{value, Array.set(U32, R.zero(), 0, bit), R.zero(), 0}))

def reduce.bits(+left: Nat, +count: Nat, +byte: U32, state: R.ModResult) -> R.ModResult:
  match left state:
    case 0n state:
      state
    case 1n+ +p R.ModResult{modulus, value}:
      reduce.bits(p, count, byte, reduce.increment(count, U32.and(U32.shrn(byte, p), 1), R.double_mod(count, modulus, value)))

def reduce.next(state: R.ModResult, next: R.ModResult -> R.ModResult) -> R.ModResult:
  next(state)

def reduce.bytes(+bytes: List<&2, U32>, +count: Nat, state: R.ModResult) -> R.ModResult:
  match bytes:
    case Nil{}:
      state
    case Con{byte, tail}:
      reduce.next(reduce.bits(8n, count, byte, state), s => reduce.bytes(tail, count, s))

def reduce(+modulus: List<&2, U32>, +bytes: List<&2, U32>) -> List<&2, U32>:
  R.result.encode(B.length(modulus), reduce.bytes(bytes, limbs(modulus), R.ModResult{R.decode(modulus), R.zero()}))

def minus_small.step(+i: U32, +borrow: U32, pair: Array<U32> & U32, next: U32 -> Array<U32> -> Array<U32>) -> Array<U32>:
  (a, digit) = pair
  +difference = U32.sub(U32.add(digit, 32768), borrow)
  next(U32.sub(1, U32.shrn(difference, 15n)), Array.set(U32, a, i, U32.and(difference, 32767)))

def minus_small.go(+left: Nat, +i: U32, +borrow: U32, a: Array<U32>) -> Array<U32>:
  match left:
    case 0n:
      a
    case 1n+p:
      minus_small.step(i, borrow, Array.get(U32, a, i), b => v => minus_small.go(p, U32.inc(i), b, v))

def minus_small(+bytes: List<&2, U32>, +amount: U32) -> List<&2, U32>:
  R.encode(B.length(bytes), minus_small.go(Nat.add(limbs(bytes), 1n), 0, amount, R.decode(bytes)))

def fixed_equal(+width: Nat, +a: List<&2, U32>, +b: List<&2, U32>) -> Bool:
  E.equal(R.encode(width, R.decode(a)), R.encode(width, R.decode(b)))

def canonical(+bytes: List<&2, U32>) -> Bool:
  Bool.and(B.valid(bytes), R.canonical_bytes(bytes))

def odd(+bytes: List<&2, U32>) -> Bool:
  U32.is_eq(U32.and(R.last_byte(bytes, 0), 1), 1)

def smaller(+bytes: List<&2, U32>, +limit: List<&2, U32>) -> Bool:
  Bool.and(canonical(bytes), R.less(bytes, limit))

def factor(+bytes: List<&2, U32>) -> Bool:
  Bool.and(Bool.and(canonical(bytes), odd(bytes)),
    Bool.and(Nat.is_ge(R.bit_length(bytes), 1024n), Nat.is_le(R.bit_length(bytes), 2048n)))

def shape(key: Private) -> Bool:
  match key:
    case Private{+n, +e, +d, +p, +q, +dp, +dq, +qi}:
      Bool.and(Bool.and(Bool.and(canonical(n), odd(n)),
        Bool.and(Nat.is_ge(R.bit_length(n), 2048n), Nat.is_le(R.bit_length(n), 4096n))),
        Bool.and(Bool.and(Bool.and(smaller(e, n), Bool.and(odd(e), R.less([1], e))), Nat.is_le(B.length(e), 4n)),
          Bool.and(Bool.and(smaller(d, n), Bool.and(factor(p), factor(q))),
            Bool.and(Bool.and(Bool.not(E.equal(p, q)), smaller(qi, p)),
              Bool.and(smaller(dp, p), smaller(dq, q))))))

def congruences(key: Private) -> Bool:
  match key:
    case Private{+n, +e, +d, +p, +q, +dp, +dq, +qi}:
      Bool.and(Bool.and(R.less(dp, minus_small(p, 1)), R.less(dq, minus_small(q, 1))),
        Bool.and(E.equal(R.encode(512n, product(p, q)), R.encode(512n, R.decode(n))),
        Bool.and(Bool.and(fixed_equal(B.length(p), reduce(minus_small(p, 1), d), dp),
                         fixed_equal(B.length(q), reduce(minus_small(q, 1), d), dq)),
          Bool.and(Bool.and(fixed_equal(B.length(p), reduce(minus_small(p, 1), R.encode(260n, product(e, dp))), [1]),
                           fixed_equal(B.length(q), reduce(minus_small(q, 1), R.encode(260n, product(e, dq))), [1])),
            fixed_equal(B.length(p), reduce(p, R.encode(512n, product(qi, q))), [1])))))

def validate.congruences(+valid: Bool, key: Private) -> Maybe<&1, Private>:
  match valid:
    case False{}:
      None{}
    case True{}:
      Some{key}

def validate.math(key: Private) -> Maybe<&1, Private>:
  match key:
    case Private{+n, +e, +d, +p, +q, +dp, +dq, +qi}:
      validate.congruences(congruences(Private{n, e, d, p, q, dp, dq, qi}), Private{n, e, d, p, q, dp, dq, qi})

# CRT consistency/ranges only. Factors must originate in trusted RSA key
# generation; this does not replace a prime-generation/primality procedure.
def validate.shape(+valid: Bool, key: Private) -> Maybe<&1, Private>:
  match valid:
    case False{}:
      None{}
    case True{}:
      validate.math(key)

def validate(key: Private) -> Maybe<&1, Private>:
  match key:
    case Private{+n, +e, +d, +p, +q, +dp, +dq, +qi}:
      validate.shape(shape(Private{n, e, d, p, q, dp, dq, qi}), Private{n, e, d, p, q, dp, dq, qi})

# Fixed four-bit windows: four squares and one multiply per nibble. Every
# lookup scans all sixteen table entries and mask-selects their limbs; neither
# branches nor array indexes depend on the private exponent nibble.
type WindowPower is Type:
  WindowPower{modulus: Array<U32>, table: List<Array<U32>>, acc: Array<U32>}

type TableBuild is Type:
  TableBuild{power: R.Power, table: List<Array<U32>>, acc: Array<U32>}

def table.cloned(+count: Nat, +inverse: U32, modulus: Array<U32>, base: Array<U32>, table: List<Array<U32>>, acc: Array<U32>, pair: Array<U32> & Array<U32>, next: TableBuild -> WindowPower) -> WindowPower:
  (value, saved) = pair
  next(TableBuild{R.power.bit(True{}, count, inverse, R.Power{modulus, base, value}), Con{saved, table}, acc})

def table.build(left: Nat, +count: Nat, +inverse: U32, state: TableBuild) -> WindowPower:
  match left state:
    case 0n TableBuild{R.Power{modulus, _, _}, table, acc}:
      WindowPower{modulus, List.reverse(&1, Array<U32>, table), acc}
    case 1n+p TableBuild{R.Power{modulus, base, value}, table, acc}:
      table.cloned(count, inverse, modulus, base, table, acc, Array.clone(U32, value),
        s => table.build(p, count, inverse, s))

type Pick is Type:
  Pick{table: List<Array<U32>>, factor: Array<U32>}

def pick.saved(value: Array<U32>, result: Pick) -> Pick:
  match result:
    case Pick{table, factor}: Pick{Con{value, table}, factor}

def pick.cloned(+count: Nat, +mask: U32, factor: Array<U32>, pair: Array<U32> & Array<U32>, next: Array<U32> -> Pick) -> Pick:
  (value, copy) = pair
  pick.saved(value, next(R.select.go(Nat.add(count, 1n), 0, mask, R.Select{factor, copy, R.zero()})))

def pick.go(table: List<Array<U32>>, +count: Nat, +index: U32, +at: U32, factor: Array<U32>) -> Pick:
  match table:
    case Nil{}: Pick{[], factor}
    case Con{value, tail}:
      # index and at are in 0..15: (index xor at)-1 has its high bit set
      # exactly on equality. All table entries take this same code path.
      mask = U32.mul(32767, U32.shrn(U32.sub(U32.xor(index, at), 1), 31n))
      pick.cloned(count, mask, factor, Array.clone(U32, value),
        f => pick.go(tail, count, index, U32.inc(at), f))

def window.product(table: List<Array<U32>>, result: R.ModResult) -> WindowPower:
  match result:
    case R.ModResult{modulus, acc}: WindowPower{modulus, table, acc}

def window.picked(+count: Nat, inverse: U32, modulus: Array<U32>, acc: Array<U32>, value: Pick) -> WindowPower:
  match value:
    case Pick{table, factor}: window.product(table, R.mont(count, inverse, modulus, acc, factor))

def window.squared(+count: Nat, inverse: U32, index: U32, table: List<Array<U32>>, power: R.Power) -> WindowPower:
  match power:
    case R.Power{modulus, _, acc}:
      window.picked(count, inverse, modulus, acc, pick.go(table, count, index, 0, R.zero()))

def window.step(+count: Nat, +inverse: U32, index: U32, state: WindowPower) -> WindowPower:
  match state:
    case WindowPower{modulus, table, acc}:
      window.squared(count, inverse, index, table,
        R.power.square(count, inverse, R.power.square(count, inverse,
          R.power.square(count, inverse, R.power.square(count, inverse, R.Power{modulus, R.zero(), acc})))))

def window.bytes(exponent: List<&2, U32>, +count: Nat, +inverse: U32, state: WindowPower) -> WindowPower:
  match exponent:
    case Nil{}: state
    case Con{+byte, tail}:
      window.bytes(tail, count, inverse,
        window.step(count, inverse, U32.and(byte, 15), window.step(count, inverse, U32.shrn(byte, 4n), state)))

def window.finished(+count: Nat, inverse: U32, state: WindowPower) -> R.ModResult:
  match state:
    case WindowPower{modulus, _, acc}: R.mont(count, inverse, modulus, acc, R.one())

def window.cloned(+count: Nat, +inverse: U32, exponent: List<&2, U32>, modulus: Array<U32>, base: Array<U32>, pair: Array<U32> & Array<U32>) -> R.ModResult:
  (value, acc) = pair
  window.finished(count, inverse, window.bytes(exponent, count, inverse,
    table.build(16n, count, inverse, TableBuild{R.Power{modulus, base, value}, [], acc})))

def window.start(+count: Nat, inverse: U32, exponent: List<&2, U32>, state: R.Power) -> R.ModResult:
  match state:
    case R.Power{modulus, base, acc}: window.cloned(count, inverse, exponent, modulus, base, Array.clone(U32, acc))

def power.low(+bits: Nat, +count: Nat, +exponent: List<&2, U32>, base: Array<U32>, pair: Array<U32> & U32) -> R.ModResult:
  (modulus, low) = pair
  +inverse = R.inverse_low(low)
  window.start(count, inverse, exponent, R.power.r_squared(count, inverse, base, R.r2(bits, count, modulus)))

def power(+modulus: List<&2, U32>, +exponent: List<&2, U32>, +base: List<&2, U32>) -> List<&2, U32>:
  R.result.encode(B.length(modulus), power.low(R.bit_length(modulus), limbs(modulus), exponent, R.decode(base), Array.get(U32, R.decode(modulus), 0)))

def multiply.second(+count: Nat, +inverse: U32, a: Array<U32>, result: R.ModResult) -> R.ModResult:
  match result:
    case R.ModResult{modulus, converted}:
      R.mont(count, inverse, modulus, a, converted)

def multiply.r2(+count: Nat, +inverse: U32, a: Array<U32>, b: Array<U32>, result: R.ModResult) -> R.ModResult:
  match result:
    case R.ModResult{modulus, r2}:
      multiply.second(count, inverse, a, R.mont(count, inverse, modulus, b, r2))

def multiply.low(+bits: Nat, +count: Nat, a: Array<U32>, b: Array<U32>, pair: Array<U32> & U32) -> R.ModResult:
  (modulus, low) = pair
  multiply.r2(count, R.inverse_low(low), a, b, R.r2(bits, count, modulus))

def multiply(+modulus: List<&2, U32>, +a: List<&2, U32>, +b: List<&2, U32>) -> List<&2, U32>:
  R.result.encode(B.length(modulus), multiply.low(R.bit_length(modulus), limbs(modulus), R.decode(a), R.decode(b), Array.get(U32, R.decode(modulus), 0)))

def inverse.checked(+valid: Bool, +signature: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      Some{signature}

def component.valid(+valid: Bool, +modulus: List<&2, U32>, +exponent: List<&2, U32>, +e: List<&2, U32>, +encoded: List<&2, U32>, +blind: List<&2, U32>, +inverse: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      Some{multiply(modulus, power(modulus, exponent,
        multiply(modulus, encoded, power(modulus, e, blind))), inverse)}

def component.inverse(+modulus: List<&2, U32>, +exponent: List<&2, U32>, +e: List<&2, U32>, +encoded: List<&2, U32>, +blind: List<&2, U32>, +inverse: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  component.valid(fixed_equal(B.length(modulus), multiply(modulus, blind, inverse), [1]), modulus, exponent, e, encoded, blind, inverse)

def component(+modulus: List<&2, U32>, +exponent: List<&2, U32>, +e: List<&2, U32>, +encoded: List<&2, U32>, +blind: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  component.inverse(modulus, exponent, e, reduce(modulus, encoded), reduce(modulus, blind),
    power(modulus, minus_small(modulus, 2), reduce(modulus, blind)))

# CRT recombination m2 + q * (((m1 - m2) mod p) * q^-1 mod p).
def difference.sub(+modulus: List<&2, U32>, state: R.Subtract) -> List<&2, U32>:
  match state:
    case R.Subtract{_, _, candidate, _}:
      R.result.encode(B.length(modulus), R.canonical(limbs(modulus), R.decode(modulus), candidate))

def difference(+modulus: List<&2, U32>, +a: List<&2, U32>, +b: List<&2, U32>) -> List<&2, U32>:
  difference.sub(modulus, R.subtract.go(Nat.add(limbs(modulus), 1n), 0,
    R.Subtract{R.decode(b), add.go(Nat.add(limbs(modulus), 1n), 0, Add{R.decode(a), R.decode(modulus), R.zero(), 0}), R.zero(), 0}))

def crt.q(key: Private, +m1: List<&2, U32>, result: Maybe<&1, List<&2, U32>>) -> Maybe<&1, List<&2, U32>>:
  match key result:
    case Private{+n, _, _, +p, +q, _, _, qi} Some{+m2}:
      Some{R.encode(B.length(n), add(R.decode(m2), product(q, multiply(p, difference(p, m1, reduce(p, m2)), qi))))}
    case _ _:
      None{}

def crt.p(key: Private, +encoded: List<&2, U32>, +blind: List<&2, U32>, result: Maybe<&1, List<&2, U32>>) -> Maybe<&1, List<&2, U32>>:
  match key result:
    case Private{n, +e, d, p, +q, dp, +dq, qi} Some{m1}:
      crt.q(Private{n, e, d, p, q, dp, dq, qi}, m1, component(q, dq, e, encoded, blind))
    case _ _:
      None{}

def crt(key: Private, +encoded: List<&2, U32>, +blind: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match key:
    case Private{n, +e, d, +p, q, +dp, dq, qi}:
      crt.p(Private{n, e, d, p, q, dp, dq, qi}, encoded, blind, component(p, dp, e, encoded, blind))

def fault.recovered(+expected: List<&2, U32>, +signature: List<&2, U32>, recovered: Maybe<&2, List<&2, U32>>) -> Maybe<&1, List<&2, U32>>:
  match recovered:
    case None{}:
      None{}
    case Some{recovered}:
      inverse.checked(E.equal(expected, recovered), signature)

def fault(+n: List<&2, U32>, +e: List<&2, U32>, +expected: List<&2, U32>, signature: Maybe<&1, List<&2, U32>>) -> Maybe<&1, List<&2, U32>>:
  match signature:
    case None{}:
      None{}
    case Some{+signature}:
      fault.recovered(expected, signature, R.public_operation(n, e, signature))

def sign.encoded(key: Private, +blind: List<&2, U32>, encoded: Maybe<&2, List<&2, U32>>) -> Maybe<&1, List<&2, U32>>:
  match key encoded:
    case Private{+n, +e, d, p, q, dp, dq, qi} Some{+encoded}:
      fault(n, e, B.append(List.replicate(U32, Nat.sub(B.length(n), B.length(encoded)), 0), encoded),
        crt(Private{n, e, d, p, q, dp, dq, qi}, encoded, blind))
    case _ _:
      None{}

def sign.valid(+valid: Bool, key: Private, +digest: List<&2, U32>, +salt: List<&2, U32>, +blind: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid key:
    case True{} Private{+n, e, d, p, q, dp, dq, qi}:
      sign.encoded(Private{n, e, d, p, q, dp, dq, qi}, blind, E.pss_encode_digest(Nat.sub(R.bit_length(n), 1n), digest, salt))
    case _ _:
      None{}

def sign.key(key: Maybe<&1, Private>, +digest: List<&2, U32>, +salt: List<&2, U32>, +blind: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match key:
    case None{}:
      None{}
    case Some{Private{+n, e, d, p, q, dp, dq, qi}}:
      sign.valid(Bool.and(Bool.and(E.valid_digest(digest), E.valid_digest(salt)),
        Bool.and(Bool.and(B.valid(blind), Nat.is_eq(B.length(blind), B.length(n))),
          Bool.and(R.less(R.encode(B.length(n), R.one()), blind), R.less(blind, n)))),
        Private{n, e, d, p, q, dp, dq, qi}, digest, salt, blind)

# Draw salt=32 bytes and blind=k bytes freshly from the host RNG per attempt.
# Never reduce a candidate into range. None consumes the key; abort, or retain
# a separate owner-controlled credential and retry with fresh RNG material.
# Invertibility is checked for each CRT factor, and the final public operation
# must recover the exact PSS encoding before any signature is released.
def sign_digest(key: Private, +digest: List<&2, U32>, +salt: List<&2, U32>, +blind: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  sign.key(validate(key), digest, salt, blind)
