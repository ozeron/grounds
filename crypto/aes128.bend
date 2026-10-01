import Base
import ./bytes.bend as B

# FIPS 197 AES-128 encryption. Byte limbs keep every arithmetic value bounded;
# the S-box uses GF(2^8) inversion/affine arithmetic, never a secret table index.
# Round/key indices and GF multiplication's eight iterations are public/fixed.
# This source form does not establish generated-runtime/JIT timing or erasure.

def xtime(+x: U32) -> U32:
  U32.xor(U32.and(U32.shln(x, 1n), 255), U32.mul(27, U32.shrn(x, 7n)))

def mul.go(left: Nat, +a: U32, +b: U32, out: U32) -> U32:
  match left:
    case 0n:
      out
    case 1n+p:
      mul.go(p, xtime(a), U32.shrn(b, 1n),
        U32.xor(out, U32.and(a, U32.mul(255, U32.and(b, 1)))))

def mul(a: U32, b: U32) -> U32:
  mul.go(8n, a, b, 0)

def square(+x: U32) -> U32:
  a = U32.xor(U32.and(x, 1), U32.mul(4, U32.and(U32.shrn(x, 1n), 1)))
  b = U32.xor(U32.mul(16, U32.and(U32.shrn(x, 2n), 1)), U32.mul(64, U32.and(U32.shrn(x, 3n), 1)))
  c = U32.xor(U32.mul(27, U32.and(U32.shrn(x, 4n), 1)), U32.mul(108, U32.and(U32.shrn(x, 5n), 1)))
  d = U32.xor(U32.mul(171, U32.and(U32.shrn(x, 6n), 1)), U32.mul(154, U32.and(U32.shrn(x, 7n), 1)))
  U32.xor(U32.xor(a, b), U32.xor(c, d))

def rotate(+x: U32, +bits: Nat) -> U32:
  U32.and(U32.or(U32.shln(x, bits), U32.shrn(x, Nat.sub(8n, bits))), 255)

def affine(+inverse: U32) -> U32:
  U32.xor(99, U32.xor(inverse, U32.xor(rotate(inverse, 1n),
    U32.xor(rotate(inverse, 2n), U32.xor(rotate(inverse, 3n), rotate(inverse, 4n))))))

def sbox(+x: U32) -> U32:
  +a2 = square(x)
  +a3 = mul(x, a2)
  a6 = square(a3)
  +a12 = square(a6)
  a15 = mul(a12, a3)
  a30 = square(a15)
  a60 = square(a30)
  a120 = square(a60)
  a240 = square(a120)
  a252 = mul(a240, a12)
  affine(mul(a252, a2))

def from_bytes(bytes: List<&2, U32>, +i: U32, out: Array<U32>) -> Array<U32>:
  match bytes:
    case Nil{}:
      out
    case Con{byte, tail}:
      from_bytes(tail, U32.inc(i), Array.set(U32, out, i, byte))

type Expanded is Type:
  Expanded{keys: Array<U32>, rcon: U32}

def expand.write(+i: U32, rcon: U32, transformed: U32, pair: Array<U32> & U32) -> Expanded:
  (keys, old) = pair
  Expanded{Array.set(U32, keys, i, U32.xor(old, transformed)), rcon}

def expand.rcon(first: Bool, end: Bool, +rcon: U32, byte: U32) -> U32 & U32:
  (Bool.pick(U32, end, xtime(rcon), rcon), U32.xor(byte, Bool.pick(U32, first, rcon, 0)))

def expand.subword(+i: U32, keys: Array<U32>, pair: U32 & U32) -> Expanded:
  (rcon, transformed) = pair
  expand.write(i, rcon, transformed, Array.get(U32, keys, U32.sub(i, 16)))

def expand.got(first_word: Bool, +i: U32, +rcon: U32, pair: Array<U32> & U32) -> Expanded:
  match first_word:
    case False{}:
      (keys, byte) = pair
      expand.write(i, rcon, byte, Array.get(U32, keys, U32.sub(i, 16)))
    case True{}:
      (keys, byte) = pair
      expand.subword(i, keys, expand.rcon(U32.is_eq(U32.mod(i, 4), 0),
        U32.is_eq(U32.mod(i, 4), 3), rcon, sbox(byte)))

def expand.index(first_word: Bool, +i: U32) -> U32:
  match first_word:
    case False{}:
      U32.sub(i, 4)
    case True{}:
      U32.add(U32.sub(U32.sub(i, U32.mod(i, 4)), 4), U32.mod(U32.inc(i), 4))

def expand.byte(+i: U32, keys: Array<U32>, rcon: U32) -> Expanded:
  +first_word = U32.is_lt(U32.mod(i, 16), 4)
  expand.got(first_word, i, rcon, Array.get(U32, keys, expand.index(first_word, i)))

def expand.go(left: Nat, +i: U32, state: Expanded) -> Array<U32>:
  match left state:
    case 0n Expanded{keys, _}:
      keys
    case 1n+p Expanded{keys, rcon}:
      expand.go(p, U32.inc(i), expand.byte(i, keys, rcon))

def expand.raw(key: List<&2, U32>) -> Array<U32>:
  expand.go(160n, 16, Expanded{from_bytes(key, 0, Array.new(U32, 8n, 0)), 1})

type Shift is Type:
  Shift{input: Array<U32>, output: Array<U32>}

def shifted.write(i: U32, output: Array<U32>, pair: Array<U32> & U32) -> Shift:
  (input, value) = pair
  Shift{input, Array.set(U32, output, i, sbox(value))}

def shifted.go(left: Nat, +i: U32, state: Shift) -> Array<U32>:
  match left state:
    case 0n Shift{_, output}:
      output
    case 1n+p Shift{input, output}:
      +row = U32.mod(i, 4)
      column = U32.div(i, 4)
      source = U32.add(row, U32.mul(4, U32.mod(U32.add(column, row), 4)))
      shifted.go(p, U32.inc(i), shifted.write(i, output, Array.get(U32, input, source)))

def shifted(input: Array<U32>) -> Array<U32>:
  shifted.go(16n, 0, Shift{input, Array.new(U32, 4n, 0)})

def mix.write(+i: U32, +a: U32, +b: U32, +c: U32, +d: U32, state: Array<U32>) -> Array<U32>:
  +total = U32.xor(U32.xor(a, b), U32.xor(c, d))
  oa = U32.xor(U32.xor(a, total), xtime(U32.xor(a, b)))
  ob = U32.xor(U32.xor(b, total), xtime(U32.xor(b, c)))
  oc = U32.xor(U32.xor(c, total), xtime(U32.xor(c, d)))
  od = U32.xor(U32.xor(d, total), xtime(U32.xor(d, a)))
  Array.set(U32, Array.set(U32, Array.set(U32, Array.set(U32, state, i, oa),
    U32.inc(i), ob), U32.add(i, 2), oc), U32.add(i, 3), od)

def mix.d(i: U32, a: U32, b: U32, c: U32, pair: Array<U32> & U32) -> Array<U32>:
  (state, d) = pair
  mix.write(i, a, b, c, d, state)

def mix.c(+i: U32, a: U32, b: U32, pair: Array<U32> & U32) -> Array<U32>:
  (state, c) = pair
  mix.d(i, a, b, c, Array.get(U32, state, U32.add(i, 3)))

def mix.b(+i: U32, a: U32, pair: Array<U32> & U32) -> Array<U32>:
  (state, b) = pair
  mix.c(i, a, b, Array.get(U32, state, U32.add(i, 2)))

def mix.a(+i: U32, pair: Array<U32> & U32) -> Array<U32>:
  (state, a) = pair
  mix.b(i, a, Array.get(U32, state, U32.inc(i)))

def mixed(left: Nat, +i: U32, state: Array<U32>) -> Array<U32>:
  match left:
    case 0n:
      state
    case 1n+p:
      mixed(p, U32.add(i, 4), mix.a(i, Array.get(U32, state, i)))

type Round is Type:
  Round{keys: Array<U32>, state: Array<U32>}

def add.key(i: U32, state: Array<U32>, value: U32, pair: Array<U32> & U32) -> Round:
  (keys, key) = pair
  Round{keys, Array.set(U32, state, i, U32.xor(value, key))}

def add.state(+i: U32, round: U32, keys: Array<U32>, pair: Array<U32> & U32) -> Round:
  (state, value) = pair
  add.key(i, state, value, Array.get(U32, keys, U32.add(U32.mul(round, 16), i)))

def add(left: Nat, +i: U32, +round: U32, work: Round) -> Round:
  match left work:
    case 0n Round{keys, state}:
      Round{keys, state}
    case 1n+p Round{keys, state}:
      add(p, U32.inc(i), round, add.state(i, round, keys, Array.get(U32, state, i)))

def rounds(left: Nat, +round: U32, work: Round) -> Round:
  match left work:
    case 0n Round{keys, state}:
      add(16n, 0, 10, Round{keys, shifted(state)})
    case 1n+p Round{keys, state}:
      rounds(p, U32.inc(round), add(16n, 0, round, Round{keys, mixed(4n, 0, shifted(state))}))

type Output is Type:
  Output{state: Array<U32>, reversed: List<&2, U32>}

def bytes.got(reversed: List<&2, U32>, pair: Array<U32> & U32) -> Output:
  (state, value) = pair
  Output{state, Con{value, reversed}}

def bytes(left: Nat, +i: U32, output: Output) -> List<&2, U32>:
  match left output:
    case 0n Output{_, reversed}:
      List.reverse(&2, U32, reversed)
    case 1n+p Output{state, reversed}:
      bytes(p, U32.inc(i), bytes.got(reversed, Array.get(U32, state, i)))

def finished(work: Round) -> Array<U32> & List<&2, U32>:
  match work:
    case Round{keys, state}:
      (keys, bytes(16n, 0, Output{state, []}))

# Internal prepared-key interface: exactly 16 valid block bytes.
def block(keys: Array<U32>, input: List<&2, U32>) -> Array<U32> & List<&2, U32>:
  finished(rounds(9n, 1, add(16n, 0, 0, Round{keys, from_bytes(input, 0, Array.new(U32, 4n, 0))})))

def encrypt.got(pair: Array<U32> & List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  (_, output) = pair
  Some{output}

def encrypt.checked(ok: Bool, key: List<&2, U32>, input: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      encrypt.got(block(expand.raw(key), input))

def encrypt(+key: List<&2, U32>, +input: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  encrypt.checked(Bool.and(Bool.and(Nat.is_eq(B.length(key), 16n), B.valid(key)),
    Bool.and(Nat.is_eq(B.length(input), 16n), B.valid(input))), key, input)
