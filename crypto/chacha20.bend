import Base
import ./bytes.bend as B

# RFC 8439 IETF ChaCha20: 256-bit key, 96-bit nonce, 32-bit block counter.
# This is the block primitive. A caller must never reuse a (key, nonce) pair.

type Quarter is Data:
  Quarter{a: U32, b: U32, c: U32, d: U32}

def rotl(+x: U32, +n: Nat) -> U32:
  U32.or(U32.shln(x, n), U32.shrn(x, Nat.sub(32n, n)))

def quarter(q: Quarter) -> Quarter:
  match q:
    case Quarter{a, +b, c, d}:
      +a1 = U32.add(a, b)
      +d1 = rotl(U32.xor(d, a1), 16n)
      +c1 = U32.add(c, d1)
      +b1 = rotl(U32.xor(b, c1), 12n)
      +a2 = U32.add(a1, b1)
      +d2 = rotl(U32.xor(d1, a2), 8n)
      +c2 = U32.add(c1, d2)
      b2 = rotl(U32.xor(b1, c2), 7n)
      Quarter{a2, b2, c2, d2}

def write_quarter(+ia: U32, +ib: U32, +ic: U32, id: U32, a: Array<U32>, q: Quarter) -> Array<U32>:
  match q:
    case Quarter{wa, wb, wc, wd}:
      Array.set(U32, Array.set(U32, Array.set(U32, Array.set(U32, a, ia, wa), ib, wb), ic, wc), id, wd)

def read_d(+ia: U32, +ib: U32, +ic: U32, +id: U32, a: U32, b: U32, c: U32, r: Array<U32> & U32) -> Array<U32>:
  (xs, d) = r
  write_quarter(ia, ib, ic, id, xs, quarter(Quarter{a, b, c, d}))

def read_c(+ia: U32, +ib: U32, +ic: U32, +id: U32, a: U32, b: U32, r: Array<U32> & U32) -> Array<U32>:
  (xs, c) = r
  read_d(ia, ib, ic, id, a, b, c, Array.get(U32, xs, id))

def read_b(+ia: U32, +ib: U32, +ic: U32, +id: U32, a: U32, r: Array<U32> & U32) -> Array<U32>:
  (xs, b) = r
  read_c(ia, ib, ic, id, a, b, Array.get(U32, xs, ic))

def read_a(+ia: U32, +ib: U32, +ic: U32, +id: U32, r: Array<U32> & U32) -> Array<U32>:
  (xs, a) = r
  read_b(ia, ib, ic, id, a, Array.get(U32, xs, ib))

def round_quarter(+ia: U32, +ib: U32, +ic: U32, +id: U32, xs: Array<U32>) -> Array<U32>:
  read_a(ia, ib, ic, id, Array.get(U32, xs, ia))

def double_round(xs: Array<U32>) -> Array<U32>:
  c0 = round_quarter(0, 4, 8, 12, xs)
  c1 = round_quarter(1, 5, 9, 13, c0)
  c2 = round_quarter(2, 6, 10, 14, c1)
  c3 = round_quarter(3, 7, 11, 15, c2)
  d0 = round_quarter(0, 5, 10, 15, c3)
  d1 = round_quarter(1, 6, 11, 12, d0)
  d2 = round_quarter(2, 7, 8, 13, d1)
  round_quarter(3, 4, 9, 14, d2)

def rounds(left: Nat, xs: Array<U32>) -> Array<U32>:
  match left:
    case 0n:
      xs
    case 1n+p:
      rounds(p, double_round(xs))

def le_word(a: U32, b: U32, c: U32, d: U32) -> U32:
  U32.or(U32.or(U32.or(a, U32.shln(b, 8n)), U32.shln(c, 16n)), U32.shln(d, 24n))

def write_values(words: List<&2, U32>, +i: U32, xs: Array<U32>) -> Array<U32>:
  match words:
    case Nil{}:
      xs
    case Con{word, tail}:
      write_values(tail, U32.inc(i), Array.set(U32, xs, i, word))

def read_words(left: Nat, +i: U32, bytes: List<&2, U32>, xs: Array<U32>) -> Array<U32>:
  match left bytes:
    case 0n _:
      xs
    case 1n+p Con{a, Con{b, Con{c, Con{d, tail}}}}:
      read_words(p, U32.inc(i), tail, Array.set(U32, xs, i, le_word(a, b, c, d)))
    case _ _:
      xs

def initial(key: List<&2, U32>, nonce: List<&2, U32>, counter: U32) -> Array<U32>:
  constants = write_values([1634760805, 857760878, 2036477234, 1797285236], 0, Array.new(U32, 4n, 0))
  with_key = read_words(8n, 4, key, constants)
  with_count = Array.set(U32, with_key, 12, counter)
  read_words(3n, 13, nonce, with_count)

type Arrays is Type:
  Arrays{original: Array<U32>, working: Array<U32>}

def add_word.got(+i: U32, original: Array<U32>, a: U32, r: Array<U32> & U32) -> Arrays:
  (working, b) = r
  Arrays{original, Array.set(U32, working, i, U32.add(a, b))}

def add_word(+i: U32, r: Array<U32> & U32, working: Array<U32>) -> Arrays:
  (original, a) = r
  add_word.got(i, original, a, Array.get(U32, working, i))

def add_all(left: Nat, +i: U32, r: Arrays) -> Array<U32>:
  match left r:
    case 0n Arrays{_, working}:
      working
    case 1n+p Arrays{original, working}:
      add_all(p, U32.inc(i), add_word(i, Array.get(U32, original, i), working))

def word_bytes(+x: U32, tail: List<&2, U32>) -> List<&2, U32>:
  Con{U32.and(x, 255),
    Con{U32.and(U32.shrn(x, 8n), 255),
      Con{U32.and(U32.shrn(x, 16n), 255),
        Con{U32.shrn(x, 24n), tail}}}}

type Serial is Type:
  Serial{words: Array<U32>, tail: List<&2, U32>}

def serialize_step(r: Array<U32> & U32, tail: List<&2, U32>) -> Serial:
  (words, word) = r
  Serial{words, word_bytes(word, tail)}

def serialize(left: Nat, st: Serial) -> List<&2, U32>:
  match left st:
    case 0n Serial{_, tail}:
      tail
    case 1n+ +p Serial{words, tail}:
      serialize(p, serialize_step(Array.get(U32, words, U32.from_nat(p)), tail))

def block.from_clone(r: Array<U32> & Array<U32>) -> List<&2, U32>:
  (original, working) = r
  serialize(16n, Serial{add_all(16n, 0, Arrays{original, rounds(10n, working)}), []})

def block.raw(key: List<&2, U32>, nonce: List<&2, U32>, counter: U32) -> List<&2, U32>:
  block.from_clone(Array.clone(U32, initial(key, nonce, counter)))

def block.checked(ok: Bool, key: List<&2, U32>, nonce: List<&2, U32>, counter: U32) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      Some{block.raw(key, nonce, counter)}

def block(+key: List<&2, U32>, +nonce: List<&2, U32>, counter: U32) -> Maybe<&2, List<&2, U32>>:
  ok = Bool.and(Bool.and(Nat.is_eq(B.length(key), 32n), B.valid(key)),
                Bool.and(Nat.is_eq(B.length(nonce), 12n), B.valid(nonce)))
  block.checked(ok, key, nonce, counter)

type Xored is Type:
  Xored{rest: List<&2, U32>, reversed: List<&2, U32>}

def xor_take(left: Nat, bytes: List<&2, U32>, stream: List<&2, U32>, reversed: List<&2, U32>) -> Xored:
  match left bytes stream:
    case 0n _ _:
      Xored{bytes, reversed}
    case 1n+p Nil{} _:
      Xored{[], reversed}
    case 1n+p Con{byte, tail} Con{key_byte, next}:
      xor_take(p, tail, next, Con{U32.xor(byte, key_byte), reversed})
    case _ _ _:
      Xored{[], reversed}

type CryptState is Type:
  CryptState{bytes: List<&2, U32>, reversed: List<&2, U32>}

def advance(r: Xored) -> CryptState:
  match r:
    case Xored{bytes, reversed}:
      CryptState{bytes, reversed}

def crypt_blocks(left: Nat, +key: List<&2, U32>, +nonce: List<&2, U32>, +counter: U32, state: CryptState) -> List<&2, U32>:
  match left state:
    case 0n CryptState{_, reversed}:
      List.reverse(&2, U32, reversed)
    case 1n+p CryptState{bytes, reversed}:
      next = advance(xor_take(64n, bytes, block.raw(key, nonce, counter), reversed))
      crypt_blocks(p, key, nonce, U32.inc(counter), next)

def crypt.checked(ok: Bool, key: List<&2, U32>, nonce: List<&2, U32>, counter: U32, bytes: List<&2, U32>, blocks: Nat) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      Some{crypt_blocks(blocks, key, nonce, counter, CryptState{bytes, []})}

def block_count.choose(is_multiple: Bool, n: Nat) -> Nat:
  match is_multiple:
    case True{}:
      Nat.div(n, 64n)
    case False{}:
      Nat.add(Nat.div(n, 64n), 1n)

def block_count(+n: Nat) -> Nat:
  block_count.choose(Nat.is_eq(Nat.mod(n, 64n), 0n), n)

def within_limit.choose(is_zero: Bool, counter: U32, blocks: Nat) -> Bool:
  match is_zero:
    case True{}:
      True{}
    case False{}:
      Nat.is_le(blocks, Nat.add(Nat.sub(4294967295n, U32.to_nat(counter)), 1n))

def within_limit(+counter: U32, blocks: Nat) -> Bool:
  within_limit.choose(U32.is_eq(counter, 0), counter, blocks)

# XOR a message with the ChaCha20 stream. This also decrypts. A request that
# would wrap the 32-bit block counter is rejected rather than reusing stream.
def crypt(+key: List<&2, U32>, +nonce: List<&2, U32>, +counter: U32, +bytes: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  +blocks = block_count(B.length(bytes))
  ok = Bool.and(Bool.and(Nat.is_eq(B.length(key), 32n), B.valid(key)),
                Bool.and(Bool.and(Nat.is_eq(B.length(nonce), 12n), B.valid(nonce)),
                  Bool.and(B.valid(bytes), within_limit(counter, blocks))))
  crypt.checked(ok, key, nonce, counter, bytes, blocks)
