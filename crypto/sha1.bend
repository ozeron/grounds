import Base
import ./bytes.bend as B

# SHA-1 (FIPS 180-4), for the RFC 6455 WebSocket handshake. This legacy hash
# is not suitable for signatures or collision-resistant protocol decisions.

type State is Data:
  State{a: U32, b: U32, c: U32, d: U32, e: U32}

def initial() -> State:
  State{1732584193, 4023233417, 2562383102, 271733878, 3285377520}

def rotl(+x: U32, +n: Nat) -> U32:
  U32.or(U32.shln(x, n), U32.shrn(x, Nat.sub(32n, n)))

def word(+a: U32, +b: U32, +c: U32, d: U32) -> U32:
  U32.or(U32.or(U32.or(U32.shln(a, 24n), U32.shln(b, 16n)), U32.shln(c, 8n)), d)

def read_words(left: Nat, +i: U32, bs: List<&2, U32>, ws: Array<U32>) -> List<&2, U32> & Array<U32>:
  match left bs:
    case 0n _:
      (bs, ws)
    case 1n+p Con{a, Con{b, Con{c, Con{d, tail}}}}:
      read_words(p, U32.inc(i), tail, Array.set(U32, ws, i, word(a, b, c, d)))
    case _ _:
      ([], ws)

def expand.last(+i: U32, +a: U32, +b: U32, +c: U32, r: Array<U32> & U32) -> Array<U32>:
  (ws, d) = r
  Array.set(U32, ws, i, rotl(U32.xor(U32.xor(a, b), U32.xor(c, d)), 1n))

def expand.c(+i: U32, a: U32, b: U32, r: Array<U32> & U32) -> Array<U32>:
  (ws, c) = r
  expand.last(i, a, b, c, Array.get(U32, ws, U32.sub(i, 16)))

def expand.b(+i: U32, a: U32, r: Array<U32> & U32) -> Array<U32>:
  (ws, b) = r
  expand.c(i, a, b, Array.get(U32, ws, U32.sub(i, 14)))

def expand.a(+i: U32, r: Array<U32> & U32) -> Array<U32>:
  (ws, a) = r
  expand.b(i, a, Array.get(U32, ws, U32.sub(i, 8)))

def expand(left: Nat, +i: U32, ws: Array<U32>) -> Array<U32>:
  match left:
    case 0n:
      ws
    case 1n+p:
      expand(p, U32.inc(i), expand.a(i, Array.get(U32, ws, U32.sub(i, 3))))

def choose(+b: U32, c: U32, d: U32) -> U32:
  U32.or(U32.and(b, c), U32.and(U32.not(b), d))

def majority(+b: U32, +c: U32, +d: U32) -> U32:
  U32.or(U32.or(U32.and(b, c), U32.and(b, d)), U32.and(c, d))

def round_f(+i: U32, +b: U32, +c: U32, +d: U32) -> U32:
  Bool.pick(U32, U32.is_lt(i, 20), choose(b, c, d),
    Bool.pick(U32, U32.is_lt(i, 40), U32.xor(U32.xor(b, c), d),
      Bool.pick(U32, U32.is_lt(i, 60), majority(b, c, d), U32.xor(U32.xor(b, c), d))))

def round_k(+i: U32) -> U32:
  Bool.pick(U32, U32.is_lt(i, 20), 1518500249,
    Bool.pick(U32, U32.is_lt(i, 40), 1859775393,
      Bool.pick(U32, U32.is_lt(i, 60), 2400959708, 3395469782)))

def step(state: State, +i: U32, w: U32) -> State:
  match state:
    case State{+a, +b, +c, +d, +e}:
      temp = U32.add(U32.add(U32.add(U32.add(rotl(a, 5n), round_f(i, b, c, d)), e), round_k(i)), w)
      State{temp, a, rotl(b, 30n), c, d}

type Cursor is Type:
  Cursor{words: Array<U32>, word: U32, state: State}

def cursor(r: Array<U32> & U32, state: State) -> Cursor:
  (words, word) = r
  Cursor{words, word, state}

def rounds(left: Nat, +i: U32, current: Cursor) -> State:
  match left current:
    case 0n Cursor{_, _, state}:
      state
    case 1n+p Cursor{words, word, state}:
      rounds(p, U32.inc(i), cursor(Array.get(U32, words, U32.inc(i)), step(state, i, word)))

def add_state(old: State, work: State) -> State:
  match old work:
    case State{a, b, c, d, e} State{aa, bb, cc, dd, ee}:
      State{U32.add(a, aa), U32.add(b, bb), U32.add(c, cc), U32.add(d, dd), U32.add(e, ee)}

def block.got(+state: State, r: List<&2, U32> & Array<U32>) -> List<&2, U32> & State:
  (tail, first) = r
  words = expand(64n, 16, first)
  (tail, add_state(state, rounds(80n, 0, cursor(Array.get(U32, words, 0), state))))

def block(bs: List<&2, U32>, state: State) -> List<&2, U32> & State:
  block.got(state, read_words(16n, 0, bs, Array.new(U32, 7n, 0)))

type Chain is Type:
  Chain{bytes: List<&2, U32>, state: State}

def chain(r: List<&2, U32> & State) -> Chain:
  match r:
    case (bytes, state):
      Chain{bytes, state}

def blocks(left: Nat, state: Chain) -> State:
  match left state:
    case 0n Chain{_, hash}:
      hash
    case 1n+p Chain{bytes, hash}:
      blocks(p, chain(block(bytes, hash)))

def length_bytes(left: Nat, +bits: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match left:
    case 0n:
      acc
    case 1n+p:
      length_bytes(p, Nat.div(bits, 256n), Con{U32.from_nat(Nat.mod(bits, 256n)), acc})

def padded(+bs: List<&2, U32>) -> List<&2, U32>:
  +n = B.length(bs)
  used = Nat.mod(Nat.add(n, 1n), 64n)
  zeros = Nat.mod(Nat.add(56n, Nat.sub(64n, used)), 64n)
  B.append(bs, Con{128, B.append(List.replicate(U32, zeros, 0),
    length_bytes(8n, Nat.mul(n, 8n), []))})

def word_bytes(+x: U32, rest: List<&2, U32>) -> List<&2, U32>:
  Con{U32.and(U32.shrn(x, 24n), 255),
    Con{U32.and(U32.shrn(x, 16n), 255),
      Con{U32.and(U32.shrn(x, 8n), 255), Con{U32.and(x, 255), rest}}}}

def output(state: State) -> List<&2, U32>:
  match state:
    case State{a, b, c, d, e}:
      word_bytes(a, word_bytes(b, word_bytes(c, word_bytes(d, word_bytes(e, [])))))

def digest.checked(ok: Bool, bytes: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      +prepared = padded(bytes)
      Some{output(blocks(Nat.div(B.length(prepared), 64n), Chain{prepared, initial()}))}

def digest(+bytes: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  digest.checked(B.valid(bytes), bytes)
