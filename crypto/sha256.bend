import Base
import ./bytes.bend as B

# SHA-256 (FIPS 180-4 / RFC 6234). The public digest rejects values outside
# the byte range; the compression function only sees validated bytes.

type State is Data:
  State{a: U32, b: U32, c: U32, d: U32, e: U32, f: U32, g: U32, h: U32}

def initial() -> State:
  State{1779033703, 3144134277, 1013904242, 2773480762,
        1359893119, 2600822924, 528734635, 1541459225}

def constants() -> List<&2, U32>:
  [1116352408, 1899447441, 3049323471, 3921009573, 961987163,
   1508970993, 2453635748, 2870763221, 3624381080, 310598401,
   607225278, 1426881987, 1925078388, 2162078206, 2614888103,
   3248222580, 3835390401, 4022224774, 264347078, 604807628,
   770255983, 1249150122, 1555081692, 1996064986, 2554220882,
   2821834349, 2952996808, 3210313671, 3336571891, 3584528711,
   113926993, 338241895, 666307205, 773529912, 1294757372,
   1396182291, 1695183700, 1986661051, 2177026350, 2456956037,
   2730485921, 2820302411, 3259730800, 3345764771, 3516065817,
   3600352804, 4094571909, 275423344, 430227734, 506948616,
   659060556, 883997877, 958139571, 1322822218, 1537002063,
   1747873779, 1955562222, 2024104815, 2227730452, 2361852424,
   2428436474, 2756734187, 3204031479, 3329325298]

def rotr(+x: U32, +n: Nat) -> U32:
  U32.or(U32.shrn(x, n), U32.shln(x, Nat.sub(32n, n)))

def small0(+x: U32) -> U32:
  U32.xor(U32.xor(rotr(x, 7n), rotr(x, 18n)), U32.shrn(x, 3n))

def small1(+x: U32) -> U32:
  U32.xor(U32.xor(rotr(x, 17n), rotr(x, 19n)), U32.shrn(x, 10n))

def big0(+x: U32) -> U32:
  U32.xor(U32.xor(rotr(x, 2n), rotr(x, 13n)), rotr(x, 22n))

def big1(+x: U32) -> U32:
  U32.xor(U32.xor(rotr(x, 6n), rotr(x, 11n)), rotr(x, 25n))

def choose(+x: U32, y: U32, z: U32) -> U32:
  U32.xor(U32.and(x, y), U32.and(U32.not(x), z))

def majority(+x: U32, +y: U32, +z: U32) -> U32:
  U32.xor(U32.xor(U32.and(x, y), U32.and(x, z)), U32.and(y, z))

def step(s: State, k: U32, w: U32) -> State:
  match s:
    case State{+a, +b, +c, d, +e, +f, +g, h}:
      +t1 = U32.add(U32.add(U32.add(U32.add(h, big1(e)), choose(e, f, g)), k), w)
      t2 = U32.add(big0(a), majority(a, b, c))
      State{U32.add(t1, t2), a, b, c, U32.add(d, t1), e, f, g}

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

def expand.got16(+i: U32, a: U32, b: U32, c: U32, r: Array<U32> & U32) -> Array<U32>:
  (ws, d) = r
  next = U32.add(U32.add(U32.add(small1(a), b), small0(c)), d)
  Array.set(U32, ws, i, next)

def expand.got15(+i: U32, a: U32, b: U32, r: Array<U32> & U32) -> Array<U32>:
  (ws, c) = r
  expand.got16(i, a, b, c, Array.get(U32, ws, U32.sub(i, 16)))

def expand.got7(+i: U32, a: U32, r: Array<U32> & U32) -> Array<U32>:
  (ws, b) = r
  expand.got15(i, a, b, Array.get(U32, ws, U32.sub(i, 15)))

def expand.got2(+i: U32, r: Array<U32> & U32) -> Array<U32>:
  (ws, a) = r
  expand.got7(i, a, Array.get(U32, ws, U32.sub(i, 7)))

def expand(left: Nat, +i: U32, ws: Array<U32>) -> Array<U32>:
  match left:
    case 0n:
      ws
    case 1n+p:
      expand(p, U32.inc(i), expand.got2(i, Array.get(U32, ws, U32.sub(i, 2))))

type Cursor is Type:
  Cursor{ws: Array<U32>, word: U32, state: State}

def cursor(r: Array<U32> & U32, state: State) -> Cursor:
  (ws, word) = r
  Cursor{ws, word, state}

def rounds(ks: List<&2, U32>, +i: U32, cur: Cursor) -> State:
  match ks cur:
    case Nil{} Cursor{_, _, state}:
      state
    case Con{k, tail} Cursor{ws, w, state}:
      rounds(tail, U32.inc(i), cursor(Array.get(U32, ws, U32.inc(i)), step(state, k, w)))

def add_state(old: State, work: State) -> State:
  match old work:
    case State{a, b, c, d, e, f, g, h} State{aa, bb, cc, dd, ee, ff, gg, hh}:
      State{U32.add(a, aa), U32.add(b, bb), U32.add(c, cc), U32.add(d, dd),
            U32.add(e, ee), U32.add(f, ff), U32.add(g, gg), U32.add(h, hh)}

def block.got(+s: State, r: List<&2, U32> & Array<U32>) -> List<&2, U32> & State:
  (tail, first) = r
  ws = expand(48n, 16, first)
  (tail, add_state(s, rounds(constants(), 0, cursor(Array.get(U32, ws, 0), s))))

def block(bs: List<&2, U32>, s: State) -> List<&2, U32> & State:
  block.got(s, read_words(16n, 0, bs, Array.new(U32, 6n, 0)))

type Chain is Type:
  Chain{bytes: List<&2, U32>, state: State}

def chain(r: List<&2, U32> & State) -> Chain:
  match r:
    case (bytes, state):
      Chain{bytes, state}

def blocks(fuel: Nat, ch: Chain) -> State:
  match fuel ch:
    case 0n Chain{_, state}:
      state
    case 1n+p Chain{bytes, state}:
      blocks(p, chain(block(bytes, state)))

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
  B.append(bs,
    Con{128, B.append(List.replicate(U32, zeros, 0),
      length_bytes(8n, Nat.mul(n, 8n), []))})

def word_bytes(+x: U32, rest: List<&2, U32>) -> List<&2, U32>:
  Con{U32.and(U32.shrn(x, 24n), 255),
    Con{U32.and(U32.shrn(x, 16n), 255),
      Con{U32.and(U32.shrn(x, 8n), 255),
        Con{U32.and(x, 255), rest}}}}

def output(s: State) -> List<&2, U32>:
  match s:
    case State{a, b, c, d, e, f, g, h}:
      word_bytes(a, word_bytes(b, word_bytes(c, word_bytes(d,
        word_bytes(e, word_bytes(f, word_bytes(g, word_bytes(h, []))))))))

def valid(bs: List<&2, U32>) -> Bool:
  B.valid(bs)

def digest.padded(+bs: List<&2, U32>) -> State:
  blocks(Nat.div(B.length(bs), 64n), Chain{bs, initial()})

def digest.checked(ok: Bool, bs: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      Some{output(digest.padded(padded(bs)))}

def digest(+bs: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  digest.checked(valid(bs), bs)

def hex_digit(+n: U32) -> Char:
  Char.from_u32(Bool.pick(U32, U32.is_lt(n, 10), U32.add(48, n), U32.add(87, n)))

def hex(bs: List<&2, U32>) -> String:
  B.hex(bs)

def digest_hex.got(r: Maybe<&2, List<&2, U32>>) -> Maybe<&2, String>:
  match r:
    case None{}:
      None{}
    case Some{bytes}:
      Some{hex(bytes)}

def digest_hex(bs: List<&2, U32>) -> Maybe<&2, String>:
  digest_hex.got(digest(bs))
