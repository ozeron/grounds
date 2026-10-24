import Base
import ./bytes.bend as B

# SHA-512 / SHA-384 (FIPS 180-4 / RFC 6234). The public digest rejects values outside
# the byte range; the compression function only sees validated bytes.

type State is Data:
  State{a: W64, b: W64, c: W64, d: W64, e: W64, f: W64, g: W64, h: W64}

def initial() -> State:
  State{W64{1779033703, 4089235720}, W64{3144134277, 2227873595}, W64{1013904242, 4271175723}, W64{2773480762, 1595750129}, W64{1359893119, 2917565137}, W64{2600822924, 725511199}, W64{528734635, 4215389547}, W64{1541459225, 327033209}}

def initial384() -> State:
  State{W64{3418070365, 3238371032}, W64{1654270250, 914150663}, W64{2438529370, 812702999}, W64{355462360, 4144912697}, W64{1731405415, 4290775857}, W64{2394180231, 1750603025}, W64{3675008525, 1694076839}, W64{1203062813, 3204075428}}

def constants() -> List<&2, W64>:
  [W64{1116352408, 3609767458},
   W64{1899447441, 602891725},
   W64{3049323471, 3964484399},
   W64{3921009573, 2173295548},
   W64{961987163, 4081628472},
   W64{1508970993, 3053834265},
   W64{2453635748, 2937671579},
   W64{2870763221, 3664609560},
   W64{3624381080, 2734883394},
   W64{310598401, 1164996542},
   W64{607225278, 1323610764},
   W64{1426881987, 3590304994},
   W64{1925078388, 4068182383},
   W64{2162078206, 991336113},
   W64{2614888103, 633803317},
   W64{3248222580, 3479774868},
   W64{3835390401, 2666613458},
   W64{4022224774, 944711139},
   W64{264347078, 2341262773},
   W64{604807628, 2007800933},
   W64{770255983, 1495990901},
   W64{1249150122, 1856431235},
   W64{1555081692, 3175218132},
   W64{1996064986, 2198950837},
   W64{2554220882, 3999719339},
   W64{2821834349, 766784016},
   W64{2952996808, 2566594879},
   W64{3210313671, 3203337956},
   W64{3336571891, 1034457026},
   W64{3584528711, 2466948901},
   W64{113926993, 3758326383},
   W64{338241895, 168717936},
   W64{666307205, 1188179964},
   W64{773529912, 1546045734},
   W64{1294757372, 1522805485},
   W64{1396182291, 2643833823},
   W64{1695183700, 2343527390},
   W64{1986661051, 1014477480},
   W64{2177026350, 1206759142},
   W64{2456956037, 344077627},
   W64{2730485921, 1290863460},
   W64{2820302411, 3158454273},
   W64{3259730800, 3505952657},
   W64{3345764771, 106217008},
   W64{3516065817, 3606008344},
   W64{3600352804, 1432725776},
   W64{4094571909, 1467031594},
   W64{275423344, 851169720},
   W64{430227734, 3100823752},
   W64{506948616, 1363258195},
   W64{659060556, 3750685593},
   W64{883997877, 3785050280},
   W64{958139571, 3318307427},
   W64{1322822218, 3812723403},
   W64{1537002063, 2003034995},
   W64{1747873779, 3602036899},
   W64{1955562222, 1575990012},
   W64{2024104815, 1125592928},
   W64{2227730452, 2716904306},
   W64{2361852424, 442776044},
   W64{2428436474, 593698344},
   W64{2756734187, 3733110249},
   W64{3204031479, 2999351573},
   W64{3329325298, 3815920427},
   W64{3391569614, 3928383900},
   W64{3515267271, 566280711},
   W64{3940187606, 3454069534},
   W64{4118630271, 4000239992},
   W64{116418474, 1914138554},
   W64{174292421, 2731055270},
   W64{289380356, 3203993006},
   W64{460393269, 320620315},
   W64{685471733, 587496836},
   W64{852142971, 1086792851},
   W64{1017036298, 365543100},
   W64{1126000580, 2618297676},
   W64{1288033470, 3409855158},
   W64{1501505948, 4234509866},
   W64{1607167915, 987167468},
   W64{1816402316, 1246189591}]

type W64 is Data:
  W64{high: U32, low: U32}

# Unsigned carry bit from Boolean gates, with no value-dependent control flow.
def add(a: W64, b: W64) -> W64:
  match a b:
    case W64{ah, +al} W64{bh, +bl}:
      +lo = U32.add(al, bl)
      carry = U32.shrn(U32.or(U32.and(al, bl), U32.and(U32.or(al, bl), U32.not(lo))), 31n)
      W64{U32.add(U32.add(ah, bh), carry), lo}

def xor(a: W64, b: W64) -> W64:
  match a b:
    case W64{ah, al} W64{bh, bl}: W64{U32.xor(ah, bh), U32.xor(al, bl)}

def and(a: W64, b: W64) -> W64:
  match a b:
    case W64{ah, al} W64{bh, bl}: W64{U32.and(ah, bh), U32.and(al, bl)}

def not(a: W64) -> W64:
  match a:
    case W64{h, l}: W64{U32.not(h), U32.not(l)}

# Rotation count is a public algorithm constant. All calls use 1..63.
def rotr.parts(big: Bool, +n: Nat, +h: U32, +l: U32) -> W64:
  match big:
    case False{}:
      W64{U32.or(U32.shrn(h, n), U32.shln(l, Nat.sub(32n, n))),
        U32.or(U32.shrn(l, n), U32.shln(h, Nat.sub(32n, n)))}
    case True{}:
      W64{U32.or(U32.shrn(l, Nat.sub(n, 32n)), U32.shln(h, Nat.sub(64n, n))),
        U32.or(U32.shrn(h, Nat.sub(n, 32n)), U32.shln(l, Nat.sub(64n, n)))}

def rotr(a: W64, +n: Nat) -> W64:
  match a:
    case W64{h, l}: rotr.parts(Nat.is_gt(n, 32n), n, h, l)

# Only the public counts 6 and 7 are used by SHA-512's small sigmas.
def shr(a: W64, +n: Nat) -> W64:
  match a:
    case W64{+h, l}:
      W64{U32.shrn(h, n), U32.or(U32.shrn(l, n), U32.shln(h, Nat.sub(32n, n)))}

def small0(+x: W64) -> W64:
  xor(xor(rotr(x, 1n), rotr(x, 8n)), shr(x, 7n))

def small1(+x: W64) -> W64:
  xor(xor(rotr(x, 19n), rotr(x, 61n)), shr(x, 6n))

def big0(+x: W64) -> W64:
  xor(xor(rotr(x, 28n), rotr(x, 34n)), rotr(x, 39n))

def big1(+x: W64) -> W64:
  xor(xor(rotr(x, 14n), rotr(x, 18n)), rotr(x, 41n))

def choose(+x: W64, y: W64, z: W64) -> W64:
  xor(and(x, y), and(not(x), z))

def majority(+x: W64, +y: W64, +z: W64) -> W64:
  xor(xor(and(x, y), and(x, z)), and(y, z))

def step(s: State, k: W64, w: W64) -> State:
  match s:
    case State{+a, +b, +c, d, +e, +f, +g, h}:
      +t1 = add(add(add(add(h, big1(e)), choose(e, f, g)), k), w)
      t2 = add(big0(a), majority(a, b, c))
      State{add(t1, t2), a, b, c, add(d, t1), e, f, g}

def word(+a: U32, +b: U32, +c: U32, d: U32) -> U32:
  U32.or(U32.or(U32.or(U32.shln(a, 24n), U32.shln(b, 16n)), U32.shln(c, 8n)), d)

def read_words(left: Nat, +i: U32, bs: List<&2, U32>, ws: Array<W64>) -> List<&2, U32> & Array<W64>:
  match left bs:
    case 0n _: (bs, ws)
    case 1n+p Con{a, Con{b, Con{c, Con{d, Con{e, Con{f, Con{g, Con{h, tail}}}}}}}}:
      read_words(p, U32.inc(i), tail, Array.set(W64, ws, i, W64{word(a, b, c, d), word(e, f, g, h)}))
    case _ _: ([], ws)

def expand.got16(+i: U32, a: W64, b: W64, c: W64, r: Array<W64> & W64) -> Array<W64>:
  (ws, d) = r
  next = add(add(add(small1(a), b), small0(c)), d)
  Array.set(W64, ws, i, next)

def expand.got15(+i: U32, a: W64, b: W64, r: Array<W64> & W64) -> Array<W64>:
  (ws, c) = r
  expand.got16(i, a, b, c, Array.get(W64, ws, U32.sub(i, 16)))

def expand.got7(+i: U32, a: W64, r: Array<W64> & W64) -> Array<W64>:
  (ws, b) = r
  expand.got15(i, a, b, Array.get(W64, ws, U32.sub(i, 15)))

def expand.got2(+i: U32, r: Array<W64> & W64) -> Array<W64>:
  (ws, a) = r
  expand.got7(i, a, Array.get(W64, ws, U32.sub(i, 7)))

def expand(left: Nat, +i: U32, ws: Array<W64>) -> Array<W64>:
  match left:
    case 0n:
      ws
    case 1n+p:
      expand(p, U32.inc(i), expand.got2(i, Array.get(W64, ws, U32.sub(i, 2))))

type Cursor is Type:
  Cursor{ws: Array<W64>, word: W64, state: State}

def cursor(r: Array<W64> & W64, state: State) -> Cursor:
  (ws, word) = r
  Cursor{ws, word, state}

def rounds(ks: List<&2, W64>, +i: U32, cur: Cursor) -> State:
  match ks cur:
    case Nil{} Cursor{_, _, state}:
      state
    case Con{k, tail} Cursor{ws, w, state}:
      rounds(tail, U32.inc(i), cursor(Array.get(W64, ws, U32.inc(i)), step(state, k, w)))

def add_state(old: State, work: State) -> State:
  match old work:
    case State{a, b, c, d, e, f, g, h} State{aa, bb, cc, dd, ee, ff, gg, hh}:
      State{add(a, aa), add(b, bb), add(c, cc), add(d, dd),
            add(e, ee), add(f, ff), add(g, gg), add(h, hh)}

def block.got(+s: State, r: List<&2, U32> & Array<W64>) -> List<&2, U32> & State:
  (tail, first) = r
  ws = expand(64n, 16, first)
  (tail, add_state(s, rounds(constants(), 0, cursor(Array.get(W64, ws, 0), s))))

def block(bs: List<&2, U32>, s: State) -> List<&2, U32> & State:
  block.got(s, read_words(16n, 0, bs, Array.new(W64, 7n, W64{0, 0})))

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
  used = Nat.mod(Nat.add(n, 1n), 128n)
  zeros = Nat.mod(Nat.add(112n, Nat.sub(128n, used)), 128n)
  B.append(bs,
    Con{128, B.append(List.replicate(U32, zeros, 0),
      length_bytes(16n, Nat.mul(n, 8n), []))})

def word_bytes(+x: U32, rest: List<&2, U32>) -> List<&2, U32>:
  Con{U32.and(U32.shrn(x, 24n), 255),
    Con{U32.and(U32.shrn(x, 16n), 255),
      Con{U32.and(U32.shrn(x, 8n), 255),
        Con{U32.and(x, 255), rest}}}}

def bytes(w: W64, rest: List<&2, U32>) -> List<&2, U32>:
  match w:
    case W64{h, l}: word_bytes(h, word_bytes(l, rest))

def output(s: State) -> List<&2, U32>:
  match s:
    case State{a, b, c, d, e, f, g, h}:
      bytes(a, bytes(b, bytes(c, bytes(d,
        bytes(e, bytes(f, bytes(g, bytes(h, []))))))))

def valid(bs: List<&2, U32>) -> Bool:
  B.valid(bs)

def digest.padded(state: State, +bs: List<&2, U32>) -> State:
  blocks(Nat.div(B.length(bs), 128n), Chain{bs, state})

def digest.checked(ok: Bool, state: State, bs: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      Some{output(digest.padded(state, padded(bs)))}

def digest(+bs: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  digest.checked(valid(bs), initial(), bs)

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
