import Base
import ./bytes.bend as B

# RFC 8439 Poly1305. Numbers are thirteen base-2^10 limbs, low limb first.
# A coefficient is at most (1 + 12*5) * (2^10-1)^2 < 2^26. Products, sums
# and incoming carries stay below 2^26, avoiding full-width unsigned terms.

type Split is Type:
  Split{first: List<&2, U32>, second: List<&2, U32>}

def split_key(left: Nat, key: List<&2, U32>, reversed: List<&2, U32>) -> Split:
  match left key:
    case 0n _:
      Split{List.reverse(&2, U32, reversed), key}
    case 1n+p Con{byte, tail}:
      split_key(p, tail, Con{byte, reversed})
    case _ _:
      Split{[], []}

def clamp_mask(+i: U32) -> U32:
  top = Bool.or(Bool.or(U32.is_eq(i, 3), U32.is_eq(i, 7)),
                Bool.or(U32.is_eq(i, 11), U32.is_eq(i, 15)))
  bottom = Bool.or(Bool.or(U32.is_eq(i, 4), U32.is_eq(i, 8)), U32.is_eq(i, 12))
  Bool.pick(U32, top, 15, Bool.pick(U32, bottom, 252, 255))

def clamp(key: List<&2, U32>, +i: U32) -> List<&2, U32>:
  match key:
    case Nil{}:
      []
    case Con{byte, tail}:
      Con{U32.and(byte, clamp_mask(i)), clamp(tail, U32.inc(i))}

def add_limb(i: U32, value: U32, r: Array<U32> & U32) -> Array<U32>:
  (limbs, old) = r
  Array.set(U32, limbs, i, U32.add(old, value))

def insert_byte(+i: U32, byte: U32, limbs: Array<U32>) -> Array<U32>:
  +position = U32.mul(i, 8)
  +index = U32.div(position, 10)
  offset = U32.mod(position, 10)
  +shifted = U32.shln(byte, U32.to_nat(offset))
  low = U32.and(shifted, 1023)
  high = U32.shrn(shifted, 10n)
  next = add_limb(index, low, Array.get(U32, limbs, index))
  add_limb(U32.inc(index), high, Array.get(U32, next, U32.inc(index)))

type Chunk is Type:
  Chunk{rest: List<&2, U32>, limbs: Array<U32>, count: U32}

def parse(left: Nat, +i: U32, bytes: List<&2, U32>, limbs: Array<U32>) -> Chunk:
  match left bytes:
    case 0n _:
      Chunk{bytes, limbs, i}
    case 1n+p Nil{}:
      Chunk{[], limbs, i}
    case 1n+p Con{byte, tail}:
      parse(p, U32.inc(i), tail, insert_byte(i, byte, limbs))

def padded_chunk(chunk: Chunk) -> Chunk:
  match chunk:
    case Chunk{rest, limbs, +count}:
      Chunk{rest, insert_byte(count, 1, limbs), count}

def carry_cell(+i: U32, carry: U32, r: Array<U32> & U32) -> Array<U32> & U32:
  (limbs, value) = r
  +sum = U32.add(value, carry)
  (Array.set(U32, limbs, i, U32.and(sum, 1023)), U32.shrn(sum, 10n))

type Carry is Type:
  Carry{limbs: Array<U32>, high: U32}

def carry_step(r: Array<U32> & U32) -> Carry:
  (limbs, high) = r
  Carry{limbs, high}

def carry_pass(left: Nat, +i: U32, state: Carry) -> Carry:
  match left state:
    case 0n Carry{limbs, high}:
      Carry{limbs, high}
    case 1n+p Carry{limbs, high}:
      carry_pass(p, U32.inc(i), carry_step(carry_cell(i, high, Array.get(U32, limbs, i))))

def fold_high(state: Carry) -> Array<U32>:
  match state:
    case Carry{limbs, high}:
      add_limb(0, U32.mul(high, 5), Array.get(U32, limbs, 0))

def normalize_once(limbs: Array<U32>) -> Array<U32>:
  fold_high(carry_pass(13n, 0, Carry{limbs, 0}))

# Coefficient k is bounded by (61-4*k)*1023^2. The first high carry is below
# 14k; folding makes only limb zero large. The next high is at most 1.
# If it is 1, limbs 2..12 have become zero, so the following fold/carry cannot
# cascade out again. Three passes suffice; retain five fixed passes. Therefore
# all normalized digits are in 0..1023, including at canonical selection.
def normalize(limbs: Array<U32>) -> Array<U32>:
  normalize_once(normalize_once(normalize_once(normalize_once(normalize_once(limbs)))))

type Added is Type:
  Added{left: Array<U32>, right: Array<U32>, out: Array<U32>}

def add_arrays.right(+i: U32, left: Array<U32>, a: U32, out: Array<U32>, r: Array<U32> & U32) -> Added:
  (right, b) = r
  Added{left, right, Array.set(U32, out, i, U32.add(a, b))}

def add_arrays.left(+i: U32, r: Array<U32> & U32, right: Array<U32>, out: Array<U32>) -> Added:
  (left, a) = r
  add_arrays.right(i, left, a, out, Array.get(U32, right, i))

def add_arrays(left: Nat, +i: U32, state: Added) -> Array<U32>:
  match left state:
    case 0n Added{_, _, out}:
      out
    case 1n+p Added{a, b, out}:
      add_arrays(p, U32.inc(i), add_arrays.left(i, Array.get(U32, a, i), b, out))

type Index is Data:
  Index{at: U32, factor: U32}

def product_index.choose(wrap: Bool, total: U32) -> Index:
  match wrap:
    case True{}:
      Index{U32.sub(total, 13), 5}
    case False{}:
      Index{total, 1}

def product_index(+total: U32) -> Index:
  product_index.choose(U32.is_ge(total, 13), total)

type Product is Type:
  Product{r: Array<U32>, out: Array<U32>}

def product_update.index(+hi: U32, idx: Index, rs: Array<U32>, rj: U32, out: Array<U32>) -> Product:
  match idx:
    case Index{+index, factor}:
      contribution = U32.mul(U32.mul(hi, rj), factor)
      Product{rs, add_limb(index, contribution, Array.get(U32, out, index))}

def product_update(hi: U32, idx: Index, r: Array<U32> & U32, out: Array<U32>) -> Product:
  (rs, rj) = r
  product_update.index(hi, idx, rs, rj, out)

def product_cell(+i: U32, +j: U32, hi: U32, state: Product) -> Product:
  match state:
    case Product{rs, out}:
      product_update(hi, product_index(U32.add(i, j)), Array.get(U32, rs, j), out)

def product_row(left: Nat, +i: U32, +j: U32, +hi: U32, state: Product) -> Product:
  match left:
    case 0n:
      state
    case 1n+p:
      product_row(p, i, U32.inc(j), hi, product_cell(i, j, hi, state))

type Multiply is Type:
  Multiply{h: Array<U32>, r: Array<U32>, out: Array<U32>}

def multiply_row.got(h: Array<U32>, state: Product) -> Multiply:
  match state:
    case Product{next_r, next_out}:
      Multiply{h, next_r, next_out}

def multiply_row(+i: U32, rr: Array<U32> & U32, r: Array<U32>, out: Array<U32>) -> Multiply:
  (h, hi) = rr
  multiply_row.got(h, product_row(13n, i, 0, hi, Product{r, out}))

def multiply(left: Nat, +i: U32, state: Multiply) -> Array<U32>:
  match left state:
    case 0n Multiply{_, _, out}:
      normalize(out)
    case 1n+p Multiply{h, r, out}:
      multiply(p, U32.inc(i), multiply_row(i, Array.get(U32, h, i), r, out))

type Work is Type:
  Work{bytes: List<&2, U32>, r: Array<U32>, acc: Array<U32>}

def process_chunk.r(rest: List<&2, U32>, block: Array<U32>, acc: Array<U32>, rr: Array<U32> & Array<U32>) -> Work:
  (r, next_r) = rr
  summed = add_arrays(13n, 0, Added{acc, block, Array.new(U32, 4n, 0)})
  Work{rest, next_r, multiply(13n, 0, Multiply{normalize(summed), r, Array.new(U32, 4n, 0)})}

def process_chunk(chunk: Chunk, acc: Array<U32>, rr: Array<U32> & Array<U32>) -> Work:
  match chunk:
    case Chunk{rest, block, _}:
      process_chunk.r(rest, block, acc, rr)

def poly_blocks(left: Nat, state: Work) -> Array<U32>:
  match left state:
    case 0n Work{_, _, acc}:
      acc
    case 1n+p Work{bytes, r, acc}:
      poly_blocks(p, process_chunk(padded_chunk(parse(16n, 0, bytes, Array.new(U32, 4n, 0))),
        acc, Array.clone(U32, r)))

def block_count.choose(multiple: Bool, n: Nat) -> Nat:
  match multiple:
    case True{}:
      Nat.div(n, 16n)
    case False{}:
      Nat.add(Nat.div(n, 16n), 1n)

def block_count(+n: Nat) -> Nat:
  block_count.choose(Nat.is_eq(Nat.mod(n, 16n), 0n), n)

type Selection is Type:
  Selection{old: Array<U32>, new: Array<U32>, out: Array<U32>}

def select_new(+i: U32, +mask: U32, old: Array<U32>, a: U32, rr: Array<U32> & U32, out: Array<U32>) -> Selection:
  (new, b) = rr
  value = U32.or(U32.and(a, U32.xor(mask, 1023)), U32.and(b, mask))
  Selection{old, new, Array.set(U32, out, i, value)}

def select_old(+i: U32, mask: U32, rr: Array<U32> & U32, new: Array<U32>, out: Array<U32>) -> Selection:
  (old, a) = rr
  select_new(i, mask, old, a, Array.get(U32, new, i), out)

def select(left: Nat, +i: U32, +mask: U32, state: Selection) -> Array<U32>:
  match left state:
    case 0n Selection{_, _, out}:
      out
    case 1n+p Selection{old, new, out}:
      select(p, U32.inc(i), mask, select_old(i, mask, Array.get(U32, old, i), new, out))

def canonical.carry(old: Array<U32>, state: Carry) -> Array<U32>:
  match state:
    case Carry{new, high}:
      # high is 1 exactly when old + 5 crossed 2^130, i.e. old >= p.
      # Both candidates have 10-bit digits and high is 0/1. Avoid a full-width
      # unsigned negative mask while selecting all bits of either digit.
      select(13n, 0, U32.mul(1023, high), Selection{old, new, Array.new(U32, 4n, 0)})

def canonical.clone(rr: Array<U32> & Array<U32>) -> Array<U32>:
  (old, copy) = rr
  plus5 = add_limb(0, 5, Array.get(U32, copy, 0))
  canonical.carry(old, carry_pass(13n, 0, Carry{plus5, 0}))

def canonical(acc: Array<U32>) -> Array<U32>:
  canonical.clone(Array.clone(U32, acc))

type ByteRead is Type:
  ByteRead{limbs: Array<U32>, byte: U32}

def read_byte.high(+offset: U32, low: U32, rr: Array<U32> & U32) -> ByteRead:
  (limbs, high) = rr
  byte = U32.and(U32.or(U32.shrn(low, U32.to_nat(offset)),
    U32.shln(high, Nat.sub(10n, U32.to_nat(offset)))), 255)
  ByteRead{limbs, byte}

def read_byte.low(+index: U32, offset: U32, rr: Array<U32> & U32) -> ByteRead:
  (limbs, low) = rr
  read_byte.high(offset, low, Array.get(U32, limbs, U32.inc(index)))

def read_byte(i: U32, limbs: Array<U32>) -> ByteRead:
  +position = U32.mul(i, 8)
  +index = U32.div(position, 10)
  offset = U32.mod(position, 10)
  read_byte.low(index, offset, Array.get(U32, limbs, index))

type TagState is Type:
  TagState{limbs: Array<U32>, pad: List<&2, U32>, carry: U32, reversed: List<&2, U32>}

def tag_step(s: U32, pad_tail: List<&2, U32>, carry: U32, reversed: List<&2, U32>, got: ByteRead) -> TagState:
  match got:
    case ByteRead{limbs, byte}:
      +sum = U32.add(U32.add(byte, s), carry)
      TagState{limbs, pad_tail, U32.shrn(sum, 8n), Con{U32.and(sum, 255), reversed}}

def tag_bytes(left: Nat, +i: U32, state: TagState) -> List<&2, U32>:
  match left state:
    case 0n TagState{_, _, _, reversed}:
      List.reverse(&2, U32, reversed)
    case 1n+p TagState{limbs, Con{byte, tail}, carry, reversed}:
      tag_bytes(p, U32.inc(i), tag_step(byte, tail, carry, reversed, read_byte(i, limbs)))
    case _ _:
      []

def parsed_r(chunk: Chunk) -> Array<U32>:
  match chunk:
    case Chunk{_, limbs, _}:
      limbs

def mac.split(data: List<&2, U32>, blocks: Nat, parts: Split) -> List<&2, U32>:
  match parts:
    case Split{first, pad}:
      r = parsed_r(parse(16n, 0, clamp(first, 0), Array.new(U32, 4n, 0)))
      acc = poly_blocks(blocks, Work{data, r, Array.new(U32, 4n, 0)})
      tag_bytes(16n, 0, TagState{canonical(acc), pad, 0, []})

def mac.checked(ok: Bool, key: List<&2, U32>, data: List<&2, U32>, blocks: Nat) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      Some{mac.split(data, blocks, split_key(16n, key, []))}

# A one-time authenticator: the 32-byte key must be unique for every message.
def mac(+key: List<&2, U32>, +data: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  blocks = block_count(B.length(data))
  ok = Bool.and(Bool.and(Nat.is_eq(B.length(key), 32n), B.valid(key)), B.valid(data))
  mac.checked(ok, key, data, blocks)
