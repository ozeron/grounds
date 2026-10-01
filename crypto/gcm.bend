import Base
import ./bytes.bend as B
import ./aes128.bend as AES

# SP 800-38D / RFC 5116 AEAD_AES_128_GCM: 96-bit nonce, full 128-bit tag.
# Callers must ensure nonce uniqueness under each key. All field limbs are
# 16-bit; GHASH uses fixed 128-bit multiplication without secret table indices.
# These source properties do not establish generated-runtime timing safety.

type Sealed is Data:
  Sealed{ciphertext: List<&2, U32>, tag: List<&2, U32>}

type Field is Data:
  Field{a: U32, b: U32, c: U32, d: U32, e: U32, f: U32, g: U32, h: U32}

def zero() -> Field:
  Field{0, 0, 0, 0, 0, 0, 0, 0}

def field(bytes: List<&2, U32>) -> Field:
  match bytes:
    case Con{a, Con{b, Con{c, Con{d, Con{e, Con{f, Con{g, Con{h,
      Con{i, Con{j, Con{k, Con{l, Con{m, Con{n, Con{o, Con{p, Nil{}}}}}}}}}}}}}}}}}:
      Field{U32.add(U32.mul(a, 256), b), U32.add(U32.mul(c, 256), d),
        U32.add(U32.mul(e, 256), f), U32.add(U32.mul(g, 256), h),
        U32.add(U32.mul(i, 256), j), U32.add(U32.mul(k, 256), l),
        U32.add(U32.mul(m, 256), n), U32.add(U32.mul(o, 256), p)}
    case _:
      zero()

def word16(+word: U32, tail: List<&2, U32>) -> List<&2, U32>:
  Con{U32.shrn(word, 8n), Con{U32.and(word, 255), tail}}

def field.bytes(value: Field) -> List<&2, U32>:
  match value:
    case Field{a, b, c, d, e, f, g, h}:
      word16(a, word16(b, word16(c, word16(d, word16(e, word16(f, word16(g, word16(h, []))))))))

def field.xor(x: Field, y: Field) -> Field:
  match x y:
    case Field{a, b, c, d, e, f, g, h} Field{i, j, k, l, m, n, o, p}:
      Field{U32.xor(a, i), U32.xor(b, j), U32.xor(c, k), U32.xor(d, l),
        U32.xor(e, m), U32.xor(f, n), U32.xor(g, o), U32.xor(h, p)}

def field.mask(+mask: U32, value: Field) -> Field:
  match value:
    case Field{a, b, c, d, e, f, g, h}:
      Field{U32.and(a, mask), U32.and(b, mask), U32.and(c, mask), U32.and(d, mask),
        U32.and(e, mask), U32.and(f, mask), U32.and(g, mask), U32.and(h, mask)}

def shifted(+current: U32, previous: U32) -> U32:
  U32.or(U32.shrn(current, 1n), U32.mul(32768, U32.and(previous, 1)))

def field.shift(value: Field) -> Field:
  match value:
    case Field{+a, +b, +c, +d, +e, +f, +g, +h}:
      Field{U32.xor(U32.shrn(a, 1n), U32.mul(57600, U32.and(h, 1))),
        shifted(b, a), shifted(c, b), shifted(d, c), shifted(e, d),
        shifted(f, e), shifted(g, f), shifted(h, g)}

type Product is Data:
  Product{v: Field, z: Field}

def multiply.word(left: Nat, +word: U32, product: Product) -> Product:
  match left product:
    case 0n Product{v, z}:
      Product{v, z}
    case 1n+ +p Product{+v, z}:
      mask = U32.mul(65535, U32.and(U32.shrn(word, p), 1))
      multiply.word(p, word, Product{field.shift(v), field.xor(z, field.mask(mask, v))})

def multiply.go(bytes: List<&2, U32>, product: Product) -> Field:
  match bytes product:
    case Nil{} Product{_, z}:
      z
    case Con{a, Con{b, tail}} _:
      multiply.go(tail, multiply.word(16n, U32.add(U32.mul(a, 256), b), product))
    case _ _:
      zero()

def multiply(x: Field, y: Field) -> Field:
  multiply.go(field.bytes(x), Product{y, zero()})

type Chunk is Data:
  Chunk{block: List<&2, U32>, tail: List<&2, U32>}

def split(left: Nat, bytes: List<&2, U32>, reversed: List<&2, U32>) -> Chunk:
  match left bytes:
    case 0n _:
      Chunk{List.reverse(&2, U32, reversed), bytes}
    case 1n+p Con{byte, tail}:
      split(p, tail, Con{byte, reversed})
    case _ Nil{}:
      Chunk{List.reverse(&2, U32, reversed), []}

type Hash is Data:
  Hash{bytes: List<&2, U32>, digest: Field}

def hash.next(chunk: Chunk, h: Field, digest: Field) -> Hash:
  match chunk:
    case Chunk{+block, tail}:
      padded = B.append(block, List.replicate(U32, Nat.sub(16n, B.length(block)), 0))
      Hash{tail, multiply(field.xor(digest, field(padded)), h)}

def hash.go(left: Nat, +h: Field, state: Hash) -> Field:
  match left state:
    case 0n Hash{_, digest}:
      digest
    case 1n+p Hash{bytes, digest}:
      hash.go(p, h, hash.next(split(16n, bytes, []), h, digest))

def word32(+word: U32) -> List<&2, U32>:
  word16(U32.shrn(word, 16n), word16(U32.and(word, 65535), []))

# Split before multiplying: a 48-bit byte length's bit count does not fit Nat.
# The high/low U32 words remain bounded even at the largest representable Nat.
def length64(+bytes: Nat) -> List<&2, U32>:
  B.append(word32(U32.from_nat(Nat.div(bytes, 536870912n))),
    word32(U32.from_nat(Nat.mul(Nat.mod(bytes, 536870912n), 8n))))

def block_count(+length: Nat) -> Nat:
  Nat.add(Nat.div(length, 16n), Bool.pick(Nat, Nat.is_eq(Nat.mod(length, 16n), 0n), 0n, 1n))

def hash.final(h: Field, aad_length: Nat, ciphertext_length: Nat, digest: Field) -> Field:
  lengths = B.append(length64(aad_length), length64(ciphertext_length))
  multiply(field.xor(digest, field(lengths)), h)

def hash.cipher(+h: Field, +ciphertext: List<&2, U32>, aad_length: Nat, digest: Field) -> Field:
  +length = B.length(ciphertext)
  hash.final(h, aad_length, length, hash.go(block_count(length), h, Hash{ciphertext, digest}))

def hash(+h: Field, +aad: List<&2, U32>, +ciphertext: List<&2, U32>) -> Field:
  +length = B.length(aad)
  hash.cipher(h, ciphertext, length, hash.go(block_count(length), h, Hash{aad, zero()}))

type Crypt is Type:
  Crypt{keys: Array<U32>, bytes: List<&2, U32>, reversed: List<&2, U32>}

def crypt.xor(stream: List<&2, U32>, bytes: List<&2, U32>, reversed: List<&2, U32>) -> List<&2, U32> & List<&2, U32>:
  match stream bytes:
    case Con{a, at} Con{b, bt}:
      crypt.xor(at, bt, Con{U32.xor(a, b), reversed})
    case _ _:
      (bytes, reversed)

def crypt.output(keys: Array<U32>, pair: List<&2, U32> & List<&2, U32>) -> Crypt:
  (bytes, reversed) = pair
  Crypt{keys, bytes, reversed}

def crypt.block(bytes: List<&2, U32>, reversed: List<&2, U32>, pair: Array<U32> & List<&2, U32>) -> Crypt:
  (keys, stream) = pair
  crypt.output(keys, crypt.xor(stream, bytes, reversed))

def crypt.go(left: Nat, +nonce: List<&2, U32>, +counter: U32, work: Crypt) -> Array<U32> & List<&2, U32>:
  match left work:
    case 0n Crypt{keys, _, reversed}:
      (keys, List.reverse(&2, U32, reversed))
    case 1n+p Crypt{keys, bytes, reversed}:
      crypt.go(p, nonce, U32.inc(counter),
        crypt.block(bytes, reversed, AES.block(keys, B.append(nonce, word32(counter)))))

def crypt(keys: Array<U32>, nonce: List<&2, U32>, +bytes: List<&2, U32>) -> Array<U32> & List<&2, U32>:
  crypt.go(block_count(B.length(bytes)), nonce, 2, Crypt{keys, bytes, []})

def tag.mask(h: Field, aad: List<&2, U32>, ciphertext: List<&2, U32>, pair: Array<U32> & List<&2, U32>) -> Array<U32> & List<&2, U32>:
  (keys, mask) = pair
  (keys, field.bytes(field.xor(field(mask), hash(h, aad, ciphertext))))

def tag.h(nonce: List<&2, U32>, aad: List<&2, U32>, ciphertext: List<&2, U32>, pair: Array<U32> & List<&2, U32>) -> Array<U32> & List<&2, U32>:
  (keys, h) = pair
  tag.mask(field(h), aad, ciphertext, AES.block(keys, B.append(nonce, [0, 0, 0, 1])))

def tag(keys: Array<U32>, nonce: List<&2, U32>, aad: List<&2, U32>, ciphertext: List<&2, U32>) -> Array<U32> & List<&2, U32>:
  tag.h(nonce, aad, ciphertext, AES.block(keys, List.replicate(U32, 16n, 0)))

def seal.tag(ciphertext: List<&2, U32>, pair: Array<U32> & List<&2, U32>) -> Maybe<&2, Sealed>:
  (_, mac) = pair
  Some{Sealed{ciphertext, mac}}

def seal.cipher(nonce: List<&2, U32>, aad: List<&2, U32>, pair: Array<U32> & List<&2, U32>) -> Maybe<&2, Sealed>:
  (keys, +ciphertext) = pair
  seal.tag(ciphertext, tag(keys, nonce, aad, ciphertext))

def plaintext_length(length: Nat) -> Bool:
  Nat.is_le(length, Nat.sub(Nat.mul(16n, Nat.add(4294967295n, 1n)), 32n))

def valid(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +bytes: List<&2, U32>) -> Bool:
  Bool.and(Bool.and(Nat.is_eq(B.length(key), 16n), B.valid(key)),
    Bool.and(Bool.and(Nat.is_eq(B.length(nonce), 12n), B.valid(nonce)),
      Bool.and(B.valid(aad), Bool.and(B.valid(bytes), plaintext_length(B.length(bytes))))))

def seal.checked(ok: Bool, key: List<&2, U32>, +nonce: List<&2, U32>, aad: List<&2, U32>, plaintext: List<&2, U32>) -> Maybe<&2, Sealed>:
  match ok:
    case False{}:
      None{}
    case True{}:
      seal.cipher(nonce, aad, crypt(AES.expand.raw(key), nonce, plaintext))

def seal(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +plaintext: List<&2, U32>) -> Maybe<&2, Sealed>:
  seal.checked(valid(key, nonce, aad, plaintext), key, nonce, aad, plaintext)

def tag_difference(expected: List<&2, U32>, supplied: List<&2, U32>, difference: U32) -> U32:
  match expected supplied:
    case Nil{} Nil{}:
      difference
    case Con{a, at} Con{b, bt}:
      tag_difference(at, bt, U32.or(difference, U32.xor(a, b)))
    case _ _:
      1

def open.output(pair: Array<U32> & List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  (_, plaintext) = pair
  Some{plaintext}

def open.verified(ok: Bool, keys: Array<U32>, nonce: List<&2, U32>, ciphertext: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      open.output(crypt(keys, nonce, ciphertext))

def open.tag(supplied: List<&2, U32>, nonce: List<&2, U32>, ciphertext: List<&2, U32>, pair: Array<U32> & List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  (keys, expected) = pair
  open.verified(U32.is_eq(tag_difference(expected, supplied, 0), 0), keys, nonce, ciphertext)

def open.checked(ok: Bool, key: List<&2, U32>, +nonce: List<&2, U32>, aad: List<&2, U32>, +ciphertext: List<&2, U32>, supplied: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      open.tag(supplied, nonce, ciphertext, tag(AES.expand.raw(key), nonce, aad, ciphertext))

def open(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +ciphertext: List<&2, U32>, +supplied: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  open.checked(Bool.and(valid(key, nonce, aad, ciphertext),
    Bool.and(Nat.is_eq(B.length(supplied), 16n), B.valid(supplied))), key, nonce, aad, ciphertext, supplied)
