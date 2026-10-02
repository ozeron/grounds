import Base
import ./bytes.bend as B
import ./sha256.bend as S

# SHA-256 RSA signature encoding only, not RSASP1/RSAVP1 or a key owner.
# PSS uses SHA-256/MGF1-SHA256 and a caller-supplied 32-byte salt (TLS profile).
# Synthetic inputs only until the complete RSA/runtime/erasure review passes.
# Bounds cover encoded representatives through 4096 bits; external RSA/TLS
# owners still must validate key sizes, algorithms, signature range and trust.

def valid_digest(+bytes: List<&2, U32>) -> Bool:
  Bool.and(Nat.is_eq(B.length(bytes), 32n), B.valid(bytes))

def counter_bytes(+counter: U32) -> List<&2, U32>:
  [U32.shrn(counter, 24n), U32.and(U32.shrn(counter, 16n), 255),
   U32.and(U32.shrn(counter, 8n), 255), U32.and(counter, 255)]

def hash_got(value: Maybe<&2, List<&2, U32>>, next: List<&2, U32> -> Maybe<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  match value:
    case None{}:
      None{}
    case Some{bytes}:
      next(bytes)

def mgf1.go(blocks: Nat, +left: Nat, +counter: U32, +seed: List<&2, U32>, reversed: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match blocks:
    case 0n:
      Some{List.reverse(&2, U32, reversed)}
    case 1n+p:
      +count = Nat.min(left, 32n)
      hash_got(S.digest(B.append(seed, counter_bytes(counter))), block =>
        mgf1.go(p, Nat.sub(left, count), U32.inc(counter), seed,
          B.append(List.reverse(&2, U32, List.take(&2, U32, block, count)), reversed)))

def mgf1.checked(valid: Bool, +length: Nat, seed: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      mgf1.go(Nat.div(Nat.add(length, 31n), 32n), length, 0, seed, [])

def mgf1(+length: Nat, +seed: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  mgf1.checked(Bool.and(Nat.is_le(length, 512n),
    Bool.and(Nat.is_le(B.length(seed), 512n), B.valid(seed))), length, seed)

def xor.go(first: List<&2, U32>, second: List<&2, U32>, reversed: List<&2, U32>) -> List<&2, U32>:
  match first second:
    case Con{a, first} Con{b, second}:
      xor.go(first, second, Con{U32.xor(a, b), reversed})
    case _ _:
      List.reverse(&2, U32, reversed)

def equal.go(first: List<&2, U32>, second: List<&2, U32>, difference: U32) -> Bool:
  match first second:
    case Nil{} Nil{}:
      U32.is_eq(difference, 0)
    case Con{a, first} Con{b, second}:
      equal.go(first, second, U32.or(difference, U32.xor(a, b)))
    case _ _:
      False{}

def equal(first: List<&2, U32>, second: List<&2, U32>) -> Bool:
  equal.go(first, second, 0)

def em_length(bits: Nat) -> Nat:
  Nat.div(Nat.add(bits, 7n), 8n)

def top_mask(+bits: Nat) -> U32:
  U32.sub(U32.shln(1, Nat.sub(8n, Nat.sub(Nat.mul(em_length(bits), 8n), bits))), 1)

def clear_top(mask: U32, bytes: List<&2, U32>) -> List<&2, U32>:
  match bytes:
    case Nil{}:
      []
    case Con{first, tail}:
      Con{U32.and(first, mask), tail}

def pss.hash(digest: List<&2, U32>, salt: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  S.digest(B.append(List.replicate(U32, 8n, 0), B.append(digest, salt)))

def pss.encoded(bits: Nat, hash: List<&2, U32>, db: List<&2, U32>, mask: Maybe<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  match mask:
    case None{}:
      None{}
    case Some{mask}:
      Some{B.append(clear_top(top_mask(bits), xor.go(db, mask, [])), B.append(hash, [188]))}

def pss.hashed(+bits: Nat, salt: List<&2, U32>, hash: Maybe<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  match hash:
    case None{}:
      None{}
    case Some{+hash}:
      pss.encoded(bits, hash,
        B.append(List.replicate(U32, Nat.sub(em_length(bits), 66n), 0), Con{1, salt}),
        mgf1(Nat.sub(em_length(bits), 33n), hash))

def pss.encode.checked(valid: Bool, bits: Nat, digest: List<&2, U32>, +salt: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      pss.hashed(bits, salt, pss.hash(digest, salt))

def pss_encode_digest(+bits: Nat, +digest: List<&2, U32>, +salt: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  pss.encode.checked(Bool.and(Bool.and(Nat.is_ge(bits, 521n), Nat.is_le(bits, 4096n)),
    Bool.and(valid_digest(digest), valid_digest(salt))), bits, digest, salt)

def split(left: Nat, bytes: List<&2, U32>, reversed: List<&2, U32>) -> List<&2, U32> & List<&2, U32>:
  match left bytes:
    case 0n bytes:
      (List.reverse(&2, U32, reversed), bytes)
    case 1n+p Con{first, tail}:
      split(p, tail, Con{first, reversed})
    case _ _:
      ([], [])

def pss.hash_equal(hash: List<&2, U32>, expected: Maybe<&2, List<&2, U32>>) -> Bool:
  match expected:
    case None{}:
      False{}
    case Some{expected}:
      equal(hash, expected)

def pss.salt(valid: Bool, digest: List<&2, U32>, salt: List<&2, U32>, hash: List<&2, U32>) -> Bool:
  match valid:
    case False{}:
      False{}
    case True{}:
      pss.hash_equal(hash, pss.hash(digest, salt))

def pss.prefix(left: Nat, db: List<&2, U32>, digest: List<&2, U32>, hash: List<&2, U32>) -> Bool:
  match left db:
    case 0n Con{1, +salt}:
      pss.salt(valid_digest(salt), digest, salt, hash)
    case 1n+p Con{0, tail}:
      pss.prefix(p, tail, digest, hash)
    case _ _:
      False{}

def pss.unmasked(+bits: Nat, digest: List<&2, U32>, db: List<&2, U32>, hash: List<&2, U32>, mask: Maybe<&2, List<&2, U32>>) -> Bool:
  match mask:
    case None{}:
      False{}
    case Some{mask}:
      pss.prefix(Nat.sub(em_length(bits), 66n), clear_top(top_mask(bits), xor.go(db, mask, [])), digest, hash)

def pss.top_checked(valid: Bool, +bits: Nat, digest: List<&2, U32>, db: List<&2, U32>, +hash: List<&2, U32>) -> Bool:
  match valid:
    case False{}:
      False{}
    case True{}:
      pss.unmasked(bits, digest, db, hash, mgf1(Nat.sub(em_length(bits), 33n), hash))

def pss.trailer_parts(+bits: Nat, digest: List<&2, U32>, db: List<&2, U32>, hash: List<&2, U32>, suffix: List<&2, U32>) -> Bool:
  match db suffix:
    case Con{+first, rest} Con{188, Nil{}}:
      pss.top_checked(U32.is_eq(U32.and(first, U32.xor(top_mask(bits), 255)), 0),
        bits, digest, Con{first, rest}, hash)
    case _ _:
      False{}

def pss.trailer(bits: Nat, digest: List<&2, U32>, db: List<&2, U32>, pair: List<&2, U32> & List<&2, U32>) -> Bool:
  (hash, tail) = pair
  pss.trailer_parts(bits, digest, db, hash, tail)

def pss.split(+bits: Nat, digest: List<&2, U32>, pair: List<&2, U32> & List<&2, U32>) -> Bool:
  (db, rest) = pair
  pss.trailer(bits, digest, db, split(32n, rest, []))

def pss.length_checked(valid: Bool, +bits: Nat, digest: List<&2, U32>, encoded: List<&2, U32>) -> Bool:
  match valid:
    case False{}:
      False{}
    case True{}:
      pss.split(bits, digest, split(Nat.sub(em_length(bits), 33n), encoded, []))

def pss.verify.checked(valid: Bool, +bits: Nat, digest: List<&2, U32>, +encoded: List<&2, U32>) -> Bool:
  match valid:
    case False{}:
      False{}
    case True{}:
      pss.length_checked(Nat.is_eq(B.length(encoded), em_length(bits)), bits, digest, encoded)

def pss_verify_digest(+bits: Nat, +digest: List<&2, U32>, +encoded: List<&2, U32>) -> Bool:
  pss.verify.checked(Bool.and(Bool.and(Nat.is_ge(bits, 521n), Nat.is_le(bits, 4096n)),
    Bool.and(valid_digest(digest), B.valid(encoded))), bits, digest, encoded)

def digest_info(digest: List<&2, U32>) -> List<&2, U32>:
  B.append([48, 49, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 4, 32], digest)

def v15.encode.checked(valid: Bool, length: Nat, digest: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      Some{Con{0, Con{1, B.append(List.replicate(U32, Nat.sub(length, 54n), 255), Con{0, digest_info(digest)})}}}

def v15_encode_digest(+length: Nat, +digest: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  v15.encode.checked(Bool.and(Bool.and(Nat.is_ge(length, 62n), Nat.is_le(length, 512n)),
    valid_digest(digest)), length, digest)

def v15.verify.expected(encoded: List<&2, U32>, expected: Maybe<&2, List<&2, U32>>) -> Bool:
  match expected:
    case None{}:
      False{}
    case Some{expected}:
      equal(encoded, expected)

def v15.verify.checked(valid: Bool, digest: List<&2, U32>, +encoded: List<&2, U32>) -> Bool:
  match valid:
    case False{}:
      False{}
    case True{}:
      v15.verify.expected(encoded, v15_encode_digest(B.length(encoded), digest))

def v15_verify_digest(digest: List<&2, U32>, +encoded: List<&2, U32>) -> Bool:
  v15.verify.checked(B.valid(encoded), digest, encoded)
