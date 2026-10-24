import Base
import ./bytes.bend as B
import ./sha384.bend as S384
import ./sha512.bend as S512
import ./rsa_encoding.bend as E

# Verification-only SHA-384/SHA-512 EMSA-PSS and PKCS#1 v1.5.
# Parameters require equal hash/MGF hash, explicit bounded salt and trailerField=1.
type Hash is Data:
  Sha384{}
  Sha512{}

def length(hash: Hash) -> Nat:
  match hash:
    case Sha384{}: 48n
    case Sha512{}: 64n

def digest(hash: Hash, bytes: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match hash:
    case Sha384{}: S384.digest(bytes)
    case Sha512{}: S512.digest(bytes)

def valid_digest(hash: Hash, +bytes: List<&2, U32>) -> Bool:
  Bool.and(Nat.is_eq(B.length(bytes), length(hash)), B.valid(bytes))

def mgf1.go(blocks: Nat, +hash: Hash, +left: Nat, +counter: U32, +seed: List<&2, U32>, reversed: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match blocks:
    case 0n: Some{List.reverse(&2, U32, reversed)}
    case 1n+p:
      +count = Nat.min(left, length(hash))
      E.hash_got(digest(hash, B.append(seed, E.counter_bytes(counter))), block =>
        mgf1.go(p, hash, Nat.sub(left, count), U32.inc(counter), seed,
          B.append(List.reverse(&2, U32, List.take(&2, U32, block, count)), reversed)))

def mgf1.checked(valid: Bool, +hash: Hash, +count: Nat, seed: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match valid:
    case False{}: None{}
    case True{}: mgf1.go(Nat.div(Nat.add(count, Nat.sub(length(hash), 1n)), length(hash)), hash, count, 0, seed, [])

def mgf1(hash: Hash, +count: Nat, +seed: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  mgf1.checked(Bool.and(Nat.is_le(count, 512n), Bool.and(Nat.is_le(B.length(seed), 512n), B.valid(seed))), hash, count, seed)

def pss.hash(hash: Hash, digest_bytes: List<&2, U32>, salt: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  digest(hash, B.append(List.replicate(U32, 8n, 0), B.append(digest_bytes, salt)))

def pss.hash_equal(hash: List<&2, U32>, expected: Maybe<&2, List<&2, U32>>) -> Bool:
  match expected:
    case None{}:
      False{}
    case Some{expected}:
      E.equal(hash, expected)

def pss.salt(+hash_kind: Hash, valid: Bool, digest: List<&2, U32>, salt: List<&2, U32>, hash: List<&2, U32>) -> Bool:
  match valid:
    case False{}:
      False{}
    case True{}:
      pss.hash_equal(hash, pss.hash(hash_kind, digest, salt))

def pss.prefix(+salt_length: Nat, +hash_kind: Hash, left: Nat, db: List<&2, U32>, digest: List<&2, U32>, hash: List<&2, U32>) -> Bool:
  match left db:
    case 0n Con{1, +salt}:
      pss.salt(hash_kind, Bool.and(Nat.is_eq(B.length(salt), salt_length), B.valid(salt)), digest, salt, hash)
    case 1n+p Con{0, tail}:
      pss.prefix(salt_length, hash_kind, p, tail, digest, hash)
    case _ _:
      False{}

def pss.unmasked(+salt_length: Nat, +hash_kind: Hash, +bits: Nat, digest: List<&2, U32>, db: List<&2, U32>, hash: List<&2, U32>, mask: Maybe<&2, List<&2, U32>>) -> Bool:
  match mask:
    case None{}:
      False{}
    case Some{mask}:
      pss.prefix(salt_length, hash_kind, Nat.sub(E.em_length(bits), Nat.add(Nat.add(length(hash_kind), salt_length), 2n)), E.clear_top(E.top_mask(bits), E.xor.go(db, mask, [])), digest, hash)

def pss.top_checked(+salt_length: Nat, +hash_kind: Hash, valid: Bool, +bits: Nat, digest: List<&2, U32>, db: List<&2, U32>, +hash: List<&2, U32>) -> Bool:
  match valid:
    case False{}:
      False{}
    case True{}:
      pss.unmasked(salt_length, hash_kind, bits, digest, db, hash, mgf1(hash_kind, Nat.sub(E.em_length(bits), Nat.add(length(hash_kind), 1n)), hash))

def pss.trailer_parts(+salt_length: Nat, +hash_kind: Hash, +bits: Nat, digest: List<&2, U32>, db: List<&2, U32>, hash: List<&2, U32>, suffix: List<&2, U32>) -> Bool:
  match db suffix:
    case Con{+first, rest} Con{188, Nil{}}:
      pss.top_checked(salt_length, hash_kind, U32.is_eq(U32.and(first, U32.xor(E.top_mask(bits), 255)), 0),
        bits, digest, Con{first, rest}, hash)
    case _ _:
      False{}

def pss.trailer(+salt_length: Nat, +hash_kind: Hash, bits: Nat, digest: List<&2, U32>, db: List<&2, U32>, pair: List<&2, U32> & List<&2, U32>) -> Bool:
  (hash, tail) = pair
  pss.trailer_parts(salt_length, hash_kind, bits, digest, db, hash, tail)

def pss.split(+salt_length: Nat, +hash_kind: Hash, +bits: Nat, digest: List<&2, U32>, pair: List<&2, U32> & List<&2, U32>) -> Bool:
  (db, rest) = pair
  pss.trailer(salt_length, hash_kind, bits, digest, db, E.split(length(hash_kind), rest, []))

def pss.length_checked(+salt_length: Nat, +hash_kind: Hash, valid: Bool, +bits: Nat, digest: List<&2, U32>, encoded: List<&2, U32>) -> Bool:
  match valid:
    case False{}:
      False{}
    case True{}:
      pss.split(salt_length, hash_kind, bits, digest, E.split(Nat.sub(E.em_length(bits), Nat.add(length(hash_kind), 1n)), encoded, []))

def pss.verify.checked(+salt_length: Nat, +hash_kind: Hash, valid: Bool, +bits: Nat, digest: List<&2, U32>, +encoded: List<&2, U32>) -> Bool:
  match valid:
    case False{}:
      False{}
    case True{}:
      pss.length_checked(salt_length, hash_kind, Nat.is_eq(B.length(encoded), E.em_length(bits)), bits, digest, encoded)

def pss_verify_digest(+salt_length: Nat, +hash_kind: Hash, +bits: Nat, +digest: List<&2, U32>, +encoded: List<&2, U32>) -> Bool:
  pss.verify.checked(salt_length, hash_kind, Bool.and(Nat.is_le(salt_length, 512n), Bool.and(Bool.and(Nat.is_ge(bits, Nat.add(Nat.mul(Nat.add(Nat.add(length(hash_kind), salt_length), 1n), 8n), 1n)), Nat.is_le(bits, 4096n)),
    Bool.and(valid_digest(hash_kind, digest), B.valid(encoded)))), bits, digest, encoded)

def digest_info(hash: Hash, digest_bytes: List<&2, U32>) -> List<&2, U32>:
  match hash:
    case Sha384{}:
      B.append([48, 65, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 5, 0, 4, 48], digest_bytes)
    case Sha512{}:
      B.append([48, 81, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3, 5, 0, 4, 64], digest_bytes)

def v15.checked(valid: Bool, +hash: Hash, +encoded: List<&2, U32>, digest_bytes: List<&2, U32>) -> Bool:
  match valid:
    case False{}: False{}
    case True{}:
      E.equal(encoded, Con{0, Con{1, B.append(List.replicate(U32, Nat.sub(B.length(encoded), Nat.add(length(hash), 22n)), 255), Con{0, digest_info(hash, digest_bytes)})}})

def v15_verify_digest(+hash: Hash, +digest_bytes: List<&2, U32>, +encoded: List<&2, U32>) -> Bool:
  v15.checked(Bool.and(valid_digest(hash, digest_bytes), Bool.and(B.valid(encoded),
    Bool.and(Nat.is_ge(B.length(encoded), Nat.add(length(hash), 30n)), Nat.is_le(B.length(encoded), 512n)))), hash, encoded, digest_bytes)
