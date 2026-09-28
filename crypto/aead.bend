import Base
import ./bytes.bend as B
import ./chacha20.bend as C
import ./poly1305.bend as P

# RFC 8439 AEAD_CHACHA20_POLY1305. Protocols must provide a nonce unique for
# each invocation under one key. Opening checks the entire tag before decrypt.

type Sealed is Data:
  Sealed{ciphertext: List<&2, U32>, tag: List<&2, U32>}

def first(left: Nat, bytes: List<&2, U32>) -> List<&2, U32>:
  match left bytes:
    case 0n _:
      []
    case 1n+p Con{byte, tail}:
      Con{byte, first(p, tail)}
    case _ _:
      []

def pad_length(n: Nat) -> Nat:
  Nat.mod(Nat.sub(16n, Nat.mod(n, 16n)), 16n)

def length64(+n: Nat) -> List<&2, U32>:
  +base = Nat.add(4294967295n, 1n)
  C.word_bytes(U32.from_nat(Nat.mod(n, base)),
    C.word_bytes(U32.from_nat(Nat.div(n, base)), []))

def mac_input(+aad: List<&2, U32>, +ciphertext: List<&2, U32>) -> List<&2, U32>:
  +a_length = B.length(aad)
  +c_length = B.length(ciphertext)
  B.append(aad,
    B.append(List.replicate(U32, pad_length(a_length), 0),
      B.append(ciphertext,
        B.append(List.replicate(U32, pad_length(c_length), 0),
          B.append(length64(a_length), length64(c_length))))))

def tag_for(key: List<&2, U32>, nonce: List<&2, U32>, aad: List<&2, U32>, ciphertext: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  one_time_key = first(32n, C.block.raw(key, nonce, 0))
  P.mac(one_time_key, mac_input(aad, ciphertext))

def seal.tag(result: Maybe<&2, List<&2, U32>>, ciphertext: List<&2, U32>) -> Maybe<&2, Sealed>:
  match result:
    case None{}:
      None{}
    case Some{tag}:
      Some{Sealed{ciphertext, tag}}

def seal.cipher(result: Maybe<&2, List<&2, U32>>, key: List<&2, U32>, nonce: List<&2, U32>, aad: List<&2, U32>) -> Maybe<&2, Sealed>:
  match result:
    case None{}:
      None{}
    case Some{+ciphertext}:
      seal.tag(tag_for(key, nonce, aad, ciphertext), ciphertext)

def seal.checked(ok: Bool, +key: List<&2, U32>, +nonce: List<&2, U32>, aad: List<&2, U32>, plaintext: List<&2, U32>) -> Maybe<&2, Sealed>:
  match ok:
    case False{}:
      None{}
    case True{}:
      seal.cipher(C.crypt(key, nonce, 1, plaintext), key, nonce, aad)

def seal(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +plaintext: List<&2, U32>) -> Maybe<&2, Sealed>:
  ok = Bool.and(Bool.and(Nat.is_eq(B.length(key), 32n), B.valid(key)),
    Bool.and(Bool.and(Nat.is_eq(B.length(nonce), 12n), B.valid(nonce)),
      Bool.and(B.valid(aad), B.valid(plaintext))))
  seal.checked(ok, key, nonce, aad, plaintext)

# XOR every tag byte before deciding; no early exit on a wrong byte.
def tag_difference(expected: List<&2, U32>, supplied: List<&2, U32>, +difference: U32) -> U32:
  match expected supplied:
    case Nil{} Nil{}:
      difference
    case Con{a, at} Con{b, bt}:
      tag_difference(at, bt, U32.or(difference, U32.xor(a, b)))
    case _ _:
      1

def open.verified(ok: Bool, key: List<&2, U32>, nonce: List<&2, U32>, ciphertext: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      C.crypt(key, nonce, 1, ciphertext)

def open.tag(result: Maybe<&2, List<&2, U32>>, supplied: List<&2, U32>, key: List<&2, U32>, nonce: List<&2, U32>, ciphertext: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match result:
    case None{}:
      None{}
    case Some{expected}:
      open.verified(U32.is_eq(tag_difference(expected, supplied, 0), 0), key, nonce, ciphertext)

def open.checked(ok: Bool, +key: List<&2, U32>, +nonce: List<&2, U32>, aad: List<&2, U32>, +ciphertext: List<&2, U32>, tag: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      open.tag(tag_for(key, nonce, aad, ciphertext), tag, key, nonce, ciphertext)

def open(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +ciphertext: List<&2, U32>, +tag: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  ok = Bool.and(Bool.and(Nat.is_eq(B.length(key), 32n), B.valid(key)),
    Bool.and(Bool.and(Nat.is_eq(B.length(nonce), 12n), B.valid(nonce)),
      Bool.and(Bool.and(B.valid(aad), B.valid(ciphertext)),
        Bool.and(Nat.is_eq(B.length(tag), 16n), B.valid(tag)))))
  open.checked(ok, key, nonce, aad, ciphertext, tag)
