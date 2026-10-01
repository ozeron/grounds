import Base
import ./bytes.bend as B
import ./hkdf.bend as H
import ./aead.bend as A
import ./gcm.bend as G

# TLS ChaCha20-Poly1305/AES-128-GCM SHA-256 traffic (RFC 9846 5.3, 7.1-7.3).
# Affine owners prevent copying a live epoch through the normal interface.
# Record framing, handshake phase and KeyUpdate message ordering belong to TLS.
# Dropping old key lists retires them logically; runtime copies are not scrubbed.

type Sequence is Data:
  Counter{high: U32, low: U32}
  Spent{}

type Epoch is Type:
  Ready{secret: List<&2, U32>, key: List<&2, U32>, iv: List<&2, U32>, sequence: Sequence}
  AesReady{secret: List<&2, U32>, key: List<&2, U32>, iv: List<&2, U32>, sequence: Sequence}
  Gone{}

type Generation is Data:
  Generation{high: U32, low: U32}

type WriteKey is Type:
  WriteKey{epoch: Epoch, generation: Generation}

type ReadKey is Type:
  ReadKey{epoch: Epoch}

type Error is Data:
  Invalid{}
  Authentication{}
  Exhausted{}
  Closed{}
  UpdateLimit{}
  UsageLimit{}

def label.checked(ok: Bool, +length: Nat, secret: List<&2, U32>, +label: List<&2, U32>, +context: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      encoded = B.append([U32.from_nat(Nat.div(length, 256n)), U32.from_nat(Nat.mod(length, 256n)),
        U32.from_nat(Nat.add(6n, B.length(label)))],
        B.append([116, 108, 115, 49, 51, 32],
          B.append(label, Con{U32.from_nat(B.length(context)), context})))
      H.expand(length, secret, encoded)

# Labels exclude the "tls13 " prefix. The lengths are TLS vector bounds and
# the existing SHA-256 HKDF output bound, not a general uint16 output length.
def expand_label(+secret: List<&2, U32>, +label: List<&2, U32>, +context: List<&2, U32>, +length: Nat) -> Maybe<&2, List<&2, U32>>:
  ok = Bool.and(Nat.is_le(length, 8160n),
    Bool.and(Bool.and(Nat.is_eq(B.length(secret), 32n), B.valid(secret)),
      Bool.and(Bool.and(Nat.is_ge(B.length(label), 1n), Nat.is_le(B.length(label), 249n)),
        Bool.and(B.valid(label), Bool.and(Nat.is_le(B.length(context), 255n), B.valid(context))))))
  label.checked(ok, length, secret, label, context)

def derived(secret: List<&2, U32>, key: Maybe<&2, List<&2, U32>>, iv: Maybe<&2, List<&2, U32>>) -> Maybe<&1, Epoch>:
  match key iv:
    case Some{key} Some{iv}:
      Some{Ready{secret, key, iv, Counter{0, 0}}}
    case _ _:
      None{}

def new_epoch(+secret: List<&2, U32>) -> Maybe<&1, Epoch>:
  derived(secret, expand_label(secret, [107, 101, 121], [], 32n),
    expand_label(secret, [105, 118], [], 12n))

def aes.derived(secret: List<&2, U32>, key: Maybe<&2, List<&2, U32>>, iv: Maybe<&2, List<&2, U32>>) -> Maybe<&1, Epoch>:
  match key iv:
    case Some{key} Some{iv}:
      Some{AesReady{secret, key, iv, Counter{0, 0}}}
    case _ _:
      None{}

def new_aes_epoch(+secret: List<&2, U32>) -> Maybe<&1, Epoch>:
  aes.derived(secret, expand_label(secret, [107, 101, 121], [], 16n),
    expand_label(secret, [105, 118], [], 12n))

def write_new(epoch: Maybe<&1, Epoch>) -> Maybe<&1, WriteKey>:
  match epoch:
    case Some{epoch}:
      Some{WriteKey{epoch, Generation{0, 0}}}
    case None{}:
      None{}

def read_new(epoch: Maybe<&1, Epoch>) -> Maybe<&1, ReadKey>:
  match epoch:
    case Some{epoch}:
      Some{ReadKey{epoch}}
    case None{}:
      None{}

# The caller supplies a distinct, correctly derived secret for each connection,
# direction and initial epoch. Reinitializing the same secret reuses its nonces.
def new_write(secret: List<&2, U32>) -> Maybe<&1, WriteKey>:
  write_new(new_epoch(secret))

def new_read(secret: List<&2, U32>) -> Maybe<&1, ReadKey>:
  read_new(new_epoch(secret))

def new_aes128_write(secret: List<&2, U32>) -> Maybe<&1, WriteKey>:
  write_new(new_aes_epoch(secret))

def new_aes128_read(secret: List<&2, U32>) -> Maybe<&1, ReadKey>:
  read_new(new_aes_epoch(secret))

def next.high(last: Bool, high: U32) -> Sequence:
  match last:
    case True{}:
      Spent{}
    case False{}:
      Counter{U32.inc(high), 0}

def next.low(carry: Bool, +high: U32, low: U32) -> Sequence:
  match carry:
    case True{}:
      next.high(U32.is_eq(high, 4294967295), high)
    case False{}:
      Counter{high, U32.inc(low)}

def next(sequence: Sequence) -> Sequence:
  match sequence:
    case Counter{high, +low}:
      next.low(U32.is_eq(low, 4294967295), high, low)
    case Spent{}:
      Spent{}

def word_be(+word: U32, tail: List<&2, U32>) -> List<&2, U32>:
  Con{U32.shrn(word, 24n), Con{U32.and(U32.shrn(word, 16n), 255),
    Con{U32.and(U32.shrn(word, 8n), 255), Con{U32.and(word, 255), tail}}}}

def xor_iv(iv: List<&2, U32>, sequence: List<&2, U32>) -> List<&2, U32>:
  match iv sequence:
    case Con{a, at} Con{b, bt}:
      Con{U32.xor(a, b), xor_iv(at, bt)}
    case _ _:
      []

def nonce(iv: List<&2, U32>, high: U32, low: U32) -> List<&2, U32>:
  xor_iv(iv, B.append([0, 0, 0, 0], word_be(high, word_be(low, []))))

def seal.result(epoch: Epoch, result: Maybe<&2, A.Sealed>) -> Epoch & Result<&2, &2, Error, A.Sealed>:
  match result:
    case Some{sealed}:
      (epoch, Done{sealed})
    case None{}:
      (Gone{}, Fail{Invalid{}})

# A conservative full-record cap below RFC 9846's approximately 2^24.5 bound.
# Size bounds keep its per-record assumptions true even through this raw API.
# Protocol callers must send old-key KeyUpdate before using the last allowance.
def aes.usage_allowed(high: U32, low: U32) -> Bool:
  Bool.and(U32.is_eq(high, 0), U32.is_lt(low, 16777216))

def aes.record_sizes(aad: List<&2, U32>, plaintext: List<&2, U32>) -> Bool:
  Bool.and(Nat.is_le(B.length(aad), 5n), Nat.is_le(B.length(plaintext), 16385n))

def seal.aes_result(epoch: Epoch, result: Maybe<&2, G.Sealed>) -> Epoch & Result<&2, &2, Error, A.Sealed>:
  match result:
    case Some{G.Sealed{ciphertext, tag}}:
      (epoch, Done{A.Sealed{ciphertext, tag}})
    case None{}:
      (Gone{}, Fail{Invalid{}})

def seal.aes_valid(valid: Bool, secret: List<&2, U32>, +key: List<&2, U32>, +iv: List<&2, U32>, +high: U32, +low: U32, aad: List<&2, U32>, plaintext: List<&2, U32>) -> Epoch & Result<&2, &2, Error, A.Sealed>:
  match valid:
    case False{}:
      (Gone{}, Fail{Invalid{}})
    case True{}:
      seal.aes_result(AesReady{secret, key, iv, next(Counter{high, low})},
        G.seal(key, nonce(iv, high, low), aad, plaintext))

def seal.aes_allowed(allowed: Bool, secret: List<&2, U32>, key: List<&2, U32>, iv: List<&2, U32>, high: U32, low: U32, +aad: List<&2, U32>, +plaintext: List<&2, U32>) -> Epoch & Result<&2, &2, Error, A.Sealed>:
  match allowed:
    case False{}:
      (Gone{}, Fail{UsageLimit{}})
    case True{}:
      seal.aes_valid(aes.record_sizes(aad, plaintext), secret, key, iv, high, low, aad, plaintext)

def seal.epoch(epoch: Epoch, aad: List<&2, U32>, plaintext: List<&2, U32>) -> Epoch & Result<&2, &2, Error, A.Sealed>:
  match epoch:
    case Gone{}:
      (Gone{}, Fail{Closed{}})
    case Ready{_, _, _, Spent{}}:
      (Gone{}, Fail{Exhausted{}})
    case Ready{secret, +key, +iv, Counter{+high, +low}}:
      seal.result(Ready{secret, key, iv, next(Counter{high, low})},
        A.seal(key, nonce(iv, high, low), aad, plaintext))
    case AesReady{_, _, _, Spent{}}:
      (Gone{}, Fail{Exhausted{}})
    case AesReady{secret, key, iv, Counter{+high, +low}}:
      seal.aes_allowed(aes.usage_allowed(high, low), secret, key, iv, high, low, aad, plaintext)

def seal.owner(generation: Generation, pair: Epoch & Result<&2, &2, Error, A.Sealed>) -> WriteKey & Result<&2, &2, Error, A.Sealed>:
  (epoch, result) = pair
  (WriteKey{epoch, generation}, result)

def seal(owner: WriteKey, aad: List<&2, U32>, plaintext: List<&2, U32>) -> WriteKey & Result<&2, &2, Error, A.Sealed>:
  match owner:
    case WriteKey{epoch, generation}:
      seal.owner(generation, seal.epoch(epoch, aad, plaintext))

def open.result(epoch: Epoch, result: Maybe<&2, List<&2, U32>>) -> Epoch & Result<&2, &2, Error, List<&2, U32>>:
  match result:
    case Some{plaintext}:
      (epoch, Done{plaintext})
    case None{}:
      (Gone{}, Fail{Authentication{}})

def open.aes_valid(valid: Bool, secret: List<&2, U32>, +key: List<&2, U32>, +iv: List<&2, U32>, +high: U32, +low: U32, aad: List<&2, U32>, ciphertext: List<&2, U32>, tag: List<&2, U32>) -> Epoch & Result<&2, &2, Error, List<&2, U32>>:
  match valid:
    case False{}:
      (Gone{}, Fail{Authentication{}})
    case True{}:
      open.result(AesReady{secret, key, iv, next(Counter{high, low})},
        G.open(key, nonce(iv, high, low), aad, ciphertext, tag))

def open.epoch(epoch: Epoch, +aad: List<&2, U32>, +ciphertext: List<&2, U32>, tag: List<&2, U32>) -> Epoch & Result<&2, &2, Error, List<&2, U32>>:
  match epoch:
    case Gone{}:
      (Gone{}, Fail{Closed{}})
    case Ready{_, _, _, Spent{}}:
      (Gone{}, Fail{Exhausted{}})
    case Ready{secret, +key, +iv, Counter{+high, +low}}:
      open.result(Ready{secret, key, iv, next(Counter{high, low})},
        A.open(key, nonce(iv, high, low), aad, ciphertext, tag))
    case AesReady{_, _, _, Spent{}}:
      (Gone{}, Fail{Exhausted{}})
    case AesReady{secret, key, iv, Counter{high, low}}:
      # Receiving owners do not apply the sending usage cap (RFC 9846 5.5).
      open.aes_valid(aes.record_sizes(aad, ciphertext), secret, key, iv, high, low, aad, ciphertext, tag)

def open.owner(pair: Epoch & Result<&2, &2, Error, List<&2, U32>>) -> ReadKey & Result<&2, &2, Error, List<&2, U32>>:
  (epoch, result) = pair
  (ReadKey{epoch}, result)

def open(owner: ReadKey, aad: List<&2, U32>, ciphertext: List<&2, U32>, tag: List<&2, U32>) -> ReadKey & Result<&2, &2, Error, List<&2, U32>>:
  match owner:
    case ReadKey{epoch}:
      open.owner(open.epoch(epoch, aad, ciphertext, tag))

def update.secret(secret: Maybe<&2, List<&2, U32>>) -> Maybe<&1, Epoch>:
  match secret:
    case None{}:
      None{}
    case Some{secret}:
      new_epoch(secret)

def update.aes_secret(secret: Maybe<&2, List<&2, U32>>) -> Maybe<&1, Epoch>:
  match secret:
    case None{}:
      None{}
    case Some{secret}:
      new_aes_epoch(secret)

def update(epoch: Epoch) -> Maybe<&1, Epoch>:
  match epoch:
    case Gone{}:
      None{}
    case Ready{secret, _, _, _}:
      update.secret(expand_label(secret, [116, 114, 97, 102, 102, 105, 99, 32, 117, 112, 100], [], 32n))
    case AesReady{secret, _, _, _}:
      update.aes_secret(expand_label(secret, [116, 114, 97, 102, 102, 105, 99, 32, 117, 112, 100], [], 32n))

def generation.next(carry: Bool, high: U32, low: U32) -> Generation:
  match carry:
    case True{}:
      Generation{U32.inc(high), 0}
    case False{}:
      Generation{high, U32.inc(low)}

def rekey.write_result(generation: Generation, result: Maybe<&1, Epoch>) -> WriteKey & Result<&2, &2, Error, Unit>:
  match result:
    case Some{epoch}:
      (WriteKey{epoch, generation}, Done{Unit{}})
    case None{}:
      (WriteKey{Gone{}, generation}, Fail{Closed{}})

def rekey.write_limit(limit: Bool, epoch: Epoch, +high: U32, +low: U32) -> WriteKey & Result<&2, &2, Error, Unit>:
  match limit:
    case True{}:
      # Keep the current traffic epoch usable; the handshake owner decides
      # whether to ignore a peer update request or close the connection.
      (WriteKey{epoch, Generation{high, low}}, Fail{UpdateLimit{}})
    case False{}:
      rekey.write_result(generation.next(U32.is_eq(low, 4294967295), high, low), update(epoch))

# Call only after sealing/sending KeyUpdate under the old key. The TLS owner
# must also enforce Finished/early-data phase and peer update-request ordering.
def rekey_write(owner: WriteKey) -> WriteKey & Result<&2, &2, Error, Unit>:
  match owner:
    case WriteKey{Gone{}, generation}:
      (WriteKey{Gone{}, generation}, Fail{Closed{}})
    case WriteKey{epoch, Generation{+high, +low}}:
      rekey.write_limit(Bool.and(U32.is_eq(high, 65535), U32.is_eq(low, 4294967295)), epoch, high, low)

def rekey.read_result(result: Maybe<&1, Epoch>) -> ReadKey & Result<&2, &2, Error, Unit>:
  match result:
    case Some{epoch}:
      (ReadKey{epoch}, Done{Unit{}})
    case None{}:
      (ReadKey{Gone{}}, Fail{Closed{}})

# Call only after authenticating and processing the peer's old-key KeyUpdate.
# RFC 9846 prohibits applying the sending update-count cap on receive.
def rekey_read(owner: ReadKey) -> ReadKey & Result<&2, &2, Error, Unit>:
  match owner:
    case ReadKey{epoch}:
      rekey.read_result(update(epoch))

def close_write(owner: WriteKey) -> WriteKey:
  match owner:
    case WriteKey{_, generation}:
      WriteKey{Gone{}, generation}

def close_read(owner: ReadKey) -> ReadKey:
  match owner:
    case ReadKey{_}:
      ReadKey{Gone{}}
