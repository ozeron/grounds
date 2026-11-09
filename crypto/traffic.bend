import Base
import ./bytes.bend as B
import ./hkdf.bend as H
import ./hkdf_sha384.bend as H384
import ./aead.bend as A
import ./gcm.bend as G

# TLS ChaCha20-Poly1305/AES-128-GCM SHA-256 and AES-256-GCM SHA-384
# traffic (RFC 9846 5.3, 7.1-7.3).
# Affine owners prevent copying a live epoch through the normal interface.
# Record framing, handshake phase and KeyUpdate message ordering belong to TLS.
# Dropping old key lists retires them logically; runtime copies are not scrubbed.

type Sequence is Data:
  Counter{high: U32, low: U32}
  Spent{}

type Epoch is Type:
  ChachaReady{secret: List<&2, U32>, key: List<&2, U32>, iv: List<&2, U32>, sequence: Sequence}
  AesReady{secret: List<&2, U32>, key: List<&2, U32>, iv: List<&2, U32>, sequence: Sequence}
  Gone{}
  # TLS 1.2 client epochs (M7): AES-GCM with a 4-byte implicit salt and an
  # 8-byte explicit nonce (RFC 5288), ChaCha20-Poly1305 with a 12-byte IV
  # (RFC 7905). Neither has a traffic secret or a KeyUpdate successor.
  Aes12Ready{key: List<&2, U32>, salt: List<&2, U32>, sequence: Sequence}
  Chacha12Ready{key: List<&2, U32>, iv: List<&2, U32>, sequence: Sequence}

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

def label384.checked(ok: Bool, +length: Nat, secret: List<&2, U32>, +label: List<&2, U32>, +context: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      encoded = B.append([U32.from_nat(Nat.div(length, 256n)), U32.from_nat(Nat.mod(length, 256n)),
        U32.from_nat(Nat.add(6n, B.length(label)))],
        B.append([116, 108, 115, 49, 51, 32],
          B.append(label, Con{U32.from_nat(B.length(context)), context})))
      H384.expand(length, secret, encoded)

# Labels exclude the "tls13 " prefix. The lengths are TLS vector bounds and
# the SHA-384 HKDF output bound, not a general uint16 output length.
def expand_label384(+secret: List<&2, U32>, +label: List<&2, U32>, +context: List<&2, U32>, +length: Nat) -> Maybe<&2, List<&2, U32>>:
  ok = Bool.and(Nat.is_le(length, 12240n),
    Bool.and(Bool.and(Nat.is_eq(B.length(secret), 48n), B.valid(secret)),
      Bool.and(Bool.and(Nat.is_ge(B.length(label), 1n), Nat.is_le(B.length(label), 249n)),
        Bool.and(B.valid(label), Bool.and(Nat.is_le(B.length(context), 255n), B.valid(context))))))
  label384.checked(ok, length, secret, label, context)

def expand_label_for(large: Bool, secret: List<&2,U32>, label: List<&2,U32>, context: List<&2,U32>, length: Nat) -> Maybe<&2,List<&2,U32>>:
  match large:
    case True{}: expand_label384(secret,label,context,length)
    case False{}: expand_label(secret,label,context,length)

def derived(secret: List<&2, U32>, key: Maybe<&2, List<&2, U32>>, iv: Maybe<&2, List<&2, U32>>) -> Maybe<&1, Epoch>:
  match key iv:
    case Some{key} Some{iv}:
      Some{ChachaReady{secret, key, iv, Counter{0, 0}}}
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

def new_aes256_epoch(+secret: List<&2,U32>) -> Maybe<&1,Epoch>:
  aes.derived(secret,expand_label384(secret,[107,101,121],[],32n),expand_label384(secret,[105,118],[],12n))

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

def new_aes256_write(secret: List<&2,U32>) -> Maybe<&1,WriteKey>:
  write_new(new_aes256_epoch(secret))

def new_aes256_read(secret: List<&2,U32>) -> Maybe<&1,ReadKey>:
  read_new(new_aes256_epoch(secret))

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
    case ChachaReady{_, _, _, Spent{}}:
      (Gone{}, Fail{Exhausted{}})
    case ChachaReady{secret, +key, +iv, Counter{+high, +low}}:
      seal.result(ChachaReady{secret, key, iv, next(Counter{high, low})},
        A.seal(key, nonce(iv, high, low), aad, plaintext))
    case AesReady{_, _, _, Spent{}}:
      (Gone{}, Fail{Exhausted{}})
    case AesReady{secret, key, iv, Counter{+high, +low}}:
      seal.aes_allowed(aes.usage_allowed(high, low), secret, key, iv, high, low, aad, plaintext)
    case Aes12Ready{_, _, _}:
      (Gone{}, Fail{Invalid{}})
    case Chacha12Ready{_, _, _}:
      (Gone{}, Fail{Invalid{}})

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
    case ChachaReady{_, _, _, Spent{}}:
      (Gone{}, Fail{Exhausted{}})
    case ChachaReady{secret, +key, +iv, Counter{+high, +low}}:
      open.result(ChachaReady{secret, key, iv, next(Counter{high, low})},
        A.open(key, nonce(iv, high, low), aad, ciphertext, tag))
    case AesReady{_, _, _, Spent{}}:
      (Gone{}, Fail{Exhausted{}})
    case AesReady{secret, key, iv, Counter{high, low}}:
      # Receiving owners do not apply the sending usage cap (RFC 9846 5.5).
      open.aes_valid(aes.record_sizes(aad, ciphertext), secret, key, iv, high, low, aad, ciphertext, tag)
    case Aes12Ready{_, _, _}:
      (Gone{}, Fail{Invalid{}})
    case Chacha12Ready{_, _, _}:
      (Gone{}, Fail{Invalid{}})

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

def update.aes_width(large: Bool, secret: List<&2,U32>) -> Maybe<&1,Epoch>:
  match large:
    case True{}: new_aes256_epoch(secret)
    case False{}: new_aes_epoch(secret)

def update.aes_secret(secret: Maybe<&2, List<&2, U32>>) -> Maybe<&1, Epoch>:
  match secret:
    case None{}:
      None{}
    case Some{+secret}:
      update.aes_width(Nat.is_eq(B.length(secret),48n),secret)

def update(epoch: Epoch) -> Maybe<&1, Epoch>:
  match epoch:
    case Gone{}:
      None{}
    case ChachaReady{secret, _, _, _}:
      update.secret(expand_label(secret, [116, 114, 97, 102, 102, 105, 99, 32, 117, 112, 100], [], 32n))
    case AesReady{+secret, _, _, _}:
      update.aes_secret(expand_label_for(Nat.is_eq(B.length(secret),48n),secret, [116, 114, 97, 102, 102, 105, 99, 32, 117, 112, 100], [], B.length(secret)))
    case Aes12Ready{_, _, _}:
      None{}
    case Chacha12Ready{_, _, _}:
      None{}

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

# ---- TLS 1.2 AEAD record protection (M7 client) ----
# RFC 5246 6.2.3.3: additional_data = seq_num || type || version || length,
# with the length of the plaintext. Senders write version 0x0303; receivers
# authenticate the version bytes of the received header (open12), so an
# on-path edit of the header version fails the tag. The record layer also
# requires 0x0303 before opening (wire/tls_record open12). AES-GCM (RFC 5288 3):
# nonce = salt(4) || nonce_explicit(8); the sender's explicit nonce is the
# 64-bit sequence number and travels in front of the ciphertext; a receiver
# uses the explicit nonce it received. ChaCha20-Poly1305 (RFC 7905 2):
# nonce = iv XOR (0^4 || seq), no explicit nonce. Sequence numbers start at
# zero for each direction when its epoch is created (after ChangeCipherSpec).

type Halves is Data:
  Halves{first: List<&2, U32>, rest: List<&2, U32>}

def halves(left: Nat, bytes: List<&2, U32>, reversed: List<&2, U32>) -> Halves:
  match left bytes:
    case 0n _:
      Halves{List.reverse(&2, U32, reversed), bytes}
    case 1n+p Con{byte, tail}:
      halves(p, tail, Con{byte, reversed})
    case _ _:
      Halves{List.reverse(&2, U32, reversed), []}

def sequence12(+high: U32, +low: U32) -> List<&2, U32>:
  word_be(high, word_be(low, []))

def aad12(+high: U32, +low: U32, +kind: U32, +length: Nat) -> List<&2, U32>:
  B.append(sequence12(high, low), [kind, 3, 3, U32.from_nat(Nat.div(length, 256n)), U32.from_nat(Nat.mod(length, 256n))])

# prefix is the received type || version (3 bytes of the record header).
def aad12.received(+high: U32, +low: U32, prefix: List<&2, U32>, +length: Nat) -> List<&2, U32>:
  B.append(sequence12(high, low), B.append(prefix, [U32.from_nat(Nat.div(length, 256n)), U32.from_nat(Nat.mod(length, 256n))]))

def kind12(+kind: U32) -> Bool:
  Bool.or(U32.is_eq(kind, 21), Bool.or(U32.is_eq(kind, 22), U32.is_eq(kind, 23)))

def new12.gcm(valid: Bool, key: List<&2, U32>, salt: List<&2, U32>) -> Maybe<&1, Epoch>:
  match valid:
    case True{}:
      Some{Aes12Ready{key, salt, Counter{0, 0}}}
    case False{}:
      None{}

def new12.chacha(valid: Bool, key: List<&2, U32>, iv: List<&2, U32>) -> Maybe<&1, Epoch>:
  match valid:
    case True{}:
      Some{Chacha12Ready{key, iv, Counter{0, 0}}}
    case False{}:
      None{}

def new12.epoch(chacha: Bool, +key: List<&2, U32>, +iv: List<&2, U32>) -> Maybe<&1, Epoch>:
  match chacha:
    case True{}:
      new12.chacha(Bool.and(Bool.and(Nat.is_eq(B.length(key), 32n), B.valid(key)), Bool.and(Nat.is_eq(B.length(iv), 12n), B.valid(iv))), key, iv)
    case False{}:
      new12.gcm(Bool.and(Bool.and(Bool.or(Nat.is_eq(B.length(key), 16n), Nat.is_eq(B.length(key), 32n)), B.valid(key)),
        Bool.and(Nat.is_eq(B.length(iv), 4n), B.valid(iv))), key, iv)

# key/iv come from one connection's RFC 5246 key block; each direction's
# material is installed exactly once (sequence zero).
def new12_write(chacha: Bool, key: List<&2, U32>, iv: List<&2, U32>) -> Maybe<&1, WriteKey>:
  write_new(new12.epoch(chacha, key, iv))

def new12_read(chacha: Bool, key: List<&2, U32>, iv: List<&2, U32>) -> Maybe<&1, ReadKey>:
  read_new(new12.epoch(chacha, key, iv))

def is12.epoch(epoch: Epoch) -> Epoch & Bool:
  match epoch:
    case Aes12Ready{key, salt, sequence}:
      (Aes12Ready{key, salt, sequence}, True{})
    case Chacha12Ready{key, iv, sequence}:
      (Chacha12Ready{key, iv, sequence}, True{})
    case epoch:
      (epoch, False{})

def is12_write.got(generation: Generation, pair: Epoch & Bool) -> WriteKey & Bool:
  (epoch, legacy) = pair
  (WriteKey{epoch, generation}, legacy)

def is12_write(owner: WriteKey) -> WriteKey & Bool:
  match owner:
    case WriteKey{epoch, generation}:
      is12_write.got(generation, is12.epoch(epoch))

def is12_read.got(pair: Epoch & Bool) -> ReadKey & Bool:
  (epoch, legacy) = pair
  (ReadKey{epoch}, legacy)

def is12_read(owner: ReadKey) -> ReadKey & Bool:
  match owner:
    case ReadKey{epoch}:
      is12_read.got(is12.epoch(epoch))

def seal12.gcm(epoch: Epoch, explicit: List<&2, U32>, result: Maybe<&2, G.Sealed>) -> Epoch & Result<&2, &2, Error, List<&2, U32>>:
  match result:
    case Some{G.Sealed{ciphertext, tag}}:
      (epoch, Done{B.append(explicit, B.append(ciphertext, tag))})
    case None{}:
      (Gone{}, Fail{Invalid{}})

def seal12.chacha(epoch: Epoch, result: Maybe<&2, A.Sealed>) -> Epoch & Result<&2, &2, Error, List<&2, U32>>:
  match result:
    case Some{A.Sealed{ciphertext, tag}}:
      (epoch, Done{B.append(ciphertext, tag)})
    case None{}:
      (Gone{}, Fail{Invalid{}})

def seal12.aes_allowed(allowed: Bool, +key: List<&2, U32>, +salt: List<&2, U32>, +high: U32, +low: U32, +kind: U32, +plaintext: List<&2, U32>) -> Epoch & Result<&2, &2, Error, List<&2, U32>>:
  match allowed:
    case False{}:
      (Gone{}, Fail{UsageLimit{}})
    case True{}:
      seal12.gcm(Aes12Ready{key, salt, next(Counter{high, low})}, sequence12(high, low),
        G.seal(key, B.append(salt, sequence12(high, low)), aad12(high, low, kind, B.length(plaintext)), plaintext))

def seal12.epoch(epoch: Epoch, +kind: U32, +plaintext: List<&2, U32>) -> Epoch & Result<&2, &2, Error, List<&2, U32>>:
  match epoch:
    case Aes12Ready{_, _, Spent{}}:
      (Gone{}, Fail{Exhausted{}})
    case Aes12Ready{key, salt, Counter{+high, +low}}:
      # The same conservative per-key record cap as the TLS 1.3 AES owners.
      seal12.aes_allowed(aes.usage_allowed(high, low), key, salt, high, low, kind, plaintext)
    case Chacha12Ready{_, _, Spent{}}:
      (Gone{}, Fail{Exhausted{}})
    case Chacha12Ready{+key, +iv, Counter{+high, +low}}:
      seal12.chacha(Chacha12Ready{key, iv, next(Counter{high, low})},
        A.seal(key, nonce(iv, high, low), aad12(high, low, kind, B.length(plaintext)), plaintext))
    case _:
      (Gone{}, Fail{Invalid{}})

def seal12.owner(generation: Generation, pair: Epoch & Result<&2, &2, Error, List<&2, U32>>) -> WriteKey & Result<&2, &2, Error, List<&2, U32>>:
  (epoch, result) = pair
  (WriteKey{epoch, generation}, result)

def seal12.checked(valid: Bool, owner: WriteKey, kind: U32, plaintext: List<&2, U32>) -> WriteKey & Result<&2, &2, Error, List<&2, U32>>:
  match valid owner:
    case False{} WriteKey{_, generation}:
      (WriteKey{Gone{}, generation}, Fail{Invalid{}})
    case True{} WriteKey{epoch, generation}:
      seal12.owner(generation, seal12.epoch(epoch, kind, plaintext))

# Returns the TLSCiphertext fragment (explicit nonce || ciphertext || tag for
# GCM; ciphertext || tag for ChaCha20). The caller adds the record header.
def seal12(owner: WriteKey, +kind: U32, +plaintext: List<&2, U32>) -> WriteKey & Result<&2, &2, Error, List<&2, U32>>:
  seal12.checked(Bool.and(kind12(kind), Bool.and(B.valid(plaintext), Nat.is_le(B.length(plaintext), 16384n))), owner, kind, plaintext)

def open12.result(epoch: Epoch, result: Maybe<&2, List<&2, U32>>) -> Epoch & Result<&2, &2, Error, List<&2, U32>>:
  match result:
    case Some{plaintext}:
      (epoch, Done{plaintext})
    case None{}:
      (Gone{}, Fail{Authentication{}})

def open12.gcm_tag(+key: List<&2, U32>, +salt: List<&2, U32>, +high: U32, +low: U32, prefix: List<&2, U32>, explicit: List<&2, U32>, parts: Halves) -> Epoch & Result<&2, &2, Error, List<&2, U32>>:
  match parts:
    case Halves{+ciphertext, tag}:
      open12.result(Aes12Ready{key, salt, next(Counter{high, low})},
        G.open(key, B.append(salt, explicit), aad12.received(high, low, prefix, B.length(ciphertext)), ciphertext, tag))

def open12.gcm(+key: List<&2, U32>, +salt: List<&2, U32>, +high: U32, +low: U32, prefix: List<&2, U32>, +length: Nat, parts: Halves) -> Epoch & Result<&2, &2, Error, List<&2, U32>>:
  match parts:
    case Halves{explicit, body}:
      open12.gcm_tag(key, salt, high, low, prefix, explicit, halves(Nat.sub(length, 24n), body, []))

def open12.chacha(+key: List<&2, U32>, +iv: List<&2, U32>, +high: U32, +low: U32, prefix: List<&2, U32>, parts: Halves) -> Epoch & Result<&2, &2, Error, List<&2, U32>>:
  match parts:
    case Halves{+ciphertext, tag}:
      open12.result(Chacha12Ready{key, iv, next(Counter{high, low})},
        A.open(key, nonce(iv, high, low), aad12.received(high, low, prefix, B.length(ciphertext)), ciphertext, tag))

def open12.gcm_sized(valid: Bool, key: List<&2, U32>, salt: List<&2, U32>, high: U32, low: U32, prefix: List<&2, U32>, +length: Nat, fragment: List<&2, U32>) -> Epoch & Result<&2, &2, Error, List<&2, U32>>:
  match valid:
    case False{}:
      (Gone{}, Fail{Authentication{}})
    case True{}:
      open12.gcm(key, salt, high, low, prefix, length, halves(8n, fragment, []))

def open12.chacha_sized(valid: Bool, key: List<&2, U32>, iv: List<&2, U32>, high: U32, low: U32, prefix: List<&2, U32>, +length: Nat, fragment: List<&2, U32>) -> Epoch & Result<&2, &2, Error, List<&2, U32>>:
  match valid:
    case False{}:
      (Gone{}, Fail{Authentication{}})
    case True{}:
      open12.chacha(key, iv, high, low, prefix, halves(Nat.sub(length, 16n), fragment, []))

# Fragments are bounded by the plaintext limit plus the suite expansion
# (24 bytes for GCM, 16 for ChaCha20-Poly1305).
def open12.epoch(epoch: Epoch, prefix: List<&2, U32>, +fragment: List<&2, U32>) -> Epoch & Result<&2, &2, Error, List<&2, U32>>:
  match epoch:
    case Aes12Ready{_, _, Spent{}}:
      (Gone{}, Fail{Exhausted{}})
    case Aes12Ready{key, salt, Counter{high, low}}:
      open12.gcm_sized(Bool.and(Nat.is_ge(B.length(fragment), 24n), Nat.is_le(B.length(fragment), 16408n)), key, salt, high, low, prefix, B.length(fragment), fragment)
    case Chacha12Ready{_, _, Spent{}}:
      (Gone{}, Fail{Exhausted{}})
    case Chacha12Ready{key, iv, Counter{high, low}}:
      open12.chacha_sized(Bool.and(Nat.is_ge(B.length(fragment), 16n), Nat.is_le(B.length(fragment), 16400n)), key, iv, high, low, prefix, B.length(fragment), fragment)
    case _:
      (Gone{}, Fail{Invalid{}})

def open12.checked(valid: Bool, owner: ReadKey, prefix: List<&2, U32>, fragment: List<&2, U32>) -> ReadKey & Result<&2, &2, Error, List<&2, U32>>:
  match valid owner:
    case False{} ReadKey{_}:
      (ReadKey{Gone{}}, Fail{Invalid{}})
    case True{} ReadKey{epoch}:
      open.owner(open12.epoch(epoch, prefix, fragment))

# Opens one TLSCiphertext fragment of the given outer content type and the
# received header version (major, minor), which enters the additional data.
# The whole tag is checked before any plaintext is released; the record layer
# owns the version rule, plaintext length limit and content-type grammar.
def open12(owner: ReadKey, +kind: U32, +major: U32, +minor: U32, +fragment: List<&2, U32>) -> ReadKey & Result<&2, &2, Error, List<&2, U32>>:
  open12.checked(Bool.and(kind12(kind), Bool.and(B.valid([major, minor]), B.valid(fragment))), owner, [kind, major, minor], fragment)
