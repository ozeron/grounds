import Base
import ../crypto/bytes.bend as B
import ../crypto/traffic.bend as T
import ../crypto/aead.bend as A

# Protected TLS 1.3 records for TLS_CHACHA20_POLY1305_SHA256. OS transport,
# plaintext handshake records, compatibility CCS and handshake phase are outside
# this module. No OpenSSL effect is used here.

type Error is Data:
  Invalid{}
  Overflow{}
  Incomplete{}
  Unexpected{}
  Crypto{error: T.Error}

type Record is Data:
  Record{kind: U32, content: List<&2, U32>, padding: Nat}

type Frame is Data:
  More{}
  Bad{error: Error}
  Framed{header: List<&2, U32>, body: List<&2, U32>, rest: List<&2, U32>}

type Split is Data:
  Split{first: List<&2, U32>, rest: List<&2, U32>}

def split(left: Nat, bytes: List<&2, U32>, reversed: List<&2, U32>) -> Split:
  match left bytes:
    case 0n _:
      Split{List.reverse(&2, U32, reversed), bytes}
    case 1n+p Con{byte, tail}:
      split(p, tail, Con{byte, reversed})
    case _ _:
      Split{List.reverse(&2, U32, reversed), []}

def header(+length: Nat) -> List<&2, U32>:
  [23, 3, 3, U32.from_nat(Nat.div(length, 256n)), U32.from_nat(Nat.mod(length, 256n))]

def content_valid(+kind: U32, +length: Nat) -> Bool:
  Bool.or(U32.is_eq(kind, 23),
    Bool.or(Bool.and(U32.is_eq(kind, 22), Nat.is_ge(length, 1n)),
      Bool.and(U32.is_eq(kind, 21), Nat.is_eq(length, 2n))))

def seal.result(owner: T.WriteKey, header: List<&2, U32>, result: Result<&2, &2, T.Error, A.Sealed>) -> T.WriteKey & Result<&2, &2, Error, List<&2, U32>>:
  match result:
    case Fail{why}:
      (owner, Fail{Crypto{why}})
    case Done{A.Sealed{ciphertext, tag}}:
      (owner, Done{B.append(header, B.append(ciphertext, tag))})

def seal.got(header: List<&2, U32>, pair: T.WriteKey & Result<&2, &2, T.Error, A.Sealed>) -> T.WriteKey & Result<&2, &2, Error, List<&2, U32>>:
  (owner, result) = pair
  seal.result(owner, header, result)

def seal.checked(valid: Bool, bounded: Bool, owner: T.WriteKey, kind: U32, padding: Nat, content: List<&2, U32>, +inner_length: Nat) -> T.WriteKey & Result<&2, &2, Error, List<&2, U32>>:
  match valid bounded:
    case False{} _:
      (T.close_write(owner), Fail{Invalid{}})
    case True{} False{}:
      (T.close_write(owner), Fail{Overflow{}})
    case True{} True{}:
      +aad = header(Nat.add(inner_length, 16n))
      inner = B.append(content, Con{kind, List.replicate(U32, padding, 0)})
      seal.got(aad, T.seal(owner, aad, inner))

def seal.bounded(valid: Bool, bounded: Bool, owner: T.WriteKey, kind: U32, +padding: Nat, content: List<&2, U32>, length: Nat) -> T.WriteKey & Result<&2, &2, Error, List<&2, U32>>:
  match valid bounded:
    case False{} _:
      (T.close_write(owner), Fail{Invalid{}})
    case True{} False{}:
      (T.close_write(owner), Fail{Overflow{}})
    case True{} True{}:
      +inner_length = Nat.add(length, Nat.add(1n, padding))
      seal.checked(True{}, Nat.is_le(inner_length, 16385n), owner, kind, padding, content, inner_length)

def seal(owner: T.WriteKey, +kind: U32, +padding: Nat, +content: List<&2, U32>) -> T.WriteKey & Result<&2, &2, Error, List<&2, U32>>:
  +length = B.length(content)
  seal.bounded(Bool.and(B.valid(content), content_valid(kind, length)),
    Bool.and(Nat.is_le(length, 16384n), Nat.is_le(padding, 16384n)),
    owner, kind, padding, content, length)

def frame.split(header: List<&2, U32>, parts: Split) -> Frame:
  match parts:
    case Split{body, rest}:
      Framed{header, body, rest}

def frame.available(enough: Bool, header: List<&2, U32>, length: Nat, body: List<&2, U32>) -> Frame:
  match enough:
    case False{}:
      More{}
    case True{}:
      frame.split(header, split(length, body, []))

def frame.length(bounded: Bool, header: List<&2, U32>, +length: Nat, +body: List<&2, U32>) -> Frame:
  match bounded:
    case False{}:
      Bad{Overflow{}}
    case True{}:
      frame.available(Nat.is_ge(B.length(body), length), header, length, body)

def frame.short(short: Bool, header: List<&2, U32>, +length: Nat, body: List<&2, U32>) -> Frame:
  match short:
    case True{}:
      Bad{Crypto{T.Authentication{}}}
    case False{}:
      frame.length(Nat.is_le(length, 16401n), header, length, body)

def frame.kind(ok: Bool, header: List<&2, U32>, +length: Nat, body: List<&2, U32>) -> Frame:
  match ok:
    case False{}:
      Bad{Unexpected{}}
    case True{}:
      # For this suite, 16 tag bytes. Authenticated empty inner plaintext is
      # rejected after decryption, like other inner records with no type byte.
      # TLSInnerPlaintext's maximum is 2^14+1, so the suite limit is 16401.
      frame.short(Nat.is_lt(length, 16n), header, length, body)

def frame.header(bytes: List<&2, U32>) -> Frame:
  match bytes:
    case Con{+kind, Con{+major, Con{+minor, Con{+high, Con{+low, body}}}}}:
      frame.kind(U32.is_eq(kind, 23), [kind, major, minor, high, low],
        U32.to_nat(U32.add(U32.mul(high, 256), low)), body)
    case _:
      More{}

def frame.valid(ok: Bool, bytes: List<&2, U32>) -> Frame:
  match ok:
    case False{}:
      Bad{Invalid{}}
    case True{}:
      frame.header(bytes)

# Retain More input in the stream owner and append more bytes before retrying.
# A Framed result consumes exactly one record and preserves coalesced records.
# Legacy version does not select the negotiated version; received header bytes
# remain authenticated. Writers always generate 0x0303.
def frame(+bytes: List<&2, U32>) -> Frame:
  frame.valid(B.valid(bytes), bytes)

def inner.checked(valid: Bool, owner: T.ReadKey, kind: U32, content: List<&2, U32>, padding: Nat) -> T.ReadKey & Result<&2, &2, Error, Record>:
  match valid:
    case False{}:
      (T.close_read(owner), Fail{Unexpected{}})
    case True{}:
      (owner, Done{Record{kind, content, padding}})

def inner.kind(owner: T.ReadKey, +kind: U32, +reversed: List<&2, U32>, padding: Nat) -> T.ReadKey & Result<&2, &2, Error, Record>:
  inner.checked(content_valid(kind, B.length(reversed)), owner,
    kind, List.reverse(&2, U32, reversed), padding)

def inner.strip(reversed: List<&2, U32>, owner: T.ReadKey, +padding: Nat) -> T.ReadKey & Result<&2, &2, Error, Record>:
  match reversed:
    case Nil{}:
      (T.close_read(owner), Fail{Unexpected{}})
    case Con{0, tail}:
      inner.strip(tail, owner, Nat.add(padding, 1n))
    case Con{kind, content}:
      inner.kind(owner, kind, content, padding)

def open.result(owner: T.ReadKey, result: Result<&2, &2, T.Error, List<&2, U32>>) -> T.ReadKey & Result<&2, &2, Error, Record>:
  match result:
    case Fail{why}:
      (owner, Fail{Crypto{why}})
    case Done{plaintext}:
      inner.strip(List.reverse(&2, U32, plaintext), owner, 0n)

def open.got(pair: T.ReadKey & Result<&2, &2, T.Error, List<&2, U32>>) -> T.ReadKey & Result<&2, &2, Error, Record>:
  (owner, result) = pair
  open.result(owner, result)

def open.split(owner: T.ReadKey, header: List<&2, U32>, parts: Split) -> T.ReadKey & Result<&2, &2, Error, Record>:
  match parts:
    case Split{ciphertext, tag}:
      open.got(T.open(owner, header, ciphertext, tag))

def open.frame(owner: T.ReadKey, framed: Frame) -> T.ReadKey & Result<&2, &2, Error, Record>:
  match framed:
    case More{}:
      (T.close_read(owner), Fail{Incomplete{}})
    case Bad{why}:
      (T.close_read(owner), Fail{why})
    case Framed{header, +body, Nil{}}:
      open.split(owner, header, split(Nat.sub(B.length(body), 16n), body, []))
    case Framed{_, _, _}:
      (T.close_read(owner), Fail{Invalid{}})

# Open takes exactly one complete record. Stream callers use frame first and
# pass the framed header/body without the retained suffix to this interface.
def open(owner: T.ReadKey, bytes: List<&2, U32>) -> T.ReadKey & Result<&2, &2, Error, Record>:
  open.frame(owner, frame(bytes))
