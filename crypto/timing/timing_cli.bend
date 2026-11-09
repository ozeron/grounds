import Base
import ../bytes.bend as B
import ../x25519.bend as X
import ../p256.bend as P
import ../ecdsa_sign256.bend as E
import ../rsa_private.bend as R
import ../rsa_integer.bend as RI
import ../gcm.bend as G
import ../aead.bend as A
import ../hmac.bend as M
import ../../wire/tls_schedule.bend as S
import ../../io/io.bend as Io

# dudect-style leakage harness (README.md). Prints one "class cycles
# instructions result" line per measurement (counters: effs/clock.c). Inputs are prepared before the first clock read; the
# measured operation runs in the continuation of that read and its result
# feeds the second read. Synthetic inputs only; no live secret is used.

def grounds_timing_cycles(dep: U32) -> IO(Nat):
  import "./effs/clock.c"
  import "./effs/clock.js"

def grounds_timing_instructions(dep: U32) -> IO(Nat):
  import "./effs/clock.c"
  import "./effs/clock.js"

# Data copy of rsa_private.Private, so one pool key can build many owners.
type RKey is Data:
  RKey{n: List<&2, U32>, e: List<&2, U32>, d: List<&2, U32>, p: List<&2, U32>,
       q: List<&2, U32>, dp: List<&2, U32>, dq: List<&2, U32>, qi: List<&2, U32>}

type In is Data:
  In{a: List<&2, U32>, b: List<&2, U32>, c: List<&2, U32>, d: List<&2, U32>, key: RKey}

def no_key() -> RKey:
  RKey{[], [], [], [], [], [], [], []}

def xorshift.c(+b: U32) -> U32:
  U32.xor(b, U32.shln(b, 5n))

def xorshift.b(+a: U32) -> U32:
  xorshift.c(U32.xor(a, U32.shrn(a, 17n)))

def xorshift(+s: U32) -> U32:
  xorshift.b(U32.xor(s, U32.shln(s, 13n)))

def mix(+s: U32, +k: U32) -> U32:
  xorshift(xorshift(U32.or(U32.xor(s, U32.mul(k, 2654435769)), 1)))

def rand.go(left: Nat, +s: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match left:
    case 0n:
      acc
    case 1n+p:
      rand.go(p, xorshift(s), Con{U32.and(U32.shrn(s, 11n), 255), acc})

def rand(left: Nat, +s: U32) -> List<&2, U32>:
  rand.go(left, xorshift(U32.or(s, 1)), [])

def zeros(left: Nat) -> List<&2, U32>:
  List.replicate(U32, left, 0)

def choose(+cls: U32, fixed: List<&2, U32>, random: List<&2, U32>) -> List<&2, U32>:
  Bool.pick(List<&2, U32>, U32.is_eq(cls, 0), fixed, random)

def with_top(+top: U32, bytes: List<&2, U32>) -> List<&2, U32>:
  match bytes:
    case Nil{}:
      []
    case Con{first, tail}:
      Con{U32.and(first, top), tail}

def flip.go(bytes: List<&2, U32>, +at: Nat, +i: Nat) -> List<&2, U32>:
  match bytes:
    case Nil{}:
      []
    case Con{+x, tail}:
      Con{Bool.pick(U32, Nat.is_eq(i, at), U32.xor(x, 1), x), flip.go(tail, at, Nat.add(i, 1n))}

def flip(+at: Nat, bytes: List<&2, U32>) -> List<&2, U32>:
  flip.go(bytes, at, 0n)

def fold(xs: List<&2, U32>, +acc: U32) -> U32:
  match xs:
    case Nil{}:
      acc
    case Con{x, tail}:
      fold(tail, U32.add(U32.mul(acc, 31), x))

def sum1(r: Maybe<&1, List<&2, U32>>) -> U32:
  match r:
    case None{}:
      7
    case Some{bytes}:
      fold(bytes, 1)

def sum2(r: Maybe<&2, List<&2, U32>>) -> U32:
  match r:
    case None{}:
      7
    case Some{bytes}:
      fold(bytes, 1)

def gcm_sum(r: Maybe<&2, G.Sealed>) -> U32:
  match r:
    case None{}:
      7
    case Some{G.Sealed{ciphertext, tag}}:
      fold(tag, fold(ciphertext, 1))

def aead_sum(r: Maybe<&2, A.Sealed>) -> U32:
  match r:
    case None{}:
      7
    case Some{A.Sealed{ciphertext, tag}}:
      fold(tag, fold(ciphertext, 1))

def gcm_tag(r: Maybe<&2, G.Sealed>) -> List<&2, U32>:
  match r:
    case None{}:
      []
    case Some{G.Sealed{_, tag}}:
      tag

def gcm_ct(r: Maybe<&2, G.Sealed>) -> List<&2, U32>:
  match r:
    case None{}:
      []
    case Some{G.Sealed{ciphertext, _}}:
      ciphertext

def aead_tag(r: Maybe<&2, A.Sealed>) -> List<&2, U32>:
  match r:
    case None{}:
      []
    case Some{A.Sealed{_, tag}}:
      tag

def aead_ct(r: Maybe<&2, A.Sealed>) -> List<&2, U32>:
  match r:
    case None{}:
      []
    case Some{A.Sealed{ciphertext, _}}:
      ciphertext

def bool_sum(ok: Bool) -> U32:
  Bool.pick(U32, ok, 3, 5)

def generator() -> List<&2, U32>:
  [4, 107, 23, 209, 242, 225, 44, 66, 71, 248, 188, 230, 229, 99, 164, 64, 242, 119, 3, 125, 129, 45, 235, 51, 160, 244, 161, 57, 69, 216, 152, 194, 150,
   79, 227, 66, 226, 254, 26, 127, 155, 142, 231, 235, 74, 124, 15, 158, 22, 43, 206, 51, 87, 107, 49, 94, 206, 203, 182, 64, 104, 55, 191, 81, 245]

def small_scalar() -> List<&2, U32>:
  B.append(zeros(31n), [1])

def aad() -> List<&2, U32>:
  [23, 3, 3, 0, 80]

# Positive control: a loop whose count is the low nibble of a secret byte.
def control.spin(left: Nat, +acc: U32) -> U32:
  match left:
    case 0n:
      acc
    case 1n+p:
      control.spin(p, xorshift(acc))

def control(bytes: List<&2, U32>) -> U32:
  match bytes:
    case Nil{}:
      0
    case Con{+x, _}:
      control.spin(U32.to_nat(U32.and(x, 15)), U32.or(x, 1))

def rsa_sign(key: RKey, +digest: List<&2, U32>, +salt: List<&2, U32>, +blind: List<&2, U32>) -> U32:
  match key:
    case RKey{n, e, d, p, q, dp, dq, qi}:
      sum1(R.sign_digest(R.Private{n, e, d, p, q, dp, dq, qi}, digest, salt, blind))

# kind: 0 x25519 shared, 1 p256 ecdh, 2 p256 keygen, 3 ecdsa sign, 4 rsa sign,
# 5 aes128-gcm seal, 6 aes256-gcm seal, 7 chacha20-poly1305 seal,
# 8 aes128-gcm open (tag error first/last byte), 9 chacha open (same),
# 10 hmac-sha256, 11 finished verify (error first/last byte), 12 empty,
# 13 positive control (secret-nibble loop), 14 RSA CRT product q*h (h top
# byte zero/full), 15 RSA blinder r < n compare (first/late difference),
# 16 P-256 d*G with 16 leading zero bits vs full-width random d (Minerva-style
# nonce-length check), 17 P-256 d*G with a fixed random-looking d vs random d.
def run(+kind: U32, input: In) -> U32:
  match kind input:
    case 0 In{a, b, _, _, _}:
      sum2(X.shared(a, b))
    case 1 In{a, b, _, _, _}:
      sum1(P.shared(a, b))
    case 2 In{a, _, _, _, _}:
      sum1(P.public_key(a))
    case 3 In{a, b, _, _, _}:
      sum1(E.sign_digest(a, b))
    case 4 In{a, b, c, _, key}:
      rsa_sign(key, a, b, c)
    case 5 In{a, b, c, _, _}:
      gcm_sum(G.seal(a, b, aad(), c))
    case 6 In{a, b, c, _, _}:
      gcm_sum(G.seal(a, b, aad(), c))
    case 7 In{a, b, c, _, _}:
      aead_sum(A.seal(a, b, aad(), c))
    case 8 In{a, b, c, d, _}:
      sum2(G.open(a, b, aad(), c, d))
    case 9 In{a, b, c, d, _}:
      sum2(A.open(a, b, aad(), c, d))
    case 10 In{a, b, _, _, _}:
      sum2(M.digest(a, b))
    case 11 In{a, b, c, _, _}:
      bool_sum(S.verify_finished(S.FinishedKey{a}, b, c))
    case 12 In{a, _, _, _, _}:
      fold(a, 1)
    case 16 In{a, _, _, _, _}:
      sum1(P.public_key(a))
    case 17 In{a, _, _, _, _}:
      sum1(P.public_key(a))
    case 14 In{a, b, _, _, _}:
      fold(RI.encode(512n, R.product(a, b)), 1)
    case 15 In{a, b, _, _, _}:
      bool_sum(RI.less(a, b))
    case _ In{a, _, _, _, _}:
      control(a)

def open_gcm.sealed(+cls: U32, +key: List<&2, U32>, +nonce: List<&2, U32>, +sealed: Maybe<&2, G.Sealed>) -> In:
  In{key, nonce, gcm_ct(sealed), flip(Bool.pick(Nat, U32.is_eq(cls, 0), 0n, 15n), gcm_tag(sealed)), no_key()}

def open_gcm(+cls: U32, +key: List<&2, U32>, +nonce: List<&2, U32>, +plain: List<&2, U32>) -> In:
  open_gcm.sealed(cls, key, nonce, G.seal(key, nonce, aad(), plain))

def open_aead.sealed(+cls: U32, +key: List<&2, U32>, +nonce: List<&2, U32>, +sealed: Maybe<&2, A.Sealed>) -> In:
  In{key, nonce, aead_ct(sealed), flip(Bool.pick(Nat, U32.is_eq(cls, 0), 0n, 15n), aead_tag(sealed)), no_key()}

def open_aead(+cls: U32, +key: List<&2, U32>, +nonce: List<&2, U32>, +plain: List<&2, U32>) -> In:
  open_aead.sealed(cls, key, nonce, A.seal(key, nonce, aad(), plain))

def expected(r: Maybe<&2, List<&2, U32>>) -> List<&2, U32>:
  match r:
    case None{}:
      []
    case Some{bytes}:
      bytes

def finished_in(+cls: U32, +key: List<&2, U32>, +hash: List<&2, U32>) -> In:
  In{key, hash, flip(Bool.pick(Nat, U32.is_eq(cls, 0), 0n, 31n), expected(S.finished(S.FinishedKey{key}, hash))), [], no_key()}

def key_of(found: Maybe<&2, RKey>) -> RKey:
  match found:
    case None{}:
      no_key()
    case Some{k}:
      k

def key_at(keys: List<&2, RKey>, +i: Nat) -> RKey:
  key_of(List.get(&2, RKey, keys, i))

def rsa_input(+s: U32, key: RKey) -> In:
  match key:
    case RKey{+n, e, d, p, q, dp, dq, qi}:
      In{rand(32n, mix(s, 1)), rand(32n, mix(s, 2)),
        Con{0, rand(Nat.sub(B.length(n), 1n), mix(s, 3))}, [], RKey{n, e, d, p, q, dp, dq, qi}}

# h = (m1 - m2) * qi mod p is |p| bytes with leading zeros: class 0 has a zero
# top byte, class 1 a full-width top byte.
def rsa_product(+cls: U32, +s: U32, key: RKey) -> In:
  match key:
    case RKey{_, _, _, +p, +q, _, _, _}:
      In{q, Con{Bool.pick(U32, U32.is_eq(cls, 0), 0, U32.or(U32.and(mix(s, 4), 127), 64)),
        rand(Nat.sub(B.length(p), 1n), mix(s, 5))}, [], [], no_key()}

# Blinder admission r < n: class 0 differs from n in its first byte, class 1
# shares n's first 128 bytes.
def rsa_less(+cls: U32, +s: U32, key: RKey) -> In:
  match key:
    case RKey{+n, _, _, _, _, _, _, _}:
      In{Bool.pick(List<&2, U32>, U32.is_eq(cls, 0), Con{0, rand(Nat.sub(B.length(n), 1n), mix(s, 6))},
          B.append(List.take(&2, U32, n, 128n), Con{0, rand(Nat.sub(B.length(n), 129n), mix(s, 6))})),
        n, [], [], no_key()}

def rsa_in(+cls: U32, +s: U32, +count: Nat, keys: List<&2, RKey>) -> In:
  +index = Bool.pick(Nat, U32.is_eq(cls, 0), 0n,
    Nat.add(1n, Nat.mod(U32.to_nat(U32.shrn(mix(s, 9), 4n)), Nat.sub(count, 1n))))
  rsa_input(s, key_at(keys, index))

def prepare(+kind: U32, +cls: U32, +s: U32, +count: Nat, +keys: List<&2, RKey>) -> In:
  match kind:
    case 0:
      In{choose(cls, zeros(32n), rand(32n, mix(s, 1))), Con{9, zeros(31n)}, [], [], no_key()}
    case 1:
      In{choose(cls, small_scalar(), with_top(127, rand(32n, mix(s, 1)))), generator(), [], [], no_key()}
    case 2:
      In{choose(cls, small_scalar(), with_top(127, rand(32n, mix(s, 1)))), [], [], [], no_key()}
    case 3:
      In{choose(cls, small_scalar(), with_top(127, rand(32n, mix(s, 1)))),
        choose(cls, zeros(32n), rand(32n, mix(s, 2))), [], [], no_key()}
    case 4:
      rsa_in(cls, s, count, keys)
    case 5:
      In{choose(cls, zeros(16n), rand(16n, mix(s, 1))), zeros(12n),
        choose(cls, zeros(64n), rand(64n, mix(s, 2))), [], no_key()}
    case 6:
      In{choose(cls, zeros(32n), rand(32n, mix(s, 1))), zeros(12n),
        choose(cls, zeros(64n), rand(64n, mix(s, 2))), [], no_key()}
    case 7:
      In{choose(cls, zeros(32n), rand(32n, mix(s, 1))), zeros(12n),
        choose(cls, zeros(64n), rand(64n, mix(s, 2))), [], no_key()}
    case 8:
      open_gcm(cls, rand(16n, mix(s, 1)), rand(12n, mix(s, 2)), rand(64n, mix(s, 3)))
    case 9:
      open_aead(cls, rand(32n, mix(s, 1)), rand(12n, mix(s, 2)), rand(64n, mix(s, 3)))
    case 10:
      In{choose(cls, zeros(32n), rand(32n, mix(s, 1))), zeros(64n), [], [], no_key()}
    case 11:
      finished_in(cls, rand(32n, mix(s, 1)), rand(32n, mix(s, 2)))
    case 16:
      In{choose(cls, Con{0, Con{0, rand(30n, mix(s, 1))}}, with_top(127, rand(32n, mix(s, 1)))), [], [], [], no_key()}
    case 17:
      In{choose(cls, with_top(127, rand(32n, 12345)), with_top(127, rand(32n, mix(s, 1)))), [], [], [], no_key()}
    case 14:
      rsa_product(cls, s, key_at(keys, 0n))
    case 15:
      rsa_less(cls, s, key_at(keys, 0n))
    case _:
      In{choose(cls, zeros(32n), rand(32n, mix(s, 1))), [], [], [], no_key()}

# Count mode: every iteration uses class/key `cls` and nothing is printed until
# the end, so instructions retired by the process (/usr/bin/time -l) compare
# control flow across secrets without clock or formatting noise. For RSA,
# cls selects the pool key and digest/salt/blinder still vary per iteration.
def prepare_count(+kind: U32, +cls: U32, +s: U32, +count: Nat, +keys: List<&2, RKey>) -> In:
  match kind:
    case 4:
      rsa_input(s, key_at(keys, U32.to_nat(cls)))
    case _:
      prepare(kind, U32.and(cls, 1), s, count, keys)

def counted(left: Nat, +kind: U32, +cls: U32, +seed: U32, +count: Nat, +keys: List<&2, RKey>, +acc: U32) -> U32:
  match left:
    case 0n:
      acc
    case 1n+p:
      +s = xorshift(seed)
      counted(p, kind, cls, s, count, keys, U32.xor(acc, run(kind, prepare_count(kind, cls, s, count, keys))))

def show(+x: Nat) -> String:
  String.append(" ", Nat.show(x))

def line(+cls: U32, +i0: Nat, +c0: Nat, +c1: Nat, +i1: Nat, +result: U32) -> String:
  String.append(U32.show(cls), String.append(show(Nat.sub(c1, c0)),
    String.append(show(Nat.sub(i1, i0)), show(U32.to_nat(result)))))

# Order: instructions, cycles, operation, cycles, instructions. The
# operation runs in the continuation of the first cycles read and its result
# feeds the second; the fixed effect overhead is the same for both classes.
def timed.end(+cls: U32, +i0: Nat, +c0: Nat, +result: U32, next: Unit -> IO(Unit), +c1: Nat) -> IO(Unit):
  IO.bind(Nat, Unit, grounds_timing_instructions(U32.from_nat(c1)),
    i1 => IO.bind(Unit, Unit, IO.print(line(cls, i0, c0, c1, i1, result)), next))

def timed.after(+cls: U32, +i0: Nat, +c0: Nat, +result: U32, next: Unit -> IO(Unit)) -> IO(Unit):
  IO.bind(Nat, Unit, grounds_timing_cycles(result), c1 => timed.end(cls, i0, c0, result, next, c1))

def timed.start(+kind: U32, +cls: U32, input: In, next: Unit -> IO(Unit), +i0: Nat) -> IO(Unit):
  IO.bind(Nat, Unit, grounds_timing_cycles(U32.from_nat(i0)),
    c0 => timed.after(cls, i0, c0, run(kind, input), next))

def timed(+kind: U32, +cls: U32, input: In, next: Unit -> IO(Unit)) -> IO(Unit):
  IO.bind(Nat, Unit, grounds_timing_instructions(cls), i0 => timed.start(kind, cls, input, next, i0))

def loop(left: Nat, +kind: U32, +seed: U32, +count: Nat, +keys: List<&2, RKey>) -> IO(Unit):
  match left:
    case 0n:
      IO.pure(Unit, Unit{})
    case 1n+p:
      +s = xorshift(seed)
      +cls = U32.and(U32.shrn(s, 7n), 1)
      timed(kind, cls, prepare(kind, cls, s, count, keys), _ => loop(p, kind, s, count, keys))

# Key pool file: repeated n,e,d,p,q,dp,dq,qi fields, each a 2-byte big-endian
# length followed by the canonical big-endian integer.
def field.split(left: Nat, bytes: List<&2, U32>, acc: List<&2, U32>) -> List<&2, U32> & List<&2, U32>:
  match left bytes:
    case 0n _:
      (List.reverse(&2, U32, acc), bytes)
    case 1n+p Con{x, tail}:
      field.split(p, tail, Con{x, acc})
    case _ Nil{}:
      (List.reverse(&2, U32, acc), [])

def field.done(pair: List<&2, U32> & List<&2, U32>, next: List<&2, U32> -> List<&2, U32> -> List<&2, RKey>) -> List<&2, RKey>:
  (value, rest) = pair
  next(value, rest)

def field(bytes: List<&2, U32>, next: List<&2, U32> -> List<&2, U32> -> List<&2, RKey>) -> List<&2, RKey>:
  match bytes:
    case Con{+h, Con{+l, tail}}:
      field.done(field.split(U32.to_nat(U32.add(U32.mul(h, 256), l)), tail, []), next)
    case _:
      next([], [])

def keys.go(fuel: Nat, bytes: List<&2, U32>, acc: List<&2, RKey>) -> List<&2, RKey>:
  match fuel bytes:
    case 0n _:
      List.reverse(&2, RKey, acc)
    case _ Nil{}:
      List.reverse(&2, RKey, acc)
    case 1n+f Con{x, tail}:
      field(Con{x, tail}, n => r1 => field(r1, e => r2 => field(r2, d => r3 => field(r3, p => r4 =>
        field(r4, q => r5 => field(r5, dp => r6 => field(r6, dq => r7 => field(r7, qi => r8 =>
          keys.go(f, r8, Con{RKey{n, e, d, p, q, dp, dq, qi}, acc})))))))))

# kind >= 100 selects count mode for kind % 100 with class/key kind / 100 - 1.
def start.mode(counting: Bool, +kind: U32, +count: Nat, +seed: U32, +keys: List<&2, RKey>) -> IO(Unit):
  match counting:
    case False{}:
      loop(count, kind, seed, List.length(&2, RKey, keys), keys)
    case True{}:
      IO.print(U32.show(counted(count, U32.mod(kind, 100), U32.sub(U32.div(kind, 100), 1), seed,
        List.length(&2, RKey, keys), keys, 0)))

def start(+kind: U32, +count: Nat, +seed: U32, +keys: List<&2, RKey>) -> IO(Unit):
  start.mode(U32.is_ge(kind, 100), kind, count, seed, keys)

def with_keys(+kind: U32, +count: Nat, +seed: U32, path: String) -> IO(Unit):
  do IO<Unit>:
    bytes : List<&2, U32> <- Io.read_bytes(path)
    start(kind, count, seed, keys.go(256n, bytes, []))

def parsed(kind: Maybe<&2, U32>, count: Maybe<&2, Nat>, seed: Maybe<&2, U32>, path: String) -> IO(Unit):
  match kind count seed:
    case Some{+k} Some{+c} Some{+s}:
      with_keys(k, c, s, path)
    case _ _ _:
      IO.die(Unit, 2, "usage: timing_cli <kind> <count> <seed> <rsa-key-pool>")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{kind, Con{count, Con{seed, Con{path, Nil{}}}}}:
      parsed(U32.read(kind), Nat.read(count), U32.read(seed), path)
    case _:
      IO.die(Unit, 2, "usage: timing_cli <kind> <count> <seed> <rsa-key-pool>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- Io.args()
    dispatch(args)
