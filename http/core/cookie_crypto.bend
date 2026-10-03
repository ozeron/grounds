import Base
import ../../crypto/hmac.bend as Hmac
import ../../utf8/utf8.bend as U

# Explicit Bend HMAC path for synthetic-key verification pending runtime review.
# Same UTF-8 value + '.' + full SHA-256 hex format as the legacy cookie effect.
def scalar(+code: U32) -> Bool:
  Bool.and(U32.is_le(code, 1114111), Bool.or(U32.is_lt(code, 55296), U32.is_gt(code, 57343)))

def text_valid(text: String, ok: Bool) -> Bool:
  match text:
    case SNil{}: ok
    case SCon{Chr{code}, tail}: text_valid(tail, Bool.and(ok, scalar(code)))

def signed(value: String, mac: Maybe<&2, String>) -> Maybe<&2, String>:
  match mac:
    case None{}: None{}
    case Some{hex}: Some{value ++ "." ++ hex}

def sign.checked(valid: Bool, key: String, +value: String) -> Maybe<&2, String>:
  match valid:
    case False{}: None{}
    case True{}: signed(value, Hmac.digest_hex(U.encode(key), U.encode(value)))

def sign(+key: String, +value: String) -> Maybe<&2, String>:
  sign.checked(Bool.and(text_valid(key, True{}), text_valid(value, True{})), key, value)

type Envelope is Data:
  Envelope{value: String, tag: String}

# Exactly 64 trailing ASCII hex characters, with a dot before them. Dots in
# the value and the empty value are valid; no ambiguous first-dot splitting.
def envelope(left: Nat, reversed: String, tag: String) -> Maybe<&2, Envelope>:
  match left reversed:
    case 0n SCon{'.', value}: Some{Envelope{String.reverse(value), tag}}
    case 0n _: None{}
    case 1n+p SCon{char, tail}: envelope(p, tail, SCon{char, tag})
    case _ _: None{}

def between(+code: U32, low: U32, high: U32) -> Bool:
  Bool.and(U32.is_ge(code, low), U32.is_le(code, high))

def hex_valid(+code: U32) -> Bool:
  Bool.or(between(code, 48, 57), Bool.or(between(code, 97, 102), between(code, 65, 70)))

def nibble(+code: U32) -> U32:
  Bool.pick(U32, between(code, 48, 57), U32.sub(code, 48),
    Bool.pick(U32, between(code, 97, 102), U32.sub(code, 87), U32.sub(code, 55)))

def unhex(text: String, reversed: List<&2, U32>, valid: Bool) -> Maybe<&2, List<&2, U32>>:
  match text:
    case SNil{}: Bool.pick(Maybe<&2, List<&2, U32>>, valid, Some{List.reverse(&2, U32, reversed)}, None{})
    case SCon{Chr{+hi}, SCon{Chr{+lo}, tail}}:
      unhex(tail, Con{U32.add(U32.mul(nibble(hi), 16), nibble(lo)), reversed},
        Bool.and(valid, Bool.and(hex_valid(hi), hex_valid(lo))))
    case _: None{}

# Complete XOR/OR reduction: no early return at the first differing byte.
# The envelope and HMAC construction supply exactly 32 bytes each. This is
# a source-level property, not a claim about optimized native/Bun timing.
def difference(actual: List<&2, U32>, supplied: List<&2, U32>, +acc: U32) -> U32:
  match actual supplied:
    case Nil{} Nil{}: acc
    case Con{a, at} Con{b, bt}: difference(at, bt, U32.or(acc, U32.xor(a, b)))
    case _ _: 1

def verified(value: String, supplied: List<&2, U32>, actual: Maybe<&2, List<&2, U32>>) -> Maybe<&2, String>:
  match actual:
    case None{}: None{}
    case Some{mac}: Bool.pick(Maybe<&2, String>, U32.is_eq(difference(mac, supplied, 0), 0), Some{value}, None{})

def verify.tag(key: String, +value: String, tag: Maybe<&2, List<&2, U32>>) -> Maybe<&2, String>:
  match tag:
    case None{}: None{}
    case Some{bytes}: verified(value, bytes, Hmac.digest(U.encode(key), U.encode(value)))

def verify.envelope(key: String, parsed: Maybe<&2, Envelope>) -> Maybe<&2, String>:
  match parsed:
    case None{}: None{}
    case Some{Envelope{value, tag}}: verify.tag(key, value, unhex(tag, [], True{}))

def verify.checked(valid: Bool, key: String, signed: String) -> Maybe<&2, String>:
  match valid:
    case False{}: None{}
    case True{}: verify.envelope(key, envelope(64n, String.reverse(signed), ""))

def verify(+key: String, +signed: String) -> Maybe<&2, String>:
  verify.checked(Bool.and(text_valid(key, True{}), text_valid(signed, True{})), key, signed)
