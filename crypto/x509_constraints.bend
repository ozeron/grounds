import Base
import ./der.bend as D
import ./bytes.bend as B

# RFC 5280 payload admission, separate from certificate/path authorization.
# Retain an arbitrary-size canonical pathLen INTEGER instead of truncating it.
type Basic is Type:
  Basic{ca: Bool, path: Maybe<&1, List<&2, U32>>}

type Usage is Type:
  Usage{bits: U32}

def natural(bytes: List<&2, U32>) -> Bool:
  match bytes:
    case Con{0, Con{second, _}}: U32.is_ge(second, 128)
    case Con{first, _}: U32.is_lt(first, 128)
    case Nil{}: False{}

def basic.path.checked(valid: Bool, bytes: List<&2, U32>) -> Maybe<&1, Basic>:
  match valid:
    case True{}: Some{Basic{True{}, Some{bytes}}}
    case False{}: None{}

def basic.path.element(element: Maybe<&1, D.Element>) -> Maybe<&1, Basic>:
  match element:
    case Some{D.Element{2, +bytes, Nil{}, _}}:
      basic.path.checked(natural(bytes), bytes)
    case _: None{}

def basic.path(bytes: List<&2, U32>) -> Maybe<&1, Basic>:
  match bytes:
    case Nil{}: Some{Basic{True{}, None{}}}
    case bytes: basic.path.element(D.read(bytes))

def basic.first(element: Maybe<&1, D.Element>) -> Maybe<&1, Basic>:
  match element:
    case Some{D.Element{1, Con{255, Nil{}}, rest, _}}: basic.path(rest)
    case _: None{}

def basic.body(bytes: Maybe<&1, List<&2, U32>>) -> Maybe<&1, Basic>:
  match bytes:
    case Some{Nil{}}: Some{Basic{False{}, None{}}}
    case Some{bytes}: basic.first(D.read(bytes))
    case None{}: None{}

def basic(bytes: List<&2, U32>) -> Maybe<&1, Basic>:
  basic.body(D.complete(48, bytes))

# Compare the validated nonnegative INTEGER with a bounded chain-depth count.
# Once its prefix exceeds 24 bits, another byte makes it exceed every U32.
# Continue consuming bytes without overflow; retain the exact original limit.
def path.go(bytes: List<&2, U32>, count: U32, +value: U32, large: Bool) -> Bool:
  match bytes large:
    case Nil{} False{}: U32.is_ge(value, count)
    case Nil{} True{}: True{}
    case Con{_, rest} True{}: path.go(rest, count, 0, True{})
    case Con{byte, rest} False{}:
      path.go(rest, count, U32.add(U32.mul(value, 256), byte), U32.is_gt(value, 16777215))

def path.checked(valid: Bool, bytes: List<&2, U32>, count: U32) -> Bool:
  match valid:
    case True{}: path.go(bytes, count, 0, False{})
    case False{}: False{}

def path_allows(limit: Maybe<&1, List<&2, U32>>, count: U32) -> Bool:
  match limit:
    case None{}: True{}
    case Some{+bytes}:
      path.checked(Bool.and(natural(bytes), Bool.and(B.valid(bytes),
        Nat.is_le(B.length(bytes), 65535n))), bytes, count)

def usage.checked(valid: Bool, bits: U32) -> Maybe<&1, Usage>:
  match valid:
    case True{}: Some{Usage{bits}}
    case False{}: None{}

# Only the nine named bits are admitted. The final set bit must be the last
# encoded bit (DER named-bit-list rule); every unused padding bit is zero.
def usage.one.checked(valid: Bool, unused: U32, +byte: U32) -> Maybe<&1, Usage>:
  match valid:
    case False{}: None{}
    case True{}:
      +unit = U32.shln(1, U32.to_nat(unused))
      usage.checked(U32.is_eq(U32.and(byte, U32.sub(U32.mul(unit, 2), 1)), unit), byte)

def usage.one(+unused: U32, +byte: U32) -> Maybe<&1, Usage>:
  usage.one.checked(U32.is_le(unused, 7), unused, byte)

def usage.body(body: Maybe<&1, List<&2, U32>>) -> Maybe<&1, Usage>:
  match body:
    case Some{Con{unused, Con{byte, Nil{}}}}: usage.one(unused, byte)
    case Some{Con{7, Con{byte, Con{128, Nil{}}}}}:
      Some{Usage{U32.add(byte, 32768)}}
    case _: None{}

def usage(bytes: List<&2, U32>) -> Maybe<&1, Usage>:
  usage.body(D.complete(3, bytes))

# Local selected-policy check: keyCertSign requires cA; pathLen requires
# keyCertSign when keyUsage exists. encipherOnly/decipherOnly without
# keyAgreement have undefined meaning and are rejected by this policy.
# This does not select a trust anchor, verify a chain, or grant a key purpose.
def consistent.usage(ca: Bool, path: Bool, +bits: U32) -> Bool:
  Bool.and(Bool.or(U32.is_eq(U32.and(bits, 4), 0), ca),
    Bool.and(Bool.or(Bool.not(path), U32.is_ne(U32.and(bits, 4), 0)),
      Bool.or(U32.is_eq(U32.and(bits, 32769), 0), U32.is_ne(U32.and(bits, 8), 0))))

def consistent.path(ca: Bool, path: Maybe<&1, List<&2, U32>>, bits: U32) -> Bool:
  match path:
    case None{}: consistent.usage(ca, False{}, bits)
    case Some{_}: consistent.usage(ca, True{}, bits)

def consistent.admitted(basic: Maybe<&1, Basic>, usage: Maybe<&1, Usage>) -> Bool:
  match basic usage:
    case _ None{}: True{}
    case None{} Some{Usage{bits}}: consistent.usage(False{}, False{}, bits)
    case Some{Basic{ca, path}} Some{Usage{bits}}: consistent.path(ca, path, bits)

def basic.admitted(value: Maybe<&1, Basic>) -> Maybe<&1, Maybe<&1, Basic>>:
  match value:
    case Some{value}: Some{Some{value}}
    case None{}: None{}

def basic.optional(value: Maybe<&2, List<&2, U32>>) -> Maybe<&1, Maybe<&1, Basic>>:
  match value:
    case None{}: Some{None{}}
    case Some{bytes}: basic.admitted(basic(bytes))

def usage.admitted(value: Maybe<&1, Usage>) -> Maybe<&1, Maybe<&1, Usage>>:
  match value:
    case Some{value}: Some{Some{value}}
    case None{}: None{}

def usage.optional(value: Maybe<&2, List<&2, U32>>) -> Maybe<&1, Maybe<&1, Usage>>:
  match value:
    case None{}: Some{None{}}
    case Some{bytes}: usage.admitted(usage(bytes))

def policy.admitted(basic: Maybe<&1, Maybe<&1, Basic>>, usage: Maybe<&1, Maybe<&1, Usage>>) -> Bool:
  match basic usage:
    case Some{basic} Some{usage}: consistent.admitted(basic, usage)
    case _ _: False{}

# Public local policy boundary. None means the extension is absent. Some{}
# must decode successfully; malformed present payloads never become absence.
def policy(basic_bytes: Maybe<&2, List<&2, U32>>, usage_bytes: Maybe<&2, List<&2, U32>>) -> Bool:
  policy.admitted(basic.optional(basic_bytes), usage.optional(usage_bytes))
