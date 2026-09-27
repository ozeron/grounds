import Base

# byte helpers for http1: every function reads its input once, so no
# List is shared. A classifier copies its byte, (b + 0 : U32), before using
# it more than once: reusing the byte of a list cell shares the list

# bytes as a list of their own: a List<U32> read and then used again makes
# Lists reference counted (the compiler takes a generic list's cells to read
# them); a list type of its own is read without taking it
type Bytes is Data:
  BNil{}
  BCon{head: U32, tail: Bytes}

def rev.go(bs: Bytes, acc: Bytes) -> Bytes:
  match bs:
    case BNil{}:
      acc
    case BCon{b, t}:
      rev.go(t, BCon{b, acc})

def rev(bs: Bytes) -> Bytes:
  rev.go(bs, BNil{})

def app(a: Bytes, b: Bytes) -> Bytes:
  rev.go(rev(a), b)

# a then b, one cell at a time: what a law can follow, where app reverses
# twice
def cat(a: Bytes, b: Bytes) -> Bytes:
  match a:
    case BNil{}:
      b
    case BCon{x, t}:
      BCon{x, cat(t, b)}

def of_list.go(xs: List<&2, U32>, acc: Bytes) -> Bytes:
  match xs:
    case Nil{}:
      rev(acc)
    case Con{x, t}:
      of_list.go(t, BCon{x, acc})

# from the List<U32> a socket gives
def of_list(xs: List<&2, U32>) -> Bytes:
  of_list.go(xs, BNil{})

def to_list.go(bs: Bytes, acc: List<&2, U32>) -> List<&2, U32>:
  match bs:
    case BNil{}:
      List.reverse(&2, U32, acc)
    case BCon{b, t}:
      to_list.go(t, Con{b, acc})

# to the List<U32> a socket takes
def to_list(bs: Bytes) -> List<&2, U32>:
  to_list.go(bs, [])

def is_digit.x(+b: U32) -> Bool:
  Bool.and(U32.is_ge(b, 48), U32.is_le(b, 57))

def is_digit(b: U32) -> Bool:
  is_digit.x((b + 0 : U32))

def is_alpha.x(+b: U32) -> Bool:
  Bool.or(Bool.and(U32.is_ge(b, 65), U32.is_le(b, 90)), Bool.and(U32.is_ge(b, 97), U32.is_le(b, 122)))

def is_alpha(b: U32) -> Bool:
  is_alpha.x((b + 0 : U32))

def is_tchar.x(+b: U32) -> Bool:
  Bool.or(Bool.or(is_digit(b), is_alpha(b)),
    Bool.or(Bool.or(Bool.or(U32.is_eq(b, 33), Bool.and(U32.is_ge(b, 35), U32.is_le(b, 39))),
      Bool.or(Bool.or(U32.is_eq(b, 42), U32.is_eq(b, 43)), Bool.or(U32.is_eq(b, 45), U32.is_eq(b, 46)))),
      Bool.or(Bool.or(U32.is_eq(b, 94), U32.is_eq(b, 95)), Bool.or(Bool.or(U32.is_eq(b, 96), U32.is_eq(b, 124)), U32.is_eq(b, 126)))))

# a token char (RFC 9110 §5.6.2): ! # $ % & ' * + - . ^ _ ` | ~ digits letters
def is_tchar(b: U32) -> Bool:
  is_tchar.x((b + 0 : U32))

def is_ctl.x(+b: U32) -> Bool:
  Bool.and(Bool.or(U32.is_lt(b, 32), U32.is_eq(b, 127)), Bool.not(U32.is_eq(b, 9)))

# a control char, other than tab: never in a field value (RFC 9110 §5.5)
def is_ctl(b: U32) -> Bool:
  is_ctl.x((b + 0 : U32))

def is_ws.x(+b: U32) -> Bool:
  Bool.or(U32.is_eq(b, 32), U32.is_eq(b, 9))

def is_ws(b: U32) -> Bool:
  is_ws.x((b + 0 : U32))

def nonempty(bs: Bytes) -> Bool:
  match bs:
    case BNil{}:
      False{}
    case _:
      True{}

# plain loops, not a template: the compiler reads a list through a plain
# loop without taking it, so the caller can use the list again
def tokens.go(bs: Bytes, ok: Bool) -> Bool:
  match bs:
    case BNil{}:
      ok
    case BCon{b, t}:
      tokens.go(t, Bool.and(ok, is_tchar(b)))

# a non-empty run of token chars
def is_token(+bs: Bytes) -> Bool:
  Bool.and(nonempty(bs), tokens.go(bs, True{}))

def value.go(bs: Bytes, ok: Bool) -> Bool:
  match bs:
    case BNil{}:
      ok
    case BCon{b, t}:
      value.go(t, Bool.and(ok, Bool.not(is_ctl(b))))

def value_ok(bs: Bytes) -> Bool:
  value.go(bs, True{})

def head_ws(bs: Bytes) -> Bool:
  match bs:
    case BCon{b, _}:
      is_ws(b)
    case BNil{}:
      False{}

# bs without leading spaces and tabs
def drop_ws(bs: Bytes) -> Bytes:
  match bs:
    case BCon{32, t}:
      drop_ws(t)
    case BCon{9, t}:
      drop_ws(t)
    case other:
      other
