import Base

# text helpers for http: compare and split Strings by reading them only.
# A String used twice is shared, and sharing any String makes every
# String in a program reference counted, so nothing here keeps one.

# equal, case-sensitive
def same(a: String, b: String, ok: Bool) -> Bool:
  match a b:
    case SNil{} SNil{}:
      ok
    case SCon{x, at} SCon{y, bt}:
      same(at, bt, Bool.and(ok, Char.is_eq(x, y)))
    case _ _:
      False{}

def lower(+x: U32) -> U32:
  Bool.pick(U32, Bool.and(U32.is_ge(x, 65), U32.is_le(x, 90)), (x + 32 : U32), x)

def fold.eq(+x: U32, +y: U32) -> Bool:
  U32.is_eq(lower(x), lower(y))

# equal ignoring ASCII case, as header names compare (RFC 9110 §5.1)
def same_ci(a: String, b: String, ok: Bool) -> Bool:
  match a b:
    case SNil{} SNil{}:
      ok
    case SCon{Chr{+x}, at} SCon{Chr{+y}, bt}:
      same_ci(at, bt, Bool.and(ok, fold.eq(x, y)))
    case _ _:
      False{}

# a String cut at the first c: the part before, and the rest after it
type Cut is Data:
  Cut{before: String, after: Maybe<&2, String>}

def head_is(s: String, +c: U32) -> Bool:
  match s:
    case SCon{Chr{+x}, _}:
      U32.is_eq(x, c)
    case SNil{}:
      False{}

# hit is head_is(s, c), found before s is read
def cut.go(+s: String, +c: U32, acc: String, hit: Bool) -> Cut:
  match s hit:
    case SNil{} _:
      Cut{String.reverse(acc), None{}}
    case SCon{_, t} True{}:
      Cut{String.reverse(acc), Some{t}}
    case SCon{x, +t} False{}:
      cut.go(t, c, SCon{x, acc}, head_is(t, c))

def cut(+s: String, +c: U32) -> Cut:
  cut.go(s, c, "", head_is(s, c))

# the value, or d when there is none
def or(m: Maybe<&2, String>, d: String) -> String:
  match m:
    case Some{s}:
      s
    case None{}:
      d

def u32.go(s: String, +acc: U32, +n: U32, ok: Bool) -> Maybe<&2, U32>:
  match s ok:
    case _ False{}:
      None{}
    case SNil{} True{}:
      Bool.pick(Maybe<&2, U32>, Bool.and(U32.is_gt(n, 0), U32.is_le(n, 9)), Some{acc}, None{})
    case SCon{Chr{+c}, t} True{}:
      u32.go(t, ((acc * 10) + (c - 48) : U32), (n + 1 : U32), Bool.and(U32.is_ge(c, 48), U32.is_le(c, 57)))

# a whole number of one to nine digits, as a path or query writes an id
def u32(s: String) -> Maybe<&2, U32>:
  u32.go(s, 0, 0, True{})
