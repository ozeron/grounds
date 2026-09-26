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
