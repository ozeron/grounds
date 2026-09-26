import Base
import ./text.bend as T
import ../utf8/utf8.bend as U

# a query string's pairs, in order and with repeats kept: ?tag=a&tag=b is
# two pairs, which a map would lose (application/x-www-form-urlencoded)
type Param is Data:
  Param{key: String, value: String}

def hex(+x: U32) -> Maybe<&2, U32>:
  Bool.pick(Maybe<&2, U32>, Bool.and(U32.is_ge(x, 48), U32.is_le(x, 57)), Some{(x - 48 : U32)},
    Bool.pick(Maybe<&2, U32>, Bool.and(U32.is_ge(x, 97), U32.is_le(x, 102)), Some{(x - 87 : U32)},
      Bool.pick(Maybe<&2, U32>, Bool.and(U32.is_ge(x, 65), U32.is_le(x, 70)), Some{(x - 55 : U32)}, None{})))

def pct.byte(a: Maybe<&2, U32>, b: Maybe<&2, U32>) -> Maybe<&2, U32>:
  match a b:
    case Some{+x} Some{+y}:
      Some{(x * 16 + y : U32)}
    case _ _:
      None{}

def pct.push(m: Maybe<&2, U32>, +x: U32, +y: U32, out: List<&2, U32>) -> List<&2, U32>:
  match m:
    case Some{b}:
      Con{b, out}
    case None{}:
      Con{y, Con{x, Con{37, out}}}

# the bytes of a component: %XX is a byte, + a space; a % not followed by
# two hex digits stays as it is
def bytes.go(s: String, out: List<&2, U32>) -> List<&2, U32>:
  match s:
    case SNil{}:
      List.reverse(&2, U32, out)
    case SCon{Chr{37}, SCon{Chr{+x}, SCon{Chr{+y}, t}}}:
      bytes.go(t, pct.push(pct.byte(hex(x), hex(y)), x, y, out))
    case SCon{Chr{43}, t}:
      bytes.go(t, Con{32, out})
    case SCon{Chr{x}, t}:
      bytes.go(t, U.enc.push(x, out))

def text.of(t: U.Text) -> String:
  match t:
    case U.TOk{s}:
      s
    case U.TBad{_, before}:
      String.reverse(before)

# a component decoded: bytes that are not UTF-8 end it where they start
def decode(s: String) -> String:
  text.of(U.decode(bytes.go(s, [])))

def pair(c: T.Cut) -> Param:
  match c:
    case T.Cut{k, Some{v}}:
      Param{decode(k), decode(v)}
    case T.Cut{k, None{}}:
      Param{decode(k), ""}

def add(p: String, acc: List<&2, Param>) -> List<&2, Param>:
  match p:
    case SNil{}:
      acc
    case SCon{c, t}:
      Con{pair(T.cut(SCon{c, t}, 61)), acc}

# c is the query cut at its first &: the pair before it, and what follows
def parse.go(fuel: Nat, c: T.Cut, acc: List<&2, Param>) -> List<&2, Param>:
  match fuel c:
    case 1n+f T.Cut{p, Some{rest}}:
      parse.go(f, T.cut(rest, 38), add(p, acc))
    case _ T.Cut{p, _}:
      List.reverse(&2, Param, add(p, acc))

# the pairs of a query string, without its ?
def parse(+q: String) -> List<&2, Param>:
  parse.go(String.length(q), T.cut(q, 38), [])
