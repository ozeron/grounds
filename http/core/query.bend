import Base
import ./text.bend as T
import ../../utf8/utf8.bend as U

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

# where a component's bytes are: at a char, just after a %, or after a %
# and one char
type BS is Data:
  N{}
  P1{}
  P2{a: U32}

type BO is Data:
  BO{st: BS, out: List<&2, U32>}

# a char not after a %: a % starts an escape, a + is a space
def b.norm(pc: Bool, plus: Bool, +x: U32, out: List<&2, U32>) -> BO:
  match pc plus:
    case True{} _:
      BO{P1{}, out}
    case False{} True{}:
      BO{N{}, Con{32, out}}
    case False{} False{}:
      BO{N{}, U.enc.push(x, out)}

def b.step(st: BS, +x: U32, out: List<&2, U32>) -> BO:
  match st:
    case N{}:
      b.norm(U32.is_eq(x, 37), U32.is_eq(x, 43), x, out)
    case P1{}:
      BO{P2{x}, out}
    case P2{+a}:
      BO{N{}, pct.push(pct.byte(hex(a), hex(x)), a, x, out)}

def b.last(o: BO) -> List<&2, U32>:
  match o:
    case BO{P1{}, out}:
      List.reverse(&2, U32, Con{37, out})
    case BO{_, out}:
      List.reverse(&2, U32, out)

# a % with fewer than two chars after it stays as it is
def b.flush(st: BS, out: List<&2, U32>) -> List<&2, U32>:
  match st:
    case N{}:
      List.reverse(&2, U32, out)
    case P1{}:
      List.reverse(&2, U32, Con{37, out})
    case P2{+a}:
      b.last(b.norm(U32.is_eq(a, 37), U32.is_eq(a, 43), a, Con{37, out}))

# the bytes of a component: %XX is a byte, + a space; a % not followed by
# two hex digits stays as it is
def bytes.go(s: String, o: BO) -> List<&2, U32>:
  match s o:
    case SNil{} BO{st, out}:
      b.flush(st, out)
    case SCon{Chr{+x}, t} BO{st, out}:
      bytes.go(t, b.step(st, x, out))

def text.of(t: U.Text) -> String:
  match t:
    case U.TOk{s}:
      s
    case U.TBad{_, before}:
      String.reverse(before)

# a component decoded: bytes that are not UTF-8 end it where they start
def decode(s: String) -> String:
  text.of(U.decode(bytes.go(s, BO{N{}, []})))

# the query so far: the key and the value of the pair it is in, reversed;
# whether it is past the pair's =; whether the pair has a char yet; and
# the pairs before it, newest first
type QS is Data:
  QS{k: String, v: String, inv: Bool, any: Bool, acc: List<&2, Param>}

# a pair ended: kept unless it was empty, as && makes
def emit(any: Bool, k: String, v: String, acc: List<&2, Param>) -> List<&2, Param>:
  match any:
    case True{}:
      Con{Param{decode(String.reverse(k)), decode(String.reverse(v))}, acc}
    case False{}:
      acc

def step.key(eq: Bool, +x: U32, k: String, v: String, acc: List<&2, Param>) -> QS:
  match eq:
    case True{}:
      QS{k, v, True{}, True{}, acc}
    case False{}:
      QS{SCon{Chr{x}, k}, v, False{}, True{}, acc}

# a & ends a pair; the first = in a pair ends its key
def step(amp: Bool, eq: Bool, +x: U32, q: QS) -> QS:
  match amp q:
    case True{} QS{k, v, _, any, acc}:
      QS{"", "", False{}, False{}, emit(any, k, v, acc)}
    case False{} QS{k, v, True{}, _, acc}:
      QS{k, SCon{Chr{x}, v}, True{}, True{}, acc}
    case False{} QS{k, v, False{}, _, acc}:
      step.key(eq, x, k, v, acc)

def parse.go(s: String, q: QS) -> List<&2, Param>:
  match s q:
    case SNil{} QS{k, v, _, any, acc}:
      List.reverse(&2, Param, emit(any, k, v, acc))
    case SCon{Chr{+x}, t} other:
      parse.go(t, step(U32.is_eq(x, 38), U32.is_eq(x, 61), x, other))

# the pairs of a query string, without its ?
def parse(q: String) -> List<&2, Param>:
  parse.go(q, QS{"", "", False{}, False{}, []})

# query's own compare: one shared with callers that pass literals would
# make it an owner, and a name used for every pair would then be shared
def same(a: String, b: String, ok: Bool) -> Bool:
  match a b:
    case SNil{} SNil{}:
      ok
    case SCon{x, at} SCon{y, bt}:
      same(at, bt, Bool.and(ok, Char.is_eq(x, y)))
    case _ _:
      False{}

def get.keep(hit: Bool, v: String, found: Maybe<&2, String>) -> Maybe<&2, String>:
  match hit found:
    case True{} None{}:
      Some{v}
    case _ other:
      other

def get.go(ps: List<&2, Param>, +name: String, found: Maybe<&2, String>) -> Maybe<&2, String>:
  match ps:
    case Nil{}:
      found
    case Con{Param{k, v}, t}:
      get.go(t, name, get.keep(same(k, name, True{}), v, found))

# the first value of a key
def get(ps: List<&2, Param>, +name: String) -> Maybe<&2, String>:
  get.go(ps, name, None{})
