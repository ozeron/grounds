import Base
import ./text.bend as T

# header fields in the order they came (RFC 9110 §5); a name may repeat,
# and names compare ignoring case
type Header is Data:
  Header{name: String, value: String}

def Headers() -> Type:
  List<&2, Header>

def keep(hit: Bool, v: String, found: Maybe<&2, String>) -> Maybe<&2, String>:
  match hit found:
    case True{} None{}:
      Some{v}
    case _ other:
      other

def get.go(hs: List<&2, Header>, +name: String, found: Maybe<&2, String>) -> Maybe<&2, String>:
  match hs:
    case Nil{}:
      found
    case Con{Header{n, v}, t}:
      get.go(t, name, keep(T.same_ci(n, name, True{}), v, found))

# the first value of a header
def get(hs: List<&2, Header>, +name: String) -> Maybe<&2, String>:
  get.go(hs, name, None{})

def all.add(hit: Bool, v: String, acc: List<&2, String>) -> List<&2, String>:
  match hit:
    case True{}:
      Con{v, acc}
    case False{}:
      acc

def all.go(hs: List<&2, Header>, +name: String, acc: List<&2, String>) -> List<&2, String>:
  match hs:
    case Nil{}:
      List.reverse(&2, String, acc)
    case Con{Header{n, v}, t}:
      all.go(t, name, all.add(T.same_ci(n, name, True{}), v, acc))

# every value of a header, in order
def all(hs: List<&2, Header>, +name: String) -> List<&2, String>:
  all.go(hs, name, [])

def drop.keep(hit: Bool, h: Header, acc: List<&2, Header>) -> List<&2, Header>:
  match hit:
    case True{}:
      acc
    case False{}:
      Con{h, acc}

def drop.go(hs: List<&2, Header>, +name: String, acc: List<&2, Header>) -> List<&2, Header>:
  match hs:
    case Nil{}:
      List.reverse(&2, Header, acc)
    case Con{Header{+n, v}, t}:
      drop.go(t, name, drop.keep(T.same_ci(n, name, True{}), Header{n, v}, acc))

# every header but those named name
def remove(hs: List<&2, Header>, +name: String) -> List<&2, Header>:
  drop.go(hs, name, [])

# one more header, after the others
def add(hs: List<&2, Header>, name: String, value: String) -> List<&2, Header>:
  List.append(&2, Header, hs, [Header{name, value}])

# the header set to one value, replacing any others
def set(hs: List<&2, Header>, +name: String, value: String) -> List<&2, Header>:
  add(remove(hs, name), name, value)
