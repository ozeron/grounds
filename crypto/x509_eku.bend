import Base
import ./der.bend as D
import ./oid.bend as O
import ./bytes.bend as B
import ./x509_constraints.bend as C

# RFC 5280 EKU payloads: retain canonical OID bytes, arbitrary-size arcs,
# unknown purposes, order and duplicates. The ASN.1 SEQUENCE is not a SET.
type State is Type:
  State{rest: List<&2, U32>, reversed: List<&2, List<&2, U32>>}

def item.checked(valid: Bool, oid: List<&2, U32>, rest: List<&2, U32>,
                 reversed: List<&2, List<&2, U32>>) -> Maybe<&1, State>:
  match valid:
    case True{}: Some{State{rest, Con{oid, reversed}}}
    case False{}: None{}

def item(element: Maybe<&1, D.Element>, reversed: List<&2, List<&2, U32>>) -> Maybe<&1, State>:
  match element:
    case Some{D.Element{6, +oid, rest, _}}: item.checked(O.contents(oid), oid, rest, reversed)
    case _: None{}

def step(state: State) -> Maybe<&1, State>:
  match state:
    case State{bytes, reversed}: item(D.read(bytes), reversed)

def walk(left: Nat, state: Maybe<&1, State>) -> Maybe<&1, List<&2, List<&2, U32>>>:
  match left state:
    case _ Some{State{Nil{}, reversed}}:
      Some{List.reverse(&2, List<&2, U32>, reversed)}
    case 1n+p Some{state}: walk(p, step(state))
    case _ _: None{}

def body(value: Maybe<&1, List<&2, U32>>) -> Maybe<&1, List<&2, List<&2, U32>>>:
  match value:
    case Some{Con{first, rest}}: walk(65535n, Some{State{Con{first, rest}, []}})
    case _: None{}

def decode(bytes: List<&2, U32>) -> Maybe<&1, List<&2, List<&2, U32>>>:
  body(D.complete(48, bytes))

def same(a: List<&2, U32>, b: List<&2, U32>, equal: Bool) -> Bool:
  match a b:
    case Nil{} Nil{}: equal
    case Con{x, xs} Con{y, ys}: same(xs, ys, Bool.and(equal, U32.is_eq(x, y)))
    case _ _: False{}

def any(oid: List<&2, U32>) -> Bool:
  match oid:
    case Con{85, Con{29, Con{37, Con{0, Nil{}}}}}: True{}
    case _: False{}

def contains(items: List<&2, List<&2, U32>>, +purpose: List<&2, U32>, +allow_any: Bool, found: Bool) -> Bool:
  match items:
    case Nil{}: found
    case Con{+oid, rest}:
      contains(rest, purpose, allow_any,
        Bool.or(found, Bool.or(same(oid, purpose, True{}), Bool.and(allow_any, any(oid)))))

def permits.decoded(items: Maybe<&1, List<&2, List<&2, U32>>>, purpose: List<&2, U32>, allow_any: Bool) -> Bool:
  match items:
    case Some{items}: contains(items, purpose, allow_any, False{})
    case None{}: False{}

def permits.checked(valid: Bool, encoded: Maybe<&2, List<&2, U32>>, purpose: List<&2, U32>, allow_any: Bool) -> Bool:
  match valid encoded:
    case True{} None{}: True{}
    case True{} Some{bytes}: permits.decoded(decode(bytes), purpose, allow_any)
    case _ _: False{}

# Decode the complete list before searching; even a matching first OID cannot
# hide malformed later entries. None means an absent extension, never an error.
def permits(encoded: Maybe<&2, List<&2, U32>>, +purpose: List<&2, U32>, allow_any: Bool) -> Bool:
  permits.checked(Bool.and(O.contents(purpose), Bool.and(B.valid(purpose),
    Nat.is_le(B.length(purpose), 65535n))), encoded, purpose, allow_any)

def signing.decoded(value: Maybe<&1, C.Usage>) -> Bool:
  match value:
    case Some{C.Usage{bits}}: U32.is_ne(U32.and(bits, 128), 0)
    case None{}: False{}

def signing(encoded: Maybe<&2, List<&2, U32>>) -> Bool:
  match encoded:
    case None{}: True{}
    case Some{bytes}: signing.decoded(C.usage(bytes))

def tls13(usage: Maybe<&2, List<&2, U32>>, eku: Maybe<&2, List<&2, U32>>, server: Bool, allow_any: Bool) -> Bool:
  Bool.and(signing(usage), permits(eku,
    Bool.pick(List<&2, U32>, server, [43, 6, 1, 5, 5, 7, 3, 1], [43, 6, 1, 5, 5, 7, 3, 2]), allow_any))
