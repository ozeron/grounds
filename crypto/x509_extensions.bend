import Base
import ./der.bend as D
import ./oid.bend as O
import ./bytes.bend as B

# Structural extension admission. Payload interpretation and critical-extension
# recognition belong to the constraint/policy owner, not this envelope decoder.
type Extension is Type:
  Extension{oid: List<&2, U32>, critical: Bool, value: List<&2, U32>}

type Bucket is Type:
  Bucket{identifiers: List<&2, List<&2, U32>>}

type State is Type:
  State{rest: List<&2, U32>, seen: Map<&1, Bucket>, reversed: List<&1, Extension>}

# FNV-1a only selects a short map bucket; exact bytes decide identity.
# Fixed-size keys avoid Base's recursive comparisons of arbitrarily long OIDs.
def hash.go(bytes: List<&2, U32>, hash: U32) -> U32:
  match bytes:
    case Nil{}: hash
    case Con{byte, rest}: hash.go(rest, U32.mul(U32.xor(hash, byte), 16777619))

def key(bytes: List<&2, U32>) -> String:
  +hash = hash.go(bytes, 2166136261)
  B.hex([U32.shrn(hash, 24n), U32.and(U32.shrn(hash, 16n), 255),
         U32.and(U32.shrn(hash, 8n), 255), U32.and(hash, 255)])

def same(a: List<&2, U32>, b: List<&2, U32>, equal: Bool) -> Bool:
  match a b:
    case Nil{} Nil{}: equal
    case Con{x, xs} Con{y, ys}: same(xs, ys, Bool.and(equal, U32.is_eq(x, y)))
    case _ _: False{}

def contains(+oid: List<&2, U32>, identifiers: List<&2, List<&2, U32>>, found: Bool) -> Bool:
  match identifiers found:
    case _ True{}: True{}
    case Nil{} False{}: False{}
    case Con{identifier, rest} False{}:
      contains(oid, rest, same(oid, identifier, True{}))

def payload(oid: List<&2, U32>, critical: Bool, element: Maybe<&1, D.Element>) -> Maybe<&1, Extension>:
  match element:
    case Some{D.Element{4, value, Nil{}, _}}:
      Some{Extension{oid, critical, value}}
    case _: None{}

def fields(oid: List<&2, U32>, element: Maybe<&1, D.Element>) -> Maybe<&1, Extension>:
  match element:
    case Some{D.Element{1, Con{255, Nil{}}, rest, _}}:
      payload(oid, True{}, D.read(rest))
    case Some{D.Element{4, value, Nil{}, _}}:
      Some{Extension{oid, False{}, value}}
    case _: None{}

def identifier(valid: Bool, oid: List<&2, U32>, rest: List<&2, U32>) -> Maybe<&1, Extension>:
  match valid:
    case True{}: fields(oid, D.read(rest))
    case False{}: None{}

def item(element: Maybe<&1, D.Element>) -> Maybe<&1, Extension>:
  match element:
    case Some{D.Element{6, +oid, rest, _}}:
      identifier(O.contents(oid), oid, rest)
    case _: None{}

def unique.checked(duplicate: Bool, key: String, +oid: List<&2, U32>, critical: Bool, value: List<&2, U32>,
                   rest: List<&2, U32>, seen: Map<&1, Bucket>, identifiers: List<&2, List<&2, U32>>,
                   reversed: List<&1, Extension>) -> Maybe<&1, State>:
  match duplicate:
    case False{}:
      Some{State{rest, Map.set(&1, Bucket, seen, key, Bucket{Con{oid, identifiers}}),
                 Con{Extension{oid, critical, value}, reversed}}}
    case True{}: None{}

def unique(key: String, entry: Extension, rest: List<&2, U32>, reversed: List<&1, Extension>,
           found: Map<&1, Bucket> & Maybe<&1, Bucket>) -> Maybe<&1, State>:
  match entry found:
    case Extension{oid, critical, value} Tuple{seen, None{}}:
      unique.checked(False{}, key, oid, critical, value, rest, seen, [], reversed)
    case Extension{+oid, critical, value} Tuple{seen, Some{Bucket{+identifiers}}}:
      unique.checked(contains(oid, identifiers, False{}), key, oid, critical, value,
                     rest, seen, identifiers, reversed)

def insert(rest: List<&2, U32>, seen: Map<&1, Bucket>, reversed: List<&1, Extension>,
           entry: Maybe<&1, Extension>) -> Maybe<&1, State>:
  match entry:
    case Some{Extension{+oid, critical, value}}:
      +bucket = key(oid)
      unique(bucket, Extension{oid, critical, value}, rest, reversed, Map.pop(&1, Bucket, seen, bucket))
    case None{}: None{}

def step.element(seen: Map<&1, Bucket>, reversed: List<&1, Extension>,
                 element: Maybe<&1, D.Element>) -> Maybe<&1, State>:
  match element:
    case Some{D.Element{48, body, rest, _}}:
      insert(rest, seen, reversed, item(D.read(body)))
    case _: None{}

def step(state: State) -> Maybe<&1, State>:
  match state:
    case State{rest, seen, reversed}:
      step.element(seen, reversed, D.read(rest))

def walk(left: Nat, state: Maybe<&1, State>) -> Maybe<&1, List<&1, Extension>>:
  match left state:
    case _ Some{State{Nil{}, _, reversed}}:
      Some{List.reverse(&1, Extension, reversed)}
    case 1n+p Some{state}:
      walk(p, step(state))
    case _ _:
      None{}

def body(bytes: Maybe<&1, List<&2, U32>>) -> Maybe<&1, List<&1, Extension>>:
  match bytes:
    case Some{Con{first, rest}}:
      walk(65535n, Some{State{Con{first, rest}, Map.new(&1, Bucket), []}})
    case _: None{}

def decode(bytes: List<&2, U32>) -> Maybe<&1, List<&1, Extension>>:
  body(D.complete(48, bytes))

def optional(bytes: Maybe<&2, List<&2, U32>>) -> Maybe<&1, List<&1, Extension>>:
  match bytes:
    case Some{bytes}: decode(bytes)
    case None{}: Some{[]}
