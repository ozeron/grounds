import Base
import ./der.bend as D
import ./x509_name_schema.bend as S

# Retain exactly the Name whose complete shared schema check has passed.
# Collection does not reinterpret values or introduce a second syntax policy.
type Attribute is Data:
  Attribute{oid: List<&2, U32>, tag: U32, bytes: List<&2, U32>, encoded: List<&2, U32>}

type Name is Data:
  Name{rdns: List<&2, List<&2, Attribute>>, supported: Bool}

type Attributes is Type:
  Attributes{rest: List<&2, U32>, reversed: List<&2, Attribute>}

type State is Type:
  State{rest: List<&2, U32>, reversed: List<&2, List<&2, Attribute>>}

def attribute.value(oid: List<&2, U32>, encoded: List<&2, U32>, rest: List<&2, U32>,
                    reversed: List<&2, Attribute>, element: Maybe<&1, D.Element>) -> Maybe<&1, Attributes>:
  match element:
    case Some{D.Element{tag, bytes, Nil{}, _}}: Some{Attributes{rest, Con{Attribute{oid, tag, bytes, encoded}, reversed}}}
    case _: None{}

def attribute.oid(encoded: List<&2, U32>, rest: List<&2, U32>, reversed: List<&2, Attribute>,
                  element: Maybe<&1, D.Element>) -> Maybe<&1, Attributes>:
  match element:
    case Some{D.Element{6, oid, bytes, _}}: attribute.value(oid, encoded, rest, reversed, D.read(bytes))
    case _: None{}

def attribute.step(state: Attributes, element: Maybe<&1, D.Element>) -> Maybe<&1, Attributes>:
  match state element:
    case Attributes{_, reversed} Some{D.Element{48, bytes, rest, encoded}}: attribute.oid(encoded, rest, reversed, D.read(bytes))
    case _ _: None{}

def attributes(left: Nat, state: Maybe<&1, Attributes>) -> Maybe<&1, Attributes>:
  match left state:
    case _ Some{Attributes{Nil{}, reversed}}: Some{Attributes{[], reversed}}
    case 1n+p Some{Attributes{+bytes, reversed}}:
      attributes(p, attribute.step(Attributes{bytes, reversed}, D.read(bytes)))
    case _ _: None{}

def rdn.got(rest: List<&2, U32>, reversed: List<&2, List<&2, Attribute>>, result: Maybe<&1, Attributes>) -> Maybe<&1, State>:
  match result:
    case Some{Attributes{Nil{}, Con{first, tail}}}: Some{State{rest, Con{List.reverse(&2, Attribute, Con{first, tail}), reversed}}}
    case _: None{}

def rdn.step(state: State, element: Maybe<&1, D.Element>) -> Maybe<&1, State>:
  match state element:
    case State{_, reversed} Some{D.Element{49, bytes, rest, _}}:
      rdn.got(rest, reversed, attributes(65535n, Some{Attributes{bytes, []}}))
    case _ _: None{}

def rdns(left: Nat, state: Maybe<&1, State>, supported: Bool) -> Maybe<&1, Name>:
  match left state:
    case _ Some{State{Nil{}, reversed}}: Some{Name{List.reverse(&2, List<&2, Attribute>, reversed), supported}}
    case 1n+p Some{State{+bytes, reversed}}:
      rdns(p, rdn.step(State{bytes, reversed}, D.read(bytes)), supported)
    case _ _: None{}

def collected(bytes: Maybe<&1, List<&2, U32>>, supported: Bool) -> Maybe<&1, Name>:
  match bytes:
    case Some{bytes}: rdns(65535n, Some{State{bytes, []}}, supported)
    case None{}: None{}

def checked(bytes: List<&2, U32>, status: Maybe<&1, Bool>) -> Maybe<&1, Name>:
  match status:
    case Some{supported}: collected(D.complete(48, bytes), supported)
    case None{}: None{}

def decode(+bytes: List<&2, U32>) -> Maybe<&1, Name>:
  checked(bytes, S.inspect(bytes, True{}))

def inspect(bytes: List<&2, U32>, allow_empty: Bool) -> Maybe<&1, Bool>:
  S.inspect(bytes, allow_empty)

def pair(issuer: List<&2, U32>, subject: List<&2, U32>) -> Maybe<&1, Bool>:
  S.pair(issuer, subject)
