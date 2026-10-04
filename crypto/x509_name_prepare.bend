import Base
import ./bytes.bend as B
import ./oid.bend as O
import ./x509_name_schema.bend as S
import ./x509_name_text.bend as T
import ./unicode32_prepare.bend as P
import ./unicode32_nfkc_compose.bend as C

# Stored caseIgnoreMatch preparation for supported Name attributes. The same
# affine tables return on every outcome, including syntax/profile rejection.
# DomainComponent/email IA5 matching and unknown equality rules are separate.
# Teletex has no configured mapping and is explicitly unsupported here.
def decoded(state: P.Tables, result: Maybe<&1, List<&2, U32>>) -> P.Tables & Maybe<&1, C.Normalized>:
  match result:
    case Some{codes}: P.prepare(state, codes, True{})
    case None{}: (state, None{})

def admitted(state: P.Tables, tag: U32, bytes: List<&2, U32>, status: Maybe<&1, Bool>) -> P.Tables & Maybe<&1, C.Normalized>:
  match status:
    case Some{True{}}: decoded(state, T.decode(tag, bytes))
    case _: (state, None{})

def typed(rule: S.Rule, tag: U32, bytes: List<&2, U32>) -> Maybe<&1, Bool>:
  match rule:
    case S.Rule{1, minimum, maximum}:
      S.value(S.Rule{1, minimum, maximum}, tag, bytes)
    case S.Rule{2, minimum, maximum}:
      S.value(S.Rule{2, minimum, maximum}, tag, bytes)
    case _: Some{False{}}

def checked(valid: Bool, oid: List<&2, U32>, tag: U32, bytes: List<&2, U32>) -> Maybe<&1, Bool>:
  match valid:
    case True{}: typed(S.rule(oid), tag, bytes)
    case False{}: None{}

# Canonical octet OID and the schema's original scalar SIZE/type constraints
# precede preparation: removals/expansion cannot rescue an invalid attribute.
def admission(+oid: List<&2, U32>, tag: U32, +bytes: List<&2, U32>) -> Maybe<&1, Bool>:
  checked(Bool.and(B.valid(oid), Bool.and(O.contents(oid),
    Bool.and(Nat.is_le(B.length(oid), 65535n),
      Bool.and(B.valid(bytes), Nat.is_le(B.length(bytes), 65535n))))), oid, tag, bytes)

def prepare(state: P.Tables, oid: List<&2, U32>, +tag: U32, +bytes: List<&2, U32>) -> P.Tables & Maybe<&1, C.Normalized>:
  admitted(state, tag, bytes, admission(oid, tag, bytes))
