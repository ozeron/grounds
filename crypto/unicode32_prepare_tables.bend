import Base
import ./unicode32_prepare_data.bend as D
import ./unicode32_fold.bend as F
import ./unicode32_profile.bend as P
import ./unicode32_nfkc_tables.bend as T
import ./bytes.bend as B
import ./sha256.bend as S

# Avoid static literal emission for the combined preparation owner.
# Authenticate the exact generated property/folding asset before array loading.
type Profile is Type:
  Profile{fold: F.Tables, profile: P.Tables}

def finish(index: Array<U32>, values: Array<U32>, unassigned: Array<U32>, result: Array<U32> & List<&2, U32>) -> Maybe<&1, Profile>:
  (marks, _) = result
  Some{Profile{F.Tables{index, values}, P.Tables{unassigned, marks}}}

def unassigned(index: Array<U32>, values: Array<U32>, result: Array<U32> & List<&2, U32>) -> Maybe<&1, Profile>:
  (unassigned, rest) = result
  finish(index, values, unassigned, T.words(D.marks.words(), rest, 0, Array.new(U32, D.marks.exponent(), 0)))

def values(index: Array<U32>, result: Array<U32> & List<&2, U32>) -> Maybe<&1, Profile>:
  (values, rest) = result
  unassigned(index, values, T.words(D.unassigned.words(), rest, 0, Array.new(U32, D.unassigned.exponent(), 0)))

def index(result: Array<U32> & List<&2, U32>) -> Maybe<&1, Profile>:
  (index, rest) = result
  values(index, T.words(D.values.words(), rest, 0, Array.new(U32, D.values.exponent(), 0)))

def payload(bytes: List<&2, U32>) -> Maybe<&1, Profile>:
  match bytes:
    case Con{_, Con{_, Con{_, Con{_, Con{_, Con{_, Con{_, Con{_, rest}}}}}}}}:
      index(T.words(D.index.words(), rest, 0, Array.new(U32, D.index.exponent(), 0)))
    case _: None{}

def match_hash(valid: Bool, bytes: List<&2, U32>) -> Maybe<&1, Profile>:
  match valid:
    case False{}: None{}
    case True{}: payload(bytes)

def hashed(bytes: List<&2, U32>, result: Maybe<&2, String>) -> Maybe<&1, Profile>:
  match result:
    case None{}: None{}
    case Some{hash}: match_hash(String.eq(hash, D.hash()), bytes)

def checked(valid: Bool, +bytes: List<&2, U32>) -> Maybe<&1, Profile>:
  match valid:
    case False{}: None{}
    case True{}: hashed(bytes, S.digest_hex(bytes))

def decode(+bytes: List<&2, U32>) -> Maybe<&1, Profile>:
  checked(Bool.and(Nat.is_eq(B.length(bytes), D.bytes()), B.valid(bytes)), bytes)
