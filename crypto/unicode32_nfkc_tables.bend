import Base
import ./unicode32_nfkc_data.bend as D
import ./bytes.bend as B
import ./sha256.bend as S

# Pure, authenticated table loading. The caller supplies bytes read by OS IO.
# Reject before table construction unless the exact pinned asset is present.
type Tables is Type:
  Tables{index: Array<U32>, values: Array<U32>, classes: Array<U32>, composition: Array<U32>}

def words.next(rest: List<&2, U32>, result: Array<U32>, next: List<&2, U32> -> Array<U32> -> Array<U32> & List<&2, U32>) -> Array<U32> & List<&2, U32>:
  next(rest, result)

def words(left: Nat, bytes: List<&2, U32>, +offset: U32, array: Array<U32>) -> Array<U32> & List<&2, U32>:
  match left bytes:
    case 0n bytes: (array, bytes)
    case 1n+p Con{a, Con{b, Con{c, Con{d, rest}}}}:
      value = U32.or(U32.shln(a, 24n), U32.or(U32.shln(b, 16n), U32.or(U32.shln(c, 8n), d)))
      words(p, rest, U32.inc(offset), Array.set(U32, array, offset, value))
    case _ _: (array, [])

def finish(index: Array<U32>, values: Array<U32>, classes: Array<U32>, result: Array<U32> & List<&2, U32>) -> Maybe<&1, Tables>:
  (composition, _) = result
  Some{Tables{index, values, classes, composition}}

def classes(index: Array<U32>, values: Array<U32>, result: Array<U32> & List<&2, U32>) -> Maybe<&1, Tables>:
  (classes, rest) = result
  finish(index, values, classes, words(D.composition.words(), rest, 0, Array.new(U32, D.composition.exponent(), 0)))

def values(index: Array<U32>, result: Array<U32> & List<&2, U32>) -> Maybe<&1, Tables>:
  (values, rest) = result
  classes(index, values, words(D.classes.words(), rest, 0, Array.new(U32, D.classes.exponent(), 0)))

def index(result: Array<U32> & List<&2, U32>) -> Maybe<&1, Tables>:
  (index, rest) = result
  values(index, words(D.values.words(), rest, 0, Array.new(U32, D.values.exponent(), 0)))

def payload(bytes: List<&2, U32>) -> Maybe<&1, Tables>:
  match bytes:
    case Con{_, Con{_, Con{_, Con{_, Con{_, Con{_, Con{_, Con{_, rest}}}}}}}}:
      index(words(D.index.words(), rest, 0, Array.new(U32, D.index.exponent(), 0)))
    case _: None{}

def match_hash(valid: Bool, bytes: List<&2, U32>) -> Maybe<&1, Tables>:
  match valid:
    case False{}: None{}
    case True{}: payload(bytes)

def checked_hash(bytes: List<&2, U32>, digest: Maybe<&2, String>) -> Maybe<&1, Tables>:
  match digest:
    case None{}: None{}
    case Some{hash}: match_hash(String.eq(hash, D.hash()), bytes)

def authenticated(+bytes: List<&2, U32>) -> Maybe<&1, Tables>:
  checked_hash(bytes, S.digest_hex(bytes))

def checked(valid: Bool, bytes: List<&2, U32>) -> Maybe<&1, Tables>:
  match valid:
    case False{}: None{}
    case True{}: authenticated(bytes)

def decode(+bytes: List<&2, U32>) -> Maybe<&1, Tables>:
  checked(Bool.and(Nat.is_eq(B.length(bytes), D.bytes()), B.valid(bytes)), bytes)
