import Base
import ./unicode32_profile.bend as P
import ./unicode32_fold.bend as F
import ./unicode32_nfkc.bend as N
import ./unicode32_nfkc_tables.bend as T
import ./unicode32_nfkc_buffer.bend as B
import ./unicode32_nfkc_decompose.bend as D
import ./unicode32_nfkc_order.bend as O
import ./unicode32_nfkc_compose.bend as C
import ./unicode32_space.bend as S
import ./unicode32_prepare_tables.bend as A

# Stored DirectoryString scalar preparation, after caller-owned transcoding.
# Literal mapping -> optional B.2 folding -> NFKC -> prohibit -> stored SPACE.
# RFC 4518 imposes no bidi restriction. No substring/numeric/telephone profile.
type Tables is Type:
  Tables{fold: F.Tables, normalization: T.Tables, profile: P.Tables}

def tables.loaded(fold: F.Tables, profile: P.Tables, result: Maybe<&1, T.Tables>) -> Maybe<&1, Tables>:
  match result:
    case None{}: None{}
    case Some{normalization}: Some{Tables{fold, normalization, profile}}

def tables.profile(bytes: List<&2, U32>, result: Maybe<&1, A.Profile>) -> Maybe<&1, Tables>:
  match result:
    case None{}: None{}
    case Some{A.Profile{fold, profile}}: tables.loaded(fold, profile, T.decode(bytes))

def tables(normalization_bytes: List<&2, U32>, profile_bytes: List<&2, U32>) -> Maybe<&1, Tables>:
  tables.profile(normalization_bytes, A.decode(profile_bytes))

# A decoded 65,535-byte DER value has at most 65,535 scalars before mapping.
def validate(codes: List<&2, U32>, +count: U32) -> Bool:
  match codes:
    case Nil{}: True{}
    case Con{code, rest}:
      N.validate.next(Bool.and(U32.is_lt(count, 65535), N.scalar(code)), u => validate(rest, U32.inc(count)))

# Unicode 3.2 private-use scalars survive literal mapping, B.2 and NFKC
# unchanged, have CCC zero and never occur in canonical composition pairs.
# Reject this stable subset early; other prohibition remains after normalization.
def private_use(+code: U32) -> Bool:
  Bool.or(P.range(code, 57344, 63743), Bool.or(P.range(code, 983040, 1048573), P.range(code, 1048576, 1114109)))

def private_admission(codes: List<&2, U32>) -> Bool:
  match codes:
    case Nil{}: True{}
    case Con{code, rest}: N.validate.next(Bool.not(private_use(code)), u => private_admission(rest))

def literal(fold: F.Tables, result: P.Mapping) -> F.Tables & F.Output:
  match result:
    case P.Invalid{}: (fold, F.Invalid{})
    case P.Removed{}: (fold, F.Folded{[]})
    case P.Mapped{code}: (fold, F.Folded{[code]})

def map(casefold: Bool, fold: F.Tables, code: U32) -> F.Tables & F.Output:
  match casefold:
    case True{}: F.map_code(fold, code)
    case False{}: literal(fold, P.map_code(code))

# A bounded cache holds only the preceding scalar's decomposed packed values.
# B.2 emits at most four scalars; compatibility decomposition emits at most 18
# each. CCC values remain intact, so ordering/composition still span the input.
type Cache is Type:
  Cache{code: U32, values: Array<U32>, length: U32}

def copy.next(code: U32, length: U32, buffer: B.Buffer, result: Array<U32> & U32,
  next: Cache -> B.Buffer -> Cache & B.Buffer) -> Cache & B.Buffer:
  (values, point) = result
  next(Cache{code, values, length}, B.put(point, buffer))

def copy.run(left: Nat, +at: U32, cache: Cache, buffer: B.Buffer) -> Cache & B.Buffer:
  match left cache:
    case 0n cache: (cache, buffer)
    case 1n+p Cache{code, values, length}:
      copy.next(code, length, buffer, Array.get(U32, values, at), c => b => copy.run(p, U32.inc(at), c, b))

def copy(cache: Cache, buffer: B.Buffer) -> Cache & B.Buffer:
  match cache:
    case Cache{code, values, +length}: copy.run(U32.to_nat(length), 0, Cache{code, values, length}, buffer)

def copied(fold: F.Tables, normalization: T.Tables, result: Cache & B.Buffer,
  next: F.Tables -> T.Tables -> B.Buffer -> Cache -> F.Tables & T.Tables & Maybe<&1, B.Buffer>) -> F.Tables & T.Tables & Maybe<&1, B.Buffer>:
  (cache, buffer) = result
  next(fold, normalization, buffer, cache)

def decomposed(fold: F.Tables, code: U32, buffer: B.Buffer, result: T.Tables & B.Buffer,
  next: F.Tables -> T.Tables -> B.Buffer -> Cache -> F.Tables & T.Tables & Maybe<&1, B.Buffer>) -> F.Tables & T.Tables & Maybe<&1, B.Buffer>:
  (normalization, expanded) = result
  match expanded:
    case B.Buffer{values, length, _, _, _, _, _}:
      copied(fold, normalization, copy(Cache{code, values, length}, buffer), next)

def mapped(code: U32, normalization: T.Tables, buffer: B.Buffer, result: F.Tables & F.Output,
  next: F.Tables -> T.Tables -> B.Buffer -> Cache -> F.Tables & T.Tables & Maybe<&1, B.Buffer>) -> F.Tables & T.Tables & Maybe<&1, B.Buffer>:
  (fold, output) = result
  match output:
    case F.Invalid{}: (fold, normalization, None{})
    case F.Folded{codes}: decomposed(fold, code, buffer, D.run(codes, normalization, B.new()), next)

def mapping.cached(same: Bool, +code: U32, casefold: Bool, cache: Cache, fold: F.Tables, normalization: T.Tables, buffer: B.Buffer,
  next: F.Tables -> T.Tables -> B.Buffer -> Cache -> F.Tables & T.Tables & Maybe<&1, B.Buffer>) -> F.Tables & T.Tables & Maybe<&1, B.Buffer>:
  match same:
    case True{}: copied(fold, normalization, copy(cache, buffer), next)
    case False{}: mapped(code, normalization, buffer, map(casefold, fold, code), next)

def mapping.scalar(+code: U32, known: Bool, casefold: Bool, cache: Cache, fold: F.Tables, normalization: T.Tables, buffer: B.Buffer,
  next: F.Tables -> T.Tables -> B.Buffer -> Cache -> F.Tables & T.Tables & Maybe<&1, B.Buffer>) -> F.Tables & T.Tables & Maybe<&1, B.Buffer>:
  match cache:
    case Cache{+previous, values, length}:
      mapping.cached(Bool.and(known, U32.is_eq(code, previous)), code, casefold, Cache{previous, values, length}, fold, normalization, buffer, next)

# Stream each original scalar directly into packed storage. The cache is
# independent of total input length; no full folded/decomposed list is created.
def mapping.run(codes: List<&2, U32>, +casefold: Bool, fold: F.Tables, normalization: T.Tables, buffer: B.Buffer,
  known: Bool, cache: Cache) -> F.Tables & T.Tables & Maybe<&1, B.Buffer>:
  match codes:
    case Nil{}: (fold, normalization, Some{buffer})
    case Con{code, rest}:
      mapping.scalar(code, known, casefold, cache, fold, normalization, buffer,
        f => n => b => c => mapping.run(rest, casefold, f, n, b, True{}, c))

# Count decomposed storage before allocating the full buffer, reusing the same
# one-scalar cache. Exact capacity avoids transient copies during array growth.
type Measure is Type:
  Measure{fold: F.Tables, normalization: T.Tables, cache: Cache, length: U32, known: Bool, valid: Bool}

def measure.expanded(fold: F.Tables, code: U32, +length: U32, result: T.Tables & B.Buffer) -> Measure:
  (normalization, expanded) = result
  match expanded:
    case B.Buffer{values, +count, _, _, _, _, _}:
      Measure{fold, normalization, Cache{code, values, count}, U32.add(length, count), True{}, True{}}

def measure.mapped(code: U32, normalization: T.Tables, length: U32, result: F.Tables & F.Output) -> Measure:
  (fold, output) = result
  match output:
    case F.Invalid{}: Measure{fold, normalization, Cache{code, Array.new(U32, 1n, 0), 0}, length, False{}, False{}}
    case F.Folded{codes}: measure.expanded(fold, code, length, D.run(codes, normalization, B.new()))

def measure.same(same: Bool, +code: U32, casefold: Bool, fold: F.Tables, normalization: T.Tables, previous: U32, values: Array<U32>, +count: U32, length: U32) -> Measure:
  match same:
    case True{}: Measure{fold, normalization, Cache{previous, values, count}, U32.add(length, count), True{}, True{}}
    case False{}: measure.mapped(code, normalization, length, map(casefold, fold, code))

def measure.step(+code: U32, casefold: Bool, measure: Measure) -> Measure:
  match measure:
    case Measure{fold, normalization, Cache{+previous, values, count}, length, known, _}:
      measure.same(Bool.and(known, U32.is_eq(code, previous)), code, casefold, fold, normalization, previous, values, count, length)

def measure.run(codes: List<&2, U32>, +casefold: Bool, measure: Measure) -> Measure:
  match codes measure:
    case _ Measure{fold, normalization, cache, length, known, False{}}: Measure{fold, normalization, cache, length, known, False{}}
    case Nil{} measure: measure
    case Con{code, rest} measure: measure.run(rest, casefold, measure.step(code, casefold, measure))

def allocation.checked(fits: Bool, capacity: U32, +exponent: Nat, next: Unit -> Maybe<&1, B.Buffer>) -> Maybe<&1, B.Buffer>:
  match fits:
    case True{}: Some{B.Buffer{Array.new(U32, exponent, 0), 0, capacity, exponent, 0, 0, True{}}}
    case False{}: next(Unit{})

def allocation(left: Nat, +capacity: U32, +exponent: Nat, +length: U32) -> Maybe<&1, B.Buffer>:
  match left:
    case 0n: None{}
    case 1n+p:
      allocation.checked(U32.is_ge(capacity, length), capacity, exponent,
        u => allocation(p, U32.mul(capacity, 2), Nat.add(exponent, 1n), length))

def mapping.allocated(codes: List<&2, U32>, casefold: Bool, fold: F.Tables, normalization: T.Tables, cache: Cache, known: Bool,
  result: Maybe<&1, B.Buffer>) -> F.Tables & T.Tables & Maybe<&1, B.Buffer>:
  match result:
    case None{}: (fold, normalization, None{})
    case Some{buffer}: mapping.run(codes, casefold, fold, normalization, buffer, known, cache)

def mapping.measured(codes: List<&2, U32>, casefold: Bool, measure: Measure) -> F.Tables & T.Tables & Maybe<&1, B.Buffer>:
  match measure:
    case Measure{fold, normalization, _, _, _, False{}}: (fold, normalization, None{})
    case Measure{fold, normalization, cache, length, known, True{}}:
      mapping.allocated(codes, casefold, fold, normalization, cache, known, allocation(24n, 2, 1n, length))

def mapping(+codes: List<&2, U32>, +casefold: Bool, fold: F.Tables, normalization: T.Tables) -> F.Tables & T.Tables & Maybe<&1, B.Buffer>:
  mapping.measured(codes, casefold,
    measure.run(codes, casefold, Measure{fold, normalization, Cache{0, Array.new(U32, 1n, 0), 0}, 0, False{}, True{}}))

def spaced(fold: F.Tables, normalization: T.Tables, result: P.Tables & Maybe<&1, C.Normalized>) -> Tables & Maybe<&1, C.Normalized>:
  (profile, prepared) = result
  (Tables{fold, normalization, profile}, prepared)

def composed(fold: F.Tables, profile: P.Tables, result: T.Tables & C.Normalized) -> Tables & Maybe<&1, C.Normalized>:
  (normalization, normalized) = result
  spaced(fold, normalization, S.prepare(profile, normalized))

def ordered(fold: F.Tables, normalization: T.Tables, profile: P.Tables, result: Array<U32> & U32) -> Tables & Maybe<&1, C.Normalized>:
  composed(fold, profile, C.compose(normalization, result))

def mapping.finished(profile: P.Tables, result: F.Tables & T.Tables & Maybe<&1, B.Buffer>) -> Tables & Maybe<&1, C.Normalized>:
  (fold, normalization, buffer) = result
  match buffer:
    case None{}: (Tables{fold, normalization, profile}, None{})
    case Some{buffer}: ordered(fold, normalization, profile, O.ordered(buffer))

def checked(valid: Bool, state: Tables, codes: List<&2, U32>, casefold: Bool) -> Tables & Maybe<&1, C.Normalized>:
  match valid state:
    case False{} state: (state, None{})
    case True{} Tables{fold, normalization, profile}:
      mapping.finished(profile, mapping(codes, casefold, fold, normalization))

def prepare(state: Tables, +codes: List<&2, U32>, casefold: Bool) -> Tables & Maybe<&1, C.Normalized>:
  checked(Bool.and(validate(codes, 0), private_admission(codes)), state, codes, casefold)
