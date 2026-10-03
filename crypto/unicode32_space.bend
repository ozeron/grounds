import Base
import ./unicode32_profile.bend as P
import ./unicode32_nfkc_compose.bend as C

# RFC 4518 stored/non-substring SPACE handling, after normalization.
# A SPACE immediately followed by a definitive Appendix A mark is not a space.
# Property admission uses that appendix, not canonical combining class.
def regular(previous: U32, mark: Bool) -> Bool:
  Bool.and(U32.is_eq(U32.shrn(previous, 8n), 32), Bool.not(mark))

# Compact regular SPACE runs inside the owned input to one marked token per
# internal run, dropping leading/trailing runs. Bit 29 is above packed scalars.
# Count includes the leading margin and both spaces for each internal run.
type Count is Type:
  Count{length: U32, seen: Bool, pending: Bool}

type Compact is Type:
  Compact{input: Array<U32>, length: U32, count: Count}

def compact.point(point: U32, compact: Compact) -> Compact:
  match compact:
    case Compact{input, +at, Count{length, False{}, _}}:
      Compact{Array.set(U32, input, at, point), U32.inc(at), Count{U32.add(length, 2), True{}, False{}}}
    case Compact{input, +at, Count{length, True{}, True{}}}:
      Compact{Array.set(U32, Array.set(U32, input, at, 536879104), U32.inc(at), point),
        U32.add(at, 2), Count{U32.add(length, 3), True{}, False{}}}
    case Compact{input, +at, Count{length, True{}, False{}}}:
      Compact{Array.set(U32, input, at, point), U32.inc(at), Count{U32.inc(length), True{}, False{}}}

def compact.classified(space: Bool, point: U32, compact: Compact) -> Compact:
  match space compact:
    case True{} Compact{input, at, Count{length, seen, _}}:
      Compact{input, at, Count{length, seen, True{}}}
    case False{} compact: compact.point(point, compact)

def compact.previous(present: Bool, +previous: U32, mark: Bool, compact: Compact) -> Compact:
  match present:
    case False{}: compact
    case True{}: compact.classified(regular(previous, mark), previous, compact)

def count.length(count: Count) -> U32:
  match count:
    case Count{_, False{}, _}: 2
    case Count{length, True{}, _}: U32.inc(length)

type Plan is Type:
  Plan{profile: P.Tables, compact: Compact, previous: U32, present: Bool, valid: Bool}

def plan.checked(valid: Bool, mark: Bool, profile: P.Tables, compact: Compact, point: U32, previous: U32, present: Bool) -> Plan:
  match valid:
    case False{}: Plan{profile, compact, previous, present, False{}}
    case True{}: Plan{profile, compact.previous(present, previous, mark, compact), point, True{}, True{}}

def plan.flags(compact: Compact, point: U32, previous: U32, present: Bool, result: P.Tables & U32) -> Plan:
  (profile, +mask) = result
  plan.checked(U32.is_eq(U32.and(mask, 4), 0), U32.is_ne(U32.and(mask, 8), 0), profile, compact, point, previous, present)

def plan.read(profile: P.Tables, length: U32, count: Count, +previous: U32, present: Bool, result: Array<U32> & U32) -> Plan:
  (input, +point) = result
  plan.flags(Compact{input, length, count}, point, previous, present,
    P.properties.admission(profile, U32.shrn(point, 8n), U32.is_eq(U32.shrn(previous, 8n), 32)))

def plan.step(at: U32, plan: Plan) -> Plan:
  match plan:
    case Plan{profile, Compact{input, length, count}, previous, present, _}:
      plan.read(profile, length, count, previous, present, Array.get(U32, input, at))

# Grow only when the prepared result exceeds the array's existing capacity.
# This preserves the normalized storage for large expansion inputs.
def reserve.checked(fits: Bool, exponent: Nat, input: Array<U32>, next: Array<U32> -> Maybe<&1, Array<U32>>) -> Maybe<&1, Array<U32>>:
  match fits:
    case True{}: Some{input}
    case False{}: next(ANode{input, Array.new(U32, exponent, 0)})

def reserve(left: Nat, +capacity: U32, +exponent: Nat, +length: U32, input: Array<U32>) -> Maybe<&1, Array<U32>>:
  match left:
    case 0n: None{}
    case 1n+p:
      reserve.checked(U32.is_ge(capacity, length), exponent, input,
        a => reserve(p, U32.mul(capacity, 2), Nat.add(exponent, 1n), length, a))

# Expand backward: each unread token has at least one free position to its
# right, because the result includes a leading margin and expands marked runs.
def expand.token(space: Bool, point: U32, +cursor: U32, input: Array<U32>) -> Array<U32> & U32:
  match space:
    case False{}: (Array.set(U32, input, U32.sub(cursor, 1), point), U32.sub(cursor, 1))
    case True{}:
      (Array.set(U32, Array.set(U32, input, U32.sub(cursor, 1), 8192), U32.sub(cursor, 2), 8192), U32.sub(cursor, 2))

def expand.next(result: Array<U32> & U32, next: Array<U32> -> U32 -> Maybe<&1, C.Normalized>) -> Maybe<&1, C.Normalized>:
  (input, cursor) = result
  next(input, cursor)

def expand.read(cursor: U32, result: Array<U32> & U32, next: Array<U32> -> U32 -> Maybe<&1, C.Normalized>) -> Maybe<&1, C.Normalized>:
  (input, +point) = result
  expand.next(expand.token(U32.is_ne(U32.and(point, 536870912), 0), point, cursor, input), next)

def expand(left: Nat, +at: U32, cursor: U32, +length: U32, input: Array<U32>) -> Maybe<&1, C.Normalized>:
  match left:
    case 0n: Some{C.Normalized{Array.set(U32, input, 0, 8192), length}}
    case 1n+p:
      expand.read(cursor, Array.get(U32, input, U32.sub(at, 1)), a => c => expand(p, U32.sub(at, 1), c, length, a))

def reserved(profile: P.Tables, +compact: U32, +length: U32, result: Maybe<&1, Array<U32>>) -> P.Tables & Maybe<&1, C.Normalized>:
  match result:
    case None{}: (profile, None{})
    case Some{input}:
      (profile, expand(U32.to_nat(compact), compact, U32.sub(length, 1), length, Array.set(U32, input, U32.sub(length, 1), 8192)))

def sized(profile: P.Tables, compact: U32, +length: U32, result: Array<U32> & U32) -> P.Tables & Maybe<&1, C.Normalized>:
  (input, +capacity) = result
  reserved(profile, compact, length, reserve(24n, capacity, U32.log2(capacity), length, input))

def plan.finished(profile: P.Tables, compact: Compact) -> P.Tables & Maybe<&1, C.Normalized>:
  match compact:
    case Compact{input, compact, count}: sized(profile, compact, count.length(count), Array.size(U32, input))

def plan.run(left: Nat, +at: U32, plan: Plan) -> P.Tables & Maybe<&1, C.Normalized>:
  match left plan:
    case _ Plan{profile, _, _, _, False{}}: (profile, None{})
    case 0n Plan{profile, compact, previous, present, True{}}:
      plan.finished(profile, compact.previous(present, previous, False{}, compact))
    case 1n+p plan: plan.run(p, U32.inc(at), plan.step(at, plan))

def prepare.checked(valid: Bool, profile: P.Tables, input: Array<U32>, +length: U32) -> P.Tables & Maybe<&1, C.Normalized>:
  match valid:
    case False{}: (profile, None{})
    case True{}:
      plan.run(U32.to_nat(length), 0, Plan{profile, Compact{input, 0, Count{0, False{}, False{}}}, 0, False{}, True{}})

def prepare(profile: P.Tables, normalized: C.Normalized) -> P.Tables & Maybe<&1, C.Normalized>:
  match normalized:
    case C.Normalized{input, +length}:
      prepare.checked(U32.is_le(length, 4718520), profile, input, length)
