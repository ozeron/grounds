import Base
import ./der.bend as D

# Civil UTC seconds since 0001-01-01T00:00:00Z, not a monotonic timestamp.
# Only integral seconds 0..59; leap-second encodings are unsupported.
type Validity is Type:
  Validity{not_before: Nat, not_after: Nat}

type Number is Type:
  Number{value: U32, rest: List<&2, U32>}

def digits.checked(valid: Bool, result: Maybe<&1, Number>) -> Maybe<&1, Number>:
  match valid:
    case True{}:
      result
    case False{}:
      None{}

def digits(left: Nat, +value: U32, bytes: List<&2, U32>) -> Maybe<&1, Number>:
  match left bytes:
    case 0n rest:
      Some{Number{value, rest}}
    case 1n+p Con{+byte, rest}:
      digits.checked(Bool.and(U32.is_ge(byte, 48), U32.is_le(byte, 57)),
        digits(p, U32.add(U32.mul(value, 10), U32.sub(byte, 48)), rest))
    case _ _:
      None{}

def leap(+year: U32) -> Bool:
  Bool.and(U32.is_eq(U32.mod(year, 4), 0),
    Bool.or(U32.is_ne(U32.mod(year, 100), 0), U32.is_eq(U32.mod(year, 400), 0)))

def month_days(year: U32, month: U32) -> U32:
  match month:
    case 1: 31
    case 2: Bool.pick(U32, leap(year), 29, 28)
    case 3: 31
    case 4: 30
    case 5: 31
    case 6: 30
    case 7: 31
    case 8: 31
    case 9: 30
    case 10: 31
    case 11: 30
    case 12: 31
    case _: 0

def month_offset(month: U32) -> U32:
  match month:
    case 1: 0
    case 2: 31
    case 3: 59
    case 4: 90
    case 5: 120
    case 6: 151
    case 7: 181
    case 8: 212
    case 9: 243
    case 10: 273
    case 11: 304
    case 12: 334
    case _: 0

def seconds(+year: U32, +month: U32, day: U32, hour: U32, minute: U32, second: U32) -> Nat:
  +previous = U32.sub(year, 1)
  years = U32.add(U32.sub(U32.add(U32.mul(previous, 365), U32.div(previous, 4)),
    U32.div(previous, 100)), U32.div(previous, 400))
  months = U32.add(month_offset(month), Bool.pick(U32, Bool.and(U32.is_gt(month, 2), leap(year)), 1, 0))
  days = U32.add(U32.add(years, months), U32.sub(day, 1))
  within = U32.add(U32.add(U32.mul(hour, 3600), U32.mul(minute, 60)), second)
  Nat.add(Nat.mul(U32.to_nat(days), 86400n), U32.to_nat(within))

def moment.checked(valid: Bool, year: U32, month: U32, day: U32,
                   hour: U32, minute: U32, second: U32) -> Maybe<&1, Nat>:
  match valid:
    case True{}:
      Some{seconds(year, month, day, hour, minute, second)}
    case False{}:
      None{}

def moment(+year: U32, +month: U32, +day: U32, +hour: U32, +minute: U32, +second: U32) -> Maybe<&1, Nat>:
  moment.checked(Bool.and(Bool.and(U32.is_ge(year, 1), U32.is_le(year, 9999)),
    Bool.and(Bool.and(U32.is_ge(day, 1), U32.is_le(day, month_days(year, month))),
      Bool.and(U32.is_le(hour, 23), Bool.and(U32.is_le(minute, 59), U32.is_le(second, 59))))),
    year, month, day, hour, minute, second)

def clock.second(year: U32, month: U32, day: U32, hour: U32, minute: U32,
                 number: Maybe<&1, Number>) -> Maybe<&1, Nat>:
  match number:
    case Some{Number{second, Con{90, Nil{}}}}:
      moment(year, month, day, hour, minute, second)
    case _:
      None{}

def clock.minute(year: U32, month: U32, day: U32, hour: U32,
                 number: Maybe<&1, Number>) -> Maybe<&1, Nat>:
  match number:
    case Some{Number{minute, rest}}:
      clock.second(year, month, day, hour, minute, digits(2n, 0, rest))
    case None{}: None{}

def clock.hour(year: U32, month: U32, day: U32, number: Maybe<&1, Number>) -> Maybe<&1, Nat>:
  match number:
    case Some{Number{hour, rest}}:
      clock.minute(year, month, day, hour, digits(2n, 0, rest))
    case None{}: None{}

def clock.day(year: U32, month: U32, number: Maybe<&1, Number>) -> Maybe<&1, Nat>:
  match number:
    case Some{Number{day, rest}}:
      clock.hour(year, month, day, digits(2n, 0, rest))
    case None{}: None{}

def clock.month(year: U32, number: Maybe<&1, Number>) -> Maybe<&1, Nat>:
  match number:
    case Some{Number{month, rest}}:
      clock.day(year, month, digits(2n, 0, rest))
    case None{}: None{}

def year_value(utc: Bool, +year: U32) -> U32:
  match utc:
    case True{}:
      U32.add(year, Bool.pick(U32, U32.is_ge(year, 50), 1900, 2000))
    case False{}:
      year

def time.year(utc: Bool, number: Maybe<&1, Number>) -> Maybe<&1, Nat>:
  match number:
    case Some{Number{year, rest}}:
      clock.month(year_value(utc, year), digits(2n, 0, rest))
    case None{}:
      None{}

def time.body(tag: U32, body: List<&2, U32>) -> Maybe<&1, Nat>:
  match tag:
    case 23:
      time.year(True{}, digits(2n, 0, body))
    case 24:
      time.year(False{}, digits(4n, 0, body))
    case _:
      None{}

def time.element(element: Maybe<&1, D.Element>) -> Maybe<&1, Nat>:
  match element:
    case Some{D.Element{tag, body, Nil{}, _}}:
      time.body(tag, body)
    case _:
      None{}

def decode_time(bytes: List<&2, U32>) -> Maybe<&1, Nat>:
  time.element(D.decode(bytes))

def ordered(valid: Bool, before: Nat, after: Nat) -> Maybe<&1, Validity>:
  match valid:
    case True{}:
      Some{Validity{before, after}}
    case False{}:
      None{}

def pair(before: Maybe<&1, Nat>, after: Maybe<&1, Nat>) -> Maybe<&1, Validity>:
  match before after:
    case Some{+before} Some{+after}:
      ordered(Nat.is_le(before, after), before, after)
    case _ _:
      None{}

def second(before: Maybe<&1, Nat>, element: Maybe<&1, D.Element>) -> Maybe<&1, Validity>:
  pair(before, time.element(element))

def first(element: Maybe<&1, D.Element>) -> Maybe<&1, Validity>:
  match element:
    case Some{D.Element{tag, body, rest, _}}:
      second(time.body(tag, body), D.read(rest))
    case _:
      None{}

def body(bytes: Maybe<&1, List<&2, U32>>) -> Maybe<&1, Validity>:
  match bytes:
    case Some{bytes}:
      first(D.read(bytes))
    case None{}:
      None{}

def decode(bytes: List<&2, U32>) -> Maybe<&1, Validity>:
  body(D.complete(48, bytes))

def last_second() -> Nat:
  Nat.sub(Nat.mul(3652059n, 86400n), 1n)

def contains(value: Maybe<&1, Validity>, +now: Nat) -> Bool:
  match value:
    case Some{Validity{before, after}}:
      Bool.and(Nat.is_le(now, last_second()), Bool.and(Nat.is_le(before, now), Nat.is_le(now, after)))
    case None{}:
      False{}

def valid_at(bytes: List<&2, U32>, now: Nat) -> Bool:
  contains(decode(bytes), now)
