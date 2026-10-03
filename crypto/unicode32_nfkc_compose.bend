import Base
import ./unicode32_nfkc_tables.bend as T
import ./unicode32_nfkc_data.bend as D

# Canonical composition after stable ordering, including algorithmic Hangul.
type Search is Type:
  Search{array: Array<U32>, low: U32, high: U32, done: Bool, found: Maybe<U32>}

def search.value(low: U32, high: U32, result: Array<U32> & U32) -> Search:
  (array, value) = result
  Search{array, low, high, True{}, Some{value}}

def search.equal(equal: Bool, +a: U32, +b: U32, +first: U32, +second: U32, +low: U32, +high: U32, +mid: U32, array: Array<U32>) -> Search:
  match equal:
    case True{}: search.value(low, high, Array.get(U32, array, U32.add(U32.mul(mid, 3), 2)))
    case False{}:
      +below = Bool.or(U32.is_lt(a, first), Bool.and(U32.is_eq(a, first), U32.is_lt(b, second)))
      Search{array, Bool.pick(U32, below, low, U32.inc(mid)), Bool.pick(U32, below, mid, high), False{}, None{}}

def search.second(+a: U32, +b: U32, +first: U32, low: U32, high: U32, mid: U32, result: Array<U32> & U32) -> Search:
  (array, +second) = result
  search.equal(Bool.and(U32.is_eq(a, first), U32.is_eq(b, second)), a, b, first, second, low, high, mid, array)

def search.first(a: U32, b: U32, low: U32, high: U32, +mid: U32, result: Array<U32> & U32) -> Search:
  (array, first) = result
  search.second(a, b, first, low, high, mid, Array.get(U32, array, U32.inc(U32.mul(mid, 3))))

def search.checked(valid: Bool, +low: U32, +high: U32, a: U32, b: U32, array: Array<U32>) -> Search:
  match valid:
    case False{}: Search{array, low, high, True{}, None{}}
    case True{}:
      +mid = U32.div(U32.add(low, high), 2)
      search.first(a, b, low, high, mid, Array.get(U32, array, U32.mul(mid, 3)))

def search.step(state: Search, a: U32, b: U32) -> Search:
  match state:
    case Search{array, +low, +high, _, _}: search.checked(U32.is_lt(low, high), low, high, a, b, array)

def search.walk(left: Nat, state: Search, +a: U32, +b: U32) -> Array<U32> & Maybe<U32>:
  match left state:
    case _ Search{array, _, _, True{}, found}: (array, found)
    case 0n Search{array, _, _, _, _}: (array, None{})
    case 1n+p state: search.walk(p, search.step(state, a, b), a, b)

def pair(a: U32, b: U32, array: Array<U32>) -> Array<U32> & Maybe<U32>:
  search.walk(32n, Search{array, 0, D.composition.rows(), False{}, None{}}, a, b)

def hangul.trailing(valid: Bool, +a: U32, b: U32) -> Maybe<U32>:
  match valid:
    case True{}: Some{U32.add(a, U32.sub(b, 4519))}
    case False{}: None{}

def hangul.leading(valid: Bool, +a: U32, +b: U32) -> Maybe<U32>:
  match valid:
    case True{}: Some{U32.add(44032, U32.add(U32.mul(U32.sub(a, 4352), 588), U32.mul(U32.sub(b, 4449), 28)))}
    case False{}:
      hangul.trailing(Bool.and(Bool.and(U32.is_ge(a, 44032), U32.is_le(a, 55203)),
        Bool.and(U32.is_eq(U32.mod(U32.sub(a, 44032), 28), 0), Bool.and(U32.is_ge(b, 4520), U32.is_le(b, 4546)))), a, b)

def hangul(+a: U32, +b: U32) -> Maybe<U32>:
  hangul.leading(Bool.and(Bool.and(U32.is_ge(a, 4352), U32.is_le(a, 4370)), Bool.and(U32.is_ge(b, 4449), U32.is_le(b, 4469))), a, b)

type State is Type:
  State{tables: T.Tables, values: Array<U32>, length: U32, starter_at: U32, starter: U32, previous: U32, active: Bool}

type Normalized is Type:
  Normalized{values: Array<U32>, length: U32}

def appended(+point: U32, state: State) -> State:
  match state:
    case State{tables, values, +length, starter_at, starter, _, active}:
      +class = U32.and(point, 255)
      +is_starter = U32.is_eq(class, 0)
      State{tables, Array.set(U32, values, length, point), U32.inc(length),
        Bool.pick(U32, is_starter, length, starter_at), Bool.pick(U32, is_starter, U32.shrn(point, 8n), starter),
        class, Bool.or(is_starter, active)}

def replaced(+code: U32, state: State) -> State:
  match state:
    case State{tables, values, length, +starter_at, _, previous, active}:
      State{tables, Array.set(U32, values, starter_at, U32.shln(code, 8n)), length, starter_at, code, previous, active}

def resolved(point: U32, state: State, result: Maybe<U32>) -> State:
  match result:
    case None{}: appended(point, state)
    case Some{code}: replaced(code, state)

def table_pair(point: U32, values: Array<U32>, length: U32, starter_at: U32, starter: U32, previous: U32, active: Bool,
  index: Array<U32>, data: Array<U32>, classes: Array<U32>, result: Array<U32> & Maybe<U32>) -> State:
  (composition, answer) = result
  resolved(point, State{T.Tables{index, data, classes, composition}, values, length, starter_at, starter, previous, active}, answer)

def canonical(+point: U32, state: State) -> State:
  match state:
    case State{T.Tables{index, data, classes, composition}, values, length, starter_at, +starter, previous, active}:
      table_pair(point, values, length, starter_at, starter, previous, active, index, data, classes, pair(starter, U32.shrn(point, 8n), composition))

def algorithm(point: U32, state: State, result: Maybe<U32>) -> State:
  match result:
    case Some{code}: replaced(code, state)
    case None{}: canonical(point, state)

def eligible(allowed: Bool, +point: U32, state: State) -> State:
  match allowed state:
    case False{} state: appended(point, state)
    case True{} State{tables, values, length, starter_at, +starter, previous, active}:
      algorithm(point, State{tables, values, length, starter_at, starter, previous, active}, hangul(starter, U32.shrn(point, 8n)))

def read(tables: T.Tables, length: U32, starter_at: U32, starter: U32, +previous: U32, +active: Bool, result: Array<U32> & U32) -> State:
  (values, +point) = result
  eligible(Bool.and(active, Bool.or(U32.is_eq(previous, 0), U32.is_lt(previous, U32.and(point, 255)))), point,
    State{tables, values, length, starter_at, starter, previous, active})

def step(at: U32, state: State) -> State:
  match state:
    case State{tables, values, length, starter_at, starter, previous, active}:
      read(tables, length, starter_at, starter, previous, active, Array.get(U32, values, at))

def run(left: Nat, +at: U32, state: State) -> T.Tables & Normalized:
  match left state:
    case 0n State{tables, values, length, _, _, _, _}: (tables, Normalized{values, length})
    case 1n+p state: run(p, U32.inc(at), step(at, state))

def compose(tables: T.Tables, result: Array<U32> & U32) -> T.Tables & Normalized:
  (values, +length) = result
  run(U32.to_nat(length), 0, State{tables, values, 0, 0, 0, 0, False{}})
