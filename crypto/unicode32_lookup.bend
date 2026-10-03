import Base

# Sorted (key,value) rows; half-open search and explicit retained ownership.
# The caller supplies the row count; the generated tables are not peer input.
def fill(values: List<&2, U32>, +index: U32, array: Array<U32>) -> Array<U32>:
  match values:
    case Nil{}: array
    case Con{value, rest}: fill(rest, U32.inc(index), Array.set(U32, array, index, value))

# Generated Nat constants avoid elaborating thousands of literal word trees.
def fill_nat(values: List<&2, Nat>, +index: U32, array: Array<U32>) -> Array<U32>:
  match values:
    case Nil{}: array
    case Con{value, rest}: fill_nat(rest, U32.inc(index), Array.set(U32, array, index, U32.from_nat(value)))

type Search is Type:
  Search{array: Array<U32>, low: U32, high: U32, done: Bool, found: Maybe<U32>}

def search.value(low: U32, high: U32, result: Array<U32> & U32) -> Search:
  (array, value) = result
  Search{array, low, high, True{}, Some{value}}

def search.equal(equal: Bool, +code: U32, +key: U32, +low: U32, +high: U32, +mid: U32, array: Array<U32>) -> Search:
  match equal:
    case True{}: search.value(low, high, Array.get(U32, array, U32.inc(U32.mul(mid, 2))))
    case False{}:
      +below = U32.is_lt(code, key)
      Search{array, Bool.pick(U32, below, low, U32.inc(mid)), Bool.pick(U32, below, mid, high), False{}, None{}}

def search.key(+code: U32, low: U32, high: U32, mid: U32, result: Array<U32> & U32) -> Search:
  (array, +key) = result
  search.equal(U32.is_eq(code, key), code, key, low, high, mid, array)

def search.checked(valid: Bool, +low: U32, +high: U32, code: U32, array: Array<U32>) -> Search:
  match valid:
    case False{}: Search{array, low, high, True{}, None{}}
    case True{}:
      +mid = U32.div(U32.add(low, high), 2)
      search.key(code, low, high, mid, Array.get(U32, array, U32.mul(mid, 2)))

def search.step(state: Search, code: U32) -> Search:
  match state:
    case Search{array, +low, +high, _, _}: search.checked(U32.is_lt(low, high), low, high, code, array)

def search.walk(left: Nat, state: Search, +code: U32) -> Array<U32> & Maybe<U32>:
  match left state:
    case _ Search{array, _, _, True{}, found}: (array, found)
    case 0n Search{array, _, _, _, _}: (array, None{})
    case 1n+p state: search.walk(p, search.step(state, code), code)

def find(rows: U32, code: U32, array: Array<U32>) -> Array<U32> & Maybe<U32>:
  search.walk(32n, Search{array, 0, rows, False{}, None{}}, code)
