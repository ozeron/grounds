import Base
import ./unicode32_fold_data.bend as D
import ./unicode32_lookup.bend as L
import ./unicode32_profile.bend as P

# Exact RFC 3454 B.2 folding, including multi-scalar mappings.
# No host case conversion. Prohibition, NFKC and SPACE handling are later stages.
type Tables is Type:
  Tables{index: Array<U32>, values: Array<U32>}

type Output is Type:
  Invalid{}
  Folded{codes: List<&2, U32>}

def tables() -> Tables:
  Tables{L.fill_nat(D.index(), 0, Array.new(U32, 12n, 0)), L.fill_nat(D.values(), 0, Array.new(U32, 11n, 0))}

def valid(+code: U32) -> Bool:
  Bool.and(U32.is_le(code, 1114111), Bool.not(Bool.and(U32.is_ge(code, 55296), U32.is_le(code, 57343))))

def collect.next(out: List<&2, U32>, result: Array<U32> & U32, next: Array<U32> -> List<&2, U32> -> Array<U32> & List<&2, U32>) -> Array<U32> & List<&2, U32>:
  (array, code) = result
  next(array, Con{code, out})

def collect(left: Nat, +offset: U32, array: Array<U32>, out: List<&2, U32>) -> Array<U32> & List<&2, U32>:
  match left:
    case 0n: (array, List.reverse(&2, U32, out))
    case 1n+p: collect.next(out, Array.get(U32, array, offset), a => v => collect(p, U32.inc(offset), a, v))

def code.collected(index: Array<U32>, result: Array<U32> & List<&2, U32>) -> Tables & Output:
  (values, codes) = result
  (Tables{index, values}, Folded{codes})

def code.found(code: U32, values: Array<U32>, result: Array<U32> & Maybe<U32>) -> Tables & Output:
  (index, found) = result
  match found:
    case None{}: (Tables{index, values}, Folded{[code]})
    case Some{+descriptor}: code.collected(index, collect(U32.to_nat(U32.and(descriptor, 7)), U32.div(descriptor, 8), values, []))

def code.checked(valid: Bool, state: Tables, +value: U32) -> Tables & Output:
  match valid state:
    case False{} state: (state, Invalid{})
    case True{} Tables{index, values}: code.found(value, values, L.find(1371, value, index))

def code(state: Tables, +value: U32) -> Tables & Output:
  code.checked(valid(value), state, value)

# Compose literal RFC 4518 mapping before folding, retaining legitimate deletion.
def mapped(state: Tables, value: P.Mapping) -> Tables & Output:
  match value:
    case P.Invalid{}: (state, Invalid{})
    case P.Removed{}: (state, Folded{[]})
    case P.Mapped{value}: code(state, value)

def map_code(state: Tables, value: U32) -> Tables & Output:
  mapped(state, P.map_code(value))

# Fold a complete scalar list without recursive stack growth or output truncation.
def string.next(out: List<&2, U32>, result: Tables & Output, next: Tables -> List<&2, U32> -> Tables & Output) -> Tables & Output:
  (state, result) = result
  match result:
    case Invalid{}: (state, Invalid{})
    case Folded{codes}: next(state, List.reverse.go(&2, U32, codes, out))

# Return the whole owned result from the tail loop, so an older JS frame does
# not retain the entire reversed output during a nested List.reverse call.
def string.finish(codes: List<&2, U32>, state: Tables, out: List<&2, U32>) -> Tables & Output:
  match codes:
    case Nil{}: (state, Folded{out})
    case Con{value, rest}: string.finish(rest, state, Con{value, out})

def string.go(codes: List<&2, U32>, state: Tables, out: List<&2, U32>, +mapping: Bool) -> Tables & Output:
  match codes:
    case Nil{}: string.finish(out, state, [])
    case Con{+value, rest}:
      match mapping:
        case False{}: string.next(out, code(state, value), s => v => string.go(rest, s, v, mapping))
        case True{}: string.next(out, map_code(state, value), s => v => string.go(rest, s, v, mapping))

def string(state: Tables, codes: List<&2, U32>, mapping: Bool) -> Tables & Output:
  string.go(codes, state, [], mapping)
