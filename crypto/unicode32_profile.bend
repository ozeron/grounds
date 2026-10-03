import Base
import ./unicode32_ranges.bend as R

# RFC 4518 literal mapping and post-normalization properties, Unicode 3.2.
# Flags: 1 remove, 2 map to space, 4 prohibited, 8 combining mark.
# Not case folding, NFKC, complete string preparation or a Name comparison.
type Tables is Type:
  Tables{unassigned: Array<U32>, marks: Array<U32>}

def fill(values: List<&2, U32>, +index: U32, array: Array<U32>) -> Array<U32>:
  match values:
    case Nil{}: array
    case Con{value, rest}: fill(rest, U32.inc(index), Array.set(U32, array, index, value))

def tables() -> Tables:
  Tables{fill(R.unassigned(), 0, Array.new(U32, 10n, 0)), fill(R.marks(), 0, Array.new(U32, 8n, 0))}

def range(+code: U32, low: U32, high: U32) -> Bool:
  Bool.and(U32.is_ge(code, low), U32.is_le(code, high))

# Binary search over sorted closed ranges, retaining the affine array.
type Search is Type:
  Search{array: Array<U32>, low: U32, high: U32, done: Bool, found: Bool}

def search.end(+code: U32, +low: U32, +high: U32, +mid: U32, +start: U32, result: Array<U32> & U32) -> Search:
  (array, end) = result
  +below = U32.is_lt(code, start)
  +above = U32.is_gt(code, end)
  +found = Bool.not(Bool.or(below, above))
  Search{array, Bool.pick(U32, above, U32.inc(mid), low), Bool.pick(U32, below, mid, high), found, found}

def search.start(code: U32, low: U32, high: U32, +mid: U32, result: Array<U32> & U32) -> Search:
  (array, start) = result
  search.end(code, low, high, mid, start, Array.get(U32, array, U32.inc(U32.mul(mid, 2))))

def search.checked(valid: Bool, +low: U32, +high: U32, code: U32, array: Array<U32>) -> Search:
  match valid:
    case False{}: Search{array, low, high, True{}, False{}}
    case True{}:
      +mid = U32.div(U32.add(low, high), 2)
      search.start(code, low, high, mid, Array.get(U32, array, U32.mul(mid, 2)))

def search.step(state: Search, code: U32) -> Search:
  match state:
    case Search{array, +low, +high, _, _}: search.checked(U32.is_lt(low, high), low, high, code, array)

def search.walk(left: Nat, state: Search, +code: U32) -> Array<U32> & Bool:
  match left state:
    case _ Search{array, _, _, True{}, found}: (array, found)
    case 0n Search{array, _, _, _, _}: (array, False{})
    case 1n+p state: search.walk(p, search.step(state, code), code)

def search(left: Nat, low: U32, high: U32, code: U32, array: Array<U32>) -> Array<U32> & Bool:
  search.walk(left, Search{array, low, high, False{}, False{}}, code)

# Includes verified RFC 4518 erratum 860: FE00-FE0F, not FF00-FE0F.
def removed(+code: U32) -> Bool:
  Bool.or(range(code, 0, 8), Bool.or(range(code, 14, 31), Bool.or(range(code, 127, 132),
    Bool.or(range(code, 134, 159), Bool.or(U32.is_eq(code, 173), Bool.or(U32.is_eq(code, 847),
      Bool.or(U32.is_eq(code, 1757), Bool.or(U32.is_eq(code, 1807), Bool.or(U32.is_eq(code, 6150),
        Bool.or(range(code, 6155, 6158), Bool.or(range(code, 8203, 8207), Bool.or(range(code, 8234, 8238),
          Bool.or(range(code, 8288, 8291), Bool.or(range(code, 8298, 8303), Bool.or(range(code, 65024, 65039),
            Bool.or(U32.is_eq(code, 65279), Bool.or(range(code, 65529, 65532),
              Bool.or(range(code, 119155, 119162), Bool.or(U32.is_eq(code, 917505), range(code, 917536, 917631))))))))))))))))))))

def space(+code: U32) -> Bool:
  Bool.or(range(code, 9, 13), Bool.or(U32.is_eq(code, 32), Bool.or(U32.is_eq(code, 133),
    Bool.or(U32.is_eq(code, 160), Bool.or(U32.is_eq(code, 5760), Bool.or(range(code, 8192, 8202),
      Bool.or(range(code, 8232, 8233), Bool.or(U32.is_eq(code, 8239), Bool.or(U32.is_eq(code, 8287), U32.is_eq(code, 12288))))))))))

def prohibited.fixed(+code: U32) -> Bool:
  Bool.or(U32.is_gt(code, 1114111), Bool.or(range(code, 55296, 57343), Bool.or(range(code, 57344, 63743),
    Bool.or(range(code, 983040, 1048573), Bool.or(range(code, 1048576, 1114109), Bool.or(range(code, 64976, 65007),
      Bool.or(U32.is_ge(U32.and(code, 65535), 65534), Bool.or(U32.is_eq(code, 65533),
        Bool.or(U32.is_eq(code, 832), Bool.or(U32.is_eq(code, 833), Bool.or(U32.is_eq(code, 8206),
          Bool.or(U32.is_eq(code, 8207), Bool.or(range(code, 8234, 8238), range(code, 8298, 8303))))))))))))))

def flags.marked(+code: U32, unassigned: Bool, array: Array<U32>, result: Array<U32> & Bool) -> Tables & U32:
  (marks, mark) = result
  flags = U32.or(Bool.pick(U32, removed(code), 1, 0), U32.or(Bool.pick(U32, space(code), 2, 0),
    U32.or(Bool.pick(U32, Bool.or(unassigned, prohibited.fixed(code)), 4, 0), Bool.pick(U32, mark, 8, 0))))
  (Tables{array, marks}, flags)

def flags.unassigned(+code: U32, marks: Array<U32>, result: Array<U32> & Bool) -> Tables & U32:
  (array, unassigned) = result
  flags.marked(code, unassigned, array, search(16n, 0, 112, code, marks))

def flags(state: Tables, +code: U32) -> Tables & U32:
  match state:
    case Tables{array, marks}: flags.unassigned(code, marks, search(16n, 0, 396, code, array))

# Literal RFC 4518 mapping only; prohibition belongs after full normalization.
# Invalid scalar input is distinct from a legitimate deletion.
type Mapping is Data:
  Removed{}
  Mapped{code: U32}
  Invalid{}

def mapped(removed: Bool, +code: U32) -> Mapping:
  match removed:
    case True{}: Removed{}
    case False{}: Mapped{Bool.pick(U32, space(code), 32, code)}

def map_code.checked(valid: Bool, +code: U32) -> Mapping:
  match valid:
    case True{}: mapped(removed(code), code)
    case False{}: Invalid{}

def map_code(+code: U32) -> Mapping:
  map_code.checked(Bool.and(U32.is_le(code, 1114111), Bool.not(range(code, 55296, 57343))), code)
