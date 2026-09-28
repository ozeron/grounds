import Base

# Tail-recursive byte-list operations. Base's List.length/append and the
# diagnostic SHA hex printer grow the JS call stack on large records.

def length.go(xs: List<&2, U32>, +count: Nat) -> Nat:
  match xs:
    case Nil{}:
      count
    case Con{_, tail}:
      length.go(tail, Nat.add(count, 1n))

def length(xs: List<&2, U32>) -> Nat:
  length.go(xs, 0n)

def valid.go(xs: List<&2, U32>, ok: Bool) -> Bool:
  match xs:
    case Nil{}:
      ok
    case Con{byte, tail}:
      valid.go(tail, Bool.and(ok, U32.is_le(byte, 255)))

def valid(xs: List<&2, U32>) -> Bool:
  valid.go(xs, True{})

def append(xs: List<&2, U32>, ys: List<&2, U32>) -> List<&2, U32>:
  List.reverse.go(&2, U32, List.reverse(&2, U32, xs), ys)

def hex_digit(+n: U32) -> Char:
  Char.from_u32(Bool.pick(U32, U32.is_lt(n, 10), U32.add(48, n), U32.add(87, n)))

def hex.go(xs: List<&2, U32>, reversed: String) -> String:
  match xs:
    case Nil{}:
      String.reverse(reversed)
    case Con{+byte, tail}:
      hex.go(tail, SCon{hex_digit(U32.and(byte, 15)),
        SCon{hex_digit(U32.shrn(byte, 4n)), reversed}})

def hex(xs: List<&2, U32>) -> String:
  hex.go(xs, "")
