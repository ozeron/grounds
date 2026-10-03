import Base
import ./unicode32_nfkc.bend as N
import ./unicode32_nfkc_tables.bend as T
import ./unicode32_nfkc_compose.bend as C
import ./unicode32_lookup.bend as L
import ../io/io.bend as Io

# Every UTF-8 stress value is exactly 65,535 bytes, the enclosing DER bound.
# The looser scalar-stage bound separately admits every possible B.2 expansion.
type Mode is Data:
  Expand{}
  Order{}
  Stable{}

def repeated(left: Nat, +code: U32, out: List<&2, U32>) -> List<&2, U32>:
  match left:
    case 0n: out
    case 1n+p: repeated(p, code, Con{code, out})

def alternating(left: Nat, +index: U32, +a: U32, +b: U32, out: List<&2, U32>) -> List<&2, U32>:
  match left:
    case 0n: List.reverse(&2, U32, out)
    case 1n+p: alternating(p, U32.inc(index), a, b, Con{Bool.pick(U32, U32.is_eq(U32.mod(index, 2), 0), a, b), out})

def input(mode: Mode) -> List<&2, U32>:
  match mode:
    case Expand{}: repeated(21845n, 65018, [])
    case Order{}: Con{65, alternating(32767n, 0, 789, 768, [])}
    case Stable{}: Con{65, alternating(32767n, 0, 769, 768, [])}

def expansion() -> Array<U32>:
  L.fill([1589, 1604, 1609, 32, 1575, 1604, 1604, 1607, 32, 1593, 1604, 1610, 1607, 32, 1608, 1587, 1604, 1605], 0, Array.new(U32, 5n, 0))

def pattern.order(+index: U32) -> U32:
  Bool.pick(U32, U32.is_eq(index, 0), 192, Bool.pick(U32, U32.is_lt(index, 16383), 768, 789))

def pattern.stable(+index: U32) -> U32:
  Bool.pick(U32, U32.is_eq(index, 0), 193, Bool.pick(U32, U32.is_eq(U32.mod(index, 2), 0), 769, 768))

def check.point(+index: U32, expected: Array<U32>, +wanted: U32, ok: Bool, result: Array<U32> & U32,
  next: Array<U32> -> Array<U32> -> Bool -> Bool) -> Bool:
  (array, packed) = result
  next(array, expected, Bool.and(ok, U32.is_eq(U32.shrn(packed, 8n), wanted)))

def check.expected(+index: U32, array: Array<U32>, ok: Bool, result: Array<U32> & U32,
  next: Array<U32> -> Array<U32> -> Bool -> Bool) -> Bool:
  (expected, wanted) = result
  check.point(index, expected, wanted, ok, Array.get(U32, array, index), next)

def check(left: Nat, +index: U32, +mode: Mode, array: Array<U32>, expected: Array<U32>, ok: Bool) -> Bool:
  match left mode:
    case 0n _: ok
    case 1n+p Expand{}:
      check.expected(index, array, ok, Array.get(U32, expected, U32.mod(index, 18)),
        a => e => valid => check(p, U32.inc(index), mode, a, e, valid))
    case 1n+p Order{}:
      check.point(index, expected, pattern.order(index), ok, Array.get(U32, array, index),
        a => e => valid => check(p, U32.inc(index), mode, a, e, valid))
    case 1n+p _:
      check.point(index, expected, pattern.stable(index), ok, Array.get(U32, array, index),
        a => e => valid => check(p, U32.inc(index), mode, a, e, valid))

def expected_length(mode: Mode) -> U32:
  match mode:
    case Expand{}: 393210
    case _: 32767

def shown(+mode: Mode, result: T.Tables & Maybe<&1, C.Normalized>) -> IO(Unit):
  (_, normalized) = result
  match normalized:
    case None{}: IO.print("false")
    case Some{C.Normalized{array, +length}}:
      wanted = expected_length(mode)
      IO.print(Bool.pick(String, check(U32.to_nat(length), 0, mode, array, expansion(), U32.is_eq(length, wanted)), "true", "false"))

def loaded(+mode: Mode, result: Maybe<&1, T.Tables>) -> IO(Unit):
  match result:
    case None{}: IO.die(Unit, 2, "invalid table asset")
    case Some{state}: shown(mode, N.normalize(state, input(mode)))

def operation.loaded(mode: Mode, path: String) -> IO(Unit):
  do IO<Unit>:
    bytes : List<&2, U32> <- Io.read_bytes(path)
    loaded(mode, T.decode(bytes))

def operation.valid(valid: Bool, mode: Mode, path: String) -> IO(Unit):
  match valid:
    case True{}: operation.loaded(mode, path)
    case False{}: IO.die(Unit, 2, "expected expand/order/stable/limit")

def operation.normal(+mode: String, path: String) -> IO(Unit):
  operation.valid(Bool.or(String.eq(mode, "expand"), Bool.or(String.eq(mode, "order"), String.eq(mode, "stable"))),
    Bool.pick(Mode, String.eq(mode, "expand"), Expand{}, Bool.pick(Mode, String.eq(mode, "order"), Order{}, Stable{})), path)

def operation.checked(limit: Bool, mode: String, path: String) -> IO(Unit):
  match limit:
    case True{}:
      IO.print(Bool.pick(String, Bool.and(N.validate(repeated(262140n, 65, []), 0), Bool.not(N.validate(repeated(262141n, 65, []), 0))), "true", "false"))
    case False{}: operation.normal(mode, path)

def operation(+mode: String, path: String) -> IO(Unit):
  operation.checked(String.eq(mode, "limit"), mode, path)

def command(args: List<String>) -> IO(Unit):
  match args:
    case Con{mode, Con{path, Nil{}}}: operation(mode, path)
    case Con{_, rest}: command(rest)
    case Nil{}: IO.die(Unit, 2, "expected mode and table asset")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    command(args)
