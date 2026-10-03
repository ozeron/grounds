import Base
import ./unicode32_prepare.bend as N
import ./unicode32_nfkc_compose.bend as C
import ./unicode32_lookup.bend as L
import ../io/io.bend as Io
import ./unicode32_prepare_cli.bend as Fixture

# Full scalar and UTF-8 byte bounds, mapping/folding/normalization/SPACE composition.
# Validation compares every packed result to independently checked literal patterns.
type Mode is Data:
  Expand{}
  Order{}
  Stable{}
  FoldBound{}
  FoldByte{}
  Protected{}
  Spaces{}
  Reject{}

def repeated(left: Nat, +code: U32, out: List<&2, U32>) -> List<&2, U32>:
  match left:
    case 0n: out
    case 1n+p: repeated(p, code, Con{code, out})

def alternating(left: Nat, +index: U32, +a: U32, +b: U32, out: List<&2, U32>) -> List<&2, U32>:
  match left:
    case 0n: List.reverse(&2, U32, out)
    case 1n+p: alternating(p, U32.inc(index), a, b, Con{Bool.pick(U32, U32.is_eq(U32.mod(index, 2), 0), a, b), out})

def pairs(left: Nat, out: List<&2, U32>) -> List<&2, U32>:
  match left:
    case 0n: out
    case 1n+p: pairs(p, Con{32, Con{2307, out}})

def input(mode: Mode) -> List<&2, U32>:
  match mode:
    case Expand{}: repeated(21845n, 65018, [])
    case Order{}: Con{65, alternating(32767n, 0, 789, 768, [])}
    case Stable{}: Con{65, alternating(32767n, 0, 769, 768, [])}
    case FoldBound{}: repeated(65535n, 13254, [])
    case FoldByte{}: repeated(21845n, 13254, [])
    case Protected{}: pairs(16383n, [65, 66, 67])
    case Spaces{}: repeated(65535n, 32, [])
    case Reject{}: repeated(65536n, 65, [])

def expansion() -> Array<U32>:
  L.fill([1589, 1604, 1609, 32, 32, 1575, 1604, 1604, 1607, 32, 32, 1593, 1604, 1610, 1607, 32, 32, 1608, 1587, 1604, 1605], 0, Array.new(U32, 5n, 0))

def expected_length(mode: Mode) -> U32:
  match mode:
    case Expand{}: 458747
    case FoldBound{}: 262142
    case FoldByte{}: 87382
    case Protected{}: 32771
    case Spaces{}: 2
    case Reject{}: 0
    case _: 32769

def pattern(+mode: Mode, +index: U32) -> U32:
  match mode:
    case Order{}: Bool.pick(U32, U32.is_eq(index, 0), 224, Bool.pick(U32, U32.is_lt(index, 16383), 768, 789))
    case Stable{}: Bool.pick(U32, U32.is_eq(index, 0), 225, Bool.pick(U32, U32.is_eq(U32.mod(index, 2), 0), 769, 768))
    case Protected{}:
      Bool.pick(U32, U32.is_lt(index, 32766), Bool.pick(U32, U32.is_eq(U32.mod(index, 2), 0), 32, 2307), U32.add(97, U32.sub(index, 32766)))
    case _:
      +at = U32.mod(index, 4)
      Bool.pick(U32, U32.is_eq(at, 0), 99, Bool.pick(U32, U32.is_eq(at, 1), 8725, Bool.pick(U32, U32.is_eq(at, 2), 107, 103)))

def check.point(+index: U32, expected: Array<U32>, +wanted: U32, ok: Bool, result: Array<U32> & U32,
  next: Array<U32> -> Array<U32> -> Bool -> Bool) -> Bool:
  (array, packed) = result
  next(array, expected, Bool.and(ok, U32.is_eq(U32.shrn(packed, 8n), wanted)))

def check.expected(+index: U32, array: Array<U32>, ok: Bool, result: Array<U32> & U32,
  next: Array<U32> -> Array<U32> -> Bool -> Bool) -> Bool:
  (expected, wanted) = result
  check.point(index, expected, wanted, ok, Array.get(U32, array, index), next)

def check.middle(mode: Mode, +index: U32, array: Array<U32>, expected: Array<U32>, ok: Bool,
  next: Array<U32> -> Array<U32> -> Bool -> Bool) -> Bool:
  match mode:
    case Expand{}:
      check.expected(index, array, ok, Array.get(U32, expected, U32.mod(U32.sub(index, 1), 21)), next)
    case _:
      check.point(index, expected, pattern(mode, U32.sub(index, 1)), ok, Array.get(U32, array, index), next)

def check.edge(edge: Bool, mode: Mode, +index: U32, array: Array<U32>, expected: Array<U32>, ok: Bool,
  next: Array<U32> -> Array<U32> -> Bool -> Bool) -> Bool:
  match edge:
    case True{}: check.point(index, expected, 32, ok, Array.get(U32, array, index), next)
    case False{}: check.middle(mode, index, array, expected, ok, next)

def check(left: Nat, +index: U32, +mode: Mode, +length: U32, array: Array<U32>, expected: Array<U32>, ok: Bool) -> Bool:
  match left:
    case 0n: ok
    case 1n+p:
      check.edge(Bool.or(U32.is_eq(index, 0), U32.is_eq(U32.inc(index), length)), mode, index, array, expected, ok,
        a => e => valid => check(p, U32.inc(index), mode, length, a, e, valid))

def shown.none(mode: Mode) -> IO(Unit):
  match mode:
    case Reject{}: IO.print("true")
    case _: IO.print("false")

def shown(+mode: Mode, result: N.Tables & Maybe<&1, C.Normalized>) -> IO(Unit):
  (_, normalized) = result
  match normalized:
    case None{}: shown.none(mode)
    case Some{C.Normalized{array, +length}}:
      IO.print(Bool.pick(String, check(U32.to_nat(length), 0, mode, length, array, expansion(), U32.is_eq(length, expected_length(mode))), "true", "false"))

def loaded(+mode: Mode, result: Maybe<&1, N.Tables>) -> IO(Unit):
  match result:
    case None{}: IO.die(Unit, 2, "invalid table asset")
    case Some{state}: shown(mode, N.prepare(state, input(mode), True{}))

def operation.loaded(mode: Mode, path: String, profile_path: String) -> IO(Unit):
  do IO<Unit>:
    tables : Maybe<&1, N.Tables> <- Fixture.read_tables(path, profile_path)
    loaded(mode, tables)

def operation.valid(valid: Bool, mode: Mode, path: String, profile_path: String) -> IO(Unit):
  match valid:
    case True{}: operation.loaded(mode, path, profile_path)
    case False{}: IO.die(Unit, 2, "expected stress mode")

def operation.normal(+mode: String, path: String, profile_path: String) -> IO(Unit):
  operation.valid(Bool.or(String.eq(mode, "expand"), Bool.or(String.eq(mode, "order"), Bool.or(String.eq(mode, "stable"),
    Bool.or(String.eq(mode, "fold-bound"), Bool.or(String.eq(mode, "fold-byte"), Bool.or(String.eq(mode, "protected"), Bool.or(String.eq(mode, "spaces"), String.eq(mode, "reject")))))))),
    Bool.pick(Mode, String.eq(mode, "expand"), Expand{}, Bool.pick(Mode, String.eq(mode, "order"), Order{}, Bool.pick(Mode, String.eq(mode, "stable"), Stable{},
      Bool.pick(Mode, String.eq(mode, "fold-bound"), FoldBound{}, Bool.pick(Mode, String.eq(mode, "fold-byte"), FoldByte{}, Bool.pick(Mode, String.eq(mode, "protected"), Protected{}, Bool.pick(Mode, String.eq(mode, "spaces"), Spaces{}, Reject{}))))))), path, profile_path)

def operation.checked(limit: Bool, mode: String, path: String, profile_path: String) -> IO(Unit):
  match limit:
    case True{}:
      IO.print(Bool.pick(String, Bool.and(N.validate(repeated(65535n, 65, []), 0), Bool.not(N.validate(repeated(65536n, 65, []), 0))), "true", "false"))
    case False{}: operation.normal(mode, path, profile_path)

def command(args: List<String>) -> IO(Unit):
  match args:
    case Con{+mode, Con{path, Con{profile_path, Nil{}}}}: operation.checked(String.eq(mode, "limit"), mode, path, profile_path)
    case Con{_, rest}: command(rest)
    case Nil{}: IO.die(Unit, 2, "expected mode and two table assets")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    command(args)
