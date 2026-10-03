import Base
import ./unicode32_profile.bend as P

# Two ASCII chars per point: property flags then literal mapping category.
# Mapping: 0 removed, 1 SPACE, 2 unchanged, 3 invalid scalar, 4 other value.
def mapping(value: P.Mapping, code: U32) -> Char:
  match value:
    case P.Removed{}: '0'
    case P.Invalid{}: '3'
    case P.Mapped{+mapped}: Char.from_u32(Bool.pick(U32, U32.is_eq(mapped, 32), 49, Bool.pick(U32, U32.is_eq(mapped, code), 50, 52)))

def chunk.next(+code: U32, out: String, result: P.Tables & U32, next: P.Tables -> String -> P.Tables & String) -> P.Tables & String:
  (state, flags) = result
  next(state, SCon{mapping(P.map_code(code), code), SCon{Char.from_u32(U32.add(48, flags)), out}})

def chunk(left: Nat, +code: U32, state: P.Tables, out: String) -> P.Tables & String:
  match left:
    case 0n: (state, String.reverse(out))
    case 1n+p: chunk.next(code, out, P.flags(state, code), s => v => chunk(p, U32.inc(code), s, v))

def run.next(result: P.Tables & String, next: P.Tables -> IO(Unit)) -> IO(Unit):
  (state, text) = result
  do IO<Unit>:
    IO.print(text)
    next(state)

def run(left: Nat, +code: U32, state: P.Tables) -> IO(Unit):
  match left:
    case 0n: IO.pure(Unit, Unit{})
    case 1n+p: run.next(chunk(4096n, code, state, ""), s => run(p, U32.add(code, 4096), s))

def main() -> IO(Unit):
  do IO<Unit>:
    run(272n, 0, P.tables())
    run(1n, 1114112, P.tables())
    run(1n, 4294963200, P.tables())
