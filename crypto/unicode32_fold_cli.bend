import Base
import ./unicode32_fold.bend as F

# Exhaustive scalar matrix: length digit then six hex digits per output scalar.
# Invalid scalar input uses X; successful literal deletion uses length zero.
def digit(+n: U32) -> Char:
  Char.from_u32(Bool.pick(U32, U32.is_lt(n, 10), U32.add(48, n), U32.add(87, n)))

def hex(+code: U32, out: String) -> String:
  SCon{digit(U32.and(code, 15)), SCon{digit(U32.and(U32.shrn(code, 4n), 15)),
    SCon{digit(U32.and(U32.shrn(code, 8n), 15)), SCon{digit(U32.and(U32.shrn(code, 12n), 15)),
      SCon{digit(U32.and(U32.shrn(code, 16n), 15)), SCon{digit(U32.shrn(code, 20n)), out}}}}}}

def size(codes: List<&2, U32>, +count: U32) -> U32:
  match codes:
    case Nil{}: count
    case Con{_, rest}: size(rest, U32.inc(count))

def encode(codes: List<&2, U32>, out: String) -> String:
  match codes:
    case Nil{}: out
    case Con{code, rest}: encode(rest, hex(code, out))

def output(value: F.Output, out: String) -> String:
  match value:
    case F.Invalid{}: SCon{'X', out}
    case F.Folded{+codes}: encode(codes, SCon{digit(size(codes, 0)), out})

def chunk.next(out: String, result: F.Tables & F.Output, next: F.Tables -> String -> F.Tables & String) -> F.Tables & String:
  (state, value) = result
  next(state, output(value, out))

def chunk(left: Nat, +code: U32, state: F.Tables, out: String, +mapping: Bool) -> F.Tables & String:
  match left:
    case 0n: (state, String.reverse(out))
    case 1n+p:
      match mapping:
        case False{}: chunk.next(out, F.code(state, code), s => v => chunk(p, U32.inc(code), s, v, mapping))
        case True{}: chunk.next(out, F.map_code(state, code), s => v => chunk(p, U32.inc(code), s, v, mapping))

def run.next(result: F.Tables & String, next: F.Tables -> IO(Unit)) -> IO(Unit):
  (state, text) = result
  do IO<Unit>:
    IO.print(text)
    next(state)

def run(left: Nat, +code: U32, state: F.Tables, +mapping: Bool) -> IO(Unit):
  match left:
    case 0n: IO.pure(Unit, Unit{})
    case 1n+p: run.next(chunk(256n, code, state, "", mapping), s => run(p, U32.add(code, 256), s, mapping))

def matrix(+mapping: Bool) -> IO(Unit):
  do IO<Unit>:
    run(4352n, 0, F.tables(), mapping)
    run(16n, 1114112, F.tables(), mapping)
    run(16n, 4294963200, F.tables(), mapping)

def example(result: F.Tables & F.Output, next: F.Tables -> IO(Unit)) -> IO(Unit):
  (state, value) = result
  do IO<Unit>:
    IO.print(String.reverse(output(value, "")))
    next(state)

def examples(state: F.Tables) -> IO(Unit):
  example(F.string(state, [], False{}), s =>
    example(F.string(s, [65, 223, 8490, 962], False{}), s =>
      example(F.string(s, [304, 944, 13254], False{}), s =>
        example(F.string(s, [0, 65, 173, 9, 223, 65024], True{}), s =>
          example(F.string(s, [0, 65, 173, 9, 223, 65024], False{}), s =>
            example(F.string(s, [65, 55296, 66], True{}), s =>
              example(F.string(s, [65, 4294967295, 66], False{}), s =>
                example(F.string(s, [5024, 7312, 119808], False{}), s => IO.pure(Unit, Unit{})))))))))

def repeat(left: Nat, out: List<&2, U32>) -> List<&2, U32>:
  match left:
    case 0n: out
    case 1n+p: repeat(p, Con{13254, out})

def pattern(+index: U32) -> U32:
  +part = U32.mod(index, 4)
  Bool.pick(U32, U32.is_eq(part, 0), 99, Bool.pick(U32, U32.is_eq(part, 1), 8725, Bool.pick(U32, U32.is_eq(part, 2), 107, 103)))

def checked(codes: List<&2, U32>, +index: U32, ok: Bool) -> Bool:
  match codes:
    case Nil{}: Bool.and(ok, U32.is_eq(index, 262140))
    case Con{code, rest}: checked(rest, U32.inc(index), Bool.and(ok, U32.is_eq(code, pattern(index))))

def stress(result: F.Tables & F.Output) -> IO(Unit):
  (_, output) = result
  match output:
    case F.Invalid{}: IO.print("stress:false")
    case F.Folded{codes}: IO.print(Bool.pick(String, checked(codes, 0, True{}), "stress:true", "stress:false"))

def main() -> IO(Unit):
  do IO<Unit>:
    matrix(False{})
    matrix(True{})
    examples(F.tables())
