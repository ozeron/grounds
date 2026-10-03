import Base
import ./unicode32_nfkc.bend as N
import ./unicode32_nfkc_tables.bend as T
import ./unicode32_nfkc_compose.bend as C
import ../io/io.bend as Io

# Test transport: U32BE record count, then each U32BE scalar count and scalars.
# Output is a status/count followed by bounded chunks of six-digit scalar hex.
type Record is Data:
  Record{codes: List<&2, U32>, rest: List<&2, U32>}

def word(a: U32, b: U32, c: U32, d: U32) -> U32:
  U32.or(U32.shln(a, 24n), U32.or(U32.shln(b, 16n), U32.or(U32.shln(c, 8n), d)))

def record.words(left: Nat, bytes: List<&2, U32>, out: List<&2, U32>) -> Maybe<Record>:
  match left bytes:
    case 0n bytes: Some{Record{List.reverse(&2, U32, out), bytes}}
    case 1n+p Con{a, Con{b, Con{c, Con{d, rest}}}}: record.words(p, rest, Con{word(a, b, c, d), out})
    case _ _: None{}

def record(bytes: List<&2, U32>) -> Maybe<Record>:
  match bytes:
    case Con{a, Con{b, Con{c, Con{d, rest}}}}: record.words(U32.to_nat(word(a, b, c, d)), rest, [])
    case _: None{}

def digit(+n: U32) -> Char:
  Char.from_u32(Bool.pick(U32, U32.is_lt(n, 10), U32.add(48, n), U32.add(87, n)))

def hex(+code: U32, out: String) -> String:
  SCon{digit(U32.and(code, 15)), SCon{digit(U32.and(U32.shrn(code, 4n), 15)),
    SCon{digit(U32.and(U32.shrn(code, 8n), 15)), SCon{digit(U32.and(U32.shrn(code, 12n), 15)),
      SCon{digit(U32.and(U32.shrn(code, 16n), 15)), SCon{digit(U32.shrn(code, 20n)), out}}}}}}

def chunk.next(out: String, result: Array<U32> & U32, next: Array<U32> -> String -> Array<U32> & String) -> Array<U32> & String:
  (array, packed) = result
  next(array, hex(U32.shrn(packed, 8n), out))

def chunk(left: Nat, +at: U32, array: Array<U32>, out: String) -> Array<U32> & String:
  match left:
    case 0n: (array, String.reverse(out))
    case 1n+p: chunk.next(out, Array.get(U32, array, at), a => s => chunk(p, U32.inc(at), a, s))

def chunks.next(result: Array<U32> & String, next: Array<U32> -> IO(Unit)) -> IO(Unit):
  (array, text) = result
  do IO<Unit>:
    IO.print(text)
    next(array)

def chunks(left: Nat, +at: U32, +count: U32, array: Array<U32>) -> IO(Unit):
  match left:
    case 0n: IO.pure(Unit, Unit{})
    case 1n+p:
      +size = U32.min(256, count)
      chunks.next(chunk(U32.to_nat(size), at, array, ""), a => chunks(p, U32.add(at, size), U32.sub(count, size), a))

def emit(result: Maybe<&1, C.Normalized>) -> IO(Unit):
  match result:
    case None{}: IO.print("none")
    case Some{C.Normalized{array, +count}}:
      do IO<Unit>:
        IO.print(String.concat(["some:", U32.show(count)]))
        chunks(U32.to_nat(U32.div(U32.add(count, 255), 256)), 0, count, array)

def batch.normalized(rest: List<&2, U32>, result: T.Tables & Maybe<&1, C.Normalized>, next: List<&2, U32> -> T.Tables -> IO(T.Tables)) -> IO(T.Tables):
  (state, normalized) = result
  do IO<T.Tables>:
    emit(normalized)
    next(rest, state)

def batch.record(state: T.Tables, result: Maybe<Record>, next: List<&2, U32> -> T.Tables -> IO(T.Tables)) -> IO(T.Tables):
  match result:
    case None{}: IO.die(T.Tables, 2, "truncated scalar record")
    case Some{Record{codes, rest}}: batch.normalized(rest, N.normalize(state, codes), next)

def batch(left: Nat, bytes: List<&2, U32>, state: T.Tables) -> IO(T.Tables):
  match left bytes:
    case 0n Nil{}: IO.pure(T.Tables, state)
    case 0n _: IO.die(T.Tables, 2, "trailing batch bytes")
    case 1n+p bytes: batch.record(state, record(bytes), xs => s => batch(p, xs, s))

def file(state: T.Tables, bytes: List<&2, U32>) -> IO(T.Tables):
  match bytes:
    case Con{a, Con{b, Con{c, Con{d, rest}}}}: batch(U32.to_nat(word(a, b, c, d)), rest, state)
    case _: IO.die(T.Tables, 2, "truncated batch header")

def dispatch(args: List<String>, state: T.Tables) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{path, rest}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        next : T.Tables <- file(state, bytes)
        dispatch(rest, next)

def loaded(args: List<String>, result: Maybe<&1, T.Tables>) -> IO(Unit):
  match result:
    case None{}: IO.die(Unit, 2, "invalid Unicode 3.2 table asset")
    case Some{state}: dispatch(args, state)

def command.asset(args: List<String>) -> IO(Unit):
  match args:
    case Con{path, rest}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        loaded(rest, T.decode(bytes))
    case _: IO.die(Unit, 2, "expected table asset and batch files")

def command.checked(valid: Bool, rest: List<String>) -> IO(Unit):
  match valid:
    case True{}: command.asset(rest)
    case False{}: IO.die(Unit, 2, "expected check command")

def command.shifted(args: List<String>) -> IO(Unit):
  match args:
    case Con{flag, rest}: command.checked(String.eq(flag, "check"), rest)
    case _: IO.die(Unit, 2, "expected check command")

def command.first(valid: Bool, rest: List<String>) -> IO(Unit):
  match valid:
    case True{}: command.asset(rest)
    case False{}: command.shifted(rest)

def command(args: List<String>) -> IO(Unit):
  match args:
    case Con{flag, rest}: command.first(String.eq(flag, "check"), rest)
    case _: IO.die(Unit, 2, "expected check command")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    command(args)
