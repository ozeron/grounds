import Base
import ./unicode32_nfkc.bend as N
import ./unicode32_nfkc_tables.bend as T
import ./unicode32_nfkc_compose.bend as C
import ./unicode32_nfkc_cli.bend as P
import ../io/io.bend as Io

# All scalars, then two 4096-value invalid-repertoire ranges. Compact output
# keeps IO/diagnostic allocation bounded while preserving every normalized value.
def append.next(out: String, result: Array<U32> & U32, next: Array<U32> -> String -> String) -> String:
  (array, packed) = result
  next(array, P.hex(U32.shrn(packed, 8n), out))

def append(left: Nat, +at: U32, array: Array<U32>, out: String) -> String:
  match left:
    case 0n: out
    case 1n+p: append.next(out, Array.get(U32, array, at), a => s => append(p, U32.inc(at), a, s))

def normalized(out: String, result: T.Tables & Maybe<&1, C.Normalized>, next: T.Tables -> String -> T.Tables & String) -> T.Tables & String:
  (state, normalized) = result
  match normalized:
    case None{}: next(state, SCon{'X', out})
    case Some{C.Normalized{array, +length}}:
      next(state, append(U32.to_nat(length), 0, array, SCon{P.digit(length), out}))

def chunk(left: Nat, +code: U32, state: T.Tables, out: String) -> T.Tables & String:
  match left:
    case 0n: (state, String.reverse(out))
    case 1n+p: normalized(out, N.normalize(state, [code]), s => v => chunk(p, U32.inc(code), s, v))

def printed(result: T.Tables & String, next: T.Tables -> IO(T.Tables)) -> IO(T.Tables):
  (state, text) = result
  do IO<T.Tables>:
    IO.print(text)
    next(state)

def run(left: Nat, +code: U32, state: T.Tables) -> IO(T.Tables):
  match left:
    case 0n: IO.pure(T.Tables, state)
    case 1n+p: printed(chunk(1024n, code, state, ""), s => run(p, U32.add(code, 1024), s))

def loaded(result: Maybe<&1, T.Tables>) -> IO(Unit):
  match result:
    case None{}: IO.die(Unit, 2, "invalid Unicode 3.2 table asset")
    case Some{state}:
      do IO<Unit>:
        first : T.Tables <- run(1088n, 0, state)
        second : T.Tables <- run(4n, 1114112, first)
        third : T.Tables <- run(4n, 4294963200, second)
        return Unit{}

def command(args: List<String>) -> IO(Unit):
  match args:
    case Con{path, Nil{}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        loaded(T.decode(bytes))
    case Con{_, rest}: command(rest)
    case Nil{}: IO.die(Unit, 2, "expected table asset path")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    command(args)
