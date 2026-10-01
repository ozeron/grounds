import Base
import ./wire.bend as W

# Reproducible local foundation measurements. All fixtures are public patterns
# or fresh synthetic RNG output; these timings do not prove secret safety.
type Stats is Data:
  Stats{length: U32, sum: U32, valid: Bool}

def stats() -> Stats:
  Stats{0, 0, True{}}

def add(+byte: U32, value: Stats) -> Stats:
  match value:
    case Stats{n, sum, ok}:
      Stats{U32.inc(n), U32.add(sum, byte), Bool.and(ok, U32.is_le(byte, 255))}

def scan(xs: List<&2, U32>, value: Stats) -> Stats:
  match xs:
    case Nil{}: value
    case Con{b, tail}: scan(tail, add(b, value))

def pattern(fuel: Nat, +at: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match fuel:
    case 0n: acc
    case 1n+p: pattern(p, U32.inc(at), Con{U32.and(at, 255), acc})

type Bytes is Data:
  End{}
  Byte{value: U32, tail: Bytes}

def bytes(fuel: Nat, +at: U32, acc: Bytes) -> Bytes:
  match fuel:
    case 0n: acc
    case 1n+p: bytes(p, U32.inc(at), Byte{U32.and(at, 255), acc})

def scan_bytes(xs: Bytes, value: Stats) -> Stats:
  match xs:
    case End{}: value
    case Byte{b, tail}: scan_bytes(tail, add(b, value))

def array(fuel: Nat, +at: U32, xs: Array<U32>) -> Array<U32>:
  match fuel:
    case 0n: xs
    case 1n+p: array(p, U32.inc(at), Array.set(U32, xs, at, U32.and(at, 255)))

def depth.choose(ok: Bool, power: Nat, again: Unit -> Nat) -> Nat:
  match ok:
    case True{}: power
    case False{}: again(Unit{})

def depth(fuel: Nat, +size: U32, +capacity: U32, +power: Nat) -> Nat:
  match fuel:
    case 0n: power
    case 1n+p:
      depth.choose(U32.is_ge(capacity, size), power, x => depth(p, size, U32.mul(capacity, 2), Nat.add(power, 1n)))

def scan_array(fuel: Nat, xs: List<&1, U32>, value: Stats) -> Stats:
  match fuel xs:
    case 0n _: value
    case 1n+p Con{b, tail}: scan_array(p, tail, add(b, value))
    case _ _: Stats{0, 0, False{}}

def storage(mode: String, +size: U32) -> Stats:
  match mode:
    case "list": scan(pattern(U32.to_nat(size), 0, []), stats())
    case "bytes": scan_bytes(bytes(U32.to_nat(size), 0, End{}), stats())
    case "array": scan_array(U32.to_nat(size), Array.to_list(U32,
      array(U32.to_nat(size), 0, Array.new(U32, depth(21n, size, 1, 0n), 0))), stats())
    case _: Stats{0, 0, False{}}

def word_bytes(fuel: Nat, left: Nat, +word: U32, acc: List<&2, U32>) -> Nat & List<&2, U32>:
  match fuel left:
    case 0n n: (n, acc)
    case _ 0n: (0n, acc)
    case 1n+p 1n+n: word_bytes(p, n, U32.shrn(word, 8n), Con{U32.and(word, 255), acc})

def word_expanded(value: Nat & List<&2, U32>,
                  again: Nat -> List<&2, U32> -> IO(Result<&1, &1, U32 & String, List<&2, U32>>)) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  (next, bytes) = value
  again(next, bytes)

def word_result(value: Result<&1, &1, U32 & String, U32>, left: Nat, acc: List<&2, U32>,
                again: Nat -> List<&2, U32> -> IO(Result<&1, &1, U32 & String, List<&2, U32>>)) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match value:
    case Done{w}: word_expanded(word_bytes(4n, left, w, acc), again)
    case Fail{e}: IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Fail{e})

def words(fuel: Nat, left: Nat, acc: List<&2, U32>) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match fuel:
    case 0n: IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Done{acc})
    case 1n+p:
      IO.bind(Result<&1, &1, U32 & String, U32>, Result<&1, &1, U32 & String, List<&2, U32>>,
        IO.random_u32(), r => word_result(r, left, acc, a => b => words(p, a, b)))

def random(mode: String, +size: U32) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match mode:
    case "bulk": W.wire_random_bytes(size)
    case "word": words(Nat.div(Nat.add(U32.to_nat(size), 3n), 4n), U32.to_nat(size), [])
    case _: IO.die(Result<&1, &1, U32 & String, List<&2, U32>>, 2, "unknown RNG mode")

def random_stats(value: Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Stats):
  match value:
    case Done{bytes}: IO.pure(Stats, scan(bytes, stats()))
    case Fail{_}: IO.die(Stats, 3, "host RNG failed")

def sample(+mode: String, size: U32) -> IO(Stats):
  match mode:
    case "bulk": IO.bind(Result<&1, &1, U32 & String, List<&2, U32>>, Stats, random(mode, size), random_stats)
    case "word": IO.bind(Result<&1, &1, U32 & String, List<&2, U32>>, Stats, random(mode, size), random_stats)
    case other: IO.pure(Stats, storage(other, size))

def checked.ok(ok: Bool, sum: U32, again: U32 -> IO(U32)) -> IO(U32):
  match ok:
    case True{}: again(sum)
    case False{}: IO.die(U32, 3, "benchmark byte count/range mismatch")

def checked(value: Stats, size: U32, sum: U32, again: U32 -> IO(U32)) -> IO(U32):
  match value:
    case Stats{n, total, ok}:
      checked.ok(Bool.and(ok, U32.is_eq(n, size)), U32.add(sum, total), again)

def rounds(fuel: Nat, +mode: String, +size: U32, sum: U32) -> IO(U32):
  match fuel:
    case 0n: IO.pure(U32, sum)
    case 1n+p: IO.bind(Stats, U32, sample(mode, size), r => checked(r, size, sum, s => rounds(p, mode, size, s)))

def report(start: Nat, checksum: U32) -> IO(Unit):
  do IO<Unit>:
    end : Nat <- IO.now()
    IO.print("{\"ms\":" ++ Nat.show(Nat.sub(end, start)) ++ ",\"checksum\":" ++ U32.show(checksum) ++ "}")

def run(+mode: String, +size: U32, +reps: U32) -> IO(Unit):
  do IO<Unit>:
    start : Nat <- IO.now()
    sum : U32 <- rounds(U32.to_nat(reps), mode, size, 0)
    report(start, sum)

def parsed.ok(ok: Bool, mode: String, size: U32, reps: U32) -> IO(Unit):
  match ok:
    case True{}: run(mode, size, reps)
    case False{}: IO.die(Unit, 2, "benchmark size/reps outside bounds")

def parsed(mode: String, size: Maybe<&2, U32>, reps: Maybe<&2, U32>) -> IO(Unit):
  match size reps:
    case Some{+n} Some{+r}:
      parsed.ok(Bool.and(U32.is_le(n, 1048576), Bool.and(U32.is_gt(r, 0), U32.is_le(r, 1000))), mode, n, r)
    case _ _: IO.die(Unit, 2, "benchmark arguments must be U32")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [mode, size, reps]: parsed(mode, U32.read(size), U32.read(reps))
    case _: IO.die(Unit, 2, "usage: bench <bulk|word|list|bytes|array> <bytes> <1..1000 repetitions>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
