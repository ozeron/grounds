import Base
# fastc.bend: fast.bend with the end-of-input row returning
#   More{m, stk, out, hi, code, key, at, ea} instead of finish(...)
import ./fastc.bend as F

# compact-reformat a file read in chunks: the loop pauses at each chunk's
# end (More), its output so far is written, and it resumes on the next

def R() -> Type:
  File & Result<&1, &1, (U32 & String), String>

def empty(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case _:
      False{}

def resume.go(eof: Bool, m: F.Mode, stk: List<&2, F.Box>, out: String, +hi: U32, +code: U32, +key: Bool, +at: U32, +ea: U32, +text: String) -> F.Out:
  match eof:
    case True{}:
      F.finish(m, stk, out, at)
    case False{}:
      F.gc(text, m, text, stk, out, hi, code, key, at, ea)

def resume(st: F.Out, +text: String) -> F.Out:
  match st:
    case F.More{m, stk, out, hi, code, key, at, ea}:
      resume.go(empty(text), m, stk, out, hi, code, key, at, ea, text)
    case done:
      done

def act(next: F.Out, f: File, k: F.Out -> R() -> IO(Unit)) -> IO(Unit):
  match next:
    case F.More{m, stk, out, hi, code, key, at, ea}:
      do IO<Unit>:
        x : Unit <- IO.write(String.reverse(out))
        IO.bind(R(), Unit, File.read(f, 1048576), y => k(F.More{m, stk, "", hi, code, key, at, ea}, y))
    case F.Ok{t}:
      IO.print(t)
    case F.Err{r, at}:
      IO.die(Unit, 1, "error at " ++ U32.show(at))

law go:
  for fuel: Nat
  for st: F.Out
  for pr: R()
  IO(Unit)

def go(fuel, st, pr):
  match fuel:
    case 0n:
      IO.die(Unit, 1, "too many chunks")
    case 1n+p:
      (f, r) = pr
      do IO<Unit>:
        +text : String <- IO.pass(String, r)
        act(resume(st, text), f, x => y => go(p, x, y))

def start(args: List<String>) -> IO(Unit):
  match args:
    case Con{path, _}:
      do IO<Unit>:
        f : File <- IO.try(File, File.open(path, "r"))
        pr : R() <- File.read(f, 1048576)
        go(1000000n, F.More{F.VStart{}, [], "", 0, 0, False{}, 0, 0}, pr)
    case _:
      IO.die(Unit, 2, "chunkfmt file")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    start(args)
