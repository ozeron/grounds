import Base
import ./bjson.bend as J
import ./fast.bend as F

# bjson [--compact] <file.json>
# pretty-prints the file, or reports where it stops being JSON

def usage() -> IO(Unit):
  IO.die(Unit, 2, "usage: bjson [--compact] <file.json>")

def emit(compact: Bool, r: Result<&2, &2, J.Error, J.Json>, path: String) -> IO(Unit):
  match compact r:
    case True{} Done{j}:
      IO.print(J.stringify(j))
    case False{} Done{j}:
      IO.print(J.pretty(j, "  "))
    case _ Fail{e}:
      IO.die(Unit, 1, path ++ ":" ++ J.message(e))

law read.text:
  for m: File & Result<&1, &1, (U32 & String), String>
  IO(String)

def read.text(m):
  (f, r) = m
  do IO<String>:
    text : String <- IO.pass(String, r)
    x : Unit <- File.close(f)
    return text

law read.size:
  for m: File & Result<&1, &1, (U32 & String), U32>
  IO(String)

def read.size(m):
  (f, r) = m
  do IO<String>:
    n : U32 <- IO.pass(U32, r)
    t : File & Result<&1, &1, (U32 & String), String> <- File.read(f, (n + 1 : U32))
    read.text(t)

def read(path: String) -> IO(String):
  do IO<String>:
    f : File <- IO.try(File, File.open(path, "r"))
    m : File & Result<&1, &1, (U32 & String), U32> <- File.size(f)
    read.size(m)

# the proven parser: slower, and it says where and why input is wrong
def slow(compact: Bool, +path: String) -> IO(Unit):
  do IO<Unit>:
    text : String <- read(path)
    emit(compact, J.parse(text), path)

# compact output takes the one-pass path. If it finds the input invalid,
# the file is read again for the proven parser to report the error:
# keeping the text around for that would slow the fast path down.
def fast_out(m: Maybe<&2, String>, +path: String) -> IO(Unit):
  match m:
    case Some{out}:
      IO.print(out)
    case None{}:
      slow(True{}, path)

def fast(+path: String) -> IO(Unit):
  do IO<Unit>:
    text : String <- read(path)
    fast_out(F.reformat(text), path)

def run(compact: Bool, +path: String) -> IO(Unit):
  match compact:
    case True{}:
      fast(path)
    case False{}:
      slow(False{}, path)

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{path, Nil{}}:
      run(False{}, path)
    case Con{+flag, Con{+path, Nil{}}}:
      Bool.pick(IO(Unit), String.eq(flag, "--compact"), run(True{}, path), usage())
    case _:
      usage()

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
