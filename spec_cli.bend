import Base
import ./bjson.bend as J

# the reference CLI for tests: everything through the proven J.parse,
# J.stringify and J.pretty. scripts/integration.py checks that bjson
# prints exactly what this prints, errors included

def usage() -> IO(Unit):
  IO.die(Unit, 2, "usage: bjson [--compact] <file.json>")

# the path of `bjson [--compact] <path>`, asked for again on an error,
# since keeping it would share a String
def path_of(args: List<String>) -> String:
  match args:
    case Con{path, Nil{}}:
      path
    case Con{_, Con{path, Nil{}}}:
      path
    case _:
      ""

def fail(e: J.Error) -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    IO.die(Unit, 1, path_of(args) ++ ":" ++ J.message(e))

def emit(compact: Bool, r: Result<&2, &2, J.Error, J.Json>) -> IO(Unit):
  match compact r:
    case True{} Done{j}:
      IO.print(J.stringify(j))
    case False{} Done{j}:
      IO.print(J.pretty(j, "  "))
    case _ Fail{e}:
      fail(e)

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

def run(compact: Bool, path: String) -> IO(Unit):
  do IO<Unit>:
    text : String <- read(path)
    emit(compact, J.parse(text))

def dispatch.flag(ok: Bool, path: String) -> IO(Unit):
  match ok:
    case True{}:
      run(True{}, path)
    case False{}:
      usage()

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{path, Nil{}}:
      run(False{}, path)
    case Con{flag, Con{path, Nil{}}}:
      dispatch.flag(String.eq(flag, "--compact"), path)
    case _:
      usage()

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
