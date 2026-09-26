import Base
import ./bjson.bend as J
import ../io/io.bend as Io

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

def run(compact: Bool, path: String) -> IO(Unit):
  do IO<Unit>:
    bytes : List<&2, U32> <- Io.read_bytes(path)
    emit(compact, J.parse_bytes(bytes))

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
