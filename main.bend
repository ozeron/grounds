import Base
import ./bjson.bend as J

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

law read_go:
  for compact: Bool
  for +path: String
  for m: File & Result<&1, &1, (U32 & String), String>
  IO(Unit)

def read_go(compact, path, m):
  (f, r) = m
  do IO<Unit>:
    text : String <- IO.pass(String, r)
    x : Unit <- File.close(f)
    emit(compact, J.parse(text), path)

law size_go:
  for compact: Bool
  for +path: String
  for m: File & Result<&1, &1, (U32 & String), U32>
  IO(Unit)

def size_go(compact, path, m):
  (f, r) = m
  do IO<Unit>:
    n : U32 <- IO.pass(U32, r)
    m2 : File & Result<&1, &1, (U32 & String), String> <- File.read(f, (n + 1 : U32))
    read_go(compact, path, m2)

def run(compact: Bool, +path: String) -> IO(Unit):
  do IO<Unit>:
    f : File <- IO.try(File, File.open(path, "r"))
    m : File & Result<&1, &1, (U32 & String), U32> <- File.size(f)
    size_go(compact, path, m)

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
