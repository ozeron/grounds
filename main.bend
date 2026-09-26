import Base
import ./bjson.bend as J
import ./fast.bend as F

# bjson [--compact] <file.json>
# pretty-prints the file, or reports where it stops being JSON.
#
# Everything goes through fast.bend's one-pass loop, which gives J.parse's
# exact answers (suite.bend and scripts/integration.py check this against
# spec_cli.bend, the same CLI on the proven parser). No String may be
# shared here: one shared String makes the runtime count references on
# every String in the program, and scripts/cold.py fails the build.

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

# the path of `bjson [--compact] <path>`
def path_of(args: List<String>) -> String:
  match args:
    case Con{path, Nil{}}:
      path
    case Con{_, Con{path, Nil{}}}:
      path
    case _:
      ""

# an error: the file is read again for its line and column, and the path
# asked for again, since keeping either would share a String
def fail.at(r: J.Reason, +at: U32, text: String, path: String) -> IO(Unit):
  IO.die(Unit, 1, path ++ ":" ++ J.message(J.position(r, at, text)))

def fail.again(r: J.Reason, +at: U32, text: String) -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    fail.at(r, at, text, path_of(args))

def fail(r: J.Reason, +at: U32) -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    text : String <- read(path_of(args))
    fail.again(r, at, text)

def out(o: F.Out) -> IO(Unit):
  match o:
    case F.Ok{text}:
      IO.print(text)
    case F.Err{r, at}:
      fail(r, at)

def format(compact: Bool, text: String) -> F.Out:
  match compact:
    case True{}:
      F.reformat(text)
    case False{}:
      F.pretty(text)

def run(compact: Bool, path: String) -> IO(Unit):
  do IO<Unit>:
    text : String <- read(path)
    out(format(compact, text))

def usage() -> IO(Unit):
  IO.die(Unit, 2, "usage: bjson [--compact] <file.json>")

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
