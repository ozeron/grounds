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

law read.bytes:
  for m: File & Result<&1, &1, (U32 & String), List<&2, U32>>
  IO(List<&2, U32>)

def read.bytes(m):
  (f, r) = m
  do IO<List<&2, U32>>:
    bs : List<&2, U32> <- IO.pass(List<&2, U32>, r)
    x : Unit <- File.close(f)
    return bs

law read.bytes.size:
  for m: File & Result<&1, &1, (U32 & String), U32>
  IO(List<&2, U32>)

def read.bytes.size(m):
  (f, r) = m
  do IO<List<&2, U32>>:
    n : U32 <- IO.pass(U32, r)
    t : File & Result<&1, &1, (U32 & String), List<&2, U32>> <- File.read_bytes(f, (n + 1 : U32))
    read.bytes(t)

def read_bytes(path: String) -> IO(List<&2, U32>):
  do IO<List<&2, U32>>:
    f : File <- IO.try(File, File.open(path, "r"))
    m : File & Result<&1, &1, (U32 & String), U32> <- File.size(f)
    read.bytes.size(m)

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

# the runtime reads text as UTF-8 and turns each bad sequence into U+FFFD,
# so only a text with one may be invalid
def replaced(s: String) -> Bool:
  match s:
    case SNil{}:
      False{}
    case SCon{'\u{FFFD}', _}:
      True{}
    case SCon{_, t}:
      replaced(t)

def format(compact: Bool, text: String) -> F.Out:
  match compact:
    case True{}:
      F.reformat(text)
    case False{}:
      F.pretty(text)

def bad_utf8(+at: U32, +before: String) -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    IO.die(Unit, 1, path_of(args) ++ ":" ++ J.message(J.bad_utf8(at, before)))

def decoded(compact: Bool, t: J.Text) -> IO(Unit):
  match t:
    case J.TOk{text}:
      out(format(compact, text))
    case J.TBad{at, before}:
      bad_utf8(at, before)

# the text had a U+FFFD: decode the bytes to tell a real one from a bad
# sequence
def recheck(compact: Bool) -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    bytes : List<&2, U32> <- read_bytes(path_of(args))
    decoded(compact, J.decode(bytes))

def checked(compact: Bool, bad: Bool, text: String) -> IO(Unit):
  match bad:
    case False{}:
      out(format(compact, text))
    case True{}:
      recheck(compact)

def run(compact: Bool, path: String) -> IO(Unit):
  do IO<Unit>:
    +text : String <- read(path)
    checked(compact, replaced(text), text)

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
