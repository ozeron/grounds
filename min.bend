import Base
import ./fast.bend as F

# bjson-min <file.json>
# prints the file as compact JSON, the same text as `bjson --compact`.
# It never links the proven parser: that code shares Strings, which makes
# the runtime count references on every String and halves the speed.
# So on invalid input it only says so; `bjson <file>` shows where and why.

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

def complain(args: List<String>) -> IO(Unit):
  match args:
    case Con{path, _}:
      IO.die(Unit, 1, path ++ ": not valid JSON (bjson shows where)")
    case Nil{}:
      IO.die(Unit, 1, "not valid JSON")

# the path is not kept for the error: sharing any String here would make
# every String counted, so the error asks for the arguments again
def out(m: Maybe<&2, String>) -> IO(Unit):
  match m:
    case Some{text}:
      IO.print(text)
    case None{}:
      do IO<Unit>:
        args : List<String> <- IO.args()
        complain(args)

def run(path: String) -> IO(Unit):
  do IO<Unit>:
    text : String <- read(path)
    out(F.reformat(text))

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{path, Nil{}}:
      run(path)
    case _:
      IO.die(Unit, 2, "usage: bjson-min <file.json>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
