import Base
import ./bjson.bend as J
import ./fast.bend as F

# bjson [--compact] [--max-bytes N] <file.json>
# pretty-prints the file, or reports where it stops being JSON. With
# --max-bytes (provisional), a bigger file is refused before it is read.
#
# Everything goes through fast.bend's one-pass loop, which gives J.parse's
# exact answers (suite.bend and scripts/integration.py check this against
# spec_cli.bend, the same CLI on the proven parser). No String may be
# shared here: one shared String makes the runtime count references on
# every String in the program, and scripts/cold.py fails the build.

# Arguments
# ---------

# the flags so far, the paths (reversed), whether a --max-bytes waits for
# its number, and whether anything was wrong
type Opts is Data:
  Opts{compact: Bool, limit: Maybe<&2, U32>, want: Bool, paths: List<&2, String>, bad: Bool}

type Arg is Data:
  ACompact{}
  AMax{}
  AFlag{}
  APath{}

def arg.go(compact: Bool, max: Bool, dash: Bool) -> Arg:
  match compact max dash:
    case True{} _ _:
      ACompact{}
    case False{} True{} _:
      AMax{}
    case False{} False{} True{}:
      AFlag{}
    case False{} False{} False{}:
      APath{}

def dash(a: String) -> Bool:
  match a:
    case SCon{'-', _}:
      True{}
    case _:
      False{}

# String.eq hands its strings back, which would share a: this only reads
def same(a: String, b: String, ok: Bool) -> Bool:
  match a b:
    case SNil{} SNil{}:
      ok
    case SCon{x, at} SCon{y, bt}:
      same(at, bt, Bool.and(ok, Char.is_eq(x, y)))
    case _ _:
      False{}

def arg(+a: String) -> Arg:
  arg.go(same(a, "--compact", True{}), same(a, "--max-bytes", True{}), dash(a))

# a decimal number: 0 while nothing is read, 1 while digits, 2 once not
def dec.state(+st: U32, digit: Bool) -> U32:
  match digit:
    case True{}:
      Bool.pick(U32, U32.is_eq(st, 2), 2, 1)
    case False{}:
      2

def dec.end(+st: U32, +n: U32) -> Maybe<&2, U32>:
  Bool.pick(Maybe<&2, U32>, U32.is_eq(st, 1), Some{n}, None{})

def dec(s: String, +n: U32, +st: U32) -> Maybe<&2, U32>:
  match s:
    case SNil{}:
      dec.end(st, n)
    case SCon{Chr{+x}, t}:
      dec(t, (n * 10 + x - 48 : U32), dec.state(st, J.in_range(x, 48, 57)))

def opts.num(m: Maybe<&2, U32>, compact: Bool, paths: List<&2, String>, bad: Bool) -> Opts:
  match m:
    case Some{n}:
      Opts{compact, Some{n}, False{}, paths, bad}
    case None{}:
      Opts{compact, None{}, False{}, paths, True{}}

def opts.arg(k: Arg, compact: Bool, limit: Maybe<&2, U32>, paths: List<&2, String>, bad: Bool, a: String) -> Opts:
  match k:
    case ACompact{}:
      Opts{True{}, limit, False{}, paths, bad}
    case AMax{}:
      Opts{compact, limit, True{}, paths, bad}
    case AFlag{}:
      Opts{compact, limit, False{}, paths, True{}}
    case APath{}:
      Opts{compact, limit, False{}, Con{a, paths}, bad}

def opts.step(o: Opts, +a: String) -> Opts:
  match o:
    case Opts{compact, limit, True{}, paths, bad}:
      opts.num(dec(a, 0, 0), compact, paths, bad)
    case Opts{compact, limit, False{}, paths, bad}:
      opts.arg(arg(a), compact, limit, paths, bad, a)

def opts(args: List<String>, o: Opts) -> Opts:
  match args:
    case Nil{}:
      o
    case Con{a, t}:
      opts(t, opts.step(o, a))

def parse_args(args: List<String>) -> Opts:
  opts(args, Opts{False{}, None{}, False{}, [], False{}})

def path.go(o: Opts) -> String:
  match o:
    case Opts{_, _, _, Con{path, Nil{}}, _}:
      path
    case _:
      ""

# the path among the arguments
def path_of(args: List<String>) -> String:
  path.go(parse_args(args))

law read.text:
  for m: File & Result<&1, &1, (U32 & String), String>
  IO(String)

def read.text(m):
  (f, r) = m
  do IO<String>:
    text : String <- IO.pass(String, r)
    x : Unit <- File.close(f)
    return text

def over(limit: Maybe<&2, U32>, +n: U32) -> Bool:
  match limit:
    case None{}:
      False{}
    case Some{x}:
      U32.is_gt(n, x)

def too_big(+n: U32, limit: Maybe<&2, U32>) -> String:
  match limit:
    case Some{x}:
      ": " ++ U32.show(n) ++ " bytes, over --max-bytes " ++ U32.show(x)
    case None{}:
      ""

def read.check(big: Bool, f: File, +n: U32, limit: Maybe<&2, U32>) -> IO(String):
  match big:
    case True{}:
      do IO<String>:
        x : Unit <- File.close(f)
        args : List<String> <- IO.args()
        IO.die(String, 1, path_of(args) ++ too_big(n, limit))
    case False{}:
      do IO<String>:
        t : File & Result<&1, &1, (U32 & String), String> <- File.read(f, (n + 1 : U32))
        read.text(t)

law read.size:
  for m: File & Result<&1, &1, (U32 & String), U32>
  for +limit: Maybe<&2, U32>
  IO(String)

def read.size(m, limit):
  (f, r) = m
  do IO<String>:
    +n : U32 <- IO.pass(U32, r)
    read.check(over(limit, n), f, n, limit)

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

def read(path: String, limit: Maybe<&2, U32>) -> IO(String):
  do IO<String>:
    f : File <- IO.try(File, File.open(path, "r"))
    m : File & Result<&1, &1, (U32 & String), U32> <- File.size(f)
    read.size(m, limit)

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
    text : String <- read(path_of(args), None{})
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

def run(compact: Bool, limit: Maybe<&2, U32>, path: String) -> IO(Unit):
  do IO<Unit>:
    +text : String <- read(path, limit)
    checked(compact, replaced(text), text)

def usage() -> IO(Unit):
  IO.die(Unit, 2, "usage: bjson [--compact] [--max-bytes N] <file.json>")

def dispatch(o: Opts) -> IO(Unit):
  match o:
    case Opts{compact, limit, False{}, Con{path, Nil{}}, False{}}:
      run(compact, limit, path)
    case _:
      usage()

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(parse_args(args))
