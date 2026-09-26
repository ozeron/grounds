import Base
import ./bjson.bend as J
import ./fast.bend as F

# Y must parse, N must fail, I may do either
type Want is Data:
  Y{}
  N{}
  I{}

# Bytes is input that is not UTF-8, which must fail as such
type Case is Data:
  Case{name: String, want: Want, input: String}
  Bytes{name: String, input: List<&2, U32>}

type Tally is Data:
  Tally{pass: U32, fail: U32, i_ok: U32, i_err: U32, failed: List<&2, String>}

def parsed(r: Result<&2, &2, J.Error, J.Json>) -> Bool:
  match r:
    case Done{_}:
      True{}
    case Fail{_}:
      False{}

def score(want: Want, got: Bool, name: String, t: Tally) -> Tally:
  match want got t:
    case Y{} True{} Tally{p, f, a, b, xs}:
      Tally{(p + 1 : U32), f, a, b, xs}
    case N{} False{} Tally{p, f, a, b, xs}:
      Tally{(p + 1 : U32), f, a, b, xs}
    case I{} True{} Tally{p, f, a, b, xs}:
      Tally{p, f, (a + 1 : U32), b, xs}
    case I{} False{} Tally{p, f, a, b, xs}:
      Tally{p, f, a, (b + 1 : U32), xs}
    case _ _ Tally{p, f, a, b, xs}:
      Tally{p, (f + 1 : U32), a, b, name <> xs}

# String.eq is not a tail call; long pretty texts overflow it
def eq.go(a: String, b: String, ok: Bool) -> Bool:
  match a b:
    case SNil{} SNil{}:
      ok
    case SCon{x, at} SCon{y, bt}:
      eq.go(at, bt, Bool.and(ok, Char.is_eq(x, y)))
    case _ _:
      False{}

def eq(a: String, b: String) -> Bool:
  eq.go(a, b, True{})

# the fast path must give J.parse's answer: the same text when valid, the
# same reason and offset when not
def same.err(r: J.Reason, +at: U32, e: J.Error) -> Bool:
  match e:
    case J.Error{r2, at2, _, _}:
      Bool.and(String.eq(J.reason(r), J.reason(r2)), U32.is_eq(at, at2))

def same(a: F.Out, b: Result<&2, &2, J.Error, J.Json>) -> Bool:
  match a b:
    case F.Ok{x} Done{j}:
      eq(x, J.stringify(j))
    case F.Err{r, at} Fail{e}:
      same.err(r, at, e)
    case _ _:
      False{}

def same_pretty.go(a: F.Out, j: J.Json) -> Bool:
  match a:
    case F.Ok{x}:
      eq(x, J.pretty(j, "  "))
    case F.Err{_, _}:
      False{}

# pretty text only for valid input: indenting 100k open brackets that
# never close would print a quadratic amount before the error
def same_pretty(r: Result<&2, &2, J.Error, J.Json>, input: String) -> Bool:
  match r:
    case Done{j}:
      same_pretty.go(F.pretty(input), j)
    case Fail{_}:
      True{}

# the fast path must agree with the proven parse and stringify
def fast(ok: Bool, name: String, t: Tally) -> Tally:
  match ok t:
    case True{} _:
      t
    case False{} Tally{p, f, a, b, xs}:
      Tally{p, (f + 1 : U32), a, b, ("fast path differs: " ++ name) <> xs}

def bad_utf8(r: Result<&2, &2, J.Error, J.Json>) -> Bool:
  match r:
    case Fail{J.Error{J.InvalidUtf8{}, _, _, _}}:
      True{}
    case _:
      False{}

def bytes(ok: Bool, name: String, t: Tally) -> Tally:
  match ok t:
    case True{} Tally{p, f, a, b, xs}:
      Tally{(p + 1 : U32), f, a, b, xs}
    case False{} Tally{p, f, a, b, xs}:
      Tally{p, (f + 1 : U32), a, b, ("not rejected as invalid UTF-8: " ++ name) <> xs}

def tally(xs: List<&2, Case>, t: Tally) -> Tally:
  match xs:
    case Nil{}:
      t
    case Con{Case{+name, want, +input}, rest}:
      tally(rest, fast(Bool.and(same(F.reformat(input), J.parse(input)), same_pretty(J.parse(input), input)), name, score(want, parsed(J.parse(input)), name, t)))
    case Con{Bytes{name, input}, rest}:
      tally(rest, bytes(bad_utf8(J.parse_bytes(input)), name, t))

def failed(xs: List<&2, String>) -> IO(Unit):
  do IO<Unit>:
    IO.print_err(String.join(List.reverse(&2, String, xs), "\n"))
    IO.die(Unit, 1, "conformance failures")

def report(t: Tally) -> IO(Unit):
  match t:
    case Tally{p, +f, a, b, xs}:
      do IO<Unit>:
        IO.print("y/n cases: " ++ U32.show(p) ++ " passed, " ++ U32.show(f) ++ " failed")
        IO.print("i cases:   " ++ U32.show(a) ++ " accepted, " ++ U32.show(b) ++ " rejected")
        Bool.pick(IO(Unit), U32.is_eq(f, 0), IO.pure(Unit, Unit{}), failed(xs))

def run(xs: List<&2, Case>) -> IO(Unit):
  report(tally(xs, Tally{0, 0, 0, 0, Nil{}}))
