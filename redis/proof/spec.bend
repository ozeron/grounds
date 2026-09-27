import Base
import ../resp.bend as R
import ./nat.bend as N

# what the command laws speak of

# an argument's length fits: at most ten digits, and at most max bytes
def fit(+a: R.Buf, +max: Nat) -> Bool:
  Bool.and(Nat.is_le(N.dlen(R.count(a, R.DNil{})), 10n), Nat.is_le(N.blen(a), max))

def fits(xs: R.Args, +max: Nat) -> Bool:
  match xs:
    case R.ANil{}:
      True{}
    case R.ACon{a, t}:
      Bool.and(fit(a, max), fits(t, max))

# the count fits too
def cfits(+xs: R.Args, +max: Nat) -> Bool:
  Bool.and(Bool.and(Nat.is_le(N.dlen(R.nargs(xs, R.DNil{})), 10n), Nat.is_le(N.alen(xs), max)), fits(xs, max))

# the parser's steps for the arguments: three each
def steps(xs: R.Args) -> Nat:
  match xs:
    case R.ANil{}:
      0n
    case R.ACon{_, t}:
      1n+1n+1n+steps(t)

# the arguments as the bulk strings they are sent as
def bulks(xs: R.Args) -> List<&2, R.Reply>:
  match xs:
    case R.ANil{}:
      []
    case R.ACon{a, t}:
      Con{R.Bulk{R.buf.list(a)}, bulks(t)}
