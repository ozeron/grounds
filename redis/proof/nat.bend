import Base
import ../../decimal/decimal.bend as D
import ../resp.bend as R
import ../../decimal/proof/nat.bend as M
import ../../decimal/proof/count.bend as Count

# RESP-specific Bool lemmas, parser folds and counts; arithmetic is shared

law and_l:
  for +a: Bool
  for +b: Bool
  for e: {Bool.and(a, b) == True{} : Bool}
  {a == True{} : Bool}

def and_l(a, b, e):
  match a:
    case True{}:
      {==}
    case False{}:
      M.absurd({False{} == True{} : Bool}, e)

law and_r:
  for +a: Bool
  for +b: Bool
  for e: {Bool.and(a, b) == True{} : Bool}
  {b == True{} : Bool}

def and_r(a, b, e):
  match a:
    case True{}:
      e
    case False{}:
      M.absurd({b == True{} : Bool}, e)

# the digits read most significant first, onto acc: as the parser reads them
def hor(+acc: Nat, d: D.Dec) -> Nat:
  match d:
    case D.DNil{}:
      acc
    case D.DCon{x, t}:
      Nat.add(Nat.mul(10n, hor(acc, t)), D.dig.val(x))

def dlen(d: D.Dec) -> Nat:
  match d:
    case D.DNil{}:
      0n
    case D.DCon{_, t}:
      1n+dlen(t)

def blen(bs: R.Buf) -> Nat:
  match bs:
    case R.BNil{}:
      0n
    case R.BCon{_, t}:
      1n+blen(t)

def alen(xs: R.Args) -> Nat:
  match xs:
    case R.ANil{}:
      0n
    case R.ACon{_, t}:
      1n+alen(t)

# At zero, the parser's high-to-low fold is decimal's positional value.
law hor_value:
  for +d: D.Dec
  {hor(0n, d) == D.value(d) : Nat}

def hor_value(d):
  match d:
    case D.DNil{}:
      {==}
    case D.DCon{x, t}:
      %Equal.sym(Nat, hor(0n, t), D.value(t), hor_value(t)) : {Nat.add(Nat.mul(10n, _), D.dig.val(x)) == D.value(D.DCon{x, t}) : Nat}
      M.add_comm(Nat.mul(10n, D.value(t)), D.dig.val(x))

# counting bytes onto d
law count_len:
  for +a: R.Buf
  for +d: D.Dec
  {D.value(R.count(a, d)) == Nat.add(blen(a), D.value(d)) : Nat}

def count_len(a, d):
  match a:
    case R.BNil{}:
      {==}
    case R.BCon{_, t}:
      Equal.trans(Nat, D.value(R.count(t, D.inc(d))), Nat.add(blen(t), D.value(D.inc(d))), 1n+Nat.add(blen(t), D.value(d)),
        count_len(t, D.inc(d)),
        Equal.trans(Nat, Nat.add(blen(t), D.value(D.inc(d))), Nat.add(blen(t), 1n+D.value(d)), 1n+Nat.add(blen(t), D.value(d)),
          Equal.cong(Nat, Nat, y => Nat.add(blen(t), y), D.value(D.inc(d)), 1n+D.value(d), Count.inc_value(d)),
          M.add_succ(blen(t), D.value(d))))

law arg_len:
  for +a: R.Buf
  {hor(0n, R.count(a, D.DNil{})) == blen(a) : Nat}

def arg_len(a):
  %Equal.sym(Nat, hor(0n, R.count(a, D.DNil{})), D.value(R.count(a, D.DNil{})), hor_value(R.count(a, D.DNil{}))) : {_ == blen(a) : Nat}
  Equal.trans(Nat, D.value(R.count(a, D.DNil{})), Nat.add(blen(a), 0n), blen(a), count_len(a, D.DNil{}), M.add_zero(blen(a)))

law nargs_len:
  for +xs: R.Args
  for +d: D.Dec
  {D.value(R.nargs(xs, d)) == Nat.add(alen(xs), D.value(d)) : Nat}

def nargs_len(xs, d):
  match xs:
    case R.ANil{}:
      {==}
    case R.ACon{_, t}:
      Equal.trans(Nat, D.value(R.nargs(t, D.inc(d))), Nat.add(alen(t), D.value(D.inc(d))), 1n+Nat.add(alen(t), D.value(d)),
        nargs_len(t, D.inc(d)),
        Equal.trans(Nat, Nat.add(alen(t), D.value(D.inc(d))), Nat.add(alen(t), 1n+D.value(d)), 1n+Nat.add(alen(t), D.value(d)),
          Equal.cong(Nat, Nat, y => Nat.add(alen(t), y), D.value(D.inc(d)), 1n+D.value(d), Count.inc_value(d)),
          M.add_succ(alen(t), D.value(d))))

law count_args:
  for +xs: R.Args
  {hor(0n, R.nargs(xs, D.DNil{})) == alen(xs) : Nat}

def count_args(xs):
  %Equal.sym(Nat, hor(0n, R.nargs(xs, D.DNil{})), D.value(R.nargs(xs, D.DNil{})), hor_value(R.nargs(xs, D.DNil{}))) : {_ == alen(xs) : Nat}
  Equal.trans(Nat, D.value(R.nargs(xs, D.DNil{})), Nat.add(alen(xs), 0n), alen(xs), nargs_len(xs, D.DNil{}), M.add_zero(alen(xs)))
