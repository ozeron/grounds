import Base
import ../resp.bend as R

# Nat and Bool lemmas, and what a Dec counts

law absurd:
  for -A: Type
  for e: {False{} == True{} : Bool}
  A

def Pick(b: Bool, X: Type, Y: Type) -> Type:
  match b:
    case True{}:
      X
    case False{}:
      Y

def absurd(A, e):
  %e : Pick(_, A, Unit)
  Unit{}

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
      absurd({False{} == True{} : Bool}, e)

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
      absurd({b == True{} : Bool}, e)

law add_zero:
  for +a: Nat
  {Nat.add(a, 0n) == a : Nat}

def add_zero(a):
  match a:
    case 0n:
      {==}
    case 1n+p:
      Equal.cong(Nat, Nat, x => 1n+x, Nat.add(p, 0n), p, add_zero(p))

law add_succ:
  for +a: Nat
  for +b: Nat
  {Nat.add(a, 1n+b) == 1n+Nat.add(a, b) : Nat}

def add_succ(a, b):
  match a:
    case 0n:
      {==}
    case 1n+p:
      Equal.cong(Nat, Nat, x => 1n+x, Nat.add(p, 1n+b), 1n+Nat.add(p, b), add_succ(p, b))

law add_comm:
  for +a: Nat
  for +b: Nat
  {Nat.add(a, b) == Nat.add(b, a) : Nat}

def add_comm(a, b):
  match a:
    case 0n:
      Equal.sym(Nat, Nat.add(b, 0n), b, add_zero(b))
    case 1n+p:
      Equal.trans(Nat, 1n+Nat.add(p, b), 1n+Nat.add(b, p), Nat.add(b, 1n+p),
        Equal.cong(Nat, Nat, x => 1n+x, Nat.add(p, b), Nat.add(b, p), add_comm(p, b)),
        Equal.sym(Nat, Nat.add(b, 1n+p), 1n+Nat.add(b, p), add_succ(b, p)))

law add_assoc:
  for +a: Nat
  for +b: Nat
  for +c: Nat
  {Nat.add(Nat.add(a, b), c) == Nat.add(a, Nat.add(b, c)) : Nat}

def add_assoc(a, b, c):
  match a:
    case 0n:
      {==}
    case 1n+p:
      Equal.cong(Nat, Nat, x => 1n+x, Nat.add(Nat.add(p, b), c), Nat.add(p, Nat.add(b, c)), add_assoc(p, b, c))

# b + (p + x) == p + (b + x)
law add_swap:
  for +b: Nat
  for +p: Nat
  for +x: Nat
  {Nat.add(b, Nat.add(p, x)) == Nat.add(p, Nat.add(b, x)) : Nat}

def add_swap(b, p, x):
  Equal.trans(Nat, Nat.add(b, Nat.add(p, x)), Nat.add(Nat.add(b, p), x), Nat.add(p, Nat.add(b, x)),
    Equal.sym(Nat, Nat.add(Nat.add(b, p), x), Nat.add(b, Nat.add(p, x)), add_assoc(b, p, x)),
    Equal.trans(Nat, Nat.add(Nat.add(b, p), x), Nat.add(Nat.add(p, b), x), Nat.add(p, Nat.add(b, x)),
      Equal.cong(Nat, Nat, y => Nat.add(y, x), Nat.add(b, p), Nat.add(p, b), add_comm(b, p)),
      add_assoc(p, b, x)))

# n * (1 + h) == n + n * h
law mul_succ:
  for +n: Nat
  for +h: Nat
  {Nat.mul(n, 1n+h) == Nat.add(n, Nat.mul(n, h)) : Nat}

def mul_succ(n, h):
  match n:
    case 0n:
      {==}
    case 1n+p:
      Equal.cong(Nat, Nat, x => 1n+x, Nat.add(h, Nat.mul(p, 1n+h)), Nat.add(p, Nat.add(h, Nat.mul(p, h))),
        Equal.trans(Nat, Nat.add(h, Nat.mul(p, 1n+h)), Nat.add(h, Nat.add(p, Nat.mul(p, h))), Nat.add(p, Nat.add(h, Nat.mul(p, h))),
          Equal.cong(Nat, Nat, y => Nat.add(h, y), Nat.mul(p, 1n+h), Nat.add(p, Nat.mul(p, h)), mul_succ(p, h)),
          add_swap(h, p, Nat.mul(p, h))))

# What a Dec counts
# -----------------

def dv(x: R.Dig) -> Nat:
  match x:
    case R.D0{}:
      0n
    case R.D1{}:
      1n
    case R.D2{}:
      2n
    case R.D3{}:
      3n
    case R.D4{}:
      4n
    case R.D5{}:
      5n
    case R.D6{}:
      6n
    case R.D7{}:
      7n
    case R.D8{}:
      8n
    case R.D9{}:
      9n

# the digits read most significant first, onto acc: as the parser reads them
def hor(+acc: Nat, d: R.Dec) -> Nat:
  match d:
    case R.DNil{}:
      acc
    case R.DCon{x, t}:
      Nat.add(Nat.mul(10n, hor(acc, t)), dv(x))

def dlen(d: R.Dec) -> Nat:
  match d:
    case R.DNil{}:
      0n
    case R.DCon{_, t}:
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

law carry:
  for +h: Nat
  {Nat.add(Nat.mul(10n, 1n+h), 0n) == 1n+Nat.add(Nat.mul(10n, h), 9n) : Nat}

def carry(h):
  Equal.trans(Nat, Nat.add(Nat.mul(10n, 1n+h), 0n), Nat.mul(10n, 1n+h), 1n+Nat.add(Nat.mul(10n, h), 9n),
    add_zero(Nat.mul(10n, 1n+h)),
    Equal.trans(Nat, Nat.mul(10n, 1n+h), Nat.add(10n, Nat.mul(10n, h)), 1n+Nat.add(Nat.mul(10n, h), 9n),
      mul_succ(10n, h),
      Equal.cong(Nat, Nat, y => 1n+y, Nat.add(9n, Nat.mul(10n, h)), Nat.add(Nat.mul(10n, h), 9n), add_comm(9n, Nat.mul(10n, h)))))

# a Dec counts up by one
law inc_val:
  for +d: R.Dec
  {hor(0n, R.inc(d)) == 1n+hor(0n, d) : Nat}

def inc_val(d):
  match d:
    case R.DNil{}:
      {==}
    case R.DCon{R.D0{}, t}:
      add_succ(Nat.mul(10n, hor(0n, t)), 0n)
    case R.DCon{R.D1{}, t}:
      add_succ(Nat.mul(10n, hor(0n, t)), 1n)
    case R.DCon{R.D2{}, t}:
      add_succ(Nat.mul(10n, hor(0n, t)), 2n)
    case R.DCon{R.D3{}, t}:
      add_succ(Nat.mul(10n, hor(0n, t)), 3n)
    case R.DCon{R.D4{}, t}:
      add_succ(Nat.mul(10n, hor(0n, t)), 4n)
    case R.DCon{R.D5{}, t}:
      add_succ(Nat.mul(10n, hor(0n, t)), 5n)
    case R.DCon{R.D6{}, t}:
      add_succ(Nat.mul(10n, hor(0n, t)), 6n)
    case R.DCon{R.D7{}, t}:
      add_succ(Nat.mul(10n, hor(0n, t)), 7n)
    case R.DCon{R.D8{}, t}:
      add_succ(Nat.mul(10n, hor(0n, t)), 8n)
    case R.DCon{R.D9{}, t}:
      %Equal.sym(Nat, hor(0n, R.inc(t)), 1n+hor(0n, t), inc_val(t)) : {Nat.add(Nat.mul(10n, _), 0n) == 1n+Nat.add(Nat.mul(10n, hor(0n, t)), 9n) : Nat}
      carry(hor(0n, t))

# counting bytes onto d
law count_len:
  for +a: R.Buf
  for +d: R.Dec
  {hor(0n, R.count(a, d)) == Nat.add(blen(a), hor(0n, d)) : Nat}

def count_len(a, d):
  match a:
    case R.BNil{}:
      {==}
    case R.BCon{_, t}:
      Equal.trans(Nat, hor(0n, R.count(t, R.inc(d))), Nat.add(blen(t), hor(0n, R.inc(d))), 1n+Nat.add(blen(t), hor(0n, d)),
        count_len(t, R.inc(d)),
        Equal.trans(Nat, Nat.add(blen(t), hor(0n, R.inc(d))), Nat.add(blen(t), 1n+hor(0n, d)), 1n+Nat.add(blen(t), hor(0n, d)),
          Equal.cong(Nat, Nat, y => Nat.add(blen(t), y), hor(0n, R.inc(d)), 1n+hor(0n, d), inc_val(d)),
          add_succ(blen(t), hor(0n, d))))

law arg_len:
  for +a: R.Buf
  {hor(0n, R.count(a, R.DNil{})) == blen(a) : Nat}

def arg_len(a):
  Equal.trans(Nat, hor(0n, R.count(a, R.DNil{})), Nat.add(blen(a), 0n), blen(a), count_len(a, R.DNil{}), add_zero(blen(a)))

law nargs_len:
  for +xs: R.Args
  for +d: R.Dec
  {hor(0n, R.nargs(xs, d)) == Nat.add(alen(xs), hor(0n, d)) : Nat}

def nargs_len(xs, d):
  match xs:
    case R.ANil{}:
      {==}
    case R.ACon{_, t}:
      Equal.trans(Nat, hor(0n, R.nargs(t, R.inc(d))), Nat.add(alen(t), hor(0n, R.inc(d))), 1n+Nat.add(alen(t), hor(0n, d)),
        nargs_len(t, R.inc(d)),
        Equal.trans(Nat, Nat.add(alen(t), hor(0n, R.inc(d))), Nat.add(alen(t), 1n+hor(0n, d)), 1n+Nat.add(alen(t), hor(0n, d)),
          Equal.cong(Nat, Nat, y => Nat.add(alen(t), y), hor(0n, R.inc(d)), 1n+hor(0n, d), inc_val(d)),
          add_succ(alen(t), hor(0n, d))))

law count_args:
  for +xs: R.Args
  {hor(0n, R.nargs(xs, R.DNil{})) == alen(xs) : Nat}

def count_args(xs):
  Equal.trans(Nat, hor(0n, R.nargs(xs, R.DNil{})), Nat.add(alen(xs), 0n), alen(xs), nargs_len(xs, R.DNil{}), add_zero(alen(xs)))
