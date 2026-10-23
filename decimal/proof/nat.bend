import Base

# Nat and Bool lemmas: sums, products, doubling and order

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

# Sums and products
# -----------------

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

law add_zero:
  for +a: Nat
  {Nat.add(a, 0n) == a : Nat}

def add_zero(a):
  match a:
    case 0n:
      {==}
    case 1n+p:
      Equal.cong(Nat, Nat, x => 1n+x, Nat.add(p, 0n), p, add_zero(p))

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

# Doubling
# --------

law double_add:
  for +a: Nat
  for +b: Nat
  {Nat.double(Nat.add(a, b)) == Nat.add(Nat.double(a), Nat.double(b)) : Nat}

def double_add(a, b):
  match a:
    case 0n:
      {==}
    case 1n+p:
      Equal.cong(Nat, Nat, x => 2n+x, Nat.double(Nat.add(p, b)), Nat.add(Nat.double(p), Nat.double(b)), double_add(p, b))

# n * 2v == 2 (n * v)
law mul_double:
  for +n: Nat
  for +v: Nat
  {Nat.mul(n, Nat.double(v)) == Nat.double(Nat.mul(n, v)) : Nat}

def mul_double(n, v):
  match n:
    case 0n:
      {==}
    case 1n+p:
      %Equal.sym(Nat, Nat.mul(p, Nat.double(v)), Nat.double(Nat.mul(p, v)), mul_double(p, v)) : {Nat.add(Nat.double(v), _) == Nat.double(Nat.add(v, Nat.mul(p, v))) : Nat}
      Equal.sym(Nat, Nat.double(Nat.add(v, Nat.mul(p, v))), Nat.add(Nat.double(v), Nat.double(Nat.mul(p, v))), double_add(v, Nat.mul(p, v)))

# Order
# -----

law le_zero:
  for +b: Nat
  {Nat.is_le(0n, b) == True{} : Bool}

def le_zero(b):
  match b:
    case 0n:
      {==}
    case 1n+p:
      {==}

law le_add:
  for +a: Nat
  for +r: Nat
  {Nat.is_le(a, Nat.add(a, r)) == True{} : Bool}

def le_add(a, r):
  match a:
    case 0n:
      le_zero(r)
    case 1n+p:
      le_add(p, r)

law le_trans:
  for +a: Nat
  for +b: Nat
  for +c: Nat
  for e1: {Nat.is_le(a, b) == True{} : Bool}
  for e2: {Nat.is_le(b, c) == True{} : Bool}
  {Nat.is_le(a, c) == True{} : Bool}

def le_trans(a, b, c, e1, e2):
  match a:
    case 0n:
      le_zero(c)
    case 1n+ap:
      match b:
        case 0n:
          absurd({Nat.is_le(1n+ap, c) == True{} : Bool}, e1)
        case 1n+bp:
          match c:
            case 0n:
              absurd({Nat.is_le(1n+ap, 0n) == True{} : Bool}, e2)
            case 1n+cp:
              le_trans(ap, bp, cp, e1, e2)

law cmp_refl:
  for +a: Nat
  {Nat.cmp(a, a) == EQ{} : Cmp}

def cmp_refl(a):
  match a:
    case 0n:
      {==}
    case 1n+p:
      cmp_refl(p)

law le_refl:
  for +a: Nat
  {Nat.is_le(a, a) == True{} : Bool}

def le_refl(a):
  %Equal.sym(Cmp, Nat.cmp(a, a), EQ{}, cmp_refl(a)) : {Cmp.is_le(_) == True{} : Bool}
  {==}

law le_subst:
  for +a: Nat
  for +b: Nat
  for +c: Nat
  for s: {a == b : Nat}
  for e: {Nat.is_le(b, c) == True{} : Bool}
  {Nat.is_le(a, c) == True{} : Bool}

def le_subst(a, b, c, s, e):
  %Equal.sym(Nat, a, b, s) : {Nat.is_le(_, c) == True{} : Bool}
  e

law cmp_double:
  for +a: Nat
  for +b: Nat
  {Nat.cmp(Nat.double(a), Nat.double(b)) == Nat.cmp(a, b) : Cmp}

def cmp_double(a, b):
  match a b:
    case 0n 0n:
      {==}
    case 0n 1n+bp:
      {==}
    case 1n+ap 0n:
      {==}
    case 1n+ap 1n+bp:
      cmp_double(ap, bp)

# 2a <= 2b + 1 exactly when a <= b
law le_double_odd:
  for +a: Nat
  for +b: Nat
  {Nat.is_le(Nat.double(a), 1n+Nat.double(b)) == Nat.is_le(a, b) : Bool}

def le_double_odd(a, b):
  match a b:
    case 0n _:
      Equal.sym(Bool, Nat.is_le(0n, b), True{}, le_zero(b))
    case 1n+ap 0n:
      {==}
    case 1n+ap 1n+bp:
      le_double_odd(ap, bp)

law le_double:
  for +a: Nat
  for +b: Nat
  {Nat.is_le(Nat.double(a), Nat.double(b)) == Nat.is_le(a, b) : Bool}

def le_double(a, b):
  %Equal.sym(Cmp, Nat.cmp(Nat.double(a), Nat.double(b)), Nat.cmp(a, b), cmp_double(a, b)) : {Cmp.is_le(_) == Nat.is_le(a, b) : Bool}
  {==}

# 2a + 1 <= 2b only when a <= b
law le_odd_double:
  for +a: Nat
  for +b: Nat
  for e: {Nat.is_le(1n+Nat.double(a), Nat.double(b)) == True{} : Bool}
  {Nat.is_le(a, b) == True{} : Bool}

def le_odd_double(a, b, e):
  match a b:
    case 0n _:
      le_zero(b)
    case 1n+ap 0n:
      absurd({Nat.is_le(1n+ap, 0n) == True{} : Bool}, e)
    case 1n+ap 1n+bp:
      le_odd_double(ap, bp, e)
