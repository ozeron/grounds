import Base
import ../text.bend as T
import ../headers.bend as H

# lemmas the http proofs share: Bool algebra, and reflexivity of the
# compares on Words, U32s and Chars

def Pick(b: Bool, X: Type, Y: Type) -> Type:
  match b:
    case True{}:
      X
    case False{}:
      Y

law absurd:
  for -A: Type
  for e: {False{} == True{} : Bool}
  A

def absurd(A, e):
  %e : Pick(_, A, Unit)
  Unit{}

law and_true:
  for +b: Bool
  {Bool.and(b, True{}) == b : Bool}

def and_true(b):
  match b:
    case True{}:
      {==}
    case False{}:
      {==}

law and_false:
  for +b: Bool
  {Bool.and(b, False{}) == False{} : Bool}

def and_false(b):
  match b:
    case True{}:
      {==}
    case False{}:
      {==}

law or_true:
  for +b: Bool
  {Bool.or(b, True{}) == True{} : Bool}

def or_true(b):
  match b:
    case True{}:
      {==}
    case False{}:
      {==}

law word_refl:
  for +n: Nat
  for +w: Word(n)
  {Word.cmp(n, w, w) == EQ{} : Cmp}

def word_refl(n, w):
  match n:
    case 0n:
      {==}
    case 1n+p:
      match w:
        case WCon{True{}, t}:
          %Equal.sym(Cmp, Word.cmp(p, t, t), EQ{}, word_refl(p, t)) : {Word.cmp.fin(True{}, True{}, _) == EQ{} : Cmp}
          {==}
        case WCon{False{}, t}:
          %Equal.sym(Cmp, Word.cmp(p, t, t), EQ{}, word_refl(p, t)) : {Word.cmp.fin(False{}, False{}, _) == EQ{} : Cmp}
          {==}

law u32_refl:
  for +x: U32
  {U32.is_eq(x, x) == True{} : Bool}

def u32_refl(x):
  match x:
    case U32{w}:
      %Equal.sym(Cmp, Word.cmp(32n, w, w), EQ{}, word_refl(32n, w)) : {Cmp.is_eq(_) == True{} : Bool}
      {==}

law char_refl:
  for +c: Char
  {Char.is_eq(c, c) == True{} : Bool}

def char_refl(c):
  match c:
    case Chr{x}:
      u32_refl(x)

# a String lowercased (ASCII), the spec the case-insensitive compares meet
def lows(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{Chr{x}, t}:
      SCon{Chr{T.lower(x)}, lows(t)}

law same_ci_lows:
  for +a: String
  for +b: String
  for +ok: Bool
  {T.same_ci(a, b, ok) == T.same(lows(a), lows(b), ok) : Bool}

def same_ci_lows(a, b, ok):
  match a b:
    case SNil{} SNil{}:
      {==}
    case SNil{} SCon{Chr{_}, _}:
      {==}
    case SCon{Chr{_}, _} SNil{}:
      {==}
    case SCon{Chr{+x}, at} SCon{Chr{+y}, bt}:
      same_ci_lows(at, bt, Bool.and(ok, T.fold.eq(x, y)))

law name_eq_lows:
  for +a: String
  for +b: String
  for +ok: Bool
  {H.name_eq(a, b, ok) == T.same(lows(a), lows(b), ok) : Bool}

def name_eq_lows(a, b, ok):
  match a b:
    case SNil{} SNil{}:
      {==}
    case SNil{} SCon{Chr{_}, _}:
      {==}
    case SCon{Chr{_}, _} SNil{}:
      {==}
    case SCon{Chr{+x}, at} SCon{Chr{+y}, bt}:
      name_eq_lows(at, bt, Bool.and(ok, T.fold.eq(x, y)))

law absurd_t:
  for -A: Type
  for e: {True{} == False{} : Bool}
  A

def absurd_t(A, e):
  absurd(A, Equal.sym(Bool, True{}, False{}, e))

law or_false_l:
  for +a: Bool
  for +b: Bool
  for e: {Bool.or(a, b) == False{} : Bool}
  {a == False{} : Bool}

def or_false_l(a, b, e):
  match a:
    case True{}:
      absurd_t({True{} == False{} : Bool}, e)
    case False{}:
      {==}

law or_false_r:
  for +a: Bool
  for +b: Bool
  for e: {Bool.or(a, b) == False{} : Bool}
  {b == False{} : Bool}

def or_false_r(a, b, e):
  match a:
    case True{}:
      absurd_t({b == False{} : Bool}, e)
    case False{}:
      e

law nat_refl:
  for +a: Nat
  {Nat.is_eq(a, a) == True{} : Bool}

def nat_refl(a):
  match a:
    case 0n:
      {==}
    case 1n+p:
      nat_refl(p)

law nat_trans:
  for +c: Nat
  for +a: Nat
  for +b: Nat
  for e1: {Nat.is_eq(c, a) == True{} : Bool}
  for e2: {Nat.is_eq(c, b) == True{} : Bool}
  {Nat.is_eq(a, b) == True{} : Bool}

def nat_trans(c, a, b, e1, e2):
  match c a b:
    case 0n 0n 0n:
      {==}
    case 0n 0n 1n+q:
      absurd({Nat.is_eq(0n, 1n+q) == True{} : Bool}, e2)
    case 0n 1n+p _:
      absurd({Nat.is_eq(1n+p, b) == True{} : Bool}, e1)
    case 1n+r 0n _:
      absurd({Nat.is_eq(0n, b) == True{} : Bool}, e1)
    case 1n+r 1n+p 0n:
      absurd({Nat.is_eq(1n+p, 0n) == True{} : Bool}, e2)
    case 1n+r 1n+p 1n+q:
      nat_trans(r, p, q, e1, e2)
