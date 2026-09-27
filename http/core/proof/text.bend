import Base

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
