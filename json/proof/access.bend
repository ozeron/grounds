import Base
import ../json.bend as J
import ../LAWS.bend as L

# Reads: a key compared with itself matches, so get finds it; and each
# read's failures other than mistyped (a missing item, a number out of
# range) are never mistyped.

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

law char_refl:
  for +c: Char
  {Char.is_eq(c, c) == True{} : Bool}

def char_refl(c):
  match c:
    case Chr{x}:
      match x:
        case U32{w}:
          %Equal.sym(Cmp, Word.cmp(32n, w, w), EQ{}, word_refl(32n, w)) : {Cmp.is_eq(_) == True{} : Bool}
          {==}

law and_true:
  for +b: Bool
  {Bool.and(b, True{}) == b : Bool}

def and_true(b):
  match b:
    case True{}:
      {==}
    case False{}:
      {==}

law same_refl:
  for +k: String
  for +ok: Bool
  {J.same(k, k, ok) == ok : Bool}

def same_refl(k, ok):
  match k:
    case SNil{}:
      {==}
    case SCon{c, t}:
      %Equal.sym(Bool, Char.is_eq(c, c), True{}, char_refl(c)) : {J.same(t, t, Bool.and(ok, _)) == ok : Bool}
      %Equal.sym(Bool, Bool.and(ok, True{}), ok, and_true(ok)) : {J.same(t, t, _) == ok : Bool}
      same_refl(t, ok)

law go_last:
  for +fs: List<&2, J.Field>
  for +k: String
  for +v: J.Json
  for +found: Maybe<&2, J.Json>
  {J.get.go(List.append(&2, J.Field, fs, [J.Field{k, v}]), k, found) == Some{v} : Maybe<&2, J.Json>}

def go_last(fs, k, v, found):
  match fs:
    case Nil{}:
      %Equal.sym(Bool, J.same(k, k, True{}), True{}, same_refl(k, True{})) : {J.get.keep(_, v, found) == Some{v} : Maybe<&2, J.Json>}
      {==}
    case Con{J.Field{fk, fv}, t}:
      go_last(t, k, v, J.get.keep(J.same(fk, k, True{}), fv, found))

law get_last:
  for +k: String
  for +v: J.Json
  for +fs: List<&2, J.Field>
  {J.get(J.JObj{List.append(&2, J.Field, fs, [J.Field{k, v}])}, k) == Done{v} : Result<&2, &2, J.Access, J.Json>}

def get_last(k, v, fs):
  %Equal.sym(Maybe<&2, J.Json>, J.get.go(List.append(&2, J.Field, fs, [J.Field{k, v}]), k, None{}), Some{v}, go_last(fs, k, v, None{})) : {J.get.fin(_, k) == Done{v} : Result<&2, &2, J.Access, J.Json>}
  {==}

law u32_range:
  for +m: Maybe<&2, U32>
  {L.mistyped(U32, J.in_range.go(m)) == False{} : Bool}

def u32_range(m):
  match m:
    case Some{_}:
      {==}
    case None{}:
      {==}

law f32_range:
  for +m: Maybe<&2, F32>
  {L.mistyped(F32, J.f32.go(m)) == False{} : Bool}

def f32_range(m):
  match m:
    case Some{_}:
      {==}
    case None{}:
      {==}

law index_found:
  for +xs: List<&2, J.Json>
  for +n: Nat
  for +i: U32
  {L.mistyped(J.Json, J.index.go(xs, n, i)) == False{} : Bool}

def index_found(xs, n, i):
  match xs n:
    case Con{_, _} 0n:
      {==}
    case Con{_, t} 1n+p:
      index_found(t, p, i)
    case Nil{} _:
      {==}

law get_found:
  for +m: Maybe<&2, J.Json>
  for +k: String
  {L.mistyped(J.Json, J.get.fin(m, k)) == False{} : Bool}

def get_found(m, k):
  match m:
    case Some{_}:
      {==}
    case None{}:
      {==}
