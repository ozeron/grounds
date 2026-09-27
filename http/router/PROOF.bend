import Base
import ./LAWS.bend as Laws
import ./router.bend as Router
import ../core/method.bend as M
import ../core/proof/text.bend as P

def Laws.found_final(R, rs, m, ps, r, p):
  match rs:
    case Nil{}:
      {==}
    case Con{Router.Route{+rm, pat, rr}, t}:
      Laws.found_final(R, t, m, ps, r, p)

law same_refl:
  for +s: String
  for +ok: Bool
  {Router.same(s, s, ok) == ok : Bool}

def same_refl(s, ok):
  match s:
    case SNil{}:
      {==}
    case SCon{c, t}:
      %Equal.sym(Bool, Char.is_eq(c, c), True{}, P.char_refl(c)) : {Router.same(t, t, Bool.and(ok, _)) == ok : Bool}
      %Equal.sym(Bool, Bool.and(ok, True{}), ok, P.and_true(ok)) : {Router.same(t, t, _) == ok : Bool}
      same_refl(t, ok)

law method_refl:
  for +m: M.Method
  {Router.method_eq(m, m) == True{} : Bool}

def method_refl(m):
  match m:
    case M.MGet{}:
      {==}
    case M.MHead{}:
      {==}
    case M.MPost{}:
      {==}
    case M.MPut{}:
      {==}
    case M.MDelete{}:
      {==}
    case M.MConnect{}:
      {==}
    case M.MOptions{}:
      {==}
    case M.MTrace{}:
      {==}
    case M.MPatch{}:
      {==}
    case M.MOther{x}:
      same_refl(x, True{})

def Laws.first_wins(R, m, pat, r, rest, ps, p, e):
  %Equal.sym(Maybe<&2, List<&2, Router.Param>>, Router.bind(pat, ps, [], True{}), Some{p}, e) : {Router.find.go(R, rest, m, ps, Router.acc.step(R, Router.ANone{[]}, _, Router.method_eq(m, m), m, r)) == Router.Found{r, p} : Router.Match<R>}
  %Equal.sym(Bool, Router.method_eq(m, m), True{}, method_refl(m)) : {Router.find.go(R, rest, m, ps, Router.acc.step(R, Router.ANone{[]}, Some{p}, _, m, r)) == Router.Found{r, p} : Router.Match<R>}
  Laws.found_final(R, rest, m, ps, r, p)

def Laws.bind_false(pat, ps, acc):
  match pat ps:
    case Nil{} Router.PNil{}:
      {==}
    case Nil{} Router.PCon{_, _}:
      {==}
    case Con{Router.Lit{_}, _} Router.PNil{}:
      {==}
    case Con{Router.Cap{_}, _} Router.PNil{}:
      {==}
    case Con{Router.Lit{l}, pt} Router.PCon{x, t}:
      Laws.bind_false(pt, t, acc)
    case Con{Router.Cap{n}, pt} Router.PCon{+x, t}:
      Laws.bind_false(pt, t, Con{Router.Param{n, Router.copy(x, "")}, acc})

def Laws.capture_filled(n, pt, t, acc, ok):
  %Equal.sym(Bool, Bool.and(ok, False{}), False{}, P.and_false(ok)) : {Router.bind(pt, t, Con{Router.Param{n, Router.copy("", "")}, acc}, _) == None{} : Maybe<&2, List<&2, Router.Param>>}
  Laws.bind_false(pt, t, Con{Router.Param{n, Router.copy("", "")}, acc})

def Laws.none_is_404(R):
  {==}

def Laws.allowed_is_405(R, x, al):
  {==}
