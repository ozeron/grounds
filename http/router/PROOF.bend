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

# what a route that does not match leaves of the Allow list
def left(al: List<&2, M.Method>, b: Maybe<&2, List<&2, Router.Param>>, s: Bool, m: M.Method) -> List<&2, M.Method>:
  match b s:
    case Some{_} True{}:
      al
    case Some{_} False{}:
      Con{m, al}
    case None{} _:
      al

law miss_step:
  for -R: Data
  for +al: List<&2, M.Method>
  for +b: Maybe<&2, List<&2, Router.Param>>
  for +s: Bool
  for +m: M.Method
  for +r: R
  for +h: {Bool.and(Laws.is_some(b), s) == False{} : Bool}
  {Router.acc.step(R, Router.ANone{al}, b, s, m, r) == Router.ANone{left(al, b, s, m)} : Router.Acc<R>}

def miss_step(R, al, b, s, m, r, h):
  match b s:
    case Some{x} True{}:
      P.absurd_t({Router.acc.step(R, Router.ANone{al}, Some{x}, True{}, m, r) == Router.ANone{left(al, Some{x}, True{}, m)} : Router.Acc<R>}, h)
    case Some{x} False{}:
      {==}
    case None{} True{}:
      {==}
    case None{} False{}:
      {==}

def Laws.first_wins(R, pre, rm, pat, r, rest, m, ps, p, al, e, em, ep):
  match pre:
    case Nil{}:
      %Equal.sym(Maybe<&2, List<&2, Router.Param>>, Router.bind(pat, ps, [], True{}), Some{p}, e) : {Router.find.go(R, rest, m, ps, Router.acc.step(R, Router.ANone{al}, _, Router.method_eq(rm, m), rm, r)) == Router.Found{r, p} : Router.Match<R>}
      %Equal.sym(Bool, Router.method_eq(rm, m), True{}, em) : {Router.find.go(R, rest, m, ps, Router.acc.step(R, Router.ANone{al}, Some{p}, _, rm, r)) == Router.Found{r, p} : Router.Match<R>}
      Laws.found_final(R, rest, m, ps, r, p)
    case Con{Router.Route{+qm, +qpat, qr}, t}:
      %Equal.sym(Router.Acc<R>, Router.acc.step(R, Router.ANone{al}, Router.bind(qpat, ps, [], True{}), Router.method_eq(qm, m), qm, qr), Router.ANone{left(al, Router.bind(qpat, ps, [], True{}), Router.method_eq(qm, m), qm)}, miss_step(R, al, Router.bind(qpat, ps, [], True{}), Router.method_eq(qm, m), qm, qr, P.not_true(Bool.and(Laws.is_some(Router.bind(qpat, ps, [], True{})), Router.method_eq(qm, m)), P.and_true_l(Bool.not(Bool.and(Laws.is_some(Router.bind(qpat, ps, [], True{})), Router.method_eq(qm, m))), Laws.misses(R, t, m, ps), ep)))) : {Router.find.go(R, List.append(&2, Router.Route<R>, t, Con{Router.Route{rm, pat, r}, rest}), m, ps, _) == Router.Found{r, p} : Router.Match<R>}
      Laws.first_wins(R, t, rm, pat, r, rest, m, ps, p, left(al, Router.bind(qpat, ps, [], True{}), Router.method_eq(qm, m), qm), e, em, P.and_true_r(Bool.not(Bool.and(Laws.is_some(Router.bind(qpat, ps, [], True{})), Router.method_eq(qm, m))), Laws.misses(R, t, m, ps), ep))

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

law capture_filled:
  for +n: String
  for +pt: List<&2, Router.Seg>
  for +t: Router.Parts
  for +acc: List<&2, Router.Param>
  for +ok: Bool
  {Router.bind(Con{Router.Cap{n}, pt}, Router.PCon{"", t}, acc, ok) == None{} : Maybe<&2, List<&2, Router.Param>>}

def capture_filled(n, pt, t, acc, ok):
  %Equal.sym(Bool, Bool.and(ok, False{}), False{}, P.and_false(ok)) : {Router.bind(pt, t, Con{Router.Param{n, Router.copy("", "")}, acc}, _) == None{} : Maybe<&2, List<&2, Router.Param>>}
  Laws.bind_false(pt, t, Con{Router.Param{n, Router.copy("", "")}, acc})

def Laws.capture_anywhere(pre, n, pt, t, acc, ok):
  match pre:
    case Nil{}:
      capture_filled(n, pt, t, acc, ok)
    case Con{Laws.Pair{Router.Lit{l}, x}, u}:
      Laws.capture_anywhere(u, n, pt, t, acc, Bool.and(ok, Router.same(l, x, True{})))
    case Con{Laws.Pair{Router.Cap{c}, +x}, u}:
      Laws.capture_anywhere(u, n, pt, t, Con{Router.Param{c, Router.copy(x, "")}, acc}, Bool.and(ok, Router.filled(x)))
