import Base
import ./router.bend as Router
import ../core/method.bend as M

# Laws grounds-http-router must keep. `bend PROOF.bend` fails while any is open or false.

def is_some(m: Maybe<&2, List<&2, Router.Param>>) -> Bool:
  match m:
    case Some{_}:
      True{}
    case None{}:
      False{}

# no route in rs matches both the method and the path
def misses(-R: Data, rs: List<&2, Router.Route<R>>, +m: M.Method, +ps: Router.Parts) -> Bool:
  match rs:
    case Nil{}:
      True{}
    case Con{Router.Route{rm, pat, _}, t}:
      Bool.and(Bool.not(Bool.and(is_some(Router.bind(pat, ps, [], True{})), Router.method_eq(rm, m))), misses(R, t, m, ps))

# once a route is found, later routes change nothing
law found_final:
  for -R: Data
  for +rs: List<&2, Router.Route<R>>
  for +m: M.Method
  for +ps: Router.Parts
  for +r: R
  for +p: List<&2, Router.Param>
  {Router.find.go(R, rs, m, ps, Router.AFound{r, p}) == Router.Found{r, p} : Router.Match<R>}

# the first route whose method and path match wins, whatever routes before
# it matched the path under other methods
law first_wins:
  for -R: Data
  for +pre: List<&2, Router.Route<R>>
  for +rm: M.Method
  for +pat: List<&2, Router.Seg>
  for +r: R
  for +rest: List<&2, Router.Route<R>>
  for +m: M.Method
  for +ps: Router.Parts
  for +p: List<&2, Router.Param>
  for +al: List<&2, M.Method>
  for +e: {Router.bind(pat, ps, [], True{}) == Some{p} : Maybe<&2, List<&2, Router.Param>>}
  for +em: {Router.method_eq(rm, m) == True{} : Bool}
  for +ep: {misses(R, pre, m, ps) == True{} : Bool}
  {Router.find.go(R, List.append(&2, Router.Route<R>, pre, Con{Router.Route{rm, pat, r}, rest}), m, ps, Router.ANone{al}) == Router.Found{r, p} : Router.Match<R>}

# a failed literal is never undone by the segments after it
law bind_false:
  for +pat: List<&2, Router.Seg>
  for +ps: Router.Parts
  for +acc: List<&2, Router.Param>
  {Router.bind(pat, ps, acc, False{}) == None{} : Maybe<&2, List<&2, Router.Param>>}

# a pattern segment and the path segment it meets
type Pair is Data:
  Pair{seg: Router.Seg, part: String}

def segs(xs: List<&2, Pair>, tl: List<&2, Router.Seg>) -> List<&2, Router.Seg>:
  match xs:
    case Nil{}:
      tl
    case Con{Pair{s, _}, t}:
      Con{s, segs(t, tl)}

def parts(xs: List<&2, Pair>, tl: Router.Parts) -> Router.Parts:
  match xs:
    case Nil{}:
      tl
    case Con{Pair{_, x}, t}:
      Router.PCon{x, parts(t, tl)}

# a capture never binds an empty segment, wherever it is in the pattern:
# /todos/ is not /todos/:id
law capture_anywhere:
  for +pre: List<&2, Pair>
  for +n: String
  for +pt: List<&2, Router.Seg>
  for +t: Router.Parts
  for +acc: List<&2, Router.Param>
  for +ok: Bool
  {Router.bind(segs(pre, Con{Router.Cap{n}, pt}), parts(pre, Router.PCon{"", t}), acc, ok) == None{} : Maybe<&2, List<&2, Router.Param>>}
