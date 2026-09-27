import Base
import ./router.bend as Router
import ../core/method.bend as M

# Laws grounds-http-router must keep. `bend PROOF.bend` fails while any is open or false.

# once a route is found, later routes change nothing
law found_final:
  for -R: Data
  for +rs: List<&2, Router.Route<R>>
  for +m: M.Method
  for +ps: Router.Parts
  for +r: R
  for +p: List<&2, Router.Param>
  {Router.find.go(R, rs, m, ps, Router.AFound{r, p}) == Router.Found{r, p} : Router.Match<R>}

# the first route whose method and path match wins
law first_wins:
  for -R: Data
  for +m: M.Method
  for +pat: List<&2, Router.Seg>
  for +r: R
  for +rest: List<&2, Router.Route<R>>
  for +ps: Router.Parts
  for +p: List<&2, Router.Param>
  for e: {Router.bind(pat, ps, [], True{}) == Some{p} : Maybe<&2, List<&2, Router.Param>>}
  {Router.find.go(R, Con{Router.Route{m, pat, r}, rest}, m, ps, Router.ANone{[]}) == Router.Found{r, p} : Router.Match<R>}

# a failed literal is never undone by the segments after it
law bind_false:
  for +pat: List<&2, Router.Seg>
  for +ps: Router.Parts
  for +acc: List<&2, Router.Param>
  {Router.bind(pat, ps, acc, False{}) == None{} : Maybe<&2, List<&2, Router.Param>>}

# a capture never binds an empty segment: /todos/ is not /todos/:id
law capture_filled:
  for +n: String
  for +pt: List<&2, Router.Seg>
  for +t: Router.Parts
  for +acc: List<&2, Router.Param>
  for +ok: Bool
  {Router.bind(Con{Router.Cap{n}, pt}, Router.PCon{"", t}, acc, ok) == None{} : Maybe<&2, List<&2, Router.Param>>}

# no match and no method is 404; a path matched under other methods is
# 405, and its Allow names at least one
law none_is_404:
  for -R: Data
  {Router.acc.end(R, Router.ANone{[]}) == Router.NotFound{} : Router.Match<R>}

law allowed_is_405:
  for -R: Data
  for +x: M.Method
  for +al: List<&2, M.Method>
  {Router.acc.end(R, Router.ANone{Con{x, al}}) == Router.MethodNotAllowed{List.reverse(&2, M.Method, Con{x, al})} : Router.Match<R>}
