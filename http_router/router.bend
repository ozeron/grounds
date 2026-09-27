import Base
import ../http/method.bend as M
import ../http/request.bend as Req
import ../http/response.bend as Res
import ../http/status.bend as S
import ../http/text.bend as T

# grounds-http-router: match a request's method and path against routes,
# and answer with data: the route value you gave, and the path's captures.
# It calls no handler; your code dispatches with an exhaustive match.
#
#   def routes() -> List<&2, Router.Route<Route>>:
#     [Router.get("/todos", ListTodos{}), Router.get("/todos/:id", GetTodo{})]
#   match Router.find(routes(), req): Found{route, params} | NotFound | MethodNotAllowed

# a pattern's segment: a literal, or a :name capture
type Seg is Data:
  Lit{text: String}
  Cap{name: String}

type Route<-R: Data> is Data:
  Route{method: M.Method, path: List<&2, Seg>, route: R}

# a captured segment
type Param is Data:
  Param{name: String, value: String}

type Match<-R: Data> is Data:
  Found{route: R, params: List<&2, Param>}
  NotFound{}
  MethodNotAllowed{allowed: List<&2, M.Method>}

# A request's path, cut at /. A type of its own, not a List<String>: every
# route reads it, and a generic List read and then used again makes Lists
# reference counted in the whole program
type Parts is Data:
  PNil{}
  PCon{head: String, tail: Parts}

# the router's own compare: sharing http's with the server makes one def
# both a reader here and an owner there
def same(a: String, b: String, ok: Bool) -> Bool:
  match a b:
    case SNil{} SNil{}:
      ok
    case SCon{x, at} SCon{y, bt}:
      same(at, bt, Bool.and(ok, Char.is_eq(x, y)))
    case _ _:
      False{}

def parts.rev(p: Parts, acc: Parts) -> Parts:
  match p:
    case PNil{}:
      acc
    case PCon{h, t}:
      parts.rev(t, PCon{h, acc})

def parts.go(s: String, cur: String, acc: Parts) -> Parts:
  match s:
    case SNil{}:
      parts.rev(PCon{String.reverse(cur), acc}, PNil{})
    case SCon{Chr{47}, t}:
      parts.go(t, "", PCon{String.reverse(cur), acc})
    case SCon{c, t}:
      parts.go(t, SCon{c, cur}, acc)

# "/todos/7" is todos, 7; "/" is one empty part; a trailing / adds one
def parts(path: String) -> Parts:
  match path:
    case SCon{Chr{47}, t}:
      parts.go(t, "", PNil{})
    case other:
      parts.go(other, "", PNil{})

def segs.go(p: Parts, acc: List<&2, Seg>) -> List<&2, Seg>:
  match p:
    case PNil{}:
      List.reverse(&2, Seg, acc)
    case PCon{SCon{Chr{58}, name}, t}:
      segs.go(t, Con{Cap{name}, acc})
    case PCon{s, t}:
      segs.go(t, Con{Lit{s}, acc})

# a pattern like "/todos/:id"
def pattern(s: String) -> List<&2, Seg>:
  segs.go(parts(s), [])

def get(-R: Data, p: String, r: R) -> Route<R>:
  Route{M.MGet{}, pattern(p), r}

def post(-R: Data, p: String, r: R) -> Route<R>:
  Route{M.MPost{}, pattern(p), r}

def put(-R: Data, p: String, r: R) -> Route<R>:
  Route{M.MPut{}, pattern(p), r}

def patch(-R: Data, p: String, r: R) -> Route<R>:
  Route{M.MPatch{}, pattern(p), r}

def delete(-R: Data, p: String, r: R) -> Route<R>:
  Route{M.MDelete{}, pattern(p), r}

def route(-R: Data, m: M.Method, p: String, r: R) -> Route<R>:
  Route{m, pattern(p), r}

# a copy, built by reading only: the request's parts are read by every route
def copy(s: String, acc: String) -> String:
  match s:
    case SNil{}:
      String.reverse(acc)
    case SCon{Chr{x}, t}:
      copy(t, SCon{Chr{x}, acc})

# a capture takes a segment with something in it: /todos/ is not /todos/:id
def filled(s: String) -> Bool:
  match s:
    case SNil{}:
      False{}
    case _:
      True{}

def bind.end(ok: Bool, acc: List<&2, Param>) -> Maybe<&2, List<&2, Param>>:
  match ok:
    case True{}:
      Some{List.reverse(&2, Param, acc)}
    case False{}:
      None{}

# the captures, if the pattern matches the parts; None if it does not. ok
# says the literals so far matched: the walk goes on either way, so there
# is one loop
def bind(pat: List<&2, Seg>, ps: Parts, acc: List<&2, Param>, ok: Bool) -> Maybe<&2, List<&2, Param>>:
  match pat ps:
    case Nil{} PNil{}:
      bind.end(ok, acc)
    case Con{Lit{l}, pt} PCon{p, t}:
      bind(pt, t, acc, Bool.and(ok, same(l, p, True{})))
    case Con{Cap{n}, pt} PCon{+p, t}:
      bind(pt, t, Con{Param{n, copy(p, "")}, acc}, Bool.and(ok, filled(p)))
    case _ _:
      None{}

def method_eq(a: M.Method, b: M.Method) -> Bool:
  match a b:
    case M.MGet{} M.MGet{}:
      True{}
    case M.MHead{} M.MHead{}:
      True{}
    case M.MPost{} M.MPost{}:
      True{}
    case M.MPut{} M.MPut{}:
      True{}
    case M.MDelete{} M.MDelete{}:
      True{}
    case M.MConnect{} M.MConnect{}:
      True{}
    case M.MOptions{} M.MOptions{}:
      True{}
    case M.MTrace{} M.MTrace{}:
      True{}
    case M.MPatch{} M.MPatch{}:
      True{}
    case M.MOther{x} M.MOther{y}:
      same(x, y, True{})
    case _ _:
      False{}

# the scan so far: a route found, or the methods of routes whose path
# matched (for 405 and its Allow header)
type Acc<-R: Data> is Data:
  AFound{route: R, params: List<&2, Param>}
  ANone{allowed: List<&2, M.Method>}

def acc.step(-R: Data, st: Acc<R>, bound: Maybe<&2, List<&2, Param>>, same: Bool, m: M.Method, r: R) -> Acc<R>:
  match st bound same:
    case AFound{fr, fp} _ _:
      AFound{fr, fp}
    case ANone{_} Some{ps} True{}:
      AFound{r, ps}
    case ANone{al} Some{_} False{}:
      ANone{Con{m, al}}
    case ANone{al} None{} _:
      ANone{al}

def acc.end(-R: Data, st: Acc<R>) -> Match<R>:
  match st:
    case AFound{r, ps}:
      Found{r, ps}
    case ANone{Nil{}}:
      NotFound{}
    case ANone{al}:
      MethodNotAllowed{List.reverse(&2, M.Method, al)}

# every route is tried, in order; the first whose method and path match wins
def find.go(-R: Data, rs: List<&2, Route<R>>, +method: M.Method, +ps: Parts, st: Acc<R>) -> Match<R>:
  match rs:
    case Nil{}:
      acc.end(R, st)
    case Con{Route{+m, pat, r}, t}:
      find.go(R, t, method, ps, acc.step(R, st, bind(pat, ps, [], True{}), method_eq(m, method), m, r))

# a copy of the target's path, up to any ?, built by reading it only
def path.of(s: String, acc: String) -> String:
  match s:
    case SNil{}:
      String.reverse(acc)
    case SCon{Chr{63}, _}:
      String.reverse(acc)
    case SCon{Chr{x}, t}:
      path.of(t, SCon{Chr{x}, acc})

# the match for a method and a target (its path before any ?)
def find(-R: Data, rs: List<&2, Route<R>>, method: M.Method, target: String) -> Match<R>:
  find.go(R, rs, method, parts(path.of(target, "")), ANone{[]})

# a match, and the request it came from, untouched
type Routed<-R: Data> is Data:
  Routed{found: Match<R>, req: Req.Request}

# match a request, handing it back for the handler. It reads the target
# here rather than through find: a def whose last use of a String is a read
# takes it, so the read must be in the def that uses the String after
def route_req(-R: Data, rs: List<&2, Route<R>>, r: Req.Request) -> Routed<R>:
  match r:
    case Req.Request{+m, +t, hs, b}:
      Routed{find.go(R, rs, m, parts(path.of(t, "")), ANone{[]}), Req.Request{m, t, hs, b}}

def param.keep(hit: Bool, v: String, acc: Maybe<&2, String>) -> Maybe<&2, String>:
  match hit acc:
    case True{} None{}:
      Some{v}
    case _ a:
      a

def get.go(ps: List<&2, Param>, +name: String, acc: Maybe<&2, String>) -> Maybe<&2, String>:
  match ps:
    case Nil{}:
      acc
    case Con{Param{n, v}, t}:
      get.go(t, name, param.keep(same(n, name, True{}), v, acc))

# a capture's value
def param(ps: List<&2, Param>, +name: String) -> Maybe<&2, String>:
  get.go(ps, name, None{})

def allow.go(ms: List<&2, M.Method>, out: String) -> String:
  match ms:
    case Nil{}:
      out
    case Con{m, Nil{}}:
      out ++ M.show(m)
    case Con{m, t}:
      allow.go(t, out ++ M.show(m) ++ ", ")

# the Allow header's value for a 405 (RFC 9110 §10.2.1): "GET, POST"
def allow(ms: List<&2, M.Method>) -> String:
  allow.go(ms, "")

def param_u32.of(m: Maybe<&2, String>) -> Maybe<&2, U32>:
  match m:
    case Some{s}:
      T.u32(s)
    case None{}:
      None{}

# a capture as a number: /todos/:id with id 7 gives Some{7}
def param_u32(ps: List<&2, Param>, +name: String) -> Maybe<&2, U32>:
  param_u32.of(param(ps, name))

def dispatch.go(-R: Data, rt: Routed<R>, on: R -> List<&2, Param> -> Req.Request -> Res.Response, miss: Res.Response, bad: List<&2, M.Method> -> Res.Response) -> Res.Response:
  match rt:
    case Routed{Found{r, ps}, req}:
      on(r, ps, req)
    case Routed{NotFound{}, _}:
      miss
    case Routed{MethodNotAllowed{al}, _}:
      bad(al)

# route a request and answer it: on gets the route, its captures and the
# request; no route is 404, a route under other methods 405 with Allow
def dispatch(-R: Data, rs: List<&2, Route<R>>, r: Req.Request, on: R -> List<&2, Param> -> Req.Request -> Res.Response) -> Res.Response:
  dispatch.go(R, route_req(R, rs, r), on, Res.not_found(), al => Res.header(Res.text(S.method_not_allowed(), "Method Not Allowed"), "allow", allow(al)))
