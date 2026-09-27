import Base
import ../router.bend as Router
import ../../core/method.bend as M
import ../../core/headers.bend as H
import ../../core/request.bend as Req

# routes as data, rebuilt for each request; three requests matched

type Route is Data:
  Home{}
  ListTodos{}
  GetTodo{}

def routes() -> List<&2, Router.Route<Route>>:
  [Router.get(Route, "/", Home{}), Router.get(Route, "/todos", ListTodos{}), Router.post(Route, "/todos", ListTodos{}), Router.get(Route, "/todos/:id", GetTodo{})]

def name(r: Route) -> String:
  match r:
    case Home{}:
      "home"
    case ListTodos{}:
      "todos"
    case GetTodo{}:
      "todo"

def id(m: Maybe<&2, String>) -> String:
  match m:
    case Some{v}:
      v
    case None{}:
      "-"

def show(m: Router.Match<Route>) -> String:
  match m:
    case Router.Found{r, ps}:
      name(r) ++ " " ++ id(Router.param(ps, "id"))
    case Router.NotFound{}:
      "404"
    case Router.MethodNotAllowed{al}:
      "405 " ++ Router.allow(al)

def req(m: M.Method, t: String) -> Req.Request:
  Req.Request{m, t, [H.Header{"Host", "x"}], []}

def found(r: Router.Routed<Route>) -> String:
  match r:
    case Router.Routed{f, _}:
      show(f)

def main() -> IO(Unit):
  do IO<Unit>:
    IO.print(found(Router.route_req(Route, routes(), req(M.MGet{}, "/todos/7?x=1"))))
    IO.print(found(Router.route_req(Route, routes(), req(M.MDelete{}, "/todos"))))
    IO.print(found(Router.route_req(Route, routes(), req(M.MGet{}, "/nope"))))
