import Base
import ../http_json.bend as HJ
import ../../json/json.bend as J
import ../../http_router/router.bend as Router
import ../../http_server/server.bend as Server
import ../../http/status.bend as S
import ../../http/request.bend as Req
import ../../http/response.bend as Res

# a JSON API: GET /todos, POST /todos, GET /todos/:id on port 8081.
# The handler keeps no state, so the list is fixed and POST answers with
# the todo it would create

type Todo is Data:
  Todo{id: U32, title: String, done: Bool}

def todos() -> List<&2, Todo>:
  [Todo{1, "grind beans", True{}}, Todo{2, "brew", False{}}, Todo{3, "drink", False{}}]

def Todo.to_json(t: Todo) -> J.Json:
  match t:
    case Todo{id, title, done}:
      J.JObj{[J.Field{"id", J.num_u32(id)}, J.Field{"title", J.JStr{title}}, J.Field{"done", J.JBool{done}}]}

def list.go(ts: List<&2, Todo>, acc: List<&2, J.Json>) -> List<&2, J.Json>:
  match ts:
    case Nil{}:
      List.reverse(&2, J.Json, acc)
    case Con{t, rest}:
      list.go(rest, Con{Todo.to_json(t), acc})

# a POST body: {"title": "...", "done": false}
def Todo.from_json(+j: J.Json) -> Result<&2, &2, J.Access, Todo>:
  J.both(String, Bool, Todo, J.string_at(j, [J.Name{"title"}]), J.bool_at(j, [J.Name{"done"}]), t => d => Todo{4, t, d})

type Route is Data:
  ListTodos{}
  CreateTodo{}
  GetTodo{}

def routes() -> List<&2, Router.Route<Route>>:
  [Router.get(Route, "/todos", ListTodos{}), Router.post(Route, "/todos", CreateTodo{}), Router.get(Route, "/todos/:id", GetTodo{})]

def digit(+c: U32) -> Bool:
  Bool.and(U32.is_ge(c, 48), U32.is_le(c, 57))

# an id: one to nine digits
def id.go(s: String, +acc: U32, +n: U32, ok: Bool) -> Maybe<&2, U32>:
  match s ok:
    case _ False{}:
      None{}
    case SNil{} True{}:
      Bool.pick(Maybe<&2, U32>, Bool.and(U32.is_gt(n, 0), U32.is_le(n, 9)), Some{acc}, None{})
    case SCon{Chr{+c}, t} True{}:
      id.go(t, ((acc * 10) + (c - 48) : U32), (n + 1 : U32), digit(c))

def id(m: Maybe<&2, String>) -> Maybe<&2, U32>:
  match m:
    case Some{s}:
      id.go(s, 0, 0, True{})
    case None{}:
      None{}

def find.pick(hit: Bool, t: Todo, found: Maybe<&2, Todo>) -> Maybe<&2, Todo>:
  match hit:
    case True{}:
      Some{t}
    case False{}:
      found

def find(ts: List<&2, Todo>, +i: U32, found: Maybe<&2, Todo>) -> Maybe<&2, Todo>:
  match ts:
    case Nil{}:
      found
    case Con{Todo{+tid, title, done}, rest}:
      find(rest, i, find.pick(U32.is_eq(tid, i), Todo{tid, title, done}, found))

def not_found() -> Res.Response:
  HJ.response(S.not_found(), HJ.error_body("not found"))

def one(m: Maybe<&2, Todo>) -> Res.Response:
  match m:
    case Some{t}:
      HJ.response(S.ok(), Todo.to_json(t))
    case None{}:
      not_found()

def lookup(m: Maybe<&2, U32>) -> Res.Response:
  match m:
    case Some{i}:
      one(find(todos(), i, None{}))
    case None{}:
      not_found()

def create(r: Result<&2, &2, HJ.DecodeError, Todo>) -> Res.Response:
  match r:
    case Done{t}:
      HJ.response(S.created(), Todo.to_json(t))
    case Fail{e}:
      HJ.error(e)

def answer(f: Router.Match<Route>, req: Req.Request) -> Res.Response:
  match f:
    case Router.Found{ListTodos{}, _}:
      HJ.response(S.ok(), J.JArr{list.go(todos(), [])})
    case Router.Found{CreateTodo{}, _}:
      create(HJ.decode(Todo, j => Todo.from_json(j), req))
    case Router.Found{GetTodo{}, ps}:
      lookup(id(Router.param(ps, "id")))
    case Router.NotFound{}:
      not_found()
    case Router.MethodNotAllowed{al}:
      Res.header(HJ.response(S.method_not_allowed(), HJ.error_body("method not allowed")), "allow", Router.allow(al))

def routed(r: Router.Routed<Route>) -> Res.Response:
  match r:
    case Router.Routed{f, req}:
      answer(f, req)

def handle(r: Req.Request) -> IO(Res.Response):
  IO.pure(Res.Response, routed(Router.route_req(Route, routes(), r)))

def main() -> IO(Unit):
  Server.serve(~handle, Server.default(8081))
