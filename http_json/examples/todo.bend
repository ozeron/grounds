import Base
import ../http_json.bend as HJ
import ../../json/json.bend as J
import ../../http_router/router.bend as Router
import ../../http_server/server.bend as Server
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

# a POST body: {"title": "...", "done": false}
def Todo.from_json(+j: J.Json) -> Result<&2, &2, J.Access, Todo>:
  J.both(String, Bool, Todo, J.string_at(j, [J.Name{"title"}]), J.bool_at(j, [J.Name{"done"}]), t => d => Todo{4, t, d})

def all(ts: List<&2, Todo>, acc: List<&2, J.Json>) -> J.Json:
  match ts:
    case Nil{}:
      J.JArr{List.reverse(&2, J.Json, acc)}
    case Con{t, rest}:
      all(rest, Con{Todo.to_json(t), acc})

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

def by_id(m: Maybe<&2, U32>) -> Maybe<&2, Todo>:
  match m:
    case Some{i}:
      find(todos(), i, None{})
    case None{}:
      None{}

type Route is Data:
  ListTodos{}
  CreateTodo{}
  GetTodo{}

def routes() -> List<&2, Router.Route<Route>>:
  [Router.get(Route, "/todos", ListTodos{}), Router.post(Route, "/todos", CreateTodo{}), Router.get(Route, "/todos/:id", GetTodo{})]

def on(r: Route, ps: List<&2, Router.Param>, req: Req.Request) -> Res.Response:
  match r:
    case ListTodos{}:
      HJ.ok(all(todos(), []))
    case CreateTodo{}:
      HJ.decoded(Todo, j => Todo.from_json(j), req, t => HJ.created(Todo.to_json(t)))
    case GetTodo{}:
      HJ.maybe(Todo, t => Todo.to_json(t), by_id(Router.param_u32(ps, "id")))

def handle(r: Req.Request) -> Res.Response:
  HJ.dispatch(Route, routes(), r, on)

def main() -> IO(Unit):
  Server.serve_pure(~handle, Server.default(8081))
