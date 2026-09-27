import Base
import ./router.bend as Router
import ../core/method.bend as M
import ../core/request.bend as Req

# each def is a test: it checks only if both sides compute to the same value

type R is Data:
  Root{}
  Todos{}
  Todo{}
  Me{}
  Other{}

def rs() -> List<&2, Router.Route<R>>:
  [Router.get(R, "/", Root{}), Router.get(R, "/todos", Todos{}), Router.post(R, "/todos", Todos{}),
   Router.get(R, "/todos/me", Me{}), Router.get(R, "/todos/:id", Todo{}), Router.get(R, "/todos/me", Other{})]

def m(-R: Data) -> Type:
  Router.Match<R>

def find(me: M.Method, t: String) -> Router.Match<R>:
  Router.find(R, rs(), me, t)

def root() -> {find(M.MGet{}, "/") == Router.Found{Root{}, []} : m(R)}:
  {==}

def capture() -> {find(M.MGet{}, "/todos/7") == Router.Found{Todo{}, [Router.Param{"id", "7"}]} : m(R)}:
  {==}

def query_ignored() -> {find(M.MGet{}, "/todos/7?full=1") == Router.Found{Todo{}, [Router.Param{"id", "7"}]} : m(R)}:
  {==}

def first_wins() -> {find(M.MGet{}, "/todos/me") == Router.Found{Me{}, []} : m(R)}:
  {==}

def not_found() -> {find(M.MGet{}, "/users") == Router.NotFound{} : m(R)}:
  {==}

def too_deep() -> {find(M.MGet{}, "/todos/7/x") == Router.NotFound{} : m(R)}:
  {==}

def trailing_slash() -> {find(M.MGet{}, "/todos/") == Router.NotFound{} : m(R)}:
  {==}

def not_allowed() -> {find(M.MDelete{}, "/todos") == Router.MethodNotAllowed{[M.MGet{}, M.MPost{}]} : m(R)}:
  {==}

def allow_text() -> {Router.allow([M.MGet{}, M.MPost{}]) == "GET, POST" : String}:
  {==}

def param_get() -> {Router.param([Router.Param{"a", "1"}, Router.Param{"id", "7"}], "id") == Some{"7"} : Maybe<&2, String>}:
  {==}

def pattern() -> {Router.pattern("/a/:b/c") == [Router.Lit{"a"}, Router.Cap{"b"}, Router.Lit{"c"}] : List<&2, Router.Seg>}:
  {==}

def req() -> Req.Request:
  Req.Request{M.MGet{}, "/todos/9", [], []}

def routed() -> {Router.route_req(R, rs(), req()) == Router.Routed{Router.Found{Todo{}, [Router.Param{"id", "9"}]}, Req.Request{M.MGet{}, "/todos/9", [], []}} : Router.Routed<R>}:
  {==}
