# grounds-http-router

Routing for [Bend 2](https://github.com/bendlang/bend) that answers with data: the route value you gave and the path's captures. It calls no handler. Your code dispatches with an exhaustive `match`, so the compiler sees every route.

```python
import ../http/router/router.bend as Router

type Route is Data:
  ListTodos{}
  GetTodo{}

def routes() -> List<&2, Router.Route<Route>>:
  [Router.get(Route, "/todos", ListTodos{}), Router.post(Route, "/todos", ListTodos{}),
   Router.get(Route, "/todos/:id", GetTodo{})]

match Router.route_req(Route, routes(), req):
  case Router.Routed{Router.Found{GetTodo{}, params}, req}: …   # Router.param(params, "id")
  case Router.Routed{Router.MethodNotAllowed{allowed}, _}: …    # 405, Allow: Router.allow(allowed)
  case Router.Routed{Router.NotFound{}, _}: …                   # 404
```

- **Dispatch:** `Router.dispatch(Route, routes(), req, on)` routes and answers: `on(route, params, req)` for a match, 404 or 405 with `Allow` otherwise. `Router.param_u32(params, "id")` reads a numeric capture.
- **Patterns:** `/`-separated literals and `:name` captures; no wildcards, no regex. A capture takes a non-empty segment, so `/todos/` is not `/todos/:id`. A trailing slash counts: `/todos/` is not `/todos`.
- **Matching:** routes are tried in order and the first whose method and path match wins. The query string is ignored.
- **405:** a path that matches under other methods gives `MethodNotAllowed` with those methods; `Router.allow` writes the `Allow` header's value (RFC 9110 §15.5.6).
- **The request comes back:** `route_req` returns the request untouched beside the match, for the handler.
- **Build `routes()` for each request.** A table built once and reused makes Lists and everything in them reference counted, measured on `examples/routes.bend` (test 2 of the M1 plan). Rebuilding a small table costs little, and the program stays cold.

`moon run http_router:check` runs `test.bend` (12 cases), the example, and the cold check.

**Laws.** `LAWS.bend`, proven in `PROOF.bend`: the first matching route wins and later routes change nothing; a failed literal is final; a capture never binds an empty segment; no match is 404, and a 405 names at least one method.
