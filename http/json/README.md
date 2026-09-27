# grounds-http-json

JSON request bodies and responses for [Bend 2](https://github.com/bendlang/bend), on grounds-json and grounds-http-core.

```python
import ../http/json/http_json.bend as HJ

def Todo.from_json(+j: J.Json) -> Result<&2, &2, J.Access, Todo>:
  J.both(String, Bool, Todo, J.string_at(j, [J.Name{"title"}]), J.bool_at(j, [J.Name{"done"}]), t => d => Todo{0, t, d})

match HJ.decode(Todo, j => Todo.from_json(j), req):
  case Done{t}: HJ.response(S.created(), Todo.to_json(t))
  case Fail{e}: HJ.error(e)        # 415, 413 or 400 with {"error": why}
```

- **`decode(A, f, req)`** checks the content type, the size, parses the body and runs `f`. It fails with one of four `DecodeError`s:
  - `UnsupportedContentType`: not `application/json` or `*/*+json` (parameters and case ignored).
  - `BodyTooLarge`: over 1 MiB.
  - `InvalidJson{J.Error}`: the body does not parse.
  - `InvalidValue{J.Access}`: `f` failed; `J.message_access` gives e.g. `$.done: expected bool, found string`.
- **`response(status, j)`** answers with `j` and `content-type: application/json`.
- **`error(e)`** turns a `DecodeError` into its answer.
- **Answers:** `ok(j)`, `created(j)`, `fail(status, msg)`, `not_found()`, `maybe(A, f, m)` (200 or 404), `decoded(A, f, req, k)` (decode, then `k`, or the error's answer), and `dispatch`: `Router.dispatch` with JSON 404 and 405 bodies.
- **Pass the decoder as a lambda** (`j => Todo.from_json(j)`): a decoder takes `+j`, which a plain function type does not.

`examples/todo.bend` is a JSON API on port 8081: `GET /todos`, `POST /todos`, `GET /todos/:id`. The handler keeps no state, so the list is fixed and POST answers with the todo it would create.

`moon run http_json:check` runs `test.bend`, curls each route of the example (404, 405, 400, 415 included), and runs the cold check.

**Laws.** `LAWS.bend`, proven in `PROOF.bend`: media-type parameters never change the JSON decision, and a body with another type or none is never parsed.
