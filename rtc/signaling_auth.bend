import Base
import ../http/core/request.bend as Req
import ../http/core/method.bend as M
import ../http/core/headers.bend as H
import ../http/core/text.bend as Text

# Explicit local fixture policy, checked before the WebSocket upgrade and UDP
# allocation. Values are synthetic public test selectors, not deployable secrets.
type Decision is Data:
  Allowed{}
  DeniedOrigin{}
  DeniedAuth{}
  BadRequest{}

def one(values: List<&2, String>, expected: String) -> Bool:
  match values:
    case [value]: String.eq(value, expected)
    case _: False{}

def checked(host: Bool, origin: Bool, auth: Bool) -> Decision:
  match host origin auth:
    case False{} _ _: BadRequest{}
    case True{} False{} _: DeniedOrigin{}
    case True{} True{} False{}: DeniedAuth{}
    case True{} True{} True{}: Allowed{}

def authorize.path(ok: Bool, +headers: List<&2, H.Header>, host: String, origin: String, cookie: String) -> Decision:
  match ok:
    case True{}:
      checked(one(H.all(headers, "host"), host), one(H.all(headers, "origin"), origin),
        one(H.all(headers, "cookie"), cookie))
    case False{}: BadRequest{}

def authorize(request: Req.Request, host: String, origin: String, cookie: String) -> Decision:
  match request:
    case Req.Request{M.MGet{}, path, headers, Nil{}}:
      authorize.path(Text.same(path, "/signal", True{}), headers, host, origin, cookie)
    case _: BadRequest{}
