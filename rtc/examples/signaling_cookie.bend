import Base
import ../signaling_cookie.bend as Cookie
import ../signaling_auth.bend as Access
import ../../http/core/headers.bend as H
import ../../http/core/request.bend as Req
import ../../http/core/method.bend as M
import ../../json/json.bend as J
import ../../io/io.bend as Io

def emit(decision: Access.Decision) -> IO(Unit):
  match decision:
    case Access.Allowed{}: IO.print("allowed")
    case Access.BadRequest{}: IO.print("bad-request")
    case Access.DeniedOrigin{}: IO.print("denied-origin")
    case Access.DeniedAuth{}: IO.print("denied-auth")

def headers(items: List<&2, J.Json>, reversed: List<&2, H.Header>) -> Maybe<&2, List<&2, H.Header>>:
  match items:
    case Nil{}: Some{List.reverse(&2, H.Header, reversed)}
    case Con{J.JArr{[J.JStr{name}, J.JStr{value}]}, tail}: headers(tail, Con{H.Header{name, value}, reversed})
    case _: None{}

def checked(key: String, session: String, deadline: Result<&2, &2, J.Access, U32>,
  now: Result<&2, &2, J.Access, U32>, method: String, path: String, body: Bool,
  fields: Maybe<&2, List<&2, H.Header>>) -> IO(Unit):
  match deadline now fields:
    case Done{+end} Done{clock} Some{fields}:
      emit(Cookie.authorize(Req.Request{M.parse(method), path, fields, Bool.pick(List<&2, U32>, body, [0], [])},
        "fixture", "local", Cookie.State{key, Cookie.payload(session, U32.to_nat(end)), U32.to_nat(end)}, U32.to_nat(clock)))
    case _ _ _: IO.die(Unit, 2, "bad fixture")

def record(value: J.Json) -> IO(Unit):
  match value:
    case J.JArr{[J.JStr{key}, J.JStr{session}, end, now, J.JStr{method}, J.JStr{path}, J.JBool{body}, J.JArr{fields}]}:
      checked(key, session, J.u32(end), J.u32(now), method, path, body, headers(fields, []))
    case _: IO.die(Unit, 2, "bad fixture")

def values(items: List<&2, J.Json>) -> IO(Unit):
  match items:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{head, tail}:
      do IO<Unit>:
        x : Unit <- record(head)
        values(tail)

def parsed(value: Result<&2, &2, J.Error, J.Json>) -> IO(Unit):
  match value:
    case Done{J.JArr{items}}: values(items)
    case _: IO.die(Unit, 2, "bad fixture")

def read(path: String) -> IO(Unit):
  do IO<Unit>:
    bytes : List<&2, U32> <- Io.read_bytes(path)
    parsed(J.parse_bytes(bytes))

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [path]: read(path)
    case [_, path]: read(path)
    case _: IO.die(Unit, 2, "usage: signaling_cookie <fixture.json>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
