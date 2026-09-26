import Base
import ./text.bend as T
import ./method.bend as M
import ./headers.bend as H
import ./query.bend as Q

# a request as the server hands it over: the method, the target as sent
# (origin-form, RFC 9112 §3.2.1: /path?query), the headers, and the body's
# bytes, read up to the server's limit
type Request is Data:
  Request{method: M.Method, target: String, headers: List<&2, H.Header>, body: List<&2, U32>}

# Each accessor takes the request whole, as Bend values are used once: to
# read several parts, match on Request{m, target, hs, body} instead

def method(r: Request) -> M.Method:
  match r:
    case Request{m, _, _, _}:
      m

def target(r: Request) -> String:
  match r:
    case Request{_, t, _, _}:
      t

def path.of(c: T.Cut) -> String:
  match c:
    case T.Cut{p, _}:
      p

# the target's path, before any ?
def path(r: Request) -> String:
  match r:
    case Request{_, t, _, _}:
      path.of(T.cut(t, 63))

def query.of(c: T.Cut) -> List<&2, Q.Param>:
  match c:
    case T.Cut{_, Some{q}}:
      Q.parse(q)
    case T.Cut{_, None{}}:
      []

# the target's query pairs, decoded
def query(r: Request) -> List<&2, Q.Param>:
  match r:
    case Request{_, t, _, _}:
      query.of(T.cut(t, 63))

def headers(r: Request) -> List<&2, H.Header>:
  match r:
    case Request{_, _, hs, _}:
      hs

# the first value of a header, whose name compares ignoring case
def header(r: Request, +name: String) -> Maybe<&2, String>:
  match r:
    case Request{_, _, hs, _}:
      H.get(hs, name)

def body(r: Request) -> List<&2, U32>:
  match r:
    case Request{_, _, _, b}:
      b
