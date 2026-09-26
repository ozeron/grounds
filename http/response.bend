import Base
import ./status.bend as S
import ./headers.bend as H
import ../utf8/utf8.bend as U

# a response: the status, the headers, and the body's bytes. The HTTP/1.1
# layer adds Content-Length when it writes one
type Response is Data:
  Response{status: S.Status, headers: List<&2, H.Header>, body: List<&2, U32>}

def new(s: S.Status, hs: List<&2, H.Header>, b: List<&2, U32>) -> Response:
  Response{s, hs, b}

def empty(s: S.Status) -> Response:
  Response{s, [], []}

def typed(s: S.Status, kind: String, b: List<&2, U32>) -> Response:
  Response{s, [H.Header{"content-type", kind}], b}

def bytes(s: S.Status, b: List<&2, U32>) -> Response:
  typed(s, "application/octet-stream", b)

def text(s: S.Status, t: String) -> Response:
  typed(s, "text/plain; charset=utf-8", U.encode(t))

def html(s: S.Status, t: String) -> Response:
  typed(s, "text/html; charset=utf-8", U.encode(t))

# 303 See Other: the client follows with a GET (RFC 9110 §15.4.4)
def redirect(location: String) -> Response:
  Response{S.see_other(), [H.Header{"location", location}], []}

def not_found() -> Response:
  text(S.not_found(), "Not Found")

def bad_request() -> Response:
  text(S.bad_request(), "Bad Request")

# one more header
def header(r: Response, name: String, value: String) -> Response:
  match r:
    case Response{s, hs, b}:
      Response{s, H.add(hs, name, value), b}

def status(r: Response) -> S.Status:
  match r:
    case Response{s, _, _}:
      s
