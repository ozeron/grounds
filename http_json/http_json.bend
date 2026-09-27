import Base
import ../json/json.bend as J
import ../utf8/utf8.bend as U
import ../http/status.bend as S
import ../http/headers.bend as H
import ../http/request.bend as Req
import ../http/response.bend as Res

# JSON bodies for http: decode a request's body into your type, and answer
# with a JSON value

# why a body did not decode
type DecodeError is Data:
  UnsupportedContentType{}
  BodyTooLarge{}
  InvalidJson{error: J.Error}
  InvalidValue{error: J.Access}

# the largest body decode reads: 1 MiB
def limit() -> U32:
  1048576

def lower.go(up: Bool, +x: U32) -> U32:
  match up:
    case True{}:
      (x + 32 : U32)
    case False{}:
      x

def lower(+x: U32) -> U32:
  lower.go(Bool.and(U32.is_ge(x, 65), U32.is_le(x, 90)), x)

# the media type, lowercased, spaces dropped, reversed: it ends at ';'
def media.go(s: String, acc: String) -> String:
  match s:
    case SNil{}:
      acc
    case SCon{';', _}:
      acc
    case SCon{' ', t}:
      media.go(t, acc)
    case SCon{'\t', t}:
      media.go(t, acc)
    case SCon{Chr{+x}, t}:
      media.go(t, SCon{Chr{lower(x)}, acc})

def starts(s: String, p: String) -> Bool:
  match s p:
    case _ SNil{}:
      True{}
    case SCon{x, st} SCon{y, pt}:
      Bool.and(Char.is_eq(x, y), starts(st, pt))
    case SNil{} SCon{_, _}:
      False{}

def same(a: String, b: String) -> Bool:
  match a b:
    case SNil{} SNil{}:
      True{}
    case SCon{x, at} SCon{y, bt}:
      Bool.and(Char.is_eq(x, y), same(at, bt))
    case _ _:
      False{}

def is_json.of(+rev: String) -> Bool:
  Bool.or(same(rev, "nosj/noitacilppa"), starts(rev, "nosj+"))

# application/json, or a type with the +json suffix (RFC 6839 §3.1)
def is_json(m: Maybe<&2, String>) -> Bool:
  match m:
    case Some{s}:
      is_json.of(media.go(s, ""))
    case None{}:
      False{}

# a body and its length, counted in one read
type Sized is Data:
  Sized{n: U32, body: List<&2, U32>}

def measure(bs: List<&2, U32>, +n: U32, acc: List<&2, U32>) -> Sized:
  match bs:
    case Nil{}:
      Sized{n, List.reverse(&2, U32, acc)}
    case Con{b, t}:
      measure(t, (n + 1 : U32), Con{b, acc})

def decode.value(-A: Data, r: Result<&2, &2, J.Access, A>) -> Result<&2, &2, DecodeError, A>:
  match r:
    case Done{a}:
      Done{a}
    case Fail{e}:
      Fail{InvalidValue{e}}

def decode.json(-A: Data, f: J.Json -> Result<&2, &2, J.Access, A>, r: Result<&2, &2, J.Error, J.Json>) -> Result<&2, &2, DecodeError, A>:
  match r:
    case Done{j}:
      decode.value(A, f(j))
    case Fail{e}:
      Fail{InvalidJson{e}}

def decode.fits(-A: Data, f: J.Json -> Result<&2, &2, J.Access, A>, ok: Bool, bs: List<&2, U32>) -> Result<&2, &2, DecodeError, A>:
  match ok:
    case True{}:
      decode.json(A, f, J.parse_bytes(bs))
    case False{}:
      Fail{BodyTooLarge{}}

def decode.sized(-A: Data, f: J.Json -> Result<&2, &2, J.Access, A>, s: Sized) -> Result<&2, &2, DecodeError, A>:
  match s:
    case Sized{n, bs}:
      decode.fits(A, f, U32.is_le(n, limit()), bs)

def decode.typed(-A: Data, f: J.Json -> Result<&2, &2, J.Access, A>, ok: Bool, bs: List<&2, U32>) -> Result<&2, &2, DecodeError, A>:
  match ok:
    case True{}:
      decode.sized(A, f, measure(bs, 0, []))
    case False{}:
      Fail{UnsupportedContentType{}}

# the body as your type: f reads the parsed JSON, e.g. with J.string_at
def decode(-A: Data, f: J.Json -> Result<&2, &2, J.Access, A>, r: Req.Request) -> Result<&2, &2, DecodeError, A>:
  match r:
    case Req.Request{_, _, hs, body}:
      decode.typed(A, f, is_json(H.get(hs, "content-type")), body)

# a JSON answer
def response(s: S.Status, j: J.Json) -> Res.Response:
  Res.typed(s, "application/json", U.encode(J.encode(j)))

def error_body(msg: String) -> J.Json:
  J.JObj{[J.Field{"error", J.JStr{msg}}]}

# the answer to a body that did not decode: 415, 413 or 400, with
# {"error": why}
def error(e: DecodeError) -> Res.Response:
  match e:
    case UnsupportedContentType{}:
      response(S.unsupported_media_type(), error_body("content-type must be application/json"))
    case BodyTooLarge{}:
      response(S.content_too_large(), error_body("body too large"))
    case InvalidJson{x}:
      response(S.bad_request(), error_body("invalid JSON: " ++ J.message(x)))
    case InvalidValue{a}:
      response(S.bad_request(), error_body(J.message_access(a)))
