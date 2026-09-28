import Base
import ../server.bend as Server
import ../../core/multipart.bend as Mp
import ../../core/request.bend as Req
import ../../core/headers.bend as H
import ../../core/response.bend as Res
import ../../core/status.bend as S
import ../../core/cookie.bend as Ck

def kind(m: Maybe<&2, String>) -> String:
  match m:
    case Some{value}:
      value
    case None{}:
      "-"

def hex_byte(+b: U32, tail: String) -> String:
  SCon{Ck.hex((b >> 4n : U32)), SCon{Ck.hex((b .&. 15 : U32)), tail}}

def hex(bs: List<&2, U32>) -> String:
  match bs:
    case Nil{}:
      ""
    case Con{+b, tail}:
      hex_byte(b, hex(tail))

def parts(ps: List<&2, Mp.Part>) -> String:
  match ps:
    case Nil{}:
      ""
    case Con{Mp.Part{name, filename, media, body}, tail}:
      "P " ++ name ++ " " ++ kind(filename) ++ " " ++ kind(media) ++ " " ++ hex(body) ++ "\n" ++ parts(tail)

def answer(parsed: Mp.Parsed) -> Res.Response:
  match parsed:
    case Done{ps}:
      Res.ok("OK\n" ++ parts(ps))
    case Fail{Mp.TooManyParts{}}:
      Res.text(S.bad_request(), "TooManyParts")
    case Fail{Mp.HeadersTooLarge{}}:
      Res.text(S.bad_request(), "HeadersTooLarge")
    case Fail{Mp.TooManyHeaders{}}:
      Res.text(S.bad_request(), "TooManyHeaders")
    case Fail{_}:
      Res.text(S.bad_request(), "Malformed")

def content_type(h: Maybe<&2, String>) -> String:
  match h:
    case Some{value}:
      value
    case None{}:
      ""

def app(req: Req.Request) -> Res.Response:
  match req:
    case Req.Request{_, _, hs, body}:
      answer(Mp.parse(content_type(H.get(hs, "content-type")), body, Mp.Limits{10n, 2048n, 8n}))

def main() -> IO(Unit):
  Server.serve_pure(~app, Server.default(8095))
