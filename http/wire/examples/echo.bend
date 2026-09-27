import Base
import ../http1.bend as H1
import ../bytes.bend as B
import ../../core/status.bend as S
import ../../core/request.bend as Req
import ../../core/response.bend as Res

# parse a request's bytes and write the response's: the whole of http1 in
# one pass, which ../../json/scripts/cold.py checks shares no String

def answer(p: H1.Parsed) -> B.Bytes:
  match p:
    case H1.Parsed{r, close, _}:
      H1.write(Res.text(S.ok(), Req.path(r)), close)
    case H1.More{}:
      B.BNil{}
    case H1.Bad{e}:
      H1.write(Res.text(H1.status(e), "bad request"), True{})

def main() -> IO(Unit):
  do IO<Unit>:
    IO.print(H1.latin1(answer(H1.parse(H1.to_bytes("GET /hello?x=1 HTTP/1.1\r\nHost: a\r\n\r\n"), 16384, 1048576))))
