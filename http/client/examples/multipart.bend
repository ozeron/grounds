import Base
import ../client.bend as C
import ../../core/multipart.bend as Mp
import ../../core/text.bend as T

def body(boundary: Maybe<&2, Mp.Boundary>) -> C.Body:
  match boundary:
    case Some{value}:
      C.multipart(value, [Mp.Part{"blob", Some{"data.bin"}, Some{"application/octet-stream"}, [0, 255, 13, 10, 65]}])
    case None{}:
      C.empty()

def shown(result: C.R(C.Reply)) -> String:
  match result:
    case Done{reply}:
      T.or(C.utf8(reply), "not UTF-8")
    case Fail{err}:
      C.show(err)

def main() -> IO(Unit):
  do IO<Unit>:
    result : C.R(C.Reply) <- C.send(C.default(), C.post("http://127.0.0.1:8095/", body(Mp.make_boundary("grounds-test-boundary"))))
    IO.print(shown(result))
