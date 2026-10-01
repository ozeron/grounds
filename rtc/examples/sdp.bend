import Base
import ../sdp.bend as Sdp
import ../ice_candidates.bend as C
import ../../crypto/bytes.bend as B
import ../../json/json.bend as J
import ../../io/io.bend as Io

def candidates(values: List<&2, C.Candidate>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{C.Candidate{component, priority, foundation, kind, +address}, tail}:
      do IO<Unit>:
        x : Unit <- IO.print("candidate:" ++ U32.show(component) ++ ":" ++ U32.show(priority) ++ ":" ++ foundation ++ ":" ++ U32.show(C.kind_code(kind)) ++ ":" ++ C.host(address) ++ ":" ++ U32.show(C.port(address)))
        candidates(tail)

def decoded(value: Sdp.Decoded) -> IO(Unit):
  match value:
    case Sdp.Invalid{reason}: IO.print("invalid:" ++ reason)
    case Sdp.Valid{Sdp.Description{ufrag, pwd, mid, fp, sctp, cs, ignored}}:
      do IO<Unit>:
        x : Unit <- IO.print("valid:" ++ ufrag ++ ":" ++ pwd ++ ":" ++ mid ++ ":" ++ B.hex(fp) ++ ":" ++ U32.show(sctp) ++ ":" ++ U32.show(ignored))
        candidates(cs)

def values(items: List<&2, J.Json>) -> IO(Unit):
  match items:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{J.JStr{text}, tail}:
      do IO<Unit>:
        x : Unit <- decoded(Sdp.decode(text))
        y : Unit <- IO.print("end")
        values(tail)
    case _: IO.die(Unit, 2, "bad fixture")

def parsed(value: Result<&2, &2, J.Error, J.Json>) -> IO(Unit):
  match value:
    case Done{J.JArr{items}}: values(items)
    case _: IO.die(Unit, 2, "bad fixture")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [path]:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        parsed(J.parse_bytes(bytes))
    case _: IO.die(Unit, 2, "usage: sdp <fixture.json>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
