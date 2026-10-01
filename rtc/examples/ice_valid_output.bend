import Base
import ../ice_valid.bend as V
import ../ice_session.bend as Session
import ../ice_attempts.bend as A
import ../ice_candidates.bend as C
import ../ice_registry.bend as R
import ../ice_scheduler.bend as S
import ./ice_session_output.bend as Output
import ./ice_accept_output.bend as Format

def local_text(local: C.Local) -> String:
  match local:
    case C.Local{C.Candidate{component, priority, foundation, kind, +address}, C.Candidate{_, _, _, _, +base}}:
      U32.show(component) ++ ":" ++ U32.show(priority) ++ ":" ++ foundation ++ ":" ++ U32.show(C.kind_code(kind)) ++ ":" ++
      C.host(address) ++ "/" ++ U32.show(C.port(address)) ++ ":" ++ C.host(base) ++ "/" ++ U32.show(C.port(base))

def path_text(path: V.Path) -> String:
  match path:
    case V.Path{id, local, C.Candidate{_, priority, foundation, _, +address}, C.Priority{high, low}, record, nominated}:
      U32.show(id) ++ ":" ++ local_text(local) ++ ":" ++ U32.show(priority) ++ ":" ++ foundation ++ ":" ++
      C.host(address) ++ "/" ++ U32.show(C.port(address)) ++ ":" ++ U32.show(high) ++ "/" ++ U32.show(low) ++ ":" ++ Output.record(record) ++ ":" ++ Format.flag(nominated)

def notice(value: V.Notice) -> IO(Unit):
  match value:
    case V.Validated{path, discovered, late}: IO.print("validated:" ++ Format.flag(discovered) ++ ":" ++ Format.flag(late) ++ ":" ++ path_text(path))
    case V.Exhausted{record}: IO.print("valid-capacity:" ++ Output.record(record))
    case V.InvalidMapping{record}: IO.print("valid-invalid:" ++ Output.record(record))

def notices(values: List<&2, V.Notice>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{head, tail}:
      do IO<Unit>:
        x : Unit <- notice(head)
        notices(tail)

def paths(values: List<&2, V.Path>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{path, tail}:
      do IO<Unit>:
        x : Unit <- IO.print("valid:" ++ path_text(path))
        paths(tail)

def locals(values: List<&2, V.Learned>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{V.Learned{id, local}, tail}:
      do IO<Unit>:
        x : Unit <- IO.print("local-learned:" ++ U32.show(id) ++ ":" ++ local_text(local))
        locals(tail)

def detail(value: Maybe<&2, V.Attempt>) -> IO(Unit):
  match value:
    case None{}: IO.print("request-info:invalid")
    case Some{V.Attempt{record, _, _, priority, nominate}}:
      IO.print("request-info:" ++ U32.show(priority) ++ ":" ++ Format.flag(nominate) ++ ":" ++ Output.record(record))

def details(values: List<&2, A.Record>, +state: Session.State) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{head, tail}:
      do IO<Unit>:
        x : Unit <- detail(V.attempt(state, head))
        details(tail, state)

def request_details(+state: Session.State) -> IO(Unit):
  match state:
    case Session.State{A.State{_, _, records, _}, _, _, _, _, _}: details(records, state)

def snapshot(state: V.State) -> IO(V.State):
  match state:
    case V.State{+s, +ls, +fs, +ps, +limit, +failed}:
      do IO<V.State>:
        next : Session.State <- Output.snapshot(s)
        a : Unit <- IO.print("valid-fault:" ++ Format.flag(failed))
        b : Unit <- request_details(s)
        c : Unit <- paths(ps)
        d : Unit <- locals(ls)
        IO.pure(V.State, V.State{next, ls, fs, ps, limit, failed})
