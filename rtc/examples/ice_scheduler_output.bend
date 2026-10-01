import Base
import ../ice_scheduler.bend as S
import ../ice_binding.bend as Ice
import ../ice_pairs.bend as Pairs
import ../ice_candidates.bend as C

# Shared fixture helpers; CLI adapters keep forwarding definitions.

def role_text(role: Ice.Role) -> String:
  match role:
    case Ice.Controlling{high, low}: "controlling:" ++ U32.show(high) ++ ":" ++ U32.show(low)
    case Ice.Controlled{high, low}: "controlled:" ++ U32.show(high) ++ ":" ++ U32.show(low)

def ref_text(reference: Pairs.Ref) -> String:
  match reference:
    case Pairs.Ref{id, component, +base, +remote}:
      U32.show(id) ++ ":" ++ U32.show(component) ++ ":" ++ C.host(base) ++ "/" ++ U32.show(C.port(base)) ++ ":" ++
      C.host(remote) ++ "/" ++ U32.show(C.port(remote))

def show_refs(refs: List<&2, Pairs.Ref>) -> IO(Unit):
  match refs:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{r, tail}:
      do IO<Unit>:
        x : Unit <- IO.print("queued:" ++ ref_text(r))
        show_refs(tail)

def show_queues(values: List<&2, S.Queue>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{S.Queue{id, refs}, tail}:
      do IO<Unit>:
        x : Unit <- IO.print("queue:" ++ U32.show(id))
        y : Unit <- show_refs(refs)
        show_queues(tail)

def show_flights(values: List<&2, S.Flight>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{S.Flight{token, ref, r}, tail}:
      do IO<Unit>:
        x : Unit <- IO.print("flight:" ++ U32.show(token) ++ ":" ++ ref_text(ref) ++ ":" ++ role_text(r))
        show_flights(tail)
