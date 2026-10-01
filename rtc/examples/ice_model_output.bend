import Base
import ../ice_candidates.bend as C
import ../ice_checklist.bend as Check

# Shared fixture helpers; CLI adapters keep forwarding definitions.

def pair_text(pair: Check.CandidatePair) -> String:
  match pair:
    case Check.CandidatePair{C.Local{C.Candidate{component, original, _, _, _},
      C.Candidate{_, base_priority, local_f, _, +base}}, C.Candidate{_, remote_priority, remote_f, _, +remote},
      C.Priority{high, low}, state}:
      "pair:" ++ U32.show(component) ++ ":" ++ U32.show(original) ++ ":" ++ U32.show(base_priority) ++ ":" ++
      C.host(base) ++ "/" ++ U32.show(C.port(base)) ++ ":" ++ U32.show(remote_priority) ++ ":" ++
      C.host(remote) ++ "/" ++ U32.show(C.port(remote)) ++ ":" ++ local_f ++ ":" ++ remote_f ++ ":" ++
      U32.show(high) ++ ":" ++ U32.show(low) ++ ":" ++ U32.show(Check.state_code(state))

def show_pairs(pairs: List<&2, Check.CandidatePair>) -> IO(Unit):
  match pairs:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{pair, tail}:
      do IO<Unit>:
        x : Unit <- IO.print(pair_text(pair))
        show_pairs(tail)

def show_lists(checklists: List<&2, Check.Checklist>) -> IO(Unit):
  match checklists:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{Check.Checklist{id, pairs}, tail}:
      do IO<Unit>:
        x : Unit <- IO.print("stream:" ++ U32.show(id))
        y : Unit <- show_pairs(pairs)
        show_lists(tail)
