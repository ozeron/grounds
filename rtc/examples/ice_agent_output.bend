import Base
import ../ice_agent.bend as Agent
import ./ice_valid_output.bend as ValidOutput
import ./ice_session_output.bend as Output
import ./ice_scheduler_output.bend as Scheduler

# Shared fixture helpers; CLI adapters keep forwarding definitions.

def status_text(status: Agent.Status) -> String:
  match status:
    case Agent.Running{}: "running"
    case Agent.Completed{}: "completed"
    case Agent.Failed{}: "failed"
    case Agent.Faulted{}: "faulted"

def lifecycle(values: List<&2, Agent.Notice>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{Agent.Nominated{path, ref, attempt}, tail}:
      do IO<Unit>:
        a : Unit <- IO.print("nominated:" ++ Scheduler.ref_text(ref) ++ ":" ++ Output.maybe_record(attempt) ++ ":" ++ ValidOutput.path_text(path))
        lifecycle(tail)
    case Con{Agent.NominationFailed{record, _}, tail}:
      do IO<Unit>:
        a : Unit <- IO.print("nomination-failed:" ++ Output.record(record))
        lifecycle(tail)
    case Con{Agent.StreamChanged{id, status}, tail}:
      do IO<Unit>:
        a : Unit <- IO.print("stream-changed:" ++ U32.show(id) ++ ":" ++ status_text(status))
        lifecycle(tail)
    case Con{Agent.SessionChanged{status}, tail}:
      do IO<Unit>:
        a : Unit <- IO.print("session-changed:" ++ status_text(status))
        lifecycle(tail)
    case Con{Agent.PacStarted{deadline}, tail}:
      do IO<Unit>:
        a : Unit <- IO.print("pac-started:" ++ Nat.show(deadline))
        lifecycle(tail)
    case Con{Agent.PacExpired{}, tail}:
      do IO<Unit>:
        a : Unit <- IO.print("pac-expired")
        lifecycle(tail)
