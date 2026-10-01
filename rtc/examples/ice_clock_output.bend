import Base
import ../ice_transactions.bend as Tx
import ../ice_reliable.bend as Reliable
import ../ice_response.bend as Response
import ../stun_auth.bend as Auth

# Shared fixture helpers; CLI adapters keep forwarding definitions.

def verdict(outcome: Reliable.Outcome) -> String:
  match outcome:
    case Reliable.TimedOut{}: "timeout"
    case Reliable.IntegrityViolation{}: "integrity"
    case Reliable.TransportError{code}: "transport" ++ U32.show(code)
    case Reliable.Received{Response.Success{_}, _}: "success"
    case _: "other"

def late(response: Response.Response, mode: Auth.Mode) -> String:
  match response mode:
    case Response.Success{_} Auth.Legacy{}: "success-legacy"
    case Response.Success{_} _: "success-sha256"
    case Response.Error{code} Auth.Legacy{}: "error" ++ U32.show(code) ++ "-legacy"
    case Response.Error{code} _: "error" ++ U32.show(code) ++ "-sha256"
    case Response.Invalid{} _: "invalid"

def events(values: List<&2, Tx.Notice>, out: String) -> String:
  match values:
    case Nil{}: out
    case Con{Tx.Send{token, _, _, _, _}, tail}: events(tail, out ++ ":send" ++ U32.show(token))
    case Con{Tx.Finished{token, reply}, tail}: events(tail, out ++ ":done" ++ U32.show(token) ++ "-" ++ verdict(reply))
    case Con{Tx.Cancelled{token}, tail}: events(tail, out ++ ":cancel" ++ U32.show(token))
    case Con{Tx.Stopped{token}, tail}: events(tail, out ++ ":stop" ++ U32.show(token))
    case Con{Tx.Retired{token}, tail}: events(tail, out ++ ":retire" ++ U32.show(token))
    case Con{Tx.LateResponse{token, response, mode}, tail}: events(tail, out ++ ":late" ++ U32.show(token) ++ "-" ++ late(response, mode))
    case Con{Tx.SocketFailure{code}, tail}: events(tail, out ++ ":socket" ++ U32.show(code))
    case Con{Tx.Datagram{_, _, _}, tail}: events(tail, out ++ ":raw")
    case Con{_, tail}: events(tail, out ++ ":other")

def entries(values: List<&2, Tx.Entry>, +base: Nat, out: String) -> String:
  match values:
    case Nil{}: out
    case Con{Tx.Entry{token, _, deadline, waits, _}, tail}:
      entries(tail, base, out ++ ":" ++ U32.show(token) ++ "/" ++ Nat.show(Nat.sub(deadline, base)) ++ "/" ++ Nat.show(List.length(&2, U32, waits)))
    case Con{Tx.Listening{token, _, deadline}, tail}:
      entries(tail, base, out ++ ":" ++ U32.show(token) ++ "/" ++ Nat.show(Nat.sub(deadline, base)) ++ "/listening")

def snapshot(state: Tx.State, +base: Nat) -> String:
  match state:
    case Tx.State{values, _, _, start, send}:
      entries(values, base, Nat.show(Nat.sub(start, base)) ++ "," ++ Nat.show(Nat.sub(send, base)))
