import Base
import ../ice_consent.bend as Consent
import ../stun_auth.bend as Auth
import ../../crypto/bytes.bend as B

# Shared fixture helpers; CLI adapters keep forwarding definitions.

def status(status: Consent.Status) -> String:
  match status:
    case Consent.Awaiting{}: "awaiting"
    case Consent.Granted{}: "granted"
    case Consent.Expired{}: "expired"
    case Consent.Revoked{}: "revoked"
    case Consent.Closed{}: "closed"

def mode(mode: Auth.Mode) -> String:
  match mode:
    case Auth.Legacy{}: "legacy"
    case Auth.Sha256{}: "sha256"
    case Auth.Dual{}: "dual"

def flag(value: Bool) -> String:
  match value:
    case True{}: "1"
    case False{}: "0"

def event(event: Consent.Notice) -> IO(Unit):
  match event:
    case Consent.Send{_, gen, token, bytes}: IO.print("send:" ++ U32.show(gen) ++ ":" ++ U32.show(token) ++ ":" ++ B.hex(bytes))
    case Consent.Sent{token}: IO.print("sent:" ++ U32.show(token))
    case Consent.Renewed{token, expires}: IO.print("renewed:" ++ U32.show(token) ++ ":" ++ Nat.show(expires))
    case Consent.TimedOut{token}: IO.print("timedout:" ++ U32.show(token))
    case Consent.Error{token, code}: IO.print("error:" ++ U32.show(token) ++ ":" ++ U32.show(code))
    case Consent.Invalid{token}: IO.print("invalid-response:" ++ U32.show(token))
    case Consent.TransportError{token, code}: IO.print("transport-error:" ++ U32.show(token) ++ ":" ++ U32.show(code))
    case Consent.Changed{s}: IO.print("status-changed:" ++ status(s))

def events(values: List<&2, Consent.Notice>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{head, tail}:
      do IO<Unit>:
        x : Unit <- event(head)
        events(tail)
