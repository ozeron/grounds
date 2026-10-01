import Base
import ../ice_binding.bend as Ice
import ../stun_auth.bend as Auth

# Shared fixture helpers; CLI adapters keep forwarding definitions.

def flag(value: Bool) -> String:
  Bool.pick(String, value, "1", "0")

def role(value: Ice.Role) -> String:
  match value:
    case Ice.Controlling{high, low}: "controlling:" ++ U32.show(high) ++ ":" ++ U32.show(low)
    case Ice.Controlled{high, low}: "controlled:" ++ U32.show(high) ++ ":" ++ U32.show(low)

def mode(value: Auth.Mode) -> String:
  match value:
    case Auth.Legacy{}: "legacy"
    case Auth.Sha256{}: "sha256"
    case Auth.Dual{}: "dual"
