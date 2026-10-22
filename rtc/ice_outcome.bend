import Base
import ./ice_response.bend as Response
import ./stun_auth.bend as Auth

# what a reliable ICE exchange ends with, and what it was sent with. Pure, so
# the engines that read these import no socket code (ice_reliable.bend)

type Outcome is Data:
  Received{response: Response.Response, algorithm: Auth.Mode}
  TimedOut{}
  IntegrityViolation{}
  TransportError{code: U32}
  FloodLimit{}
  InvalidInput{}

type Context is Data:
  Context{host: String, port: U32, transaction: List<&2, U32>, key: List<&2, U32>, mode: Auth.Mode, bytes: List<&2, U32>}
