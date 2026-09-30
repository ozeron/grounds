import Base
import ../ice_binding.bend as Ice
import ../ice_reliable.bend as Client
import ../ice_response.bend as Response
import ../stun_retry.bend as Retry
import ../stun_auth.bend as Auth
import ../stun_client.bend as Discovery
import ./ice_exchange.bend as Fixture
import ./binding.bend as Output

def show(outcome: Client.Outcome) -> IO(Unit):
  match outcome:
    case Client.Received{Response.Success{address}, _}: Output.show(Some{address})
    case Client.Received{Response.Error{code}, _}: IO.print("error:" ++ U32.show(code))
    case Client.Received{Response.Invalid{}, _}: IO.print("invalid-response")
    case Client.TimedOut{}: IO.print("timeout")
    case Client.IntegrityViolation{}: IO.print("integrity-violation")
    case Client.TransportError{code}: IO.print("transport:" ++ U32.show(code))
    case Client.FloodLimit{}: IO.print("flood-limit")
    case Client.InvalidInput{}: IO.print("invalid-input")

def selected(outcome: Client.Outcome, fallback: Auth.Mode) -> Auth.Mode:
  match outcome:
    case Client.Received{_, mode}: mode
    case _: fallback

def again(port: U32, mode: Auth.Mode, reply: Client.Reply()) -> IO(Unit):
  (socket, +outcome) = reply
  do IO<Unit>:
    x : Unit <- show(outcome)
    second : Client.Reply() <- Client.exchange(socket, Discovery.transaction(4, 5, 6), "127.0.0.1", port,
      Retry.Policy{500, 3, 1}, Fixture.credentials(), Ice.Check{1845494271, Ice.Controlled{4275878552, 1985229328}}, selected(outcome, mode))
    result : Client.Outcome <- Client.closed(second)
    show(result)

def reuse(+port: U32, +mode: Auth.Mode) -> IO(Unit):
  do IO<Unit>:
    socket : Socket <- IO.try(Socket, UDP.bind(0))
    first : Client.Reply() <- Client.exchange(socket, Discovery.transaction(1, 2, 3), "127.0.0.1", port,
      Retry.Policy{500, 1, 1}, Fixture.credentials(), Ice.Check{1845494271, Ice.Controlling{4275878552, 1985229328}}, mode)
    again(port, mode, first)

def run(port: U32, mode: Auth.Mode, policy: Retry.Policy, host: String) -> IO(Unit):
  do IO<Unit>:
    result : Client.Outcome <- Client.request(host, port, policy, Fixture.credentials(),
      Ice.Check{1845494271, Ice.Controlling{4275878552, 1985229328}}, mode)
    show(result)

def policy_run(policy: String, port: U32, mode: Auth.Mode) -> IO(Unit):
  match policy:
    case "default": run(port, mode, Retry.default(), "127.0.0.1")
    case "short": run(port, mode, Retry.Policy{500, 3, 1}, "127.0.0.1")
    case "once": run(port, mode, Retry.Policy{500, 1, 1}, "127.0.0.1")
    case "invalid": run(port, mode, Retry.Policy{499, 7, 16}, "127.0.0.1")
    case "transport": run(port, mode, Retry.default(), "invalid address")
    case "reuse": reuse(port, mode)
    case "reuse-success": reuse(port, mode)
    case _: IO.die(Unit, 2, "unknown retry policy")

def mode_run(mode: String, policy: String, port: U32) -> IO(Unit):
  match mode:
    case "legacy": policy_run(policy, port, Auth.Legacy{})
    case "sha256": policy_run(policy, port, Auth.Sha256{})
    case "dual": policy_run(policy, port, Auth.Dual{})
    case _: IO.die(Unit, 2, "unknown integrity mode")

def port_got(port: Maybe<&2, U32>, mode: String, policy: String) -> IO(Unit):
  match port:
    case Some{p}: mode_run(mode, policy, p)
    case None{}: IO.die(Unit, 2, "invalid port")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [port, mode, policy]: port_got(U32.read(port), mode, policy)
    case _: IO.die(Unit, 2, "usage: ice_retry <port> <mode> <policy>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
