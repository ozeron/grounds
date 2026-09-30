import Base
import ../ice_binding.bend as Ice
import ../ice_client.bend as Client
import ../stun_auth.bend as Auth
import ../stun.bend as Stun
import ../stun_client.bend as Discovery
import ./binding.bend as Output

def credentials() -> Ice.Credentials:
  Ice.Credentials{"localFrag", "remoteFrag", "SyntheticPassword123456789"}

def run(port: U32, mode: Auth.Mode, role: Ice.Role) -> IO(Unit):
  do IO<Unit>:
    reply : Maybe<&2, Stun.IPv4> <- Client.request("127.0.0.1", port, 250, credentials(), Ice.Check{1845494271, role}, mode)
    Output.show(reply)

def again(port: U32, first: Client.Reply()) -> IO(Unit):
  (socket, address) = first
  do IO<Unit>:
    x : Unit <- Output.show(address)
    second : Client.Reply() <- Client.exchange(socket, Discovery.transaction(4, 5, 6), "127.0.0.1", port,
      250, credentials(), Ice.Check{1845494271, Ice.Controlled{4275878552, 1985229328}}, Auth.Dual{})
    reply : Maybe<&2, Stun.IPv4> <- Client.closed(second)
    Output.show(reply)

def twice(+port: U32) -> IO(Unit):
  do IO<Unit>:
    socket : Socket <- IO.try(Socket, UDP.bind(0))
    first : Client.Reply() <- Client.exchange(socket, Discovery.transaction(1, 2, 3), "127.0.0.1", port,
      250, credentials(), Ice.Check{1845494271, Ice.Controlling{4275878552, 1985229328}}, Auth.Dual{})
    again(port, first)

def role_run(role: String, port: U32, mode: Auth.Mode) -> IO(Unit):
  match role:
    case "controlling":
      run(port, mode, Ice.Controlling{4275878552, 1985229328})
    case "controlled":
      run(port, mode, Ice.Controlled{4275878552, 1985229328})
    case _:
      IO.die(Unit, 2, "unknown ICE role")

def mode_run(mode: String, role: String, port: U32) -> IO(Unit):
  match mode:
    case "legacy":
      role_run(role, port, Auth.Legacy{})
    case "sha256":
      role_run(role, port, Auth.Sha256{})
    case "dual":
      role_run(role, port, Auth.Dual{})
    case "reuse":
      twice(port)
    case _:
      IO.die(Unit, 2, "unknown ICE mode")

def port_got(port: Maybe<&2, U32>, mode: String, role: String) -> IO(Unit):
  match port:
    case Some{p}:
      mode_run(mode, role, p)
    case None{}:
      IO.die(Unit, 2, "invalid port")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [port, mode, role]:
      port_got(U32.read(port), mode, role)
    case _:
      IO.die(Unit, 2, "usage: ice_exchange <port> <mode> <role>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
