import Base
import ../ice_binding.bend as Ice
import ../stun_auth.bend as Auth
import ../../io/io.bend as Io
import ./auth.bend as Output

def with_role(role: String, +high: U32, +low: U32, priority: U32,
              credentials: Ice.Credentials, mode: Auth.Mode, transaction: List<&2, U32>) -> IO(Unit):
  match role:
    case "controlling":
      Output.emit(Ice.request(transaction, credentials, Ice.Check{priority, Ice.Controlling{high, low}}, mode))
    case "controlled":
      Output.emit(Ice.request(transaction, credentials, Ice.Check{priority, Ice.Controlled{high, low}}, mode))
    case _:
      IO.die(Unit, 2, "unknown ICE role")

def with_numbers(priority: Maybe<&2, U32>, high: Maybe<&2, U32>, low: Maybe<&2, U32>,
                 role: String, credentials: Ice.Credentials, mode: Auth.Mode, transaction: List<&2, U32>) -> IO(Unit):
  match priority high low:
    case Some{p} Some{h} Some{l}:
      with_role(role, h, l, p, credentials, mode, transaction)
    case _ _ _:
      IO.die(Unit, 2, "invalid ICE numeric argument")

def with_mode(name: String, role: String, credentials: Ice.Credentials,
              priority: String, high: String, low: String, transaction: List<&2, U32>) -> IO(Unit):
  match name:
    case "legacy":
      with_numbers(U32.read(priority), U32.read(high), U32.read(low), role, credentials, Auth.Legacy{}, transaction)
    case "sha256":
      with_numbers(U32.read(priority), U32.read(high), U32.read(low), role, credentials, Auth.Sha256{}, transaction)
    case "dual":
      with_numbers(U32.read(priority), U32.read(high), U32.read(low), role, credentials, Auth.Dual{}, transaction)
    case _:
      IO.die(Unit, 2, "unknown ICE mode")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [mode, role, local, remote, password, priority, high, low, path]:
      do IO<Unit>:
        transaction : List<&2, U32> <- Io.read_bytes(path)
        with_mode(mode, role, Ice.Credentials{local, remote, password}, priority, high, low, transaction)
    case _:
      IO.die(Unit, 2, "usage: ice_build <mode> <role> <local> <remote> <password> <priority> <high> <low> <transaction-file>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
