import Base
import ../stun_auth.bend as Auth
import ../stun.bend as Stun
import ../../crypto/bytes.bend as B
import ../../io/io.bend as Io

# File-based test adapter for independent native/JS protocol checks.
def emit(result: Maybe<&2, List<&2, U32>>) -> IO(Unit):
  match result:
    case Some{bytes}:
      IO.print(B.hex(bytes))
    case None{}:
      IO.die(Unit, 1, "invalid STUN authentication input")

def attrs(items: List<&2, Stun.Attribute>) -> IO(Unit):
  match items:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{Stun.Attribute{kind, value}, tail}:
      do IO<Unit>:
        x : Unit <- IO.print(U32.show(kind) ++ ":" ++ B.hex(value))
        attrs(tail)

def report(packet: Maybe<&2, Stun.Packet>) -> IO(Unit):
  match packet:
    case Some{Stun.Packet{_, _, items}}:
      do IO<Unit>:
        x : Unit <- IO.print("authenticated")
        attrs(items)
    case None{}:
      IO.die(Unit, 1, "invalid STUN authentication input")

def run(op: String, raw: List<&2, U32>, key: List<&2, U32>, mode: Auth.Mode) -> IO(Unit):
  match op:
    case "seal":
      emit(Auth.seal(raw, key, mode))
    case "sign":
      emit(Auth.sign(raw, key, mode))
    case "verify":
      report(Auth.authenticate(raw, key, mode))
    case "response":
      report(Auth.authenticate_response(raw, key, mode))
    case _:
      IO.die(Unit, 2, "unknown STUN operation")

def mode_run(name: String, op: String, raw: List<&2, U32>, key: List<&2, U32>) -> IO(Unit):
  match name:
    case "legacy":
      run(op, raw, key, Auth.Legacy{})
    case "sha256":
      run(op, raw, key, Auth.Sha256{})
    case "dual":
      run(op, raw, key, Auth.Dual{})
    case _:
      IO.die(Unit, 2, "unknown STUN integrity mode")

def files(op: String, mode: String, raw_path: String, key_path: String) -> IO(Unit):
  do IO<Unit>:
    raw : List<&2, U32> <- Io.read_bytes(raw_path)
    key : List<&2, U32> <- Io.read_bytes(key_path)
    mode_run(mode, op, raw, key)

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{op, Con{mode, Con{raw_path, Con{key_path, Nil{}}}}}:
      files(op, mode, raw_path, key_path)
    case _:
      IO.die(Unit, 2, "usage: auth seal|sign|verify|response legacy|sha256|dual <packet-file> <key-file>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
