import Base
import ./hmac_sha1.bend as Hmac
import ./bytes.bend as B
import ../io/io.bend as Io

def emit(result: Maybe<&2, List<&2, U32>>) -> IO(Unit):
  match result:
    case None{}:
      IO.die(Unit, 1, "invalid HMAC-SHA1 input")
    case Some{bytes}:
      IO.print(B.hex(bytes))

def run(key_path: String, message_path: String) -> IO(Unit):
  do IO<Unit>:
    key : List<&2, U32> <- Io.read_bytes(key_path)
    message : List<&2, U32> <- Io.read_bytes(message_path)
    emit(Hmac.digest(key, message))

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{key_path, Con{message_path, Nil{}}}:
      run(key_path, message_path)
    case _:
      IO.die(Unit, 2, "usage: hmac_sha1_cli <key-file> <message-file>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
