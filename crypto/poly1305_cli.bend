import Base
import ./poly1305.bend as P
import ./bytes.bend as B
import ../io/io.bend as Io

def emit(result: Maybe<&2, List<&2, U32>>) -> IO(Unit):
  match result:
    case Some{bytes}:
      IO.print(B.hex(bytes))
    case None{}:
      IO.die(Unit, 1, "invalid Poly1305 input")

def run(key_path: String, data_path: String) -> IO(Unit):
  do IO<Unit>:
    key : List<&2, U32> <- Io.read_bytes(key_path)
    data : List<&2, U32> <- Io.read_bytes(data_path)
    emit(P.mac(key, data))

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{key, Con{data, Nil{}}}:
      run(key, data)
    case _:
      IO.die(Unit, 2, "usage: poly1305_cli <one-time-key-file> <message-file>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
