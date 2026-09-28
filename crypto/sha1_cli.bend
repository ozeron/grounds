import Base
import ./sha1.bend as Sha1
import ./bytes.bend as B
import ../io/io.bend as Io

def emit(result: Maybe<&2, List<&2, U32>>) -> IO(Unit):
  match result:
    case None{}:
      IO.die(Unit, 1, "invalid SHA-1 byte")
    case Some{bytes}:
      IO.print(B.hex(bytes))

def run(path: String) -> IO(Unit):
  do IO<Unit>:
    bytes : List<&2, U32> <- Io.read_bytes(path)
    emit(Sha1.digest(bytes))

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{path, Nil{}}:
      run(path)
    case _:
      IO.die(Unit, 2, "usage: sha1_cli <file>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
