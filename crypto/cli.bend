import Base
import ./sha256.bend as Sha
import ./hmac.bend as Hmac
import ../io/io.bend as Io

# Test adapter: hash a file's exact bytes and print its lowercase digest.
def emit(result: Maybe<&2, String>) -> IO(Unit):
  match result:
    case Some{hex}:
      IO.print(hex)
    case None{}:
      IO.die(Unit, 1, "invalid byte")

def run(path: String) -> IO(Unit):
  do IO<Unit>:
    bytes : List<&2, U32> <- Io.read_bytes(path)
    emit(Sha.digest_hex(bytes))

def run_hmac(key_path: String, path: String) -> IO(Unit):
  do IO<Unit>:
    key : List<&2, U32> <- Io.read_bytes(key_path)
    bytes : List<&2, U32> <- Io.read_bytes(path)
    emit(Hmac.digest_hex(key, bytes))

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{path, Nil{}}:
      run(path)
    case Con{key_path, Con{path, Nil{}}}:
      run_hmac(key_path, path)
    case _:
      IO.die(Unit, 2, "usage: crypto <file> | crypto <key-file> <file>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
