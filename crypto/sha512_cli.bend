import Base
import ./sha512_file.bend as FileSha
import ./hmac_sha384.bend as Hmac
import ../io/io.bend as Io

def emit(result: Maybe<&2, String>) -> IO(Unit):
  match result:
    case Some{hex}: IO.print(hex)
    case None{}: IO.die(Unit, 1, "invalid byte")

def run(sha384: Bool, path: String) -> IO(Unit):
  do IO<Unit>:
    result : Maybe<&2, String> <- FileSha.digest_hex(sha384, path)
    emit(result)

def run_hmac(key_path: String, path: String) -> IO(Unit):
  do IO<Unit>:
    key : List<&2, U32> <- Io.read_bytes(key_path)
    bytes : List<&2, U32> <- Io.read_bytes(path)
    emit(Hmac.digest_hex(key, bytes))

def mode_run(mode: String, path: String) -> IO(Unit):
  match mode:
    case "sha384": run(True{}, path)
    case "sha512": run(False{}, path)
    case _: IO.die(Unit, 2, "expected sha384 or sha512")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{mode, Con{path, Nil{}}}:
      mode_run(mode, path)
    case Con{key_path, Con{path, Con{"hmac", Nil{}}}}:
      run_hmac(key_path, path)
    case _: IO.die(Unit, 2, "usage: sha512 <sha384|sha512> <file> | <key-file> <file> hmac")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- Io.args()
    dispatch(args)
