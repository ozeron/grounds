import Base
import ./chacha20.bend as ChaCha
import ./bytes.bend as B
import ../io/io.bend as Io

# Test adapter: print one 64-byte RFC 8439 block as lowercase hex.
def emit(result: Maybe<&2, List<&2, U32>>) -> IO(Unit):
  match result:
    case Some{bytes}:
      IO.print(B.hex(bytes))
    case None{}:
      IO.die(Unit, 1, "invalid ChaCha20 key or nonce")

def run(key_path: String, nonce_path: String, counter: U32) -> IO(Unit):
  do IO<Unit>:
    key : List<&2, U32> <- Io.read_bytes(key_path)
    nonce : List<&2, U32> <- Io.read_bytes(nonce_path)
    emit(ChaCha.block(key, nonce, counter))

def run_crypt(key_path: String, nonce_path: String, counter: U32, path: String) -> IO(Unit):
  do IO<Unit>:
    key : List<&2, U32> <- Io.read_bytes(key_path)
    nonce : List<&2, U32> <- Io.read_bytes(nonce_path)
    bytes : List<&2, U32> <- Io.read_bytes(path)
    emit(ChaCha.crypt(key, nonce, counter, bytes))

def parsed(r: Maybe<&2, U32>, key_path: String, nonce_path: String) -> IO(Unit):
  match r:
    case None{}:
      IO.die(Unit, 2, "counter must be a U32")
    case Some{counter}:
      run(key_path, nonce_path, counter)

def parsed_crypt(r: Maybe<&2, U32>, key_path: String, nonce_path: String, path: String) -> IO(Unit):
  match r:
    case None{}:
      IO.die(Unit, 2, "counter must be a U32")
    case Some{counter}:
      run_crypt(key_path, nonce_path, counter, path)

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{key_path, Con{nonce_path, Con{counter, Nil{}}}}:
      parsed(U32.read(counter), key_path, nonce_path)
    case Con{key_path, Con{nonce_path, Con{counter, Con{path, Nil{}}}}}:
      parsed_crypt(U32.read(counter), key_path, nonce_path, path)
    case _:
      IO.die(Unit, 2, "usage: chacha_cli <key-file> <nonce-file> <counter> [message-file]")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
