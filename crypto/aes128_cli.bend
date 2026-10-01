import Base
import ./aes128.bend as AES
import ./bytes.bend as B
import ../io/io.bend as Io

# Test adapter; production callers use the pure block interface.
def emit(result: Maybe<&2, List<&2, U32>>) -> IO(Unit):
  match result:
    case Some{bytes}:
      IO.print(B.hex(bytes))
    case None{}:
      IO.die(Unit, 1, "AES-128 requires a 16-byte key and block")

def run(key_path: String, block_path: String) -> IO(Unit):
  do IO<Unit>:
    key : List<&2, U32> <- Io.read_bytes(key_path)
    block : List<&2, U32> <- Io.read_bytes(block_path)
    emit(AES.encrypt(key, block))

def table(left: Nat, +byte: U32, reversed: List<&2, U32>) -> List<&2, U32>:
  match left:
    case 0n:
      List.reverse(&2, U32, reversed)
    case 1n+p:
      table(p, U32.inc(byte), Con{AES.sbox(byte), reversed})

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{"sbox", Nil{}}:
      IO.print(B.hex(table(256n, 0, [])))
    case Con{key_path, Con{block_path, Nil{}}}:
      run(key_path, block_path)
    case _:
      IO.die(Unit, 2, "usage: aes128_cli <key-file> <block-file> | sbox")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
