import Base
import ./gcm.bend as A
import ./bytes.bend as B
import ../io/io.bend as Io

def emit_seal(result: Maybe<&2, A.Sealed>) -> IO(Unit):
  match result:
    case None{}:
      IO.die(Unit, 1, "invalid AEAD input")
    case Some{A.Sealed{ciphertext, tag}}:
      do IO<Unit>:
        x : Unit <- IO.print(B.hex(ciphertext))
        IO.print(B.hex(tag))

def emit_open(result: Maybe<&2, List<&2, U32>>) -> IO(Unit):
  match result:
    case None{}:
      IO.die(Unit, 1, "AEAD authentication failed")
    case Some{plaintext}:
      IO.print(B.hex(plaintext))

def seal_files(key_path: String, nonce_path: String, aad_path: String, plaintext_path: String) -> IO(Unit):
  do IO<Unit>:
    key : List<&2, U32> <- Io.read_bytes(key_path)
    nonce : List<&2, U32> <- Io.read_bytes(nonce_path)
    aad : List<&2, U32> <- Io.read_bytes(aad_path)
    plaintext : List<&2, U32> <- Io.read_bytes(plaintext_path)
    emit_seal(A.seal(key, nonce, aad, plaintext))

def open_files(key_path: String, nonce_path: String, aad_path: String, ciphertext_path: String, tag_path: String) -> IO(Unit):
  do IO<Unit>:
    key : List<&2, U32> <- Io.read_bytes(key_path)
    nonce : List<&2, U32> <- Io.read_bytes(nonce_path)
    aad : List<&2, U32> <- Io.read_bytes(aad_path)
    ciphertext : List<&2, U32> <- Io.read_bytes(ciphertext_path)
    tag : List<&2, U32> <- Io.read_bytes(tag_path)
    emit_open(A.open(key, nonce, aad, ciphertext, tag))

# Test-only length diagnostics reach counter limits without allocating messages.
def length_emit(+length: Nat) -> IO(Unit):
  do IO<Unit>:
    x : Unit <- IO.print(B.hex(A.length64(length)))
    y : Unit <- IO.print(Bool.pick(String, A.plaintext_length(length), "true", "false"))
    IO.print(Nat.show(A.block_count(length)))

def length_checked(ok: Bool, high: U32, low: U32) -> IO(Unit):
  match ok:
    case False{}:
      IO.die(Unit, 2, "length exceeds Bend Nat")
    case True{}:
      length_emit(Nat.add(Nat.mul(U32.to_nat(high), Nat.add(4294967295n, 1n)), U32.to_nat(low)))

def length_parsed(high: Maybe<&2, U32>, low: Maybe<&2, U32>) -> IO(Unit):
  match high low:
    case Some{+high} Some{low}:
      length_checked(U32.is_le(high, 65535), high, low)
    case _ _:
      IO.die(Unit, 2, "length words must be U32")

def multiply_checked(ok: Bool, left: List<&2, U32>, right: List<&2, U32>) -> IO(Unit):
  match ok:
    case False{}:
      IO.die(Unit, 2, "field operands must be 16 bytes")
    case True{}:
      IO.print(B.hex(A.field.bytes(A.multiply(A.field(left), A.field(right)))))

def multiply_input(+left: List<&2, U32>, +right: List<&2, U32>) -> IO(Unit):
  multiply_checked(Bool.and(Nat.is_eq(B.length(left), 16n), Nat.is_eq(B.length(right), 16n)), left, right)

def multiply_files(left_path: String, right_path: String) -> IO(Unit):
  do IO<Unit>:
    left : List<&2, U32> <- Io.read_bytes(left_path)
    right : List<&2, U32> <- Io.read_bytes(right_path)
    multiply_input(left, right)

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{"multiply", Con{left, Con{right, Nil{}}}}:
      multiply_files(left, right)
    case Con{"length", Con{high, Con{low, Nil{}}}}:
      length_parsed(U32.read(high), U32.read(low))
    case Con{"seal", Con{key, Con{nonce, Con{aad, Con{plaintext, Nil{}}}}}}:
      seal_files(key, nonce, aad, plaintext)
    case Con{"open", Con{key, Con{nonce, Con{aad, Con{ciphertext, Con{tag, Nil{}}}}}}}:
      open_files(key, nonce, aad, ciphertext, tag)
    case _:
      IO.die(Unit, 2, "usage: gcm_cli seal <key> <nonce> <aad> <plaintext> | open <key> <nonce> <aad> <ciphertext> <tag>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
