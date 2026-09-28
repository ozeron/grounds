import Base
import ./aead.bend as A
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

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{"seal", Con{key, Con{nonce, Con{aad, Con{plaintext, Nil{}}}}}}:
      seal_files(key, nonce, aad, plaintext)
    case Con{"open", Con{key, Con{nonce, Con{aad, Con{ciphertext, Con{tag, Nil{}}}}}}}:
      open_files(key, nonce, aad, ciphertext, tag)
    case _:
      IO.die(Unit, 2, "usage: aead_cli seal <key> <nonce> <aad> <plaintext> | open <key> <nonce> <aad> <ciphertext> <tag>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
