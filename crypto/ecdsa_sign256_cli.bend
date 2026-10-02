import Base
import ./ecdsa_sign256.bend as S
import ./bytes.bend as B
import ../io/io.bend as Io

def result(value: Maybe<&1, List<&2, U32>>) -> IO(Unit):
  match value:
    case None{}:
      IO.print("invalid")
    case Some{signature}:
      IO.print(B.hex(signature))

def read(private_path: String, digest_path: String) -> IO(Unit):
  do IO<Unit>:
    private : List<&2, U32> <- Io.read_bytes(private_path)
    digest : List<&2, U32> <- Io.read_bytes(digest_path)
    result(S.sign_digest(private, digest))

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{private, Con{digest, tail}}:
      do IO<Unit>:
        read(private, digest)
        dispatch(tail)
    case _:
      IO.die(Unit, 2, "usage: ecdsa_sign256_cli <private-file> <digest-file>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
