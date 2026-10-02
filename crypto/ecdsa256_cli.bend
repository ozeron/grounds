import Base
import ./ecdsa256.bend as E
import ../io/io.bend as Io

def result(valid: Bool) -> IO(Unit):
  match valid:
    case False{}:
      IO.print("false")
    case True{}:
      IO.print("true")

def verify.read(peer_path: String, digest_path: String, signature_path: String) -> IO(Unit):
  do IO<Unit>:
    peer : List<&2, U32> <- Io.read_bytes(peer_path)
    digest : List<&2, U32> <- Io.read_bytes(digest_path)
    signature : List<&2, U32> <- Io.read_bytes(signature_path)
    result(E.verify_digest(peer, digest, signature))

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{peer, Con{digest, Con{signature, tail}}}:
      do IO<Unit>:
        verify.read(peer, digest, signature)
        dispatch(tail)
    case _:
      IO.die(Unit, 2, "usage: ecdsa256_cli <peer-file> <digest-file> <raw-signature-file>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
