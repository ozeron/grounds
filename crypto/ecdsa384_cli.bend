import Base
import ./ecdsa384.bend as E
import ./ecdsa_der384.bend as D
import ../io/io.bend as Io

def result(valid: Bool) -> IO(Unit):
  match valid:
    case False{}:
      IO.print("false")
    case True{}:
      IO.print("true")

def verify.parsed(peer: List<&2, U32>, digest: List<&2, U32>, value: Maybe<&1, List<&2, U32>>) -> IO(Unit):
  match value:
    case None{}: result(False{})
    case Some{signature}: result(E.verify_digest(peer, digest, signature))

def verify.mode(mode: String, peer: List<&2, U32>, digest: List<&2, U32>, signature: List<&2, U32>) -> IO(Unit):
  match mode:
    case "raw": result(E.verify_digest(peer, digest, signature))
    case "der": verify.parsed(peer, digest, D.decode(signature))
    case _: IO.die(Unit, 2, "expected raw or der")

def verify.read(mode: String, peer_path: String, digest_path: String, signature_path: String) -> IO(Unit):
  do IO<Unit>:
    peer : List<&2, U32> <- Io.read_bytes(peer_path)
    digest : List<&2, U32> <- Io.read_bytes(digest_path)
    signature : List<&2, U32> <- Io.read_bytes(signature_path)
    verify.mode(mode, peer, digest, signature)

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{mode, Con{peer, Con{digest, Con{signature, tail}}}}:
      do IO<Unit>:
        verify.read(mode, peer, digest, signature)
        dispatch(tail)
    case _:
      IO.die(Unit, 2, "usage: ecdsa384_cli <raw|der> <peer-file> <digest-file> <signature-file>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- Io.args()
    dispatch(args)
