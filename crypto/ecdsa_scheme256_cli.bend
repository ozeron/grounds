import Base
import ./ecdsa_scheme256.bend as E
import ./bytes.bend as B
import ../io/io.bend as Io

# Exercise both public DER digest APIs without the internal rejection hooks.
def signature(value: Maybe<&1, List<&2, U32>>) -> IO(Unit):
  match value:
    case None{}:
      IO.print("invalid")
    case Some{value}:
      IO.print(B.hex(value))

def validity(value: Bool) -> IO(Unit):
  match value:
    case False{}:
      IO.print("false")
    case True{}:
      IO.print("true")

def sign(private_path: String, digest_path: String) -> IO(Unit):
  do IO<Unit>:
    private : List<&2, U32> <- Io.read_bytes(private_path)
    digest : List<&2, U32> <- Io.read_bytes(digest_path)
    signature(E.sign_digest(private, digest))

def verify(peer_path: String, digest_path: String, signature_path: String) -> IO(Unit):
  do IO<Unit>:
    peer : List<&2, U32> <- Io.read_bytes(peer_path)
    digest : List<&2, U32> <- Io.read_bytes(digest_path)
    encoded : List<&2, U32> <- Io.read_bytes(signature_path)
    validity(E.verify_digest(peer, digest, encoded))

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{"sign", Con{private, Con{digest, tail}}}:
      do IO<Unit>:
        sign(private, digest)
        dispatch(tail)
    case Con{"verify", Con{peer, Con{digest, Con{encoded, tail}}}}:
      do IO<Unit>:
        verify(peer, digest, encoded)
        dispatch(tail)
    case _:
      IO.die(Unit, 2, "usage: ecdsa_scheme256_cli <sign|verify> <files>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
