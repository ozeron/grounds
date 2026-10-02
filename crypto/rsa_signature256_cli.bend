import Base
import ./rsa_signature256.bend as S
import ../io/io.bend as Io

def emit(value: Bool) -> IO(Unit):
  match value:
    case False{}:
      IO.print("false")
    case True{}:
      IO.print("true")

def pss(n: String, e: String, d: String, s: String) -> IO(Unit):
  do IO<Unit>:
    modulus : List<&2, U32> <- Io.read_bytes(n)
    exponent : List<&2, U32> <- Io.read_bytes(e)
    digest : List<&2, U32> <- Io.read_bytes(d)
    signature : List<&2, U32> <- Io.read_bytes(s)
    emit(S.verify_pss_digest(modulus, exponent, digest, signature))

def v15(n: String, e: String, d: String, s: String) -> IO(Unit):
  do IO<Unit>:
    modulus : List<&2, U32> <- Io.read_bytes(n)
    exponent : List<&2, U32> <- Io.read_bytes(e)
    digest : List<&2, U32> <- Io.read_bytes(d)
    signature : List<&2, U32> <- Io.read_bytes(s)
    emit(S.verify_v15_digest(modulus, exponent, digest, signature))

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{"0", Con{n, Con{e, Con{d, Con{s, tail}}}}}:
      do IO<Unit>:
        pss(n, e, d, s)
        dispatch(tail)
    case Con{"1", Con{n, Con{e, Con{d, Con{s, tail}}}}}:
      do IO<Unit>:
        v15(n, e, d, s)
        dispatch(tail)
    case _:
      IO.die(Unit, 2, "usage: rsa_signature256_cli <0=pss|1=v15> <n> <e> <digest> <signature>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
