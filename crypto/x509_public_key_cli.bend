import Base
import ./x509_public_key.bend as K
import ./x509_algorithm.bend as A
import ./bytes.bend as B
import ../io/io.bend as Io

def algorithm(value: A.Key) -> String:
  match value:
    case A.Rsa{}:
      "rsa"
    case A.PssAny{}:
      "pss-any"
    case A.Pss256{salt}:
      String.concat(["pss256-", U32.show(salt)])
    case A.P256{}:
      "p256"

def show(value: Maybe<&1, K.PublicKey>) -> String:
  match value:
    case Some{K.Rsa{kind, modulus, exponent}}:
      String.concat([algorithm(kind), ":", B.hex(modulus), ":", B.hex(exponent)])
    case Some{K.P256{encoded}}:
      String.concat(["p256:", B.hex(encoded)])
    case None{}:
      "none"

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{path, tail}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(show(K.decode(bytes)))
        dispatch(tail)

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
