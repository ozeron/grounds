import Base
import ./x509_certificate.bend as C
import ./x509_algorithm.bend as A
import ./bytes.bend as B
import ../io/io.bend as Io

def optional(value: Maybe<&2, List<&2, U32>>) -> String:
  match value:
    case Some{bytes}:
      B.hex(bytes)
    case None{}:
      "none"

def algorithm(value: A.Signature) -> String:
  match value:
    case A.RsaPss256{}:
      "pss256"
    case A.RsaV15256{}:
      "v15256"
    case A.Ecdsa256{}:
      "ecdsa256"

def show(value: Maybe<&1, C.Certificate>) -> String:
  match value:
    case Some{C.Certificate{C.Tbs{C.Header{encoded, version, serial, _}, C.Identity{issuer, validity, subject, spki}, C.Tail{issuer_id, subject_id, extensions}}, kind, signature}}:
      String.concat([U32.show(version), ":", B.hex(serial), ":", algorithm(kind), ":", B.hex(encoded),
        ":", B.hex(issuer), ":", B.hex(validity), ":", B.hex(subject), ":", B.hex(spki),
        ":", optional(issuer_id), ":", optional(subject_id), ":", optional(extensions), ":", B.hex(signature)])
    case None{}:
      "none"

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{path, tail}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(show(C.decode(bytes)))
        dispatch(tail)

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
