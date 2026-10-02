import Base
import ./rsa_encoding.bend as E
import ./bytes.bend as B
import ../io/io.bend as Io

# Numeric fixture opcodes avoid long String literal-pattern expansion:
# 0=MGF1, 1=PSS encode, 2=PSS verify, 3=v1.5 encode, 4=v1.5 verify.
def emit(value: Maybe<&2, List<&2, U32>>) -> IO(Unit):
  match value:
    case None{}:
      IO.print("invalid")
    case Some{bytes}:
      IO.print(B.hex(bytes))

def validity(value: Bool) -> IO(Unit):
  match value:
    case False{}:
      IO.print("false")
    case True{}:
      IO.print("true")

def number(value: Maybe<&2, U32>, next: Nat -> IO(Unit)) -> IO(Unit):
  match value:
    case None{}:
      IO.die(Unit, 2, "expected a decimal count")
    case Some{value}:
      next(U32.to_nat(value))

def mgf(length: Nat, seed_path: String) -> IO(Unit):
  do IO<Unit>:
    seed : List<&2, U32> <- Io.read_bytes(seed_path)
    emit(E.mgf1(length, seed))

def pss_encoded(bits: Nat, digest_path: String, salt_path: String) -> IO(Unit):
  do IO<Unit>:
    digest : List<&2, U32> <- Io.read_bytes(digest_path)
    salt : List<&2, U32> <- Io.read_bytes(salt_path)
    emit(E.pss_encode_digest(bits, digest, salt))

def pss_verified(bits: Nat, digest_path: String, encoded_path: String) -> IO(Unit):
  do IO<Unit>:
    digest : List<&2, U32> <- Io.read_bytes(digest_path)
    encoded : List<&2, U32> <- Io.read_bytes(encoded_path)
    validity(E.pss_verify_digest(bits, digest, encoded))

def v15_encoded(length: Nat, digest_path: String) -> IO(Unit):
  do IO<Unit>:
    digest : List<&2, U32> <- Io.read_bytes(digest_path)
    emit(E.v15_encode_digest(length, digest))

def v15_verified(digest_path: String, encoded_path: String) -> IO(Unit):
  do IO<Unit>:
    digest : List<&2, U32> <- Io.read_bytes(digest_path)
    encoded : List<&2, U32> <- Io.read_bytes(encoded_path)
    validity(E.v15_verify_digest(digest, encoded))

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{"0", Con{count, Con{seed, tail}}}:
      do IO<Unit>:
        number(U32.read(count), n => mgf(n, seed))
        dispatch(tail)
    case Con{"1", Con{bits, Con{digest, Con{salt, tail}}}}:
      do IO<Unit>:
        number(U32.read(bits), n => pss_encoded(n, digest, salt))
        dispatch(tail)
    case Con{"2", Con{bits, Con{digest, Con{encoded, tail}}}}:
      do IO<Unit>:
        number(U32.read(bits), n => pss_verified(n, digest, encoded))
        dispatch(tail)
    case Con{"3", Con{count, Con{digest, tail}}}:
      do IO<Unit>:
        number(U32.read(count), n => v15_encoded(n, digest))
        dispatch(tail)
    case Con{"4", Con{digest, Con{encoded, tail}}}:
      do IO<Unit>:
        v15_verified(digest, encoded)
        dispatch(tail)
    case _:
      IO.die(Unit, 2, "usage: rsa_encoding_cli <operation> <count?> <files>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
