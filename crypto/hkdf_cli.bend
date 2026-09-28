import Base
import ./sha256.bend as Sha
import ./hkdf.bend as Hkdf
import ../io/io.bend as Io

def emit(result: Maybe<&2, String>) -> IO(Unit):
  match result:
    case Some{hex}:
      IO.print(hex)
    case None{}:
      IO.die(Unit, 1, "invalid HKDF input")

def report(result: Maybe<&2, List<&2, U32>>, info: List<&2, U32>, length: Nat) -> IO(Unit):
  match result:
    case None{}:
      IO.die(Unit, 1, "invalid HKDF input")
    case Some{+prk}:
      do IO<Unit>:
        x : Unit <- IO.print(Sha.hex(prk))
        emit(Hkdf.expand_hex(length, prk, info))

def run(salt_path: String, ikm_path: String, info_path: String, length: Nat) -> IO(Unit):
  do IO<Unit>:
    salt : List<&2, U32> <- Io.read_bytes(salt_path)
    ikm : List<&2, U32> <- Io.read_bytes(ikm_path)
    info : List<&2, U32> <- Io.read_bytes(info_path)
    report(Hkdf.extract(salt, ikm), info, length)

def length_got(got: Maybe<&2, U32>, salt_path: String, ikm_path: String, info_path: String) -> IO(Unit):
  match got:
    case None{}:
      IO.die(Unit, 2, "length must be a decimal byte count")
    case Some{length}:
      run(salt_path, ikm_path, info_path, U32.to_nat(length))

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{salt_path, Con{ikm_path, Con{info_path, Con{length, Nil{}}}}}:
      length_got(U32.read(length), salt_path, ikm_path, info_path)
    case _:
      IO.die(Unit, 2, "usage: hkdf <salt-file> <ikm-file> <info-file> <length>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
