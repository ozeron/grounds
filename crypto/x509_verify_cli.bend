import Base
import ./x509_signature.bend as S
import ../io/io.bend as Io

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{issuer_path, Con{certificate_path, rest}}:
      do IO<Unit>:
        issuer : List<&2, U32> <- Io.read_bytes(issuer_path)
        certificate : List<&2, U32> <- Io.read_bytes(certificate_path)
        IO.print(Bool.pick(String, S.verify_signature(issuer, certificate), "true", "false"))
        dispatch(rest)
    case _:
      IO.die(Unit, 2, "usage: x509_verify_cli verify <issuer-spki> <certificate> ...")

# Bend 2.0.27 returns only arguments; 2.0.32+ includes the invoked program.
# Require an explicit fixture command in either position so paths are never
# guessed from argument parity. No certificate logic lives in this adapter.
def command.checked(valid: Bool, rest: List<String>) -> IO(Unit):
  match valid:
    case True{}:
      dispatch(rest)
    case False{}:
      IO.die(Unit, 2, "usage: x509_verify_cli verify <issuer-spki> <certificate> ...")

def command.shifted(args: List<String>) -> IO(Unit):
  match args:
    case Con{flag, rest}:
      command.checked(String.eq(flag, "verify"), rest)
    case _:
      IO.die(Unit, 2, "usage: x509_verify_cli verify <issuer-spki> <certificate> ...")

def command.first(valid: Bool, rest: List<String>) -> IO(Unit):
  match valid:
    case True{}:
      dispatch(rest)
    case False{}:
      command.shifted(rest)

def command(args: List<String>) -> IO(Unit):
  match args:
    case Con{flag, rest}:
      command.first(String.eq(flag, "verify"), rest)
    case _:
      IO.die(Unit, 2, "usage: x509_verify_cli verify <issuer-spki> <certificate> ...")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    command(args)
