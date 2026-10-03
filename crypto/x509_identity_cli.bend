import Base
import ./x509_identity.bend as I
import ./bytes.bend as B
import ../io/io.bend as Io

def show_bool(value: Bool) -> String:
  Bool.pick(String, value, "true", "false")

def query(mode: String, bytes: List<&2, U32>, reference: List<&2, U32>) -> Bool:
  match mode:
    case "0": I.dns(bytes, reference)
    case "1": I.ip(bytes, reference)
    case _: False{}

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{mode, Con{path, Con{reference_path, rest}}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        reference : List<&2, U32> <- Io.read_bytes(reference_path)
        IO.print(show_bool(query(mode, bytes, reference)))
        dispatch(rest)
    case _: IO.die(Unit, 2, "expected identity check operation and files")

def command.checked(valid: Bool, rest: List<String>) -> IO(Unit):
  match valid:
    case True{}: dispatch(rest)
    case False{}: IO.die(Unit, 2, "expected check command")

def command.shifted(args: List<String>) -> IO(Unit):
  match args:
    case Con{flag, rest}: command.checked(String.eq(flag, "check"), rest)
    case _: IO.die(Unit, 2, "expected check command")

def command.first(valid: Bool, rest: List<String>) -> IO(Unit):
  match valid:
    case True{}: dispatch(rest)
    case False{}: command.shifted(rest)

def command(args: List<String>) -> IO(Unit):
  match args:
    case Con{flag, rest}: command.first(String.eq(flag, "check"), rest)
    case _: IO.die(Unit, 2, "expected check command")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    command(args)
