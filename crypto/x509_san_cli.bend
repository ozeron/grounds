import Base
import ./x509_san.bend as S
import ../io/io.bend as Io

def show(value: Maybe<&1, Bool>) -> String:
  match value:
    case Some{True{}}: "supported"
    case Some{False{}}: "deferred"
    case None{}: "none"

def optional(path: String) -> IO(Maybe<&2, List<&2, U32>>):
  match path:
    case "-": IO.pure(Maybe<&2, List<&2, U32>>, None{})
    case path:
      do IO<Maybe<&2, List<&2, U32>>>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.pure(Maybe<&2, List<&2, U32>>, Some{bytes})

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{"0", Con{path, rest}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(show(S.inspect(bytes)))
        dispatch(rest)
    case Con{"1", Con{path, Con{extensions_path, rest}}}:
      do IO<Unit>:
        subject_bytes : List<&2, U32> <- Io.read_bytes(path)
        extensions : Maybe<&2, List<&2, U32>> <- optional(extensions_path)
        IO.print(Bool.pick(String, S.subject(subject_bytes, extensions), "true", "false"))
        dispatch(rest)
    case _: IO.die(Unit, 2, "expected SAN operation and files")

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
