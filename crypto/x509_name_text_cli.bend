import Base
import ./x509_name_text.bend as T
import ../io/io.bend as Io

# Fixture transport: decimal ASN.1 tag and raw value file, repeated. Direct
# out-of-octet U32 inputs are covered by the checked Bend constructor test.
def codes(items: List<&2, U32>, reversed: String) -> String:
  match items:
    case Nil{}: String.reverse(reversed)
    case Con{code, rest}:
      codes(rest, String.reverse.go(String.concat([U32.show(code), ","]), reversed))

def show(result: Maybe<&1, List<&2, U32>>) -> String:
  match result:
    case Some{items}: String.concat(["some:", codes(items, "")])
    case None{}: "none"

def file(tag: Maybe<&2, U32>, path: String) -> IO(Unit):
  match tag:
    case Some{tag}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(show(T.decode(tag, bytes)))
    case None{}: IO.die(Unit, 2, "invalid string tag")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{tag, Con{path, rest}}:
      do IO<Unit>:
        file(U32.read(tag), path)
        dispatch(rest)
    case _: IO.die(Unit, 2, "expected string tag and value file")

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
