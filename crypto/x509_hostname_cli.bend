import Base
import ./x509_identity.bend as I
import ./x509_hostname.bend as H
import ./bytes.bend as B
import ../io/io.bend as Io

def show_bool(value: Bool) -> String:
  Bool.pick(String, value, "true", "false")

def show_items(items: List<&2, H.Name>, reversed: String) -> String:
  match items:
    case Nil{}: String.reverse(reversed)
    case Con{H.Name{tag, bytes}, rest}:
      show_items(rest, String.reverse.go(String.concat([U32.show(tag), ":", B.hex(bytes), ";"]), reversed))

def show(items: Maybe<&1, List<&2, H.Name>>) -> String:
  match items:
    case None{}: "none"
    case Some{items}: show_items(items, "")

def query(mode: String, bytes: List<&2, U32>, reference: List<&2, U32>, kind: String) -> Bool:
  match mode kind:
    case "0" _: I.dns(bytes, reference)
    case "1" _: I.ip(bytes, reference)
    case "2" "0": H.san(bytes, 0, reference)
    case "2" "1": H.san(bytes, 1, reference)
    case "3" "0": H.extensions(bytes, 0, reference)
    case "3" "1": H.extensions(bytes, 1, reference)
    case "4" "0": H.certificate(bytes, 0, reference)
    case "4" "1": H.certificate(bytes, 1, reference)
    case _ _: False{}

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{"5", Con{path, rest}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(show(H.frame(bytes)))
        dispatch(rest)
    case Con{mode, Con{path, Con{reference_path, Con{kind, rest}}}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        reference : List<&2, U32> <- Io.read_bytes(reference_path)
        IO.print(show_bool(query(mode, bytes, reference, kind)))
        dispatch(rest)
    case _: IO.die(Unit, 2, "expected hostname check operation and files")

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
