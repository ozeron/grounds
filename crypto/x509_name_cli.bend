import Base
import ./x509_name.bend as N
import ./x509_name_certificate.bend as C
import ./bytes.bend as B
import ../io/io.bend as Io

def attributes(items: List<&2, N.Attribute>, reversed: String) -> String:
  match items:
    case Nil{}: String.reverse(reversed)
    case Con{N.Attribute{oid, tag, bytes, encoded}, rest}:
      attributes(rest, String.reverse.go(String.concat([B.hex(oid), ":", U32.show(tag), ":", B.hex(bytes), ":", B.hex(encoded), ";"]), reversed))

def rdns(items: List<&2, List<&2, N.Attribute>>, reversed: String) -> String:
  match items:
    case Nil{}: String.reverse(reversed)
    case Con{members, rest}: rdns(rest, String.reverse.go(String.concat([attributes(members, ""), "/"]), reversed))

def show(value: Maybe<&1, N.Name>) -> String:
  match value:
    case None{}: "none"
    case Some{N.Name{items, supported}}:
      String.concat([Bool.pick(String, supported, "supported", "deferred"), "|", rdns(items, "")])

def inspect(value: Maybe<&1, Bool>) -> String:
  match value:
    case None{}: "none"
    case Some{supported}: Bool.pick(String, supported, "supported", "deferred")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{"0", Con{path, rest}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(show(N.decode(bytes)))
        dispatch(rest)
    case Con{"1", Con{path, rest}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(inspect(N.inspect(bytes, False{})))
        dispatch(rest)
    case Con{"2", Con{path, rest}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(inspect(C.certificate(bytes)))
        dispatch(rest)
    case _: IO.die(Unit, 2, "expected Name operation and files")

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
