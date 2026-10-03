import Base
import ./x509_extension_policy.bend as P
import ./x509_extensions.bend as E
import ./bytes.bend as B
import ../io/io.bend as Io

def show_bool(value: Bool) -> String:
  Bool.pick(String, value, "true", "false")

def payload(value: Maybe<&2, List<&2, U32>>, critical: Bool) -> String:
  match value:
    case None{}: "absent"
    case Some{bytes}: String.concat([show_bool(critical), ":", B.hex(bytes)])

def deferred(entries: List<&1, E.Extension>, reversed: String) -> String:
  match entries:
    case Nil{}: String.reverse(reversed)
    case Con{E.Extension{oid, _, bytes}, rest}:
      deferred(rest, String.reverse.go(String.concat([B.hex(oid), ":", B.hex(bytes), ";"]), reversed))

def show(value: Maybe<&1, P.Admission>) -> String:
  match value:
    case None{}: "none"
    case Some{P.Admission{basic, basic_critical, usage, usage_critical, rest}}:
      String.concat([payload(basic, basic_critical), "|", payload(usage, usage_critical), "|", deferred(rest, "")])

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{"0", Con{path, rest}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(show(P.decode(bytes)))
        dispatch(rest)
    case Con{"1", Con{path, rest}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(show(P.certificate(bytes)))
        dispatch(rest)
    case Con{"2", rest}:
      do IO<Unit>:
        IO.print(show(P.optional(None{})))
        dispatch(rest)
    case _: IO.die(Unit, 2, "expected <0=extensions|1=certificate|2=absent> and files")

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
