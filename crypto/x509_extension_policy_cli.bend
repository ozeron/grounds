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
    case Con{E.Extension{oid, critical, bytes}, rest}:
      deferred(rest, String.reverse.go(String.concat([B.hex(oid), ":",
        Bool.pick(String, critical, "critical:", ""), B.hex(bytes), ";"]), reversed))

def show(value: Maybe<&1, P.Admission>) -> String:
  match value:
    case None{}: "none"
    case Some{P.Admission{basic, basic_critical, usage, usage_critical, rest}}:
      String.concat([payload(basic, basic_critical), "|", payload(usage, usage_critical), "|", deferred(rest, "")])

def flag(+value: String) -> Bool:
  Bool.or(String.eq(value, "0"), String.eq(value, "1"))

def tls_print.checked(valid: Bool, certificate: Bool, bytes: List<&2, U32>, role: Bool, any: Bool) -> IO(Unit):
  match valid certificate:
    case True{} False{}:
      IO.print(show_bool(P.tls13_extensions(bytes, role, any)))
    case True{} True{}:
      IO.print(show_bool(P.tls13_certificate(bytes, role, any)))
    case _ _: IO.die(Unit, 2, "expected role and any-purpose flags 0 or 1")

def tls_print(certificate: Bool, bytes: List<&2, U32>, +role: String, +any: String) -> IO(Unit):
  tls_print.checked(Bool.and(flag(role), flag(any)), certificate, bytes, String.eq(role, "1"), String.eq(any, "1"))

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
    case Con{"3", Con{path, Con{role, Con{any, rest}}}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        tls_print(False{}, bytes, role, any)
        dispatch(rest)
    case Con{"4", Con{path, Con{role, Con{any, rest}}}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        tls_print(True{}, bytes, role, any)
        dispatch(rest)
    case _: IO.die(Unit, 2, "expected extension policy operation and files")

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
