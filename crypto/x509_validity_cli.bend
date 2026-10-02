import Base
import ./x509_validity.bend as V
import ./x509_certificate.bend as C
import ../io/io.bend as Io

def show_time(value: Maybe<&1, Nat>) -> String:
  match value:
    case Some{value}: Nat.show(value)
    case None{}: "none"

def show_validity(value: Maybe<&1, V.Validity>) -> String:
  match value:
    case Some{V.Validity{before, after}}: String.concat([Nat.show(before), ":", Nat.show(after)])
    case None{}: "none"

def at(value: List<&2, U32>, now: Maybe<&1, Nat>) -> Bool:
  match now:
    case Some{now}: V.valid_at(value, now)
    case None{}: False{}

def certificate(value: Maybe<&1, C.Certificate>, now: Maybe<&1, Nat>) -> Bool:
  match value:
    case Some{C.Certificate{C.Tbs{_, C.Identity{_, validity, _, _}, _}, _, _}}:
      at(validity, now)
    case None{}: False{}

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{"0", Con{path, rest}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(show_time(V.decode_time(bytes)))
        dispatch(rest)
    case Con{"1", Con{path, rest}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(show_validity(V.decode(bytes)))
        dispatch(rest)
    case Con{"2", Con{path, Con{now_path, rest}}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        now : List<&2, U32> <- Io.read_bytes(now_path)
        IO.print(Bool.pick(String, at(bytes, V.decode_time(now)), "true", "false"))
        dispatch(rest)
    case Con{"3", Con{path, Con{now_path, rest}}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        now : List<&2, U32> <- Io.read_bytes(now_path)
        IO.print(Bool.pick(String, certificate(C.decode(bytes), V.decode_time(now)), "true", "false"))
        dispatch(rest)
    case _: IO.die(Unit, 2, "usage: x509_validity_cli check <0=time|1=validity|2=at|3=certificate-at> <files> ...")

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
