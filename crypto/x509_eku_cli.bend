import Base
import ./x509_eku.bend as X
import ./bytes.bend as B
import ../io/io.bend as Io

def show_bool(value: Bool) -> String:
  Bool.pick(String, value, "true", "false")

def show_items(items: List<&2, List<&2, U32>>, reversed: String) -> String:
  match items:
    case Nil{}: String.reverse(reversed)
    case Con{oid, rest}: show_items(rest, String.reverse.go(String.concat([B.hex(oid), ";"]), reversed))

def show(items: Maybe<&1, List<&2, List<&2, U32>>>) -> String:
  match items:
    case None{}: "none"
    case Some{items}: show_items(items, "")

def optional(path: String) -> IO(Maybe<&2, List<&2, U32>>):
  match path:
    case "-": IO.pure(Maybe<&2, List<&2, U32>>, None{})
    case _:
      do IO<Maybe<&2, List<&2, U32>>>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.pure(Maybe<&2, List<&2, U32>>, Some{bytes})

def flag(+value: String) -> Bool:
  Bool.or(String.eq(value, "0"), String.eq(value, "1"))

def permits_print.checked(valid: Bool, bytes: Maybe<&2, List<&2, U32>>, purpose: List<&2, U32>, any: Bool) -> IO(Unit):
  match valid:
    case True{}: IO.print(show_bool(X.permits(bytes, purpose, any)))
    case False{}: IO.die(Unit, 2, "expected any-purpose flag 0 or 1")

def permits_print(bytes: Maybe<&2, List<&2, U32>>, purpose: List<&2, U32>, +any: String) -> IO(Unit):
  permits_print.checked(flag(any), bytes, purpose, String.eq(any, "1"))

def tls_print.checked(valid: Bool, usage: Maybe<&2, List<&2, U32>>, eku: Maybe<&2, List<&2, U32>>, role: Bool, any: Bool) -> IO(Unit):
  match valid:
    case True{}: IO.print(show_bool(X.tls13(usage, eku, role, any)))
    case False{}: IO.die(Unit, 2, "expected role and any-purpose flags 0 or 1")

def tls_print(usage: Maybe<&2, List<&2, U32>>, eku: Maybe<&2, List<&2, U32>>, +role: String, +any: String) -> IO(Unit):
  tls_print.checked(Bool.and(flag(role), flag(any)), usage, eku, String.eq(role, "1"), String.eq(any, "1"))

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{"0", Con{path, rest}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(show(X.decode(bytes)))
        dispatch(rest)
    case Con{"1", Con{path, Con{purpose_path, Con{any, rest}}}}:
      do IO<Unit>:
        bytes : Maybe<&2, List<&2, U32>> <- optional(path)
        purpose : List<&2, U32> <- Io.read_bytes(purpose_path)
        permits_print(bytes, purpose, any)
        dispatch(rest)
    case Con{"2", Con{usage_path, Con{eku_path, Con{role, Con{any, rest}}}}}:
      do IO<Unit>:
        usage : Maybe<&2, List<&2, U32>> <- optional(usage_path)
        eku : Maybe<&2, List<&2, U32>> <- optional(eku_path)
        tls_print(usage, eku, role, any)
        dispatch(rest)
    case _: IO.die(Unit, 2, "expected EKU check operation and files")

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
