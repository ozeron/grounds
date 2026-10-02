import Base
import ./oid.bend as O
import ./x509_extensions.bend as X
import ./x509_certificate.bend as C
import ./bytes.bend as B
import ../io/io.bend as Io

def show_oid(value: Maybe<&1, List<&2, U32>>) -> String:
  match value:
    case Some{bytes}: B.hex(bytes)
    case None{}: "none"

def separator(first: Bool, reversed: String) -> String:
  match first:
    case True{}: reversed
    case False{}: SCon{Char.from_u32(44), reversed}

def record(entry: X.Extension, reversed: String) -> String:
  match entry:
    case X.Extension{oid, critical, value}:
      String.reverse.go(B.hex(value), SCon{Char.from_u32(58),
        String.reverse.go(Bool.pick(String, critical, "true", "false"),
          SCon{Char.from_u32(58), String.reverse.go(B.hex(oid), reversed)})})

# Accumulate output directly; Base String.join recursively retains every row.
def records(entries: List<&1, X.Extension>, reversed: String, first: Bool) -> String:
  match entries:
    case Nil{}: String.reverse(reversed)
    case Con{entry, rest}:
      records(rest, record(entry, separator(first, reversed)), False{})

def show(value: Maybe<&1, List<&1, X.Extension>>) -> String:
  match value:
    case Some{entries}: records(entries, "", True{})
    case None{}: "none"

def certificate(value: Maybe<&1, C.Certificate>) -> Maybe<&1, List<&1, X.Extension>>:
  match value:
    case Some{C.Certificate{C.Tbs{_, _, C.Tail{_, _, extensions}}, _, _}}:
      X.optional(extensions)
    case None{}: None{}

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{"0", Con{path, rest}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(show_oid(O.decode(bytes)))
        dispatch(rest)
    case Con{"1", Con{path, rest}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(show(X.decode(bytes)))
        dispatch(rest)
    case Con{"2", Con{path, rest}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(show(certificate(C.decode(bytes))))
        dispatch(rest)
    case _: IO.die(Unit, 2, "usage: x509_extensions_cli check <0=oid|1=extensions|2=certificate> <file> ...")

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
