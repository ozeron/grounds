import Base
import ./x509_constraints.bend as X
import ./bytes.bend as B
import ../io/io.bend as Io

def show_bool(value: Bool) -> String:
  Bool.pick(String, value, "true", "false")

def show_basic(value: Maybe<&1, X.Basic>) -> String:
  match value:
    case None{}: "none"
    case Some{X.Basic{ca, None{}}}: String.concat([show_bool(ca), ":none"])
    case Some{X.Basic{ca, Some{bytes}}}: String.concat([show_bool(ca), ":", B.hex(bytes)])

def show_usage(value: Maybe<&1, X.Usage>) -> String:
  match value:
    case None{}: "none"
    case Some{X.Usage{bits}}: U32.show(bits)

def allows(basic: Maybe<&1, X.Basic>, count: List<&2, U32>) -> Bool:
  match basic count:
    case Some{X.Basic{_, path}} Con{a, Con{b, Con{c, Con{d, Nil{}}}}}:
      X.path_allows(path, U32.add(U32.shln(a, 24n),
        U32.add(U32.shln(b, 16n), U32.add(U32.shln(c, 8n), d))))
    case _ _: False{}

def raw_allows(bytes: List<&2, U32>, count: List<&2, U32>) -> Bool:
  match count:
    case Con{a, Con{b, Con{c, Con{d, Nil{}}}}}:
      X.path_allows(Some{bytes}, U32.add(U32.shln(a, 24n),
        U32.add(U32.shln(b, 16n), U32.add(U32.shln(c, 8n), d))))
    case _: False{}

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{"0", Con{path, rest}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(show_basic(X.basic(bytes)))
        dispatch(rest)
    case Con{"1", Con{path, rest}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(show_usage(X.usage(bytes)))
        dispatch(rest)
    case Con{"2", Con{path, Con{count_path, rest}}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        count : List<&2, U32> <- Io.read_bytes(count_path)
        IO.print(show_bool(allows(X.basic(bytes), count)))
        dispatch(rest)
    case Con{"3", Con{basic_path, Con{usage_path, rest}}}:
      do IO<Unit>:
        basic : List<&2, U32> <- Io.read_bytes(basic_path)
        usage : List<&2, U32> <- Io.read_bytes(usage_path)
        IO.print(show_bool(X.policy(Some{basic}, Some{usage})))
        dispatch(rest)
    case Con{"4", Con{path, rest}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(show_bool(X.policy(None{}, Some{bytes})))
        dispatch(rest)
    case Con{"5", rest}:
      do IO<Unit>:
        IO.print(show_bool(X.policy(None{}, None{})))
        dispatch(rest)
    case Con{"6", Con{path, rest}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(show_bool(X.policy(Some{bytes}, None{})))
        dispatch(rest)
    case Con{"7", Con{path, Con{count_path, rest}}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        count : List<&2, U32> <- Io.read_bytes(count_path)
        IO.print(show_bool(raw_allows(bytes, count)))
        dispatch(rest)
    case _: IO.die(Unit, 2, "expected constraint check operation and files")

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
