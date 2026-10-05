import Base
import ./x509_name_match.bend as N
import ./unicode32_prepare.bend as U
import ./unicode32_prepare_cli.bend as A
import ./x509_name_prepare_cli.bend as F
import ./unicode32_nfkc_cli.bend as R
import ../io/io.bend as Io

# U32BE count, then left length/DER and right length/DER per comparison.
type Record is Data:
  Record{a: List<&2, U32>, b: List<&2, U32>, rest: List<&2, U32>}

def record.right(a: List<&2, U32>, result: Maybe<F.Part>) -> Maybe<Record>:
  match result:
    case Some{F.Part{b, rest}}: Some{Record{a, b, rest}}
    case None{}: None{}

def record.left(result: Maybe<F.Part>) -> Maybe<Record>:
  match result:
    case Some{F.Part{a, Con{x, Con{y, Con{z, Con{w, rest}}}}}}:
      record.right(a, F.part(U32.to_nat(R.word(x, y, z, w)), rest, []))
    case _: None{}

def record(bytes: List<&2, U32>) -> Maybe<Record>:
  match bytes:
    case Con{x, Con{y, Con{z, Con{w, rest}}}}:
      record.left(F.part(U32.to_nat(R.word(x, y, z, w)), rest, []))
    case _: None{}

def show(result: Maybe<&1, Bool>) -> String:
  match result:
    case Some{True{}}: "same"
    case Some{False{}}: "different"
    case None{}: "none"

def batch.compared(rest: List<&2, U32>, result: U.Tables & Maybe<&1, Bool>,
  next: List<&2, U32> -> U.Tables -> IO(U.Tables)) -> IO(U.Tables):
  (tables, value) = result
  do IO<U.Tables>:
    IO.print(show(value))
    next(rest, tables)

def batch.record(tables: U.Tables, result: Maybe<Record>,
  next: List<&2, U32> -> U.Tables -> IO(U.Tables)) -> IO(U.Tables):
  match result:
    case Some{Record{a, b, rest}}: batch.compared(rest, N.compare(tables, a, b), next)
    case None{}: IO.die(U.Tables, 2, "truncated Name pair record")

def batch(left: Nat, bytes: List<&2, U32>, tables: U.Tables) -> IO(U.Tables):
  match left bytes:
    case 0n Nil{}: IO.pure(U.Tables, tables)
    case 0n _: IO.die(U.Tables, 2, "trailing batch bytes")
    case 1n+p bytes: batch.record(tables, record(bytes), xs => t => batch(p, xs, t))

def file(tables: U.Tables, bytes: List<&2, U32>) -> IO(U.Tables):
  match bytes:
    case Con{x, Con{y, Con{z, Con{w, rest}}}}: batch(U32.to_nat(R.word(x, y, z, w)), rest, tables)
    case _: IO.die(U.Tables, 2, "truncated batch header")

def read_file(tables: U.Tables, path: String) -> IO(U.Tables):
  do IO<U.Tables>:
    bytes : List<&2, U32> <- Io.read_bytes(path)
    file(tables, bytes)

def dispatch(args: List<String>, tables: U.Tables) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{path, rest}:
      do IO<Unit>:
        next : U.Tables <- read_file(tables, path)
        dispatch(rest, next)

def loaded(args: List<String>, result: Maybe<&1, U.Tables>) -> IO(Unit):
  match result:
    case Some{tables}: dispatch(args, tables)
    case None{}: IO.die(Unit, 2, "invalid Unicode 3.2 table asset")

def asset(args: List<String>) -> IO(Unit):
  match args:
    case Con{path, Con{profile_path, rest}}:
      do IO<Unit>:
        tables : Maybe<&1, U.Tables> <- A.read_tables(path, profile_path)
        loaded(rest, tables)
    case _: IO.die(Unit, 2, "expected two table assets and batch files")

def command.checked(valid: Bool, rest: List<String>) -> IO(Unit):
  match valid:
    case True{}: asset(rest)
    case False{}: IO.die(Unit, 2, "expected check command")

def command.shifted(args: List<String>) -> IO(Unit):
  match args:
    case Con{flag, rest}: command.checked(String.eq(flag, "check"), rest)
    case _: IO.die(Unit, 2, "expected check command")

def command.first(valid: Bool, rest: List<String>) -> IO(Unit):
  match valid:
    case True{}: asset(rest)
    case False{}: command.shifted(rest)

def command(args: List<String>) -> IO(Unit):
  match args:
    case Con{flag, rest}: command.first(String.eq(flag, "check"), rest)
    case _: IO.die(Unit, 2, "expected check command")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    command(args)
