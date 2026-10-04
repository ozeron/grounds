import Base
import ./x509_name_prepare.bend as N
import ./unicode32_prepare.bend as P
import ./unicode32_prepare_cli.bend as A
import ./unicode32_nfkc_cli.bend as R
import ./unicode32_nfkc_compose.bend as C
import ../io/io.bend as Io

# U32BE count, then tag, OID length/bytes, value length/bytes per record.
type Part is Data:
  Part{bytes: List<&2, U32>, rest: List<&2, U32>}

type Record is Data:
  Record{oid: List<&2, U32>, tag: U32, bytes: List<&2, U32>, rest: List<&2, U32>}

def part(left: Nat, bytes: List<&2, U32>, reversed: List<&2, U32>) -> Maybe<Part>:
  match left bytes:
    case 0n bytes: Some{Part{List.reverse(&2, U32, reversed), bytes}}
    case 1n+p Con{byte, rest}: part(p, rest, Con{byte, reversed})
    case _ _: None{}

def record.value(oid: List<&2, U32>, tag: U32, result: Maybe<Part>) -> Maybe<Record>:
  match result:
    case Some{Part{bytes, rest}}: Some{Record{oid, tag, bytes, rest}}
    case None{}: None{}

def record.oid(tag: U32, result: Maybe<Part>) -> Maybe<Record>:
  match result:
    case Some{Part{oid, Con{a, Con{b, Con{c, Con{d, rest}}}}}}:
      record.value(oid, tag, part(U32.to_nat(R.word(a, b, c, d)), rest, []))
    case _: None{}

def record(bytes: List<&2, U32>) -> Maybe<Record>:
  match bytes:
    case Con{a, Con{b, Con{c, Con{d, Con{e, Con{f, Con{g, Con{h, rest}}}}}}}}:
      record.oid(R.word(a, b, c, d), part(U32.to_nat(R.word(e, f, g, h)), rest, []))
    case _: None{}

def batch.prepared(rest: List<&2, U32>, result: P.Tables & Maybe<&1, C.Normalized>,
  next: List<&2, U32> -> P.Tables -> IO(P.Tables)) -> IO(P.Tables):
  (tables, value) = result
  do IO<P.Tables>:
    R.emit(value)
    next(rest, tables)

def batch.record(tables: P.Tables, result: Maybe<Record>,
  next: List<&2, U32> -> P.Tables -> IO(P.Tables)) -> IO(P.Tables):
  match result:
    case Some{Record{oid, tag, bytes, rest}}:
      batch.prepared(rest, N.prepare(tables, oid, tag, bytes), next)
    case None{}: IO.die(P.Tables, 2, "truncated attribute record")

def batch(left: Nat, bytes: List<&2, U32>, tables: P.Tables) -> IO(P.Tables):
  match left bytes:
    case 0n Nil{}: IO.pure(P.Tables, tables)
    case 0n _: IO.die(P.Tables, 2, "trailing batch bytes")
    case 1n+p bytes: batch.record(tables, record(bytes), xs => t => batch(p, xs, t))

def file(tables: P.Tables, bytes: List<&2, U32>) -> IO(P.Tables):
  match bytes:
    case Con{a, Con{b, Con{c, Con{d, rest}}}}: batch(U32.to_nat(R.word(a, b, c, d)), rest, tables)
    case _: IO.die(P.Tables, 2, "truncated batch header")

def read_file(tables: P.Tables, path: String) -> IO(P.Tables):
  do IO<P.Tables>:
    bytes : List<&2, U32> <- Io.read_bytes(path)
    file(tables, bytes)

def dispatch(args: List<String>, tables: P.Tables) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{path, rest}:
      do IO<Unit>:
        next : P.Tables <- read_file(tables, path)
        dispatch(rest, next)

def loaded(args: List<String>, result: Maybe<&1, P.Tables>) -> IO(Unit):
  match result:
    case Some{tables}: dispatch(args, tables)
    case None{}: IO.die(Unit, 2, "invalid Unicode 3.2 table asset")

def asset(args: List<String>) -> IO(Unit):
  match args:
    case Con{path, Con{profile_path, rest}}:
      do IO<Unit>:
        tables : Maybe<&1, P.Tables> <- A.read_tables(path, profile_path)
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
