import Base
import ./unicode32_prepare.bend as S
import ./unicode32_nfkc_compose.bend as C
import ./unicode32_nfkc_cli.bend as R
import ../io/io.bend as Io

# Scalar batch fixture transport shared with the standalone NFKC checker.
type Session is Type:
  Session{tables: S.Tables, casefold: Bool}

def prepared(casefold: Bool, result: S.Tables & Maybe<&1, C.Normalized>) -> Session & Maybe<&1, C.Normalized>:
  (tables, value) = result
  (Session{tables, casefold}, value)

def prepare(state: Session, codes: List<&2, U32>) -> Session & Maybe<&1, C.Normalized>:
  match state:
    case Session{tables, +casefold}: prepared(casefold, S.prepare(tables, codes, casefold))

def batch.normalized(rest: List<&2, U32>, result: Session & Maybe<&1, C.Normalized>, next: List<&2, U32> -> Session -> IO(Session)) -> IO(Session):
  (state, normalized) = result
  do IO<Session>:
    R.emit(normalized)
    next(rest, state)

def batch.record(state: Session, result: Maybe<R.Record>, next: List<&2, U32> -> Session -> IO(Session)) -> IO(Session):
  match result:
    case None{}: IO.die(Session, 2, "truncated scalar record")
    case Some{R.Record{codes, rest}}: batch.normalized(rest, prepare(state, codes), next)

def batch(left: Nat, bytes: List<&2, U32>, state: Session) -> IO(Session):
  match left bytes:
    case 0n Nil{}: IO.pure(Session, state)
    case 0n _: IO.die(Session, 2, "trailing batch bytes")
    case 1n+p bytes: batch.record(state, R.record(bytes), xs => s => batch(p, xs, s))

def file(state: Session, bytes: List<&2, U32>) -> IO(Session):
  match bytes:
    case Con{a, Con{b, Con{c, Con{d, rest}}}}: batch(U32.to_nat(R.word(a, b, c, d)), rest, state)
    case _: IO.die(Session, 2, "truncated batch header")

# Release each fixture's byte-reading continuation before the next file.
def read_file(state: Session, path: String) -> IO(Session):
  do IO<Session>:
    bytes : List<&2, U32> <- Io.read_bytes(path)
    file(state, bytes)

def dispatch(args: List<String>, state: Session) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{path, rest}:
      do IO<Unit>:
        next : Session <- read_file(state, path)
        dispatch(rest, next)

def loaded(args: List<String>, casefold: Bool, result: Maybe<&1, S.Tables>) -> IO(Unit):
  match result:
    case None{}: IO.die(Unit, 2, "invalid Unicode 3.2 table asset")
    case Some{tables}: dispatch(args, Session{tables, casefold})

# Finish loading as a separate IO action. Byte-reading continuations return
# before any preparation loop starts, releasing their captured byte lists.
def read_tables(path: String, profile_path: String) -> IO(Maybe<&1, S.Tables>):
  do IO<Maybe<&1, S.Tables>>:
    bytes : List<&2, U32> <- Io.read_bytes(path)
    profile_bytes : List<&2, U32> <- Io.read_bytes(profile_path)
    IO.pure(Maybe<&1, S.Tables>, S.tables(bytes, profile_bytes))

def asset(args: List<String>, casefold: Bool) -> IO(Unit):
  match args:
    case Con{path, Con{profile_path, rest}}:
      do IO<Unit>:
        tables : Maybe<&1, S.Tables> <- read_tables(path, profile_path)
        loaded(rest, casefold, tables)
    case _: IO.die(Unit, 2, "expected two table assets and batch files")

def command.checked(valid: Bool, mode: String, rest: List<String>) -> IO(Unit):
  match valid:
    case True{}: asset(rest, String.eq(mode, "fold"))
    case False{}: IO.die(Unit, 2, "expected fold/exact command")

def command.shifted(args: List<String>) -> IO(Unit):
  match args:
    case Con{+mode, rest}:
      command.checked(Bool.or(String.eq(mode, "fold"), String.eq(mode, "exact")), mode, rest)
    case Nil{}: IO.die(Unit, 2, "expected fold/exact command")

def command.first(valid: Bool, mode: String, rest: List<String>) -> IO(Unit):
  match valid:
    case True{}: asset(rest, String.eq(mode, "fold"))
    case False{}: command.shifted(rest)

def command(args: List<String>) -> IO(Unit):
  match args:
    case Con{+mode, rest}:
      command.first(Bool.or(String.eq(mode, "fold"), String.eq(mode, "exact")), mode, rest)
    case Nil{}: IO.die(Unit, 2, "expected fold/exact and table asset")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    command(args)
