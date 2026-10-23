import Base
import ./x509_chain.bend as C
import ./x509_validity.bend as V
import ./unicode32_prepare.bend as U
import ./unicode32_prepare_cli.bend as A
import ./x509_name_prepare_cli.bend as F
import ./unicode32_nfkc_cli.bend as R
import ../io/io.bend as Io

# Test transport only: U32BE count followed by length-prefixed blobs. A case
# contains four blobs: DER clock, typed identity, peer list, explicit anchors.
type Parts is Data:
  Parts{items: List<&2, List<&2, U32>>, rest: List<&2, U32>}

def parts.got(reversed: List<&2, List<&2, U32>>, value: Maybe<F.Part>,
  next: List<&2, List<&2, U32>> -> List<&2, U32> -> Maybe<Parts>) -> Maybe<Parts>:
  match value:
    case Some{F.Part{bytes, rest}}: next(Con{bytes, reversed}, rest)
    case None{}: None{}

def parts(left: Nat, bytes: List<&2, U32>, reversed: List<&2, List<&2, U32>>) -> Maybe<Parts>:
  match left bytes:
    case 0n bytes: Some{Parts{List.reverse(&2, List<&2, U32>, reversed), bytes}}
    case 1n+p Con{a, Con{b, Con{c, Con{d, rest}}}}:
      parts.got(reversed, F.part(U32.to_nat(R.word(a,b,c,d)), rest, []), xs => tail => parts(p, tail, xs))
    case _ _: None{}

def list(bytes: List<&2, U32>) -> Maybe<Parts>:
  match bytes:
    case Con{a, Con{b, Con{c, Con{d, rest}}}}: parts(U32.to_nat(R.word(a,b,c,d)), rest, [])
    case _: None{}

def printed(result: U.Tables & C.Verification) -> IO(U.Tables):
  (tables, value) = result
  do IO<U.Tables>:
    IO.print(C.show(value))
    IO.pure(U.Tables, tables)

def evaluate(tables: U.Tables, time: Maybe<&1, Nat>, id: List<&2, U32>,
  peers: Maybe<Parts>, anchors: Maybe<Parts>) -> IO(U.Tables):
  match time id peers anchors:
    case Some{now} Con{0, reference} Some{Parts{peers, Nil{}}} Some{Parts{anchors, Nil{}}}:
      printed(C.verify(tables, peers, anchors, C.Dns{reference}, C.ServerAuth{}, now))
    case Some{now} Con{1, reference} Some{Parts{peers, Nil{}}} Some{Parts{anchors, Nil{}}}:
      printed(C.verify(tables, peers, anchors, C.Ip{reference}, C.ServerAuth{}, now))
    case _ _ _ _: IO.die(U.Tables, 2, "malformed chain fixture fields")

def record(tables: U.Tables, value: Maybe<Parts>) -> IO(U.Tables):
  match value:
    case Some{Parts{[time, id, peers, anchors], Nil{}}}:
      evaluate(tables, V.decode_time(time), id, list(peers), list(anchors))
    case _: IO.die(U.Tables, 2, "malformed chain fixture record")

def batch(records: List<&2, List<&2, U32>>, tables: U.Tables) -> IO(U.Tables):
  match records:
    case Nil{}: IO.pure(U.Tables, tables)
    case Con{bytes, rest}:
      do IO<U.Tables>:
        tables : U.Tables <- record(tables, list(bytes))
        batch(rest, tables)

def file(tables: U.Tables, value: Maybe<Parts>) -> IO(U.Tables):
  match value:
    case Some{Parts{records, Nil{}}}: batch(records, tables)
    case _: IO.die(U.Tables, 2, "malformed chain fixture batch")

def dispatch(args: List<String>, tables: U.Tables) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{path, rest}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        tables : U.Tables <- file(tables, list(bytes))
        dispatch(rest, tables)

def loaded(args: List<String>, value: Maybe<&1, U.Tables>) -> IO(Unit):
  match value:
    case Some{tables}: dispatch(args, tables)
    case None{}: IO.die(Unit, 2, "invalid Unicode assets")

def asset(args: List<String>) -> IO(Unit):
  match args:
    case Con{path, Con{profile, rest}}:
      do IO<Unit>:
        tables : Maybe<&1, U.Tables> <- A.read_tables(path, profile)
        loaded(rest, tables)
    case _: IO.die(Unit, 2, "expected Unicode assets and fixture batches")

def command.checked(valid: Bool, rest: List<String>) -> IO(Unit):
  match valid:
    case True{}: asset(rest)
    case False{}: IO.die(Unit, 2, "expected check command")

def command(args: List<String>) -> IO(Unit):
  match args:
    case Con{flag, rest}:
      command.checked(String.eq(flag, "check"), rest)
    case _: IO.die(Unit, 2, "expected check command")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- Io.args()
    command(args)
