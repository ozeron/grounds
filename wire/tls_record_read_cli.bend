import Base
import ./tls_record.bend as R
import ../crypto/traffic.bend as T
import ../crypto/traffic_fixture_support.bend as C
import ./tls_record_fixture_support.bend as S
import ../io/io.bend as Io

# Retain one affine record owner for the complete evaluator scenario.

def read_got(pair: T.ReadKey & Result<&2, &2, R.Error, R.Record>) -> IO(T.ReadKey):
  (owner, result) = pair
  do IO<T.ReadKey>:
    x : Unit <- S.opened(result)
    S.read_report(owner)

def read_loop(args: List<String>, owner: T.ReadKey) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{"open", Con{record, tail}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(record)
        next : T.ReadKey <- read_got(R.open(owner, bytes))
        read_loop(tail, next)
    case Con{"update", tail}:
      do IO<Unit>:
        next : T.ReadKey <- S.read_updated(T.rekey_read(owner))
        read_loop(tail, next)
    case Con{"close", tail}:
      do IO<Unit>:
        next : T.ReadKey <- S.read_report(T.close_read(owner))
        read_loop(tail, next)
    case Con{"seed", Con{high, Con{low, tail}}}:
      do IO<Unit>:
        next : T.ReadKey <- S.read_report(S.seed_read(owner, C.decimal(high), C.decimal(low)))
        read_loop(tail, next)
    case _:
      IO.die(Unit, 2, "invalid record read command")

def read_started(result: Maybe<&1, T.ReadKey>, args: List<String>) -> IO(Unit):
  match result:
    case None{}:
      IO.die(Unit, 1, "invalid traffic secret")
    case Some{owner}:
      do IO<Unit>:
        next : T.ReadKey <- S.read_report(owner)
        read_loop(args, next)

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{"read-aes", Con{secret, tail}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(secret)
        read_started(T.new_aes128_read(bytes), tail)
    case Con{"read", Con{secret, tail}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(secret)
        read_started(T.new_read(bytes), tail)
    case Con{"frame", Con{path, Nil{}}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        S.framed(R.frame(bytes))
    case _:
      IO.die(Unit, 2, "invalid record evaluator mode")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
