import Base
import ./tls_record.bend as R
import ../crypto/traffic.bend as T
import ../crypto/traffic_fixture_support.bend as C
import ./tls_record_fixture_support.bend as S
import ../io/io.bend as Io

# Retain one affine record owner for the complete evaluator scenario.

def write_got(pair: T.WriteKey & Result<&2, &2, R.Error, List<&2, U32>>) -> IO(T.WriteKey):
  (owner, result) = pair
  do IO<T.WriteKey>:
    x : Unit <- S.emitted(result)
    S.write_report(owner)

def write_loop(args: List<String>, owner: T.WriteKey) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{"seal", Con{kind, Con{padding, Con{content, tail}}}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(content)
        next : T.WriteKey <- write_got(R.seal(owner, C.decimal(kind), U32.to_nat(C.decimal(padding)), bytes))
        write_loop(tail, next)
    case Con{"update", tail}:
      do IO<Unit>:
        next : T.WriteKey <- S.write_updated(T.rekey_write(owner))
        write_loop(tail, next)
    case Con{"close", tail}:
      do IO<Unit>:
        next : T.WriteKey <- S.write_report(T.close_write(owner))
        write_loop(tail, next)
    case Con{"seed", Con{high, Con{low, tail}}}:
      do IO<Unit>:
        next : T.WriteKey <- S.write_report(S.seed_write(owner, C.decimal(high), C.decimal(low)))
        write_loop(tail, next)
    case _:
      IO.die(Unit, 2, "invalid record write command")

def write_started(result: Maybe<&1, T.WriteKey>, args: List<String>) -> IO(Unit):
  match result:
    case None{}:
      IO.die(Unit, 1, "invalid traffic secret")
    case Some{owner}:
      do IO<Unit>:
        next : T.WriteKey <- S.write_report(owner)
        write_loop(args, next)

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{"write-aes", Con{secret, tail}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(secret)
        write_started(T.new_aes128_write(bytes), tail)
    case Con{"write", Con{secret, tail}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(secret)
        write_started(T.new_write(bytes), tail)
    case _:
      IO.die(Unit, 2, "invalid record evaluator mode")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
