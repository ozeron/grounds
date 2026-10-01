import Base
import ./tls_record.bend as R
import ../crypto/traffic.bend as T
import ../crypto/traffic_cli.bend as D
import ../crypto/bytes.bend as B
import ../io/io.bend as Io

# Local synthetic evaluator. D supplies diagnostics, never protocol logic.

def error(error: R.Error) -> String:
  match error:
    case R.Invalid{}: "invalid"
    case R.Overflow{}: "overflow"
    case R.Incomplete{}: "incomplete"
    case R.Unexpected{}: "unexpected"
    case R.Crypto{why}: String.append("crypto-", D.error(why))

def emitted(result: Result<&2, &2, R.Error, List<&2, U32>>) -> IO(Unit):
  match result:
    case Fail{why}:
      IO.print(String.append("seal-error:", error(why)))
    case Done{record}:
      IO.print(String.append("sealed:", B.hex(record)))

def opened(result: Result<&2, &2, R.Error, R.Record>) -> IO(Unit):
  match result:
    case Fail{why}:
      IO.print(String.append("open-error:", error(why)))
    case Done{R.Record{kind, content, padding}}:
      IO.print(String.concat(["record:", U32.show(kind), ":", Nat.show(padding), ":", B.hex(content)]))

def write_got(pair: T.WriteKey & Result<&2, &2, R.Error, List<&2, U32>>) -> IO(T.WriteKey):
  (owner, result) = pair
  do IO<T.WriteKey>:
    x : Unit <- emitted(result)
    D.write_report(owner)

def read_got(pair: T.ReadKey & Result<&2, &2, R.Error, R.Record>) -> IO(T.ReadKey):
  (owner, result) = pair
  do IO<T.ReadKey>:
    x : Unit <- opened(result)
    D.read_report(owner)

def write_loop(args: List<String>, owner: T.WriteKey) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{"seal", Con{kind, Con{padding, Con{content, tail}}}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(content)
        next : T.WriteKey <- write_got(R.seal(owner, D.decimal(kind), U32.to_nat(D.decimal(padding)), bytes))
        write_loop(tail, next)
    case Con{"update", tail}:
      do IO<Unit>:
        next : T.WriteKey <- D.write_updated(T.rekey_write(owner))
        write_loop(tail, next)
    case Con{"close", tail}:
      do IO<Unit>:
        next : T.WriteKey <- D.write_report(T.close_write(owner))
        write_loop(tail, next)
    case Con{"seed", Con{high, Con{low, tail}}}:
      do IO<Unit>:
        next : T.WriteKey <- D.write_report(D.seed_write(owner, D.decimal(high), D.decimal(low)))
        write_loop(tail, next)
    case _:
      IO.die(Unit, 2, "invalid record write command")

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
        next : T.ReadKey <- D.read_updated(T.rekey_read(owner))
        read_loop(tail, next)
    case Con{"close", tail}:
      do IO<Unit>:
        next : T.ReadKey <- D.read_report(T.close_read(owner))
        read_loop(tail, next)
    case Con{"seed", Con{high, Con{low, tail}}}:
      do IO<Unit>:
        next : T.ReadKey <- D.read_report(D.seed_read(owner, D.decimal(high), D.decimal(low)))
        read_loop(tail, next)
    case _:
      IO.die(Unit, 2, "invalid record read command")

def write_started(result: Maybe<&1, T.WriteKey>, args: List<String>) -> IO(Unit):
  match result:
    case None{}:
      IO.die(Unit, 1, "invalid traffic secret")
    case Some{owner}:
      do IO<Unit>:
        next : T.WriteKey <- D.write_report(owner)
        write_loop(args, next)

def read_started(result: Maybe<&1, T.ReadKey>, args: List<String>) -> IO(Unit):
  match result:
    case None{}:
      IO.die(Unit, 1, "invalid traffic secret")
    case Some{owner}:
      do IO<Unit>:
        next : T.ReadKey <- D.read_report(owner)
        read_loop(args, next)

def framed(result: R.Frame) -> IO(Unit):
  match result:
    case R.More{}:
      IO.print("more")
    case R.Bad{why}:
      IO.print(String.append("frame-error:", error(why)))
    case R.Framed{header, body, rest}:
      IO.print(String.concat(["frame:", B.hex(header), ":", B.hex(body), ":", B.hex(rest)]))

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{"write-aes", Con{secret, tail}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(secret)
        write_started(T.new_aes128_write(bytes), tail)
    case Con{"read-aes", Con{secret, tail}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(secret)
        read_started(T.new_aes128_read(bytes), tail)
    case Con{"write", Con{secret, tail}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(secret)
        write_started(T.new_write(bytes), tail)
    case Con{"read", Con{secret, tail}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(secret)
        read_started(T.new_read(bytes), tail)
    case Con{"frame", Con{path, Nil{}}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        framed(R.frame(bytes))
    case _:
      IO.die(Unit, 2, "usage: tls_record_cli write|read <secret> <commands...> | frame <file>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
