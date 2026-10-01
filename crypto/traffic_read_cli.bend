import Base
import ./traffic.bend as T
import ./aead.bend as A
import ./bytes.bend as B
import ./traffic_fixture_support.bend as S
import ../io/io.bend as Io

# This fixture retains one affine read owner across every command.

def read_state.got(pair: T.Epoch & String) -> T.ReadKey & String:
  (next, state) = pair
  (T.ReadKey{next}, String.append("read-state:", state))

def read_state(owner: T.ReadKey) -> T.ReadKey & String:
  match owner:
    case T.ReadKey{epoch}:
      read_state.got(S.epoch_state(epoch))

def seed_read(owner: T.ReadKey, high: U32, low: U32) -> T.ReadKey:
  match owner:
    case T.ReadKey{epoch}:
      T.ReadKey{S.seed_epoch(epoch, high, low)}

def read_report.got(pair: T.ReadKey & String) -> IO(T.ReadKey):
  (next, state) = pair
  do IO<T.ReadKey>:
    x : Unit <- IO.print(state)
    IO.pure(T.ReadKey, next)

def read_report(owner: T.ReadKey) -> IO(T.ReadKey):
  read_report.got(read_state(owner))

def read_opened(pair: T.ReadKey & Result<&2, &2, T.Error, List<&2, U32>>) -> IO(T.ReadKey):
  (owner, result) = pair
  do IO<T.ReadKey>:
    x : Unit <- S.emit_open(result)
    read_report(owner)

def read_updated(pair: T.ReadKey & Result<&2, &2, T.Error, Unit>) -> IO(T.ReadKey):
  (owner, result) = pair
  do IO<T.ReadKey>:
    x : Unit <- S.emit_update(result)
    read_report(owner)

def read_loop(args: List<String>, owner: T.ReadKey) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{"open", Con{aad, Con{ciphertext, Con{tag, tail}}}}:
      do IO<Unit>:
        a : List<&2, U32> <- Io.read_bytes(aad)
        c : List<&2, U32> <- Io.read_bytes(ciphertext)
        t : List<&2, U32> <- Io.read_bytes(tag)
        next : T.ReadKey <- read_opened(T.open(owner, a, c, t))
        read_loop(tail, next)
    case Con{"update", tail}:
      do IO<Unit>:
        next : T.ReadKey <- read_updated(T.rekey_read(owner))
        read_loop(tail, next)
    case Con{"close", tail}:
      do IO<Unit>:
        next : T.ReadKey <- read_report(T.close_read(owner))
        read_loop(tail, next)
    case Con{"seed", Con{high, Con{low, tail}}}:
      do IO<Unit>:
        next : T.ReadKey <- read_report(seed_read(owner, S.decimal(high), S.decimal(low)))
        read_loop(tail, next)
    case _:
      IO.die(Unit, 2, "invalid read evaluator command")

def read_started(result: Maybe<&1, T.ReadKey>, args: List<String>) -> IO(Unit):
  match result:
    case None{}:
      IO.die(Unit, 1, "invalid traffic secret")
    case Some{owner}:
      do IO<Unit>:
        next : T.ReadKey <- read_report(owner)
        read_loop(args, next)

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{"read", Con{secret, tail}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(secret)
        read_started(T.new_read(bytes), tail)
    case Con{"read-aes", Con{secret, tail}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(secret)
        read_started(T.new_aes128_read(bytes), tail)
    case Con{"label", Con{secret, Con{label, Con{context, Con{length, Nil{}}}}}}:
      do IO<Unit>:
        secret_bytes : List<&2, U32> <- Io.read_bytes(secret)
        label_bytes : List<&2, U32> <- Io.read_bytes(label)
        context_bytes : List<&2, U32> <- Io.read_bytes(context)
        S.label_emit(T.expand_label(secret_bytes, label_bytes, context_bytes, U32.to_nat(S.decimal(length))))
    case _:
      IO.die(Unit, 2, "invalid traffic evaluator mode")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
