import Base
import ./traffic.bend as T
import ./aead.bend as A
import ./bytes.bend as B
import ./traffic_fixture_support.bend as S
import ../io/io.bend as Io

# This fixture retains one affine write owner across every command.

def write_state.got(+high: U32, +low: U32, pair: T.Epoch & String) -> T.WriteKey & String:
  (next, state) = pair
  (T.WriteKey{next, T.Generation{high, low}}, String.append("write-state:",
    String.append(state, String.append(":", String.append(U32.show(high), String.append(":", U32.show(low)))))))

def write_state(owner: T.WriteKey) -> T.WriteKey & String:
  match owner:
    case T.WriteKey{epoch, T.Generation{+high, +low}}:
      write_state.got(high, low, S.epoch_state(epoch))

def seed_write(owner: T.WriteKey, high: U32, low: U32) -> T.WriteKey:
  match owner:
    case T.WriteKey{epoch, generation}:
      T.WriteKey{S.seed_epoch(epoch, high, low), generation}

def seed_generation(owner: T.WriteKey, high: U32, low: U32) -> T.WriteKey:
  match owner:
    case T.WriteKey{epoch, _}:
      T.WriteKey{epoch, T.Generation{high, low}}

def write_report.got(pair: T.WriteKey & String) -> IO(T.WriteKey):
  (next, state) = pair
  do IO<T.WriteKey>:
    x : Unit <- IO.print(state)
    IO.pure(T.WriteKey, next)

def write_report(owner: T.WriteKey) -> IO(T.WriteKey):
  write_report.got(write_state(owner))

def write_sealed(pair: T.WriteKey & Result<&2, &2, T.Error, A.Sealed>) -> IO(T.WriteKey):
  (owner, result) = pair
  do IO<T.WriteKey>:
    x : Unit <- S.emit_seal(result)
    write_report(owner)

def write_updated(pair: T.WriteKey & Result<&2, &2, T.Error, Unit>) -> IO(T.WriteKey):
  (owner, result) = pair
  do IO<T.WriteKey>:
    x : Unit <- S.emit_update(result)
    write_report(owner)

def write_loop(args: List<String>, owner: T.WriteKey) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{"seal", Con{aad, Con{message, tail}}}:
      do IO<Unit>:
        a : List<&2, U32> <- Io.read_bytes(aad)
        m : List<&2, U32> <- Io.read_bytes(message)
        next : T.WriteKey <- write_sealed(T.seal(owner, a, m))
        write_loop(tail, next)
    case Con{"bad", tail}:
      do IO<Unit>:
        next : T.WriteKey <- write_sealed(T.seal(owner, [256], []))
        write_loop(tail, next)
    case Con{"update", tail}:
      do IO<Unit>:
        next : T.WriteKey <- write_updated(T.rekey_write(owner))
        write_loop(tail, next)
    case Con{"close", tail}:
      do IO<Unit>:
        next : T.WriteKey <- write_report(T.close_write(owner))
        write_loop(tail, next)
    case Con{"seed", Con{high, Con{low, tail}}}:
      do IO<Unit>:
        next : T.WriteKey <- write_report(seed_write(owner, S.decimal(high), S.decimal(low)))
        write_loop(tail, next)
    case Con{"generation", Con{high, Con{low, tail}}}:
      do IO<Unit>:
        next : T.WriteKey <- write_report(seed_generation(owner, S.decimal(high), S.decimal(low)))
        write_loop(tail, next)
    case _:
      IO.die(Unit, 2, "invalid write evaluator command")

def write_started(result: Maybe<&1, T.WriteKey>, args: List<String>) -> IO(Unit):
  match result:
    case None{}:
      IO.die(Unit, 1, "invalid traffic secret")
    case Some{owner}:
      do IO<Unit>:
        next : T.WriteKey <- write_report(owner)
        write_loop(args, next)

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{"write", Con{secret, tail}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(secret)
        write_started(T.new_write(bytes), tail)
    case Con{"write-aes", Con{secret, tail}}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(secret)
        write_started(T.new_aes128_write(bytes), tail)
    case _:
      IO.die(Unit, 2, "invalid traffic evaluator mode")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
