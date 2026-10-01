import Base
import ./traffic.bend as T
import ./aead.bend as A
import ./bytes.bend as B
import ../io/io.bend as Io

# Synthetic evaluator only: seed/generation commands reach otherwise impractical
# counter boundaries. Protocol callers must never reconstruct a live owner.

def error(error: T.Error) -> String:
  match error:
    case T.Invalid{}: "invalid"
    case T.Authentication{}: "authentication"
    case T.Exhausted{}: "exhausted"
    case T.Closed{}: "closed"
    case T.UpdateLimit{}: "update-limit"
    case T.UsageLimit{}: "usage-limit"

def sequence(sequence: T.Sequence) -> String:
  match sequence:
    case T.Counter{high, low}:
      String.append(U32.show(high), String.append(":", U32.show(low)))
    case T.Spent{}:
      "spent"

def epoch_state(epoch: T.Epoch) -> T.Epoch & String:
  match epoch:
    case T.Gone{}:
      (T.Gone{}, "closed")
    case T.Ready{secret, key, iv, +counter}:
      (T.Ready{secret, key, iv, counter}, sequence(counter))
    case T.AesReady{secret, key, iv, +counter}:
      (T.AesReady{secret, key, iv, counter}, sequence(counter))

def write_state.got(+high: U32, +low: U32, pair: T.Epoch & String) -> T.WriteKey & String:
  (next, state) = pair
  (T.WriteKey{next, T.Generation{high, low}}, String.append("write-state:",
    String.append(state, String.append(":", String.append(U32.show(high), String.append(":", U32.show(low)))))))

def write_state(owner: T.WriteKey) -> T.WriteKey & String:
  match owner:
    case T.WriteKey{epoch, T.Generation{+high, +low}}:
      write_state.got(high, low, epoch_state(epoch))

def read_state.got(pair: T.Epoch & String) -> T.ReadKey & String:
  (next, state) = pair
  (T.ReadKey{next}, String.append("read-state:", state))

def read_state(owner: T.ReadKey) -> T.ReadKey & String:
  match owner:
    case T.ReadKey{epoch}:
      read_state.got(epoch_state(epoch))

def emit_seal(result: Result<&2, &2, T.Error, A.Sealed>) -> IO(Unit):
  match result:
    case Fail{why}:
      IO.print(String.append("seal-error:", error(why)))
    case Done{A.Sealed{ciphertext, tag}}:
      do IO<Unit>:
        x : Unit <- IO.print(String.append("ciphertext:", B.hex(ciphertext)))
        IO.print(String.append("tag:", B.hex(tag)))

def emit_open(result: Result<&2, &2, T.Error, List<&2, U32>>) -> IO(Unit):
  match result:
    case Fail{why}:
      IO.print(String.append("open-error:", error(why)))
    case Done{plaintext}:
      IO.print(String.append("plaintext:", B.hex(plaintext)))

def emit_update(result: Result<&2, &2, T.Error, Unit>) -> IO(Unit):
  match result:
    case Fail{why}:
      IO.print(String.append("update-error:", error(why)))
    case Done{Unit{}}:
      IO.print("updated")

def seed_epoch(epoch: T.Epoch, high: U32, low: U32) -> T.Epoch:
  match epoch:
    case T.Gone{}:
      T.Gone{}
    case T.Ready{secret, key, iv, _}:
      T.Ready{secret, key, iv, T.Counter{high, low}}
    case T.AesReady{secret, key, iv, _}:
      T.AesReady{secret, key, iv, T.Counter{high, low}}

def seed_write(owner: T.WriteKey, high: U32, low: U32) -> T.WriteKey:
  match owner:
    case T.WriteKey{epoch, generation}:
      T.WriteKey{seed_epoch(epoch, high, low), generation}

def seed_read(owner: T.ReadKey, high: U32, low: U32) -> T.ReadKey:
  match owner:
    case T.ReadKey{epoch}:
      T.ReadKey{seed_epoch(epoch, high, low)}

def seed_generation(owner: T.WriteKey, high: U32, low: U32) -> T.WriteKey:
  match owner:
    case T.WriteKey{epoch, _}:
      T.WriteKey{epoch, T.Generation{high, low}}

def decimal.got(value: Maybe<&2, U32>) -> U32:
  match value:
    case None{}: 0
    case Some{value}: value

def decimal(value: String) -> U32:
  decimal.got(U32.read(value))

def write_report.got(pair: T.WriteKey & String) -> IO(T.WriteKey):
  (next, state) = pair
  do IO<T.WriteKey>:
    x : Unit <- IO.print(state)
    IO.pure(T.WriteKey, next)

def write_report(owner: T.WriteKey) -> IO(T.WriteKey):
  write_report.got(write_state(owner))

def read_report.got(pair: T.ReadKey & String) -> IO(T.ReadKey):
  (next, state) = pair
  do IO<T.ReadKey>:
    x : Unit <- IO.print(state)
    IO.pure(T.ReadKey, next)

def read_report(owner: T.ReadKey) -> IO(T.ReadKey):
  read_report.got(read_state(owner))

def write_sealed(pair: T.WriteKey & Result<&2, &2, T.Error, A.Sealed>) -> IO(T.WriteKey):
  (owner, result) = pair
  do IO<T.WriteKey>:
    x : Unit <- emit_seal(result)
    write_report(owner)

def read_opened(pair: T.ReadKey & Result<&2, &2, T.Error, List<&2, U32>>) -> IO(T.ReadKey):
  (owner, result) = pair
  do IO<T.ReadKey>:
    x : Unit <- emit_open(result)
    read_report(owner)

def write_updated(pair: T.WriteKey & Result<&2, &2, T.Error, Unit>) -> IO(T.WriteKey):
  (owner, result) = pair
  do IO<T.WriteKey>:
    x : Unit <- emit_update(result)
    write_report(owner)

def read_updated(pair: T.ReadKey & Result<&2, &2, T.Error, Unit>) -> IO(T.ReadKey):
  (owner, result) = pair
  do IO<T.ReadKey>:
    x : Unit <- emit_update(result)
    read_report(owner)

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
        next : T.WriteKey <- write_report(seed_write(owner, decimal(high), decimal(low)))
        write_loop(tail, next)
    case Con{"generation", Con{high, Con{low, tail}}}:
      do IO<Unit>:
        next : T.WriteKey <- write_report(seed_generation(owner, decimal(high), decimal(low)))
        write_loop(tail, next)
    case _:
      IO.die(Unit, 2, "invalid write evaluator command")

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
        next : T.ReadKey <- read_report(seed_read(owner, decimal(high), decimal(low)))
        read_loop(tail, next)
    case _:
      IO.die(Unit, 2, "invalid read evaluator command")

def write_started(result: Maybe<&1, T.WriteKey>, args: List<String>) -> IO(Unit):
  match result:
    case None{}:
      IO.die(Unit, 1, "invalid traffic secret")
    case Some{owner}:
      do IO<Unit>:
        next : T.WriteKey <- write_report(owner)
        write_loop(args, next)

def read_started(result: Maybe<&1, T.ReadKey>, args: List<String>) -> IO(Unit):
  match result:
    case None{}:
      IO.die(Unit, 1, "invalid traffic secret")
    case Some{owner}:
      do IO<Unit>:
        next : T.ReadKey <- read_report(owner)
        read_loop(args, next)

def label_emit(result: Maybe<&2, List<&2, U32>>) -> IO(Unit):
  match result:
    case None{}:
      IO.die(Unit, 1, "invalid TLS label")
    case Some{bytes}:
      IO.print(B.hex(bytes))

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
    case Con{"label", Con{secret, Con{label, Con{context, Con{length, Nil{}}}}}}:
      do IO<Unit>:
        s : List<&2, U32> <- Io.read_bytes(secret)
        l : List<&2, U32> <- Io.read_bytes(label)
        c : List<&2, U32> <- Io.read_bytes(context)
        label_emit(T.expand_label(s, l, c, U32.to_nat(decimal(length))))
    case _:
      IO.die(Unit, 2, "usage: traffic_cli write|read <secret> <commands...> | label <secret> <label> <context> <length>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
