import Base
import ./tls_record.bend as R
import ../crypto/traffic.bend as T
import ../crypto/traffic_fixture_support.bend as D
import ../crypto/bytes.bend as B

# Synthetic record evaluator formatting only.

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

def framed(result: R.Frame) -> IO(Unit):
  match result:
    case R.More{}:
      IO.print("more")
    case R.Bad{why}:
      IO.print(String.append("frame-error:", error(why)))
    case R.Framed{header, body, rest}:
      IO.print(String.concat(["frame:", B.hex(header), ":", B.hex(body), ":", B.hex(rest)]))

# Shared synthetic owner-state diagnostics; no seal/open or command loops.

def write_state.got(+high: U32, +low: U32, pair: T.Epoch & String) -> T.WriteKey & String:
  (next, state) = pair
  (T.WriteKey{next, T.Generation{high, low}}, String.append("write-state:",
    String.append(state, String.append(":", String.append(U32.show(high), String.append(":", U32.show(low)))))))

def write_state(owner: T.WriteKey) -> T.WriteKey & String:
  match owner:
    case T.WriteKey{epoch, T.Generation{+high, +low}}:
      write_state.got(high, low, D.epoch_state(epoch))

def read_state.got(pair: T.Epoch & String) -> T.ReadKey & String:
  (next, state) = pair
  (T.ReadKey{next}, String.append("read-state:", state))

def read_state(owner: T.ReadKey) -> T.ReadKey & String:
  match owner:
    case T.ReadKey{epoch}:
      read_state.got(D.epoch_state(epoch))

def seed_write(owner: T.WriteKey, high: U32, low: U32) -> T.WriteKey:
  match owner:
    case T.WriteKey{epoch, generation}:
      T.WriteKey{D.seed_epoch(epoch, high, low), generation}

def seed_read(owner: T.ReadKey, high: U32, low: U32) -> T.ReadKey:
  match owner:
    case T.ReadKey{epoch}:
      T.ReadKey{D.seed_epoch(epoch, high, low)}

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

def write_updated(pair: T.WriteKey & Result<&2, &2, T.Error, Unit>) -> IO(T.WriteKey):
  (owner, result) = pair
  do IO<T.WriteKey>:
    x : Unit <- D.emit_update(result)
    write_report(owner)

def read_updated(pair: T.ReadKey & Result<&2, &2, T.Error, Unit>) -> IO(T.ReadKey):
  (owner, result) = pair
  do IO<T.ReadKey>:
    x : Unit <- D.emit_update(result)
    read_report(owner)
