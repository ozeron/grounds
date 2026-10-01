import Base
import ./traffic.bend as T
import ./aead.bend as A
import ./bytes.bend as B

# Synthetic evaluator formatting and public boundary injection only.

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

def decimal.got(value: Maybe<&2, U32>) -> U32:
  match value:
    case None{}: 0
    case Some{value}: value

def decimal(value: String) -> U32:
  decimal.got(U32.read(value))

def label_emit(result: Maybe<&2, List<&2, U32>>) -> IO(Unit):
  match result:
    case None{}:
      IO.die(Unit, 1, "invalid TLS label")
    case Some{bytes}:
      IO.print(B.hex(bytes))
