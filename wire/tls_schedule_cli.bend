import Base
import ./tls_schedule.bend as S
import ../crypto/bytes.bend as B
import ../io/io.bend as Io

# Synthetic-key evaluator only. Exposes intermediate values for independent
# vector checks; this diagnostics interface is not used by a TLS connection.

def emit(value: Maybe<&2, List<&2, U32>>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{bytes}: IO.print(B.hex(bytes))

def emit_application(value: Maybe<&1, S.ApplicationTraffic>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{S.ApplicationTraffic{client, server}}:
      do IO<Unit>:
        IO.print(B.hex(client))
        IO.print(B.hex(server))

def emit_flow(server_hash: List<&2, U32>, +application_hash: List<&2, U32>, value: Maybe<&1, S.Handshake>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{S.Handshake{S.ToApplication{+secret}, S.HandshakeTraffic{client, server}, S.FinishedKey{+ck}, S.FinishedKey{+sk}}}:
      do IO<Unit>:
        IO.print(B.hex(secret))
        IO.print(B.hex(client))
        IO.print(B.hex(server))
        IO.print(B.hex(ck))
        IO.print(B.hex(sk))
        emit(S.finished(S.FinishedKey{sk}, server_hash))
        emit(S.finished(S.FinishedKey{ck}, application_hash))
        emit_application(S.application(S.ToApplication{secret}, application_hash))

def admitted(value: Maybe<&1, S.Handshake>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{_}: IO.print("valid")

def guards() -> IO(Unit):
  do IO<Unit>:
    admitted(S.start(Con{256, List.replicate(U32, 31n, 0)}, S.zeros()))
    admitted(S.start(S.zeros(), Con{256, List.replicate(U32, 31n, 0)}))
    emit(S.finished(S.FinishedKey{Con{256, List.replicate(U32, 31n, 0)}}, S.zeros()))
    emit(S.finished(S.FinishedKey{S.zeros()}, Con{256, List.replicate(U32, 31n, 0)}))
    emit_application(S.application(S.ToApplication{Con{256, List.replicate(U32, 31n, 0)}}, S.zeros()))
    IO.print(Bool.pick(String, S.verify_finished(S.FinishedKey{S.zeros()}, S.zeros(),
      Con{256, List.replicate(U32, 31n, 0)}), "true", "false"))

def loop(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{"flow", Con{shared, Con{hello, Con{server, Con{application, rest}}}}}:
      do IO<Unit>:
        a : List<&2, U32> <- Io.read_bytes(shared)
        b : List<&2, U32> <- Io.read_bytes(hello)
        c : List<&2, U32> <- Io.read_bytes(server)
        d : List<&2, U32> <- Io.read_bytes(application)
        emit_flow(c, d, S.start(a, b))
        loop(rest)
    case Con{"app", Con{secret, Con{hash, rest}}}:
      do IO<Unit>:
        a : List<&2, U32> <- Io.read_bytes(secret)
        b : List<&2, U32> <- Io.read_bytes(hash)
        emit_application(S.application(S.ToApplication{a}, b))
        loop(rest)
    case Con{"finished", Con{key, Con{hash, rest}}}:
      do IO<Unit>:
        a : List<&2, U32> <- Io.read_bytes(key)
        b : List<&2, U32> <- Io.read_bytes(hash)
        emit(S.finished(S.FinishedKey{a}, b))
        loop(rest)
    case Con{"verify", Con{key, Con{hash, Con{tag, rest}}}}:
      do IO<Unit>:
        a : List<&2, U32> <- Io.read_bytes(key)
        b : List<&2, U32> <- Io.read_bytes(hash)
        c : List<&2, U32> <- Io.read_bytes(tag)
        IO.print(Bool.pick(String, S.verify_finished(S.FinishedKey{a}, b, c), "true", "false"))
        loop(rest)
    case Con{"guards", rest}:
      do IO<Unit>:
        guards()
        loop(rest)
    case _: IO.die(Unit, 2, "tls_schedule_cli run <flow|app|finished|verify|guards> <files> ...")

def command(args: List<String>) -> IO(Unit):
  match args:
    case Con{"run", rest}: loop(rest)
    case _: IO.die(Unit, 2, "tls_schedule_cli run <commands>")

def args(args: List<String>) -> IO(Unit):
  match args:
    case Con{"run", rest}: loop(rest)
    case Con{_, rest}: command(rest)
    case _: command([])

def main() -> IO(Unit):
  do IO<Unit>:
    values : List<String> <- IO.args()
    args(values)
