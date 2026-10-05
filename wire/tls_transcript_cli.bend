import Base
import ./tls_transcript.bend as T
import ../crypto/bytes.bend as B
import ../io/io.bend as Io

def emit(value: Maybe<&2, List<&2, U32>>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{bytes}: IO.print(B.hex(bytes))

def append(owner: Maybe<&1, T.Transcript>, bytes: List<&2, U32>) -> Maybe<&1, T.Transcript>:
  match owner:
    case None{}: None{}
    case Some{transcript}: T.append(transcript, bytes)

def report_snapshot(pair: T.Transcript & Maybe<&2, List<&2, U32>>) -> IO(Maybe<&1, T.Transcript>):
  (owner, value) = pair
  do IO<Maybe<&1, T.Transcript>>:
    emit(value)
    IO.pure(Maybe<&1, T.Transcript>, Some{owner})

def report(owner: Maybe<&1, T.Transcript>) -> IO(Maybe<&1, T.Transcript>):
  match owner:
    case None{}:
      do IO<Maybe<&1, T.Transcript>>:
        IO.print("invalid")
        IO.pure(Maybe<&1, T.Transcript>, None{})
    case Some{transcript}: report_snapshot(T.snapshot(transcript))

def loop(paths: List<String>, owner: Maybe<&1, T.Transcript>) -> IO(Unit):
  match paths:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{"reset", tail}: loop(tail, Some{T.start()})
    case Con{path, tail}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        next : Maybe<&1, T.Transcript> <- report(append(owner, bytes))
        loop(tail, next)

def guards() -> IO(Unit):
  do IO<Unit>:
    a : Maybe<&1, T.Transcript> <- report(Some{T.start()})
    b : Maybe<&1, T.Transcript> <- report(append(a, [1, 0, 0, 1, 256]))
    c : Maybe<&1, T.Transcript> <- report(append(b, [1, 0, 0, 0]))
    IO.pure(Unit, Unit{})

def command(args: List<String>) -> IO(Unit):
  match args:
    case Con{"run", tail}: loop(tail, Some{T.start()})
    case Con{"guards", Nil{}}: guards()
    case _: IO.die(Unit, 2, "tls_transcript_cli run <message-file|reset> ... | guards")

def args(args: List<String>) -> IO(Unit):
  match args:
    case Con{"run", tail}: loop(tail, Some{T.start()})
    case Con{"guards", Nil{}}: guards()
    case Con{_, rest}: command(rest)
    case _: command([])

def main() -> IO(Unit):
  do IO<Unit>:
    values : List<String> <- IO.args()
    args(values)
