import Base
import ./tls_handshake_stream.bend as S
import ../crypto/bytes.bend as B
import ../crypto/sha256_stream.bend as H
import ../io/io.bend as Io

# File/diagnostic effects only. Feed files each represent one record payload.
def error(error: S.Error) -> String:
  match error:
    case S.Invalid{}: "error:invalid"
    case S.Overflow{}: "error:overflow"
    case S.Alignment{}: "error:alignment"

def digest(length: Nat, value: Maybe<&2, String>) -> IO(Unit):
  match value:
    case None{}: IO.print("message:invalid")
    case Some{hex}: IO.print("message:" ++ Nat.show(length) ++ ":" ++ hex)

def hashed(owner: Maybe<&1, H.Stream>) -> Maybe<&2, String>:
  match owner:
    case None{}: None{}
    case Some{stream}: H.finish_hex(stream)

def messages(values: List<&2, List<&2, U32>>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{+bytes, tail}:
      do IO<Unit>:
        digest(B.length(bytes), hashed(H.update(bytes, H.start())))
        messages(tail)

def report(value: Result<&2, &1, S.Error, S.Batch>) -> IO(Maybe<&1, S.Decoder>):
  match value:
    case Fail{why}:
      do IO<Maybe<&1, S.Decoder>>:
        IO.print(error(why))
        IO.pure(Maybe<&1, S.Decoder>, None{})
    case Done{S.Batch{decoder, values}}:
      do IO<Maybe<&1, S.Decoder>>:
        messages(values)
        IO.print("record")
        IO.pure(Maybe<&1, S.Decoder>, Some{decoder})

def feed(owner: Maybe<&1, S.Decoder>, bytes: List<&2, U32>) -> IO(Maybe<&1, S.Decoder>):
  match owner:
    case None{}:
      do IO<Maybe<&1, S.Decoder>>:
        IO.print("error:closed")
        IO.pure(Maybe<&1, S.Decoder>, None{})
    case Some{decoder}: report(S.feed(decoder, bytes))

def boundary_result(owner: Maybe<&1, S.Decoder>) -> IO(Maybe<&1, S.Decoder>):
  match owner:
    case None{}:
      do IO<Maybe<&1, S.Decoder>>:
        IO.print("error:boundary")
        IO.pure(Maybe<&1, S.Decoder>, None{})
    case Some{decoder}:
      do IO<Maybe<&1, S.Decoder>>:
        IO.print("boundary")
        IO.pure(Maybe<&1, S.Decoder>, Some{decoder})

def boundary(owner: Maybe<&1, S.Decoder>) -> IO(Maybe<&1, S.Decoder>):
  match owner:
    case None{}: boundary_result(None{})
    case Some{decoder}: boundary_result(S.boundary(decoder))

def finish(owner: Maybe<&1, S.Decoder>) -> IO(Unit):
  match owner:
    case None{}: IO.print("closed")
    case Some{decoder}: IO.print(Bool.pick(String, S.finish(decoder), "clean", "incomplete"))

def loop(args: List<String>, owner: Maybe<&1, S.Decoder>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{"reset", rest}: loop(rest, Some{S.start()})
    case Con{"boundary", rest}:
      do IO<Unit>:
        next : Maybe<&1, S.Decoder> <- boundary(owner)
        loop(rest, next)
    case Con{"end", rest}:
      do IO<Unit>:
        finish(owner)
        loop(rest, None{})
    case Con{"nonbyte", rest}:
      do IO<Unit>:
        next : Maybe<&1, S.Decoder> <- feed(owner, [256])
        loop(rest, next)
    case Con{path, rest}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        next : Maybe<&1, S.Decoder> <- feed(owner, bytes)
        loop(rest, next)

def command(args: List<String>) -> IO(Unit):
  match args:
    case Con{"run", rest}: loop(rest, Some{S.start()})
    case _: IO.die(Unit, 2, "tls_handshake_stream_cli run <file|reset|boundary|end|nonbyte> ...")

def args(args: List<String>) -> IO(Unit):
  match args:
    case Con{"run", rest}: loop(rest, Some{S.start()})
    case Con{_, rest}: command(rest)
    case _: command([])

def main() -> IO(Unit):
  do IO<Unit>:
    values : List<String> <- IO.args()
    args(values)
