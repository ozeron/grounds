import Base
import ./tls_hello.bend as H
import ./tls_extensions_cli.bend as D
import ../crypto/bytes.bend as B
import ../io/io.bend as Io

# Diagnostic field printer; no negotiation or socket effects.
def suite_bytes(values: List<&2, U32>, reversed: List<&2, U32>) -> List<&2, U32>:
  match values:
    case Nil{}: List.reverse(&2, U32, reversed)
    case Con{+value, rest}:
      suite_bytes(rest, Con{U32.and(value, 255), Con{U32.shrn(value, 8n), reversed}})

def describe_kind(retry: Bool, value: H.Hello) -> String:
  match value:
    case H.Client{random, session, offered, extensions}:
      "client:" ++ B.hex(random) ++ ":" ++ B.hex(session) ++ ":" ++ B.hex(suite_bytes(offered, [])) ++ ":" ++ D.flatten(extensions, [], 0n)
    case H.Server{random, session, selected, extensions}:
      Bool.pick(String, retry, "retry:", "server:") ++ B.hex(random) ++ ":" ++ B.hex(session) ++ ":" ++ B.hex(suite_bytes([selected], [])) ++ ":" ++ D.flatten(extensions, [], 0n)

def describe(+value: H.Hello) -> String:
  describe_kind(H.is_retry(value), value)

def report(value: Result<&2, &2, H.Error, H.Hello>) -> String:
  match value:
    case Fail{H.Decode{}}: "error:decode"
    case Fail{H.Version{}}: "error:version"
    case Fail{H.Compression{}}: "error:compression"
    case Fail{H.Overflow{}}: "error:overflow"
    case Done{hello}: describe(hello)

def loop(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{"nonbyte", rest}:
      do IO<Unit>:
        IO.print(report(H.parse([1, 0, 0, 2, 3, 256])))
        loop(rest)
    case Con{path, rest}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(report(H.parse(bytes)))
        loop(rest)

def command(args: List<String>) -> IO(Unit):
  match args:
    case Con{"run", rest}: loop(rest)
    case _: IO.die(Unit, 2, "tls_hello_cli run <file|nonbyte> ...")

def args(args: List<String>) -> IO(Unit):
  match args:
    case Con{"run", rest}: loop(rest)
    case Con{_, rest}: command(rest)
    case _: command([])

def main() -> IO(Unit):
  do IO<Unit>:
    values : List<String> <- IO.args()
    args(values)
