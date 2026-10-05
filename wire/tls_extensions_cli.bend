import Base
import ./tls_extensions.bend as E
import ../crypto/bytes.bend as B
import ../io/io.bend as Io

# Rebuild diagnostic output from parsed fields, never echo the input buffer.
def flatten(values: List<&2, E.Extension>, reversed: List<&2, U32>, +count: Nat) -> String:
  match values:
    case Nil{}: "ok:" ++ Nat.show(count) ++ ":" ++ B.hex(List.reverse(&2, U32, reversed))
    case Con{E.Extension{+kind, +body}, rest}:
      +size = B.length(body)
      header : List<&2, U32> = Con{U32.from_nat(Nat.mod(size, 256n)), Con{U32.from_nat(Nat.div(size, 256n)),
        Con{U32.and(kind, 255), Con{U32.shrn(kind, 8n), reversed}}}}
      flatten(rest, B.append(List.reverse(&2, U32, body), header), Nat.add(count, 1n))

def report(value: Maybe<&2, List<&2, E.Extension>>) -> String:
  match value:
    case None{}: "invalid"
    case Some{entries}: flatten(entries, [], 0n)

def loop(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{"nonbyte", rest}:
      do IO<Unit>:
        IO.print(report(E.parse([0, 4, 256, 0, 0, 0])))
        loop(rest)
    case Con{path, rest}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(report(E.parse(bytes)))
        loop(rest)

def command(args: List<String>) -> IO(Unit):
  match args:
    case Con{"run", rest}: loop(rest)
    case _: IO.die(Unit, 2, "tls_extensions_cli run <file|nonbyte> ...")

def args(args: List<String>) -> IO(Unit):
  match args:
    case Con{"run", rest}: loop(rest)
    case Con{_, rest}: command(rest)
    case _: command([])

def main() -> IO(Unit):
  do IO<Unit>:
    values : List<String> <- IO.args()
    args(values)
