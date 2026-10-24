import Base
import ../bend_transport.bend as Tr
import ../client.bend as C
import ../../../io/io.bend as Io

def counted(count: Nat, started: Nat) -> IO(Unit):
  do IO<Unit>:
    ended : Nat <- IO.now()
    IO.print("ok:" ++ Nat.show(count) ++ ":" ++ Nat.show(Nat.sub(ended,started)))

def prepared(value: C.R(Tr.Policy), started: Nat) -> IO(Unit):
  match value:
    case Done{Tr.Policy{_,_,roots,_}}: counted(List.length(&2,List<&2,U32>,roots),started)
    case Fail{C.Tls{reason}}: IO.print(reason)
    case Fail{_}: IO.print("unexpected-error")

def load(mode: String, path: String, started: Nat) -> IO(Unit):
  match mode:
    case "file":
      do IO<Unit>:
        value : C.R(Tr.Policy) <- Tr.from_bundle_file([],[],path,Tr.Clock{0n,0n})
        prepared(value,started)
    case _:
      do IO<Unit>:
        bytes : List<&2,U32> <- Io.read_bytes(path)
        at : Nat <- IO.now()
        prepared(Tr.from_bundle([],[],bytes,Tr.Clock{0n,0n}),at)

def paths(+mode: String, args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit,Unit{})
    case Con{path,rest}:
      do IO<Unit>:
        started : Nat <- IO.now()
        load(mode,path,started)
        paths(mode,rest)

def command(args: List<String>) -> IO(Unit):
  match args:
    case Con{mode,rest}: paths(mode,rest)
    case _: IO.die(Unit,2,"bytes|file bundle.pem ...")

def main() -> IO(Unit):
  IO.bind(List<String>,Unit,Io.args(),command)
