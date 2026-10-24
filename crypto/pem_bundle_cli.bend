import Base
import ./pem_bundle.bend as P
import ../io/io.bend as Io

def show(value: Result<&2,&2,P.Error,List<&2,List<&2,U32>>>) -> IO(Unit):
  match value:
    case Done{roots}: IO.print("ok:" ++ Nat.show(List.length(&2,List<&2,U32>,roots)))
    case Fail{reason}: IO.print(P.show(reason))

def paths(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit,Unit{})
    case Con{path,rest}:
      do IO<Unit>:
        bytes : List<&2,U32> <- Io.read_bytes(path)
        show(P.decode(bytes))
        paths(rest)

def main() -> IO(Unit):
  IO.bind(List<String>,Unit,Io.args(),paths)
