import Base
import ../method.bend as M
import ../../../io/io.bend as Io

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [name]: IO.print(M.show(M.parse(name)))
    case _: IO.die(Unit, 2, "usage: method_cold <name>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- Io.args()
    dispatch(args)
