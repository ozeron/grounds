import Base
import ../cookie_sign.bend as Cookie
import ../../../io/io.bend as Io

# Native migration oracle: produce actual legacy effect output, not a proxy.
def command(args: List<String>) -> IO(Unit):
  match args:
    case [key,value]:
      do IO<Unit>:
        signed : String <- IO.try(String,Cookie.sign(key,value))
        IO.print(signed)
    case _: IO.die(Unit,2,"key value")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- Io.args()
    command(args)
