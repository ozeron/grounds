import Base
import ./bjson.bend as J

def main() -> IO(Unit):
  do IO<Unit>:
    IO.print(Bool.show(J.is_null(J.JNull{})))
