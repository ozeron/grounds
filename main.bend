import Base
import ./bjson.bend as J

def show(r: Result<&2, &2, J.Error, J.Json>) -> String:
  match r:
    case Done{J.JNull{}}:
      "null"
    case Done{J.JBool{b}}:
      Bool.show(b)
    case Done{_}:
      "value"
    case Fail{J.UnexpectedEnd{}}:
      "error: unexpected end"
    case Fail{J.UnexpectedChar{c}}:
      "error: unexpected " ++ Char.show(c)
    case Fail{J.TrailingInput{}}:
      "error: trailing input"

def main() -> IO(Unit):
  do IO<Unit>:
    IO.print(show(J.parse("  true ")))
    IO.print(show(J.parse("nul")))
    IO.print(show(J.parse("True")))
