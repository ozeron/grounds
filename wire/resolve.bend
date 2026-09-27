import Base
import ./wire.bend as W

# wire_resolve: localhost and an address resolve; a name that does not
# exist fails

def says(r: Result<&1, &1, U32 & String, String>) -> String:
  match r:
    case Done{ip}:
      ip
    case Fail{_}:
      "fails"

def main() -> IO(Unit):
  do IO<Unit>:
    a : Result<&1, &1, U32 & String, String> <- W.wire_resolve("localhost")
    b : Result<&1, &1, U32 & String, String> <- W.wire_resolve("10.1.2.3")
    c : Result<&1, &1, U32 & String, String> <- W.wire_resolve("no-such-host.invalid")
    IO.print(says(a) ++ " " ++ says(b) ++ " " ++ says(c))
