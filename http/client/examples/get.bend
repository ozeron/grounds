import Base
import ../client.bend as Client
import ../../core/text.bend as T

# bend examples/get.bend -o get && ./get: GETs URL, or the local server,
# and prints the body

def said(r: Client.R()) -> String:
  match r:
    case Done{res}:
      T.or(Client.text(res), "(not UTF-8)")
    case Fail{e}:
      Client.show(e)

def main() -> IO(Unit):
  IO.bind(Client.R(), Unit, Client.get("http://localhost:8080/?name=client"), r => IO.print(said(r)))
