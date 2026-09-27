import Base
import ../client.bend as Client
import ../../../json/json.bend as J

# GETs a JSON object and prints its "name"

def name(j: J.Json) -> Result<&2, &2, J.Access, String>:
  J.string_at(j, [J.Name{"name"}])

def said(r: Client.JR(String)) -> String:
  match r:
    case Done{s}:
      s
    case Fail{e}:
      Client.jshow(e)

def main() -> IO(Unit):
  IO.bind(Client.JR(String), Unit, Client.get_json(String, "http://127.0.0.1:7316/item", name), r => IO.print(said(r)))
