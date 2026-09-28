import Base
import ../client.bend as C
import ../../../json/json.bend as J

# GETs a JSON object and prints its "name"; POSTs one and prints the reply

def name(j: J.Json) -> Result<&2, &2, J.Access, String>:
  J.string_at(j, [J.Name{"name"}])

def said(r: C.R(String)) -> String:
  match r:
    case Done{s}:
      s
    case Fail{e}:
      C.show(e)

def order() -> J.Json:
  J.JObj{[J.Field{"item", J.JStr{"cup"}}]}

def main() -> IO(Unit):
  do IO<Unit>:
    a : C.R(String) <- C.fetch_json(String, "http://127.0.0.1:7316/item", name)
    x : Unit <- IO.print(said(a))
    b : C.R(String) <- C.send_json(String, C.default(), C.bearer(C.post("http://127.0.0.1:7316/orders", C.json(order())), "t0ken"), name)
    IO.print(said(b))
