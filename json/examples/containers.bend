import Base
import ../json.bend as J

type Containers is Data:
  Containers{items: List<&2, J.Json>, fields: List<&2, J.Field>, name: String}

def decode(+j: J.Json) -> Result<&2, &2, J.Access, Containers>:
  J.both3(List<&2, J.Json>, List<&2, J.Field>, String, Containers,
    J.array_at(j, [J.Name{"items"}]), J.object_at(j, [J.Name{"object"}]), J.string_at(j, [J.Name{"name"}]),
    xs => fs => n => Containers{xs, fs, n})

def show(r: Result<&2, &2, J.Access, Containers>) -> String:
  match r:
    case Done{Containers{xs, fs, n}}:
      J.encode(J.JArr{xs}) ++ " " ++ J.encode(J.JObj{fs}) ++ " " ++ n
    case Fail{e}:
      J.message_access(e)

def main() -> IO(Unit):
  IO.print(show(decode(J.obj([J.field_str("name", "again"), [J.Field{"items", J.JArr{[J.JObj{[J.Field{"nested", J.JStr{"value"}}]}, J.JBool{True{}}]}}], [J.Field{"object", J.JObj{[J.Field{"key", J.JArr{[J.JStr{"inside"}]}}]}}]]))))
