import Base
import ../json.bend as J

type Person is Data:
  Person{name: String, age: U32}

type Batch is Data:
  Batch{title: String, users: List<&2, Person>}

# Literal template callbacks inline the reads, so the source stays borrowed.
def decode(+j: J.Json) -> Result<&2, &2, J.Access, Batch>:
  J.both(String, List<&2, Person>, Batch,
    J.string_at(j, [J.Name{"title"}]),
    J.list_at(~Person, ~(+x => J.both(String, U32, Person, J.string_at(x, [J.Name{"name"}]), J.u32_at(x, [J.Name{"age"}]), n => a => Person{n, a})), j, [J.Name{"users"}]),
    title => users => Batch{title, users})

def names(xs: List<&2, Person>, out: String) -> String:
  match xs:
    case Nil{}:
      out
    case Con{Person{n, a}, t}:
      names(t, out ++ " " ++ n ++ ":" ++ U32.show(a))

def show(r: Result<&2, &2, J.Access, Batch>) -> String:
  match r:
    case Done{Batch{title, users}}:
      names(users, title)
    case Fail{e}:
      J.message_access(e)

def sample() -> String:
  show(decode(J.obj([J.field_str("title", "team"), [J.Field{"users", J.JArr{[J.obj([J.field_str("name", "Alex"), J.field_u32("age", 31)])]}}]])))

def main() -> IO(Unit):
  IO.print(sample())
