import Base
import ../json.bend as J

# the decoder recipe: one expression per type, from path reads and J.both;
# scripts/cold.py checks that it leaves Strings free of reference counting

type User is Data:
  User{name: String, age: U32}

def User.from_json(+j: J.Json) -> Result<&2, &2, J.Access, User>:
  J.both(String, U32, User, J.string_at(j, [J.Name{"name"}]), J.u32_at(j, [J.Name{"age"}]), n => a => User{n, a})

def text() -> String:
  "{\"user\": {\"name\": \"Alex\", \"age\": 31, \"tags\": [\"quant\", \"coffee\"]}}"

def show(r: Result<&2, &2, J.Access, User>) -> String:
  match r:
    case Done{User{n, a}}:
      n ++ " " ++ U32.show(a)
    case Fail{a}:
      J.message_access(a)

def show_s(r: Result<&2, &2, J.Access, String>) -> String:
  match r:
    case Done{s}:
      s
    case Fail{a}:
      J.message_access(a)

def user(r: Result<&2, &2, J.Error, J.Json>) -> Result<&2, &2, J.Access, User>:
  match r:
    case Done{j}:
      User.from_json(j)
    case Fail{_}:
      Fail{J.Missing{[]}}

def root(r: Result<&2, &2, J.Error, J.Json>) -> J.Json:
  match r:
    case Done{j}:
      j
    case Fail{_}:
      J.JNull{}

def tag(j: J.Json) -> String:
  show_s(J.string_at(j, [J.Name{"user"}, J.Name{"tags"}, J.Index{1}]))

def age(j: J.Json) -> String:
  show_s(J.string_at(j, [J.Name{"user"}, J.Name{"age"}]))

# the reads sit in defs: a read called in main itself owns its argument,
# which shares the documents the decoder reads twice
def main() -> IO(Unit):
  do IO<Unit>:
    IO.print(show(user(J.parse("{\"name\": \"Alex\", \"age\": 31}"))))
    IO.print(show(user(J.parse("{\"name\": \"Alex\", \"age\": \"31\"}"))))
    IO.print(tag(root(J.parse(text()))))
    IO.print(age(root(J.parse(text()))))
