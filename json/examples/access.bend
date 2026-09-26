import Base
import ../json.bend as J

# level A reads on a parsed document; scripts/cold.py checks that using them
# leaves Strings free of reference counting

def text() -> String:
  "{\"user\": {\"name\": \"Alex\", \"age\": 31, \"tags\": [\"quant\", \"coffee\"]}}"

def show(r: Result<&2, &2, J.Access, String>) -> String:
  match r:
    case Done{s}:
      s
    case Fail{a}:
      J.message_access(a)

def string_of(r: Result<&2, &2, J.Access, J.Json>) -> Result<&2, &2, J.Access, String>:
  match r:
    case Done{v}:
      J.string(v)
    case Fail{a}:
      Fail{a}

def key(r: Result<&2, &2, J.Access, J.Json>, k: String) -> Result<&2, &2, J.Access, J.Json>:
  match r:
    case Done{v}:
      J.get(v, k)
    case Fail{a}:
      Fail{a}

def item(r: Result<&2, &2, J.Access, J.Json>, +i: U32) -> Result<&2, &2, J.Access, J.Json>:
  match r:
    case Done{v}:
      J.index(v, i)
    case Fail{a}:
      Fail{a}

def root(r: Result<&2, &2, J.Error, J.Json>) -> Result<&2, &2, J.Access, J.Json>:
  match r:
    case Done{j}:
      Done{j}
    case Fail{_}:
      Fail{J.Missing{[]}}

def main() -> IO(Unit):
  do IO<Unit>:
    IO.print(show(string_of(key(key(root(J.parse(text())), "user"), "name"))))
    IO.print(show(string_of(item(key(key(root(J.parse(text())), "user"), "tags"), 1))))
    IO.print(show(string_of(key(key(root(J.parse(text())), "user"), "age"))))
