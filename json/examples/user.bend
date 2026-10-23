import Base
import ../json.bend as J
import ../PROOF.bend as Proof
import ../proof/access.bend as Access
import ../proof/u32.bend as Unsigned
import ../proof/parse.bend as Text

# the decoder recipe: one expression per type, from path reads and J.both;
# scripts/cold.py checks that it leaves Strings free of reference counting

type User is Data:
  User{name: String, age: U32}

def User.to_json(u: User) -> J.Json:
  match u:
    case User{n, a}:
      J.JObj{[J.Field{"name", J.JStr{n}}, J.Field{"age", J.num_u32(a)}]}

def User.from_json(+j: J.Json) -> Result<&2, &2, J.Access, User>:
  J.both(String, U32, User, J.string_at(j, [J.Name{"name"}]), J.u32_at(j, [J.Name{"age"}]), n => a => User{n, a})

law user_round_trip:
  for +u: User
  {User.from_json(User.to_json(u)) == Done{u} : Result<&2, &2, J.Access, User>}

def user_round_trip(u):
  match u:
    case User{n, a}:
      %Equal.sym(String, J.copy_text(n, ""), n, Access.copy_text_go(n, "")) : {J.both(String, U32, User, Done{_}, J.read_at.fin(U32, J.u32(J.copy_leaf(J.num_u32(a))), [J.Name{"age"}]), n => a => User{n, a}) == Done{User{n, a}} : Result<&2, &2, J.Access, User>}
      %Equal.sym(J.Json, J.copy_leaf(J.num_u32(a)), J.num_u32(a), Access.copy_num_u32(a)) : {J.both(String, U32, User, Done{n}, J.read_at.fin(U32, J.u32(_), [J.Name{"age"}]), n => a => User{n, a}) == Done{User{n, a}} : Result<&2, &2, J.Access, User>}
      %Equal.sym(Result<&2, &2, J.Access, U32>, J.u32(J.num_u32(a)), Done{a}, Unsigned.u32_round_trip(a)) : {J.both(String, U32, User, Done{n}, J.read_at.fin(U32, _, [J.Name{"age"}]), n => a => User{n, a}) == Done{User{n, a}} : Result<&2, &2, J.Access, User>}
      {==}

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

# `user` unwraps the parse result before the typed read.
law user_text_round_trip:
  for +u: User
  {user(J.parse(J.encode(User.to_json(u)))) == Done{u} : Result<&2, &2, J.Access, User>}

def user_text_round_trip(u):
  %Equal.sym(Result<&2, &2, J.Error, J.Json>, J.parse(J.encode(User.to_json(u))), Done{User.to_json(u)}, Text.round_trip(User.to_json(u))) : {user(_) == Done{u} : Result<&2, &2, J.Access, User>}
  user_round_trip(u)

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

def encoded_user() -> String:
  show(User.from_json(User.to_json(User{"Alex", 31})))

# the reads sit in defs: a read called in main itself owns its argument,
# which shares the documents the decoder reads twice
def main() -> IO(Unit):
  do IO<Unit>:
    IO.print(encoded_user())
    IO.print(show(user(J.parse("{\"name\": \"Alex\", \"age\": 31}"))))
    IO.print(show(user(J.parse("{\"name\": \"Alex\", \"age\": \"31\"}"))))
    IO.print(tag(root(J.parse(text()))))
    IO.print(age(root(J.parse(text()))))
