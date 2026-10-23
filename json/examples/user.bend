import Base
import ../json.bend as J

type User is Data:
  User{name: String, age: U32, admin: Bool, email: Maybe<&2, String>, tags: List<&2, String>}

def User.to_json(u: User) -> J.Json:
  match u:
    case User{n, a, b, e, t}:
      J.obj([J.field_str("name", n), J.field_u32("age", a), J.field_bool("admin", b), J.field_opt(String, "email", e, s => J.JStr{s}), J.field_list(~String, ~(s => J.JStr{s}), "tags", t)])

def User.from_json(+j: J.Json) -> Result<&2, &2, J.Access, User>:
  J.both5(String, U32, Bool, Maybe<&2, String>, List<&2, String>, User,
    J.string_at(j, [J.Name{"name"}]), J.u32_at(j, [J.Name{"age"}]), J.bool_at(j, [J.Name{"admin"}]),
    J.string_opt_at(j, [J.Name{"email"}]), J.list_at(~String, ~(x => J.string_at(x, [])), j, [J.Name{"tags"}]),
    n => a => b => e => t => User{n, a, b, e, t})

def user(r: Result<&2, &2, J.Error, J.Json>) -> Result<&2, &2, J.Access, User>:
  match r:
    case Done{j}:
      User.from_json(j)
    case Fail{_}:
      Fail{J.Missing{[]}}

def show_email(e: Maybe<&2, String>) -> String:
  match e:
    case None{}:
      ""
    case Some{s}:
      " " ++ s

def show_tags(xs: List<&2, String>, out: String) -> String:
  match xs:
    case Nil{}:
      out
    case Con{h, t}:
      show_tags(t, out ++ " " ++ h)

def show(r: Result<&2, &2, J.Access, User>) -> String:
  match r:
    case Done{User{n, a, _, e, t}}:
      show_tags(t, n ++ " " ++ U32.show(a) ++ show_email(e))
    case Fail{e}:
      J.message_access(e)

def encoded_user() -> String:
  show(User.from_json(User.to_json(User{"Alex", 31, False{}, None{}, ["quant", "coffee"]})))

# Keep reads in defs: main owns its arguments.
def main() -> IO(Unit):
  do IO<Unit>:
    IO.print(encoded_user())
    IO.print(show(user(J.parse("{\"name\":\"Alex\",\"age\":31,\"admin\":false,\"tags\":[\"quant\"]}"))))
