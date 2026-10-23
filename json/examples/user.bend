import Base
import ../json.bend as J

type Pet is Data:
  Pet{name: String}

def Pet.to_json(p: Pet) -> J.Json:
  match p:
    case Pet{n}:
      J.obj([J.field_str("name", n)])

def Pet.from_json(j: J.Json) -> Result<&2, &2, J.Access, Pet>:
  J.map(String, Pet, J.string_at(j, [J.Name{"name"}]), n => Pet{n})

type Address is Data:
  Address{city: String, zip: U32}

def Address.to_json(a: Address) -> J.Json:
  match a:
    case Address{c, z}:
      J.obj([J.field_str("city", c), J.field_u32("zip", z)])

def Address.from_json(+j: J.Json) -> Result<&2, &2, J.Access, Address>:
  J.both(String, U32, Address, J.string_at(j, [J.Name{"city"}]), J.u32_at(j, [J.Name{"zip"}]), c => z => Address{c, z})

type User is Data:
  User{name: String, age: U32, admin: Bool, email: Maybe<&2, String>, tags: List<&2, String>, address: Address, pets: List<&2, Pet>}

def User.to_json(u: User) -> J.Json:
  match u:
    case User{n, a, b, e, t, address, pets}:
      J.obj([J.field_str("name", n), J.field_u32("age", a), J.field_bool("admin", b), J.field_opt(String, "email", e, s => J.JStr{s}), J.field_list(~String, ~(s => J.JStr{s}), "tags", t), J.field_obj(Address, "address", address, Address.to_json), J.field_list(~Pet, ~Pet.to_json, "pets", pets)])

def User.from_json(+j: J.Json) -> Result<&2, &2, J.Access, User>:
  J.both7(String, U32, Bool, Maybe<&2, String>, List<&2, String>, Address, List<&2, Pet>, User,
    J.string_at(j, [J.Name{"name"}]), J.u32_at(j, [J.Name{"age"}]), J.bool_at(j, [J.Name{"admin"}]),
    J.string_opt_at(j, [J.Name{"email"}]), J.list_at(~String, ~(x => J.string_at(x, [])), j, [J.Name{"tags"}]),
    J.decode_at(~Address, ~(x => Address.from_json(x)), j, [J.Name{"address"}]), J.list_at(~Pet, ~Pet.from_json, j, [J.Name{"pets"}]),
    n => a => b => e => t => address => pets => User{n, a, b, e, t, address, pets})

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

def show_pets(xs: List<&2, Pet>, out: String) -> String:
  match xs:
    case Nil{}:
      out
    case Con{Pet{n}, t}:
      show_pets(t, out ++ " " ++ n)

def show(r: Result<&2, &2, J.Access, User>) -> String:
  match r:
    case Done{User{n, a, _, e, t, Address{c, z}, pets}}:
      show_pets(pets, show_tags(t, n ++ " " ++ U32.show(a) ++ show_email(e)) ++ " " ++ c ++ " " ++ U32.show(z))
    case Fail{e}:
      J.message_access(e)

def encoded_user() -> String:
  show(User.from_json(User.to_json(User{"Alex", 31, False{}, None{}, ["quant", "coffee"], Address{"Lisbon", 1000}, [Pet{"Milo"}, Pet{"Luna"}]})))

def show_users.go(xs: List<&2, User>, out: String) -> String:
  match xs:
    case Nil{}:
      out
    case Con{u, t}:
      show_users.go(t, out ++ " | " ++ show(Done{u}))

def show_users(r: Result<&2, &2, J.Access, List<&2, User>>) -> String:
  match r:
    case Done{xs}:
      show_users.go(xs, "users")
    case Fail{e}:
      J.message_access(e)

def encoded_users() -> String:
  show_users(J.list_at(~User, ~(x => User.from_json(x)), J.list_json(~User, ~User.to_json, [User{"Alex", 31, False{}, None{}, [], Address{"Lisbon", 1000}, [Pet{"Milo"}]}, User{"Sam", 27, True{}, Some{"s@b"}, ["coffee"], Address{"Porto", 4000}, []}]), []))

# Keep reads in defs: main owns its arguments.
def main() -> IO(Unit):
  do IO<Unit>:
    IO.print(encoded_user())
    IO.print(encoded_users())
    IO.print(show(user(J.parse("{\"name\":\"Alex\",\"age\":31,\"admin\":false,\"tags\":[\"quant\"],\"address\":{\"city\":\"Lisbon\",\"zip\":1000},\"pets\":[{\"name\":\"Milo\"}]}"))))
