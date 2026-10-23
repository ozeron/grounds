import Base
import ./json.bend as J
import ./examples/users.bend as Users
import ./examples/user.bend as Recipe
import ./PROOF.bend as Proof
import ./proof/typed.bend as T

def R(-A: Data) -> Data:
  Result<&2, &2, J.Access, A>

def optional_missing() -> {J.string_opt_at(J.JObj{[]}, [J.Name{"email"}]) == Done{None{}} : R(Maybe<&2, String>)}:
  {==}

def optional_null() -> {J.string_opt_at(J.obj([[J.Field{"email", J.JNull{}}]]), [J.Name{"email"}]) == Done{None{}} : R(Maybe<&2, String>)}:
  {==}

def optional_some() -> {J.string_opt_at(J.obj([J.field_str("email", "a@b")]), [J.Name{"email"}]) == Done{Some{"a@b"}} : R(Maybe<&2, String>)}:
  {==}

def optional_parent_missing() -> {J.string_opt_at(J.JObj{[]}, [J.Name{"user"}, J.Name{"email"}]) == Fail{J.Missing{[J.Name{"user"}]}} : R(Maybe<&2, String>)}:
  {==}

def optional_parent_null() -> {J.string_opt_at(J.obj([[J.Field{"user", J.JNull{}}]]), [J.Name{"user"}, J.Name{"email"}]) == Fail{J.Expected{[J.Name{"user"}], J.KObject{}, J.KNull{}}} : R(Maybe<&2, String>)}:
  {==}

def optional_index_missing() -> {J.string_opt_at(J.JArr{[]}, [J.Index{0}]) == Fail{J.Missing{[J.Index{0}]}} : R(Maybe<&2, String>)}:
  {==}

def optional_index_null() -> {J.string_opt_at(J.JArr{[J.JNull{}]}, [J.Index{0}]) == Done{None{}} : R(Maybe<&2, String>)}:
  {==}

def optional_wrong_kind() -> {J.string_opt_at(J.obj([J.field_bool("email", False{})]), [J.Name{"email"}]) == Fail{J.Expected{[J.Name{"email"}], J.KString{}, J.KBool{}}} : R(Maybe<&2, String>)}:
  {==}

def optional_last_duplicate() -> {J.string_opt_at(J.obj([J.field_str("email", "old"), [J.Field{"email", J.JNull{}}]]), [J.Name{"email"}]) == Done{None{}} : R(Maybe<&2, String>)}:
  {==}

def optional_range() -> {J.u32_opt_at(J.JNum{J.Number{True{}, J.INon{J.L1{}, []}, J.FNone{}, J.ENone{}}}, []) == Fail{J.OutOfRange{[]}} : R(Maybe<&2, U32>)}:
  {==}

def default_error() -> {J.default(String, Fail{J.Missing{[J.Name{"parent"}]}}, "fallback") == Fail{J.Missing{[J.Name{"parent"}]}} : R(String)}:
  {==}

def list_order() -> {J.list_at(~String, ~(x => J.string_at(x, [])), J.obj([J.field_list(~String, ~(s => J.JStr{s}), "tags", ["a", "b", "c"])]), [J.Name{"tags"}]) == Done{["a", "b", "c"]} : R(List<&2, String>)}:
  {==}

def list_empty() -> {J.list_at(~String, ~(x => J.string_at(x, [])), J.JArr{[]}, []) == Done{[]} : R(List<&2, String>)}:
  {==}

def list_wrong_kind() -> {J.list_at(~String, ~(x => J.string_at(x, [])), J.obj([J.field_bool("tags", True{})]), [J.Name{"tags"}]) == Fail{J.Expected{[J.Name{"tags"}], J.KArray{}, J.KBool{}}} : R(List<&2, String>)}:
  {==}

def list_parent_missing() -> {J.list_at(~String, ~(x => J.string_at(x, [])), J.JObj{[]}, [J.Name{"tags"}]) == Fail{J.Missing{[J.Name{"tags"}]}} : R(List<&2, String>)}:
  {==}

def list_first_error() -> {J.list_at(~String, ~(x => J.string_at(x, [])), J.JArr{[J.JStr{"ok"}, J.JBool{True{}}, J.JNull{}]}, []) == Fail{J.Expected{[J.Index{1}], J.KString{}, J.KBool{}}} : R(List<&2, String>)}:
  {==}

def person(n: String, age: J.Json) -> J.Json:
  J.obj([J.field_str("name", n), [J.Field{"age", age}]])

def users_ok() -> {Users.decode(J.obj([J.field_str("title", "team"), [J.Field{"users", J.JArr{[person("A", J.num_u32(7)), person("B", J.num_u32(8))]}}]])) == Done{Users.Batch{"team", [Users.Person{"A", 7}, Users.Person{"B", 8}]}} : R(Users.Batch)}:
  {==}

def users_error() -> {Users.decode(J.obj([J.field_str("title", "team"), [J.Field{"users", J.JArr{[person("A", J.num_u32(7)), person("B", J.num_u32(8)), person("C", J.num_u32(9)), person("D", J.JBool{True{}})]}}]])) == Fail{J.Expected{[J.Name{"users"}, J.Index{3}, J.Name{"age"}], J.KNumber{}, J.KBool{}}} : R(Users.Batch)}:
  {==}

def users_message() -> {J.message_access(J.Expected{[J.Name{"users"}, J.Index{3}, J.Name{"age"}], J.KNumber{}, J.KBool{}}) == "$.users[3].age: expected number, found bool" : String}:
  {==}

def list_missing_item_key() -> {J.list_at(~U32, ~(x => J.u32_at(x, [J.Name{"age"}])), J.obj([[J.Field{"users", J.JArr{[J.JObj{[]}]}}]]), [J.Name{"users"}]) == Fail{J.Missing{[J.Name{"users"}, J.Index{0}, J.Name{"age"}]}} : R(List<&2, U32>)}:
  {==}

def nested_lists() -> {J.list_at(~List<&2, String>, ~(x => J.list_at(~String, ~(v => J.string_at(v, [])), x, [])), J.obj([[J.Field{"groups", J.JArr{[J.JArr{[]}, J.JArr{[J.JNull{}]}]}}]]), [J.Name{"groups"}]) == Fail{J.Expected{[J.Name{"groups"}, J.Index{1}, J.Index{0}], J.KString{}, J.KNull{}}} : R(List<&2, List<&2, String>>)}:
  {==}

# Instantiate the reusable helper theorems with a real scalar codec.
def optional_some_law(+k: String, +s: String) -> {J.string_opt_at(J.obj([J.field_opt(String, k, Some{s}, x => J.JStr{x})]), [J.Name{k}]) == Done{Some{s}} : R(Maybe<&2, String>)}:
  T.optional_some_round_trip(~String, ~(x => J.JStr{x}), ~(j => J.string_at(j, [])), ~T.string_copy_round_trip, ~(x => {==}), k, s)

def optional_none_law(+k: String) -> {J.string_opt_at(J.obj([J.field_opt(String, k, None{}, x => J.JStr{x})]), [J.Name{k}]) == Done{None{}} : R(Maybe<&2, String>)}:
  T.optional_none_round_trip(~String, ~(x => J.JStr{x}), ~(j => J.string_at(j, [])), k)

def both3_order() -> {J.both3(U32, U32, U32, List<&2, U32>, Done{1}, Done{2}, Done{3}, a => b => c => [a, b, c]) == Done{[1, 2, 3]} : R(List<&2, U32>)}:
  {==}

def both3_error_0() -> {J.both3(U32, U32, U32, List<&2, U32>, Fail{J.Missing{[J.Index{0}]}}, Fail{J.Missing{[J.Index{1}]}}, Fail{J.Missing{[J.Index{2}]}}, a => b => c => [a, b, c]) == Fail{J.Missing{[J.Index{0}]}} : R(List<&2, U32>)}:
  {==}

def both3_error_1() -> {J.both3(U32, U32, U32, List<&2, U32>, Done{1}, Fail{J.Missing{[J.Index{1}]}}, Fail{J.Missing{[J.Index{2}]}}, a => b => c => [a, b, c]) == Fail{J.Missing{[J.Index{1}]}} : R(List<&2, U32>)}:
  {==}

def both3_error_2() -> {J.both3(U32, U32, U32, List<&2, U32>, Done{1}, Done{2}, Fail{J.Missing{[J.Index{2}]}}, a => b => c => [a, b, c]) == Fail{J.Missing{[J.Index{2}]}} : R(List<&2, U32>)}:
  {==}

def both4_order() -> {J.both4(U32, U32, U32, U32, List<&2, U32>, Done{1}, Done{2}, Done{3}, Done{4}, a => b => c => d => [a, b, c, d]) == Done{[1, 2, 3, 4]} : R(List<&2, U32>)}:
  {==}

def both4_error_0() -> {J.both4(U32, U32, U32, U32, List<&2, U32>, Fail{J.Missing{[J.Index{0}]}}, Fail{J.Missing{[J.Index{1}]}}, Fail{J.Missing{[J.Index{2}]}}, Fail{J.Missing{[J.Index{3}]}}, a => b => c => d => [a, b, c, d]) == Fail{J.Missing{[J.Index{0}]}} : R(List<&2, U32>)}:
  {==}

def both4_error_1() -> {J.both4(U32, U32, U32, U32, List<&2, U32>, Done{1}, Fail{J.Missing{[J.Index{1}]}}, Fail{J.Missing{[J.Index{2}]}}, Fail{J.Missing{[J.Index{3}]}}, a => b => c => d => [a, b, c, d]) == Fail{J.Missing{[J.Index{1}]}} : R(List<&2, U32>)}:
  {==}

def both4_error_2() -> {J.both4(U32, U32, U32, U32, List<&2, U32>, Done{1}, Done{2}, Fail{J.Missing{[J.Index{2}]}}, Fail{J.Missing{[J.Index{3}]}}, a => b => c => d => [a, b, c, d]) == Fail{J.Missing{[J.Index{2}]}} : R(List<&2, U32>)}:
  {==}

def both4_error_3() -> {J.both4(U32, U32, U32, U32, List<&2, U32>, Done{1}, Done{2}, Done{3}, Fail{J.Missing{[J.Index{3}]}}, a => b => c => d => [a, b, c, d]) == Fail{J.Missing{[J.Index{3}]}} : R(List<&2, U32>)}:
  {==}

def both5_order() -> {J.both5(U32, U32, U32, U32, U32, List<&2, U32>, Done{1}, Done{2}, Done{3}, Done{4}, Done{5}, a => b => c => d => e => [a, b, c, d, e]) == Done{[1, 2, 3, 4, 5]} : R(List<&2, U32>)}:
  {==}

def both5_error_0() -> {J.both5(U32, U32, U32, U32, U32, List<&2, U32>, Fail{J.Missing{[J.Index{0}]}}, Fail{J.Missing{[J.Index{1}]}}, Fail{J.Missing{[J.Index{2}]}}, Fail{J.Missing{[J.Index{3}]}}, Fail{J.Missing{[J.Index{4}]}}, a => b => c => d => e => [a, b, c, d, e]) == Fail{J.Missing{[J.Index{0}]}} : R(List<&2, U32>)}:
  {==}

def both5_error_1() -> {J.both5(U32, U32, U32, U32, U32, List<&2, U32>, Done{1}, Fail{J.Missing{[J.Index{1}]}}, Fail{J.Missing{[J.Index{2}]}}, Fail{J.Missing{[J.Index{3}]}}, Fail{J.Missing{[J.Index{4}]}}, a => b => c => d => e => [a, b, c, d, e]) == Fail{J.Missing{[J.Index{1}]}} : R(List<&2, U32>)}:
  {==}

def both5_error_2() -> {J.both5(U32, U32, U32, U32, U32, List<&2, U32>, Done{1}, Done{2}, Fail{J.Missing{[J.Index{2}]}}, Fail{J.Missing{[J.Index{3}]}}, Fail{J.Missing{[J.Index{4}]}}, a => b => c => d => e => [a, b, c, d, e]) == Fail{J.Missing{[J.Index{2}]}} : R(List<&2, U32>)}:
  {==}

def both5_error_3() -> {J.both5(U32, U32, U32, U32, U32, List<&2, U32>, Done{1}, Done{2}, Done{3}, Fail{J.Missing{[J.Index{3}]}}, Fail{J.Missing{[J.Index{4}]}}, a => b => c => d => e => [a, b, c, d, e]) == Fail{J.Missing{[J.Index{3}]}} : R(List<&2, U32>)}:
  {==}

def both5_error_4() -> {J.both5(U32, U32, U32, U32, U32, List<&2, U32>, Done{1}, Done{2}, Done{3}, Done{4}, Fail{J.Missing{[J.Index{4}]}}, a => b => c => d => e => [a, b, c, d, e]) == Fail{J.Missing{[J.Index{4}]}} : R(List<&2, U32>)}:
  {==}

def both6_order() -> {J.both6(U32, U32, U32, U32, U32, U32, List<&2, U32>, Done{1}, Done{2}, Done{3}, Done{4}, Done{5}, Done{6}, a => b => c => d => e => f => [a, b, c, d, e, f]) == Done{[1, 2, 3, 4, 5, 6]} : R(List<&2, U32>)}:
  {==}

def both6_error_0() -> {J.both6(U32, U32, U32, U32, U32, U32, List<&2, U32>, Fail{J.Missing{[J.Index{0}]}}, Fail{J.Missing{[J.Index{1}]}}, Fail{J.Missing{[J.Index{2}]}}, Fail{J.Missing{[J.Index{3}]}}, Fail{J.Missing{[J.Index{4}]}}, Fail{J.Missing{[J.Index{5}]}}, a => b => c => d => e => f => [a, b, c, d, e, f]) == Fail{J.Missing{[J.Index{0}]}} : R(List<&2, U32>)}:
  {==}

def both6_error_1() -> {J.both6(U32, U32, U32, U32, U32, U32, List<&2, U32>, Done{1}, Fail{J.Missing{[J.Index{1}]}}, Fail{J.Missing{[J.Index{2}]}}, Fail{J.Missing{[J.Index{3}]}}, Fail{J.Missing{[J.Index{4}]}}, Fail{J.Missing{[J.Index{5}]}}, a => b => c => d => e => f => [a, b, c, d, e, f]) == Fail{J.Missing{[J.Index{1}]}} : R(List<&2, U32>)}:
  {==}

def both6_error_2() -> {J.both6(U32, U32, U32, U32, U32, U32, List<&2, U32>, Done{1}, Done{2}, Fail{J.Missing{[J.Index{2}]}}, Fail{J.Missing{[J.Index{3}]}}, Fail{J.Missing{[J.Index{4}]}}, Fail{J.Missing{[J.Index{5}]}}, a => b => c => d => e => f => [a, b, c, d, e, f]) == Fail{J.Missing{[J.Index{2}]}} : R(List<&2, U32>)}:
  {==}

def both6_error_3() -> {J.both6(U32, U32, U32, U32, U32, U32, List<&2, U32>, Done{1}, Done{2}, Done{3}, Fail{J.Missing{[J.Index{3}]}}, Fail{J.Missing{[J.Index{4}]}}, Fail{J.Missing{[J.Index{5}]}}, a => b => c => d => e => f => [a, b, c, d, e, f]) == Fail{J.Missing{[J.Index{3}]}} : R(List<&2, U32>)}:
  {==}

def both6_error_4() -> {J.both6(U32, U32, U32, U32, U32, U32, List<&2, U32>, Done{1}, Done{2}, Done{3}, Done{4}, Fail{J.Missing{[J.Index{4}]}}, Fail{J.Missing{[J.Index{5}]}}, a => b => c => d => e => f => [a, b, c, d, e, f]) == Fail{J.Missing{[J.Index{4}]}} : R(List<&2, U32>)}:
  {==}

def both6_error_5() -> {J.both6(U32, U32, U32, U32, U32, U32, List<&2, U32>, Done{1}, Done{2}, Done{3}, Done{4}, Done{5}, Fail{J.Missing{[J.Index{5}]}}, a => b => c => d => e => f => [a, b, c, d, e, f]) == Fail{J.Missing{[J.Index{5}]}} : R(List<&2, U32>)}:
  {==}

def optional_object() -> {J.optional_at(~Users.Person, ~(+x => J.both(String, U32, Users.Person, J.string_at(x, [J.Name{"name"}]), J.u32_at(x, [J.Name{"age"}]), n => a => Users.Person{n, a})), J.obj([[J.Field{"user", person("A", J.num_u32(7))}]]), [J.Name{"user"}]) == Done{Some{Users.Person{"A", 7}}} : R(Maybe<&2, Users.Person>)}:
  {==}

def optional_object_error() -> {J.optional_at(~Users.Person, ~(+x => J.both(String, U32, Users.Person, J.string_at(x, [J.Name{"name"}]), J.u32_at(x, [J.Name{"age"}]), n => a => Users.Person{n, a})), J.obj([[J.Field{"user", person("A", J.JBool{True{}})}]]), [J.Name{"user"}]) == Fail{J.Expected{[J.Name{"user"}, J.Name{"age"}], J.KNumber{}, J.KBool{}}} : R(Maybe<&2, Users.Person>)}:
  {==}

def encoder_omits_none() -> {J.obj([J.field_opt(String, "email", None{}, s => J.JStr{s})]) == J.JObj{[]} : J.Json}:
  {==}

def encoder_keeps_some() -> {J.obj([J.field_opt(String, "email", Some{"a@b"}, s => J.JStr{s})]) == J.JObj{[J.Field{"email", J.JStr{"a@b"}}]} : J.Json}:
  {==}

# Nested decoder paths compose with outer records and list indices.
def nested_city_missing() -> {J.decode_at(~Recipe.Address, ~(x => Recipe.Address.from_json(x)), J.JObj{[J.Field{"user", J.JObj{[J.Field{"address", J.JObj{[]}}]}}]}, [J.Name{"user"}, J.Name{"address"}]) == Fail{J.Missing{[J.Name{"user"}, J.Name{"address"}, J.Name{"city"}]}} : R(Recipe.Address)}:
  {==}

def nested_wrong_parent() -> {J.decode_at(~Recipe.Address, ~(x => Recipe.Address.from_json(x)), J.JBool{True{}}, [J.Name{"user"}]) == Fail{J.Expected{[], J.KObject{}, J.KBool{}}} : R(Recipe.Address)}:
  {==}

def nested_wrong_leaf() -> {J.decode_at(~Recipe.Address, ~(x => Recipe.Address.from_json(x)), J.JObj{[J.Field{"address", J.JBool{True{}}}]}, [J.Name{"address"}]) == Fail{J.Expected{[J.Name{"address"}], J.KObject{}, J.KBool{}}} : R(Recipe.Address)}:
  {==}

def nested_zip_kind() -> {J.decode_at(~U32, ~(x => J.u32_at(x, [J.Name{"zip"}])), J.JObj{[J.Field{"address", J.JObj{[J.Field{"zip", J.JBool{False{}}}]}}]}, [J.Name{"address"}]) == Fail{J.Expected{[J.Name{"address"}, J.Name{"zip"}], J.KNumber{}, J.KBool{}}} : R(U32)}:
  {==}

def nested_actual_range() -> {J.decode_at(~U32, ~(x => J.u32_at(x, [J.Name{"zip"}])), J.JObj{[J.Field{"address", J.JObj{[J.Field{"zip", J.JNum{J.Number{True{}, J.INon{J.L1{}, []}, J.FNone{}, J.ENone{}}}}]}}]}, [J.Name{"address"}]) == Fail{J.OutOfRange{[J.Name{"address"}, J.Name{"zip"}]}} : R(U32)}:
  {==}

def nested_root() -> {J.decode_at(~Recipe.Pet, ~Recipe.Pet.from_json, Recipe.Pet.to_json(Recipe.Pet{"Milo"}), []) == Done{Recipe.Pet{"Milo"}} : R(Recipe.Pet)}:
  {==}

def nested_duplicate() -> {J.decode_at(~Recipe.Pet, ~Recipe.Pet.from_json, J.JObj{[J.Field{"pet", Recipe.Pet.to_json(Recipe.Pet{"first"})}, J.Field{"pet", Recipe.Pet.to_json(Recipe.Pet{"last"})}]}, [J.Name{"pet"}]) == Done{Recipe.Pet{"last"}} : R(Recipe.Pet)}:
  {==}

def nested_list_error() -> {J.decode_at(~List<&2, Recipe.Pet>, ~(x => J.list_at(~Recipe.Pet, ~Recipe.Pet.from_json, x, [J.Name{"pets"}])), J.JObj{[J.Field{"user", J.JObj{[J.Field{"pets", J.JArr{[Recipe.Pet.to_json(Recipe.Pet{"Milo"}), J.JObj{[]}]}}]}}]}, [J.Name{"user"}]) == Fail{J.Missing{[J.Name{"user"}, J.Name{"pets"}, J.Index{1}, J.Name{"name"}]}} : R(List<&2, Recipe.Pet>)}:
  {==}

def nested_message() -> {J.message_access(J.Missing{[J.Name{"user"}, J.Name{"address"}, J.Name{"city"}]}) == "$.user.address.city: missing" : String}:
  {==}

def user_with_nested_values() -> {Recipe.User.from_json(Recipe.User.to_json(Recipe.User{"Alex", 31, True{}, Some{"a@b"}, ["quant", "coffee"], Recipe.Address{"Lisbon", 1000}, [Recipe.Pet{"Milo"}, Recipe.Pet{"Luna"}]})) == Done{Recipe.User{"Alex", 31, True{}, Some{"a@b"}, ["quant", "coffee"], Recipe.Address{"Lisbon", 1000}, [Recipe.Pet{"Milo"}, Recipe.Pet{"Luna"}]}} : R(Recipe.User)}:
  {==}

def copy_budget_zero() -> {J.copy_json.go(0n, J.CopyValue{}, J.JStr{"kept"}, [], []) == Fail{J.OutOfRange{[]}} : R(J.Json)}:
  {==}

def copy_budget_child() -> {J.copy_json.go(2n, J.CopyValue{}, J.JArr{[J.JBool{True{}}]}, [], []) == Fail{J.OutOfRange{[]}} : R(J.Json)}:
  {==}

def copy_budget_object() -> {J.copy_json.go(2n, J.CopyValue{}, J.JObj{[J.Field{"key", J.JNull{}}]}, [], []) == Fail{J.OutOfRange{[]}} : R(J.Json)}:
  {==}

def both7_error_1() -> {J.both7(U32, U32, U32, U32, U32, U32, U32, U32, Fail{J.Missing{[J.Index{1}]}}, Fail{J.Missing{[J.Index{2}]}}, Fail{J.Missing{[J.Index{3}]}}, Fail{J.Missing{[J.Index{4}]}}, Fail{J.Missing{[J.Index{5}]}}, Fail{J.Missing{[J.Index{6}]}}, Fail{J.Missing{[J.Index{7}]}}, a => b => c => d => e => f => g => g) == Fail{J.Missing{[J.Index{1}]}} : R(U32)}:
  {==}

def both7_error_2() -> {J.both7(U32, U32, U32, U32, U32, U32, U32, U32, Done{1}, Fail{J.Missing{[J.Index{2}]}}, Fail{J.Missing{[J.Index{3}]}}, Fail{J.Missing{[J.Index{4}]}}, Fail{J.Missing{[J.Index{5}]}}, Fail{J.Missing{[J.Index{6}]}}, Fail{J.Missing{[J.Index{7}]}}, a => b => c => d => e => f => g => g) == Fail{J.Missing{[J.Index{2}]}} : R(U32)}:
  {==}

def both7_error_3() -> {J.both7(U32, U32, U32, U32, U32, U32, U32, U32, Done{1}, Done{2}, Fail{J.Missing{[J.Index{3}]}}, Fail{J.Missing{[J.Index{4}]}}, Fail{J.Missing{[J.Index{5}]}}, Fail{J.Missing{[J.Index{6}]}}, Fail{J.Missing{[J.Index{7}]}}, a => b => c => d => e => f => g => g) == Fail{J.Missing{[J.Index{3}]}} : R(U32)}:
  {==}

def both7_error_4() -> {J.both7(U32, U32, U32, U32, U32, U32, U32, U32, Done{1}, Done{2}, Done{3}, Fail{J.Missing{[J.Index{4}]}}, Fail{J.Missing{[J.Index{5}]}}, Fail{J.Missing{[J.Index{6}]}}, Fail{J.Missing{[J.Index{7}]}}, a => b => c => d => e => f => g => g) == Fail{J.Missing{[J.Index{4}]}} : R(U32)}:
  {==}

def both7_error_5() -> {J.both7(U32, U32, U32, U32, U32, U32, U32, U32, Done{1}, Done{2}, Done{3}, Done{4}, Fail{J.Missing{[J.Index{5}]}}, Fail{J.Missing{[J.Index{6}]}}, Fail{J.Missing{[J.Index{7}]}}, a => b => c => d => e => f => g => g) == Fail{J.Missing{[J.Index{5}]}} : R(U32)}:
  {==}

def both7_error_6() -> {J.both7(U32, U32, U32, U32, U32, U32, U32, U32, Done{1}, Done{2}, Done{3}, Done{4}, Done{5}, Fail{J.Missing{[J.Index{6}]}}, Fail{J.Missing{[J.Index{7}]}}, a => b => c => d => e => f => g => g) == Fail{J.Missing{[J.Index{6}]}} : R(U32)}:
  {==}

def both7_error_7() -> {J.both7(U32, U32, U32, U32, U32, U32, U32, U32, Done{1}, Done{2}, Done{3}, Done{4}, Done{5}, Done{6}, Fail{J.Missing{[J.Index{7}]}}, a => b => c => d => e => f => g => g) == Fail{J.Missing{[J.Index{7}]}} : R(U32)}:
  {==}

def copy_budget_tail() -> {J.copy_json.go(3n, J.CopyValue{}, J.JArr{[J.JNull{}, J.JNull{}]}, [], []) == Fail{J.OutOfRange{[]}} : R(J.Json)}:
  {==}

def copy_budget_path() -> {J.decode_at(~J.Json, ~(x => J.copy_json.go(1n, J.CopyValue{}, x, [], [])), J.JObj{[J.Field{"data", J.JArr{[J.JNull{}]}}]}, [J.Name{"data"}]) == Fail{J.OutOfRange{[J.Name{"data"}]}} : R(J.Json)}:
  {==}

# A real structural witness exercises the general identity theorem; arbitrary
# keys and strings prevent a closed example from substituting for the law.
def copy_budget_law(+k: String, +s: String) -> {J.copy_json.go(5n, J.CopyValue{}, J.JObj{[J.Field{k, J.JArr{[J.JStr{s}]}}]}, [], []) == Done{J.JObj{[J.Field{k, J.JArr{[J.JStr{s}]}}]}} : R(J.Json)}:
  T.copy_json.go_id(5n, J.CopyValue{}, J.JObj{[J.Field{k, J.JArr{[J.JStr{s}]}}]}, [], [], ((Unit{}, Unit{}), Unit{}))
