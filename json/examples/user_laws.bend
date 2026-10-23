import Base
import ./user.bend as Recipe
import ../json.bend as J
import ../PROOF.bend as Proof
import ../proof/typed.bend as T
import ../proof/parse.bend as Text

law user_round_trip:
  for +u: Recipe.User
  {Recipe.User.from_json(Recipe.User.to_json(u)) == Done{u} : T.R(Recipe.User)}

def user_round_trip(u):
  match u:
    case Recipe.User{n, a, b, None{}, t}:
      T.both5_reads(String, U32, Bool, Maybe<&2, String>, List<&2, String>, Recipe.User, n, a, b, None{}, t,
        J.string_at(J.JStr{n}, []), J.read_at.fin(U32, J.u32(J.copy_leaf(J.num_u32(a))), [J.Name{"age"}]), J.bool_at(J.JBool{b}, []), Done{None{}}, J.list_read(~String, ~(x => J.string_at(x, [])), J.list_json(~String, ~(x => J.JStr{x}), t), [J.Name{"tags"}]),
        n => a => b => e => t => Recipe.User{n, a, b, e, t}, T.string_copy_round_trip(n), T.u32_copy_at(a, [J.Name{"age"}]), T.bool_copy_round_trip(b), {==}, T.list_round_trip(~String, ~(x => J.JStr{x}), ~(x => J.string_at(x, [])), ~T.string_copy_round_trip, t, [J.Name{"tags"}]))
    case Recipe.User{n, a, b, Some{e}, t}:
      T.both5_reads(String, U32, Bool, Maybe<&2, String>, List<&2, String>, Recipe.User, n, a, b, Some{e}, t,
        J.string_at(J.JStr{n}, []), J.read_at.fin(U32, J.u32(J.copy_leaf(J.num_u32(a))), [J.Name{"age"}]), J.bool_at(J.JBool{b}, []), J.optional(~String, ~J.string, J.copy_leaf(J.JStr{e})), J.list_read(~String, ~(x => J.string_at(x, [])), J.list_json(~String, ~(x => J.JStr{x}), t), [J.Name{"tags"}]),
        n => a => b => e => t => Recipe.User{n, a, b, e, t}, T.string_copy_round_trip(n), T.u32_copy_at(a, [J.Name{"age"}]), T.bool_copy_round_trip(b), T.string_optional_present(e), T.list_round_trip(~String, ~(x => J.JStr{x}), ~(x => J.string_at(x, [])), ~T.string_copy_round_trip, t, [J.Name{"tags"}]))

law user_text_round_trip:
  for +u: Recipe.User
  {Recipe.user(J.parse(J.encode(Recipe.User.to_json(u)))) == Done{u} : T.R(Recipe.User)}

def user_text_round_trip(u):
  %Equal.sym(Result<&2, &2, J.Error, J.Json>, J.parse(J.encode(Recipe.User.to_json(u))), Done{Recipe.User.to_json(u)}, Text.round_trip(Recipe.User.to_json(u))) : {Recipe.user(_) == Done{u} : T.R(Recipe.User)}
  user_round_trip(u)

def main() -> IO(Unit):
  Recipe.main()

law users_round_trip:
  for +users: List<&2, Recipe.User>
  {J.list_at(~Recipe.User, ~(x => Recipe.User.from_json(x)), J.list_json(~Recipe.User, ~Recipe.User.to_json, users), []) == Done{users} : T.R(List<&2, Recipe.User>)}

def users_round_trip(users):
  T.list_at_round_trip(~Recipe.User, ~Recipe.User.to_json, ~(x => Recipe.User.from_json(x)), ~user_round_trip, users)
