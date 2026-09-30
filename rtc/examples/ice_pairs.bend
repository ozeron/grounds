import Base
import ../ice_pairs.bend as Pairs
import ../ice_checklist.bend as Check
import ../stun.bend as Stun
import ./ice_model.bend as Model
import ../../json/json.bend as J
import ../../io/io.bend as Io

type Saved is Data:
  Saved{name: String, reference: Pairs.Ref}

type Fixture is Data:
  Fixture{streams: List<&2, Check.Checklist>, references: List<&2, Saved>}

def saved(values: List<&2, Saved>, +name: String) -> Maybe<&2, Pairs.Ref>:
  match values:
    case Nil{}: None{}
    case Con{Saved{+got, +reference}, tail}:
      Bool.pick(Maybe<&2, Pairs.Ref>, String.eq(got, name), Some{reference}, saved(tail, name))

def remember(pair: Maybe<&2, Check.CandidatePair>, stream: U32, name: String,
             streams: List<&2, Check.Checklist>, values: List<&2, Saved>) -> Maybe<&2, Fixture>:
  match pair:
    case None{}: None{}
    case Some{p}: Some{Fixture{streams, Con{Saved{name, Pairs.reference(stream, p)}, values}}}

def remember_numbers(stream: Result<&2, &2, J.Access, U32>, index: Result<&2, &2, J.Access, U32>,
                     name: String, +streams: List<&2, Check.Checklist>, values: List<&2, Saved>) -> Maybe<&2, Fixture>:
  match stream index:
    case Done{+id} Done{i}: remember(Check.get_stream(streams, id, U32.to_nat(i)), id, name, streams, values)
    case _ _: None{}

def changed(streams: Maybe<&2, List<&2, Check.Checklist>>, values: List<&2, Saved>) -> Maybe<&2, Fixture>:
  match streams:
    case None{}: None{}
    case Some{s}: Some{Fixture{s, values}}

def mutate(name: String, reference: Maybe<&2, Pairs.Ref>, streams: List<&2, Check.Checklist>, values: List<&2, Saved>) -> Maybe<&2, Fixture>:
  match name reference:
    case "begin" Some{r}: changed(Pairs.begin(streams, r), values)
    case "success" Some{r}: changed(Pairs.finish_check(streams, r, True{}), values)
    case "failure" Some{r}: changed(Pairs.finish_check(streams, r, False{}), values)
    case _ _: None{}

def reference_numbers(id: Result<&2, &2, J.Access, U32>, component: Result<&2, &2, J.Access, U32>,
                      base: Maybe<&2, Stun.IPv4>, remote: Maybe<&2, Stun.IPv4>, name: String,
                      streams: List<&2, Check.Checklist>, values: List<&2, Saved>) -> Maybe<&2, Fixture>:
  match id component base remote:
    case Done{i} Done{c} Some{b} Some{r}: Some{Fixture{streams, Con{Saved{name, Pairs.Ref{i, c, b, r}}, values}}}
    case _ _ _ _: None{}

def action(step: J.Json, fixture: Fixture) -> Maybe<&2, Fixture>:
  match step fixture:
    case J.JArr{[J.JStr{"remember"}, J.JStr{name}, id, index]} Fixture{streams, values}:
      remember_numbers(J.u32(id), J.u32(index), name, streams, values)
    case J.JArr{[J.JStr{"reference"}, J.JStr{name}, id, component, base, remote]} Fixture{streams, values}:
      reference_numbers(J.u32(id), J.u32(component), Model.address(base), Model.address(remote), name, streams, values)
    case J.JArr{[J.JStr{"role"}, J.JBool{control}]} Fixture{streams, values}:
      changed(Pairs.reorder(streams, control), values)
    case J.JArr{[J.JStr{name}, J.JStr{ref}]} Fixture{streams, +values}:
      mutate(name, saved(values, ref), streams, values)
    case _ _: None{}

def location(position: Maybe<&2, Pairs.Position>) -> IO(Unit):
  match position:
    case Some{Pairs.Position{stream, index, _}}: IO.print("location:" ++ U32.show(stream) ++ ":" ++ Nat.show(index))
    case None{}: IO.print("missing")

def locate(reference: Maybe<&2, Pairs.Ref>, streams: List<&2, Check.Checklist>) -> IO(Unit):
  match reference:
    case None{}: IO.print("missing")
    case Some{r}: location(Pairs.lookup(streams, r))

def actions(fuel: Nat, steps: List<&2, J.Json>, fixture: Maybe<&2, Fixture>) -> IO(Unit):
  match fuel steps fixture:
    case _ _ None{}: IO.print("invalid")
    case 0n _ _: IO.print("invalid")
    case 1n+_ Nil{} Some{Fixture{streams, _}}: Model.show_lists(streams)
    case 1n+p Con{J.JArr{[J.JStr{"locate"}, J.JStr{name}]}, tail} Some{Fixture{+streams, +values}}:
      do IO<Unit>:
        x : Unit <- locate(saved(values, name), streams)
        actions(p, tail, Some{Fixture{streams, values}})
    case 1n+p Con{step, tail} Some{f}: actions(p, tail, action(step, f))

def built(streams: Maybe<&2, List<&2, Check.Checklist>>, steps: List<&2, J.Json>) -> IO(Unit):
  match streams:
    case None{}: IO.print("invalid")
    case Some{s}: actions(1024n, steps, Some{Fixture{s, []}})

def parsed(streams: Maybe<&2, List<&2, Check.Stream>>, controlling: Bool, steps: List<&2, J.Json>) -> IO(Unit):
  match streams:
    case None{}: IO.print("invalid")
    case Some{s}: built(Check.build(s, controlling, 256), steps)

def decoded(result: Result<&2, &2, J.Error, J.Json>) -> IO(Unit):
  match result:
    case Done{J.JArr{[J.JBool{control}, J.JArr{streams}, J.JArr{steps}]}}: parsed(Model.streams(18n, streams, []), control, steps)
    case _: IO.print("invalid")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [path]:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        decoded(J.parse_bytes(bytes))
    case _: IO.die(Unit, 2, "usage: ice_pairs <fixture.json>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
