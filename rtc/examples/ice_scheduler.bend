import Base
import ../ice_scheduler.bend as S
import ../ice_binding.bend as Ice
import ../ice_pairs.bend as Pairs
import ../ice_checklist.bend as Check
import ../ice_candidates.bend as C
import ./ice_model.bend as Model
import ../../json/json.bend as J
import ../../io/io.bend as Io

type Notice is Data:
  Notice{state: S.State, text: String}

def role(control: Bool, +high: U32, +low: U32) -> Ice.Role:
  Bool.pick(Ice.Role, control, Ice.Controlling{high, low}, Ice.Controlled{high, low})

def role_text(role: Ice.Role) -> String:
  match role:
    case Ice.Controlling{high, low}: "controlling:" ++ U32.show(high) ++ ":" ++ U32.show(low)
    case Ice.Controlled{high, low}: "controlled:" ++ U32.show(high) ++ ":" ++ U32.show(low)

def ref_text(reference: Pairs.Ref) -> String:
  match reference:
    case Pairs.Ref{id, component, +base, +remote}:
      U32.show(id) ++ ":" ++ U32.show(component) ++ ":" ++ C.host(base) ++ "/" ++ U32.show(C.port(base)) ++ ":" ++
      C.host(remote) ++ "/" ++ U32.show(C.port(remote))

def changed(value: Maybe<&2, S.State>, old: S.State) -> Notice:
  match value:
    case None{}: Notice{old, "rejected"}
    case Some{s}: Notice{s, "changed"}

def interrupted(value: Maybe<&2, U32>) -> String:
  match value:
    case None{}: "none"
    case Some{t}: U32.show(t)

def change(value: Maybe<&2, S.Change>, old: S.State) -> Notice:
  match value:
    case None{}: Notice{old, "rejected"}
    case Some{S.Change{s, token}}: Notice{s, "triggered:" ++ interrupted(token)}

def selected(choice: S.Choice, old: S.State) -> Notice:
  match choice:
    case S.Rejected{}: Notice{old, "rejected"}
    case S.Idle{s}: Notice{s, "idle"}
    case S.Selected{s, ref, token, sent}: Notice{s, "selected:" ++ U32.show(token) ++ ":" ++ ref_text(ref) ++ ":" ++ role_text(sent)}

def proposed(value: Notice, original: S.State) -> Notice:
  match value:
    case Notice{_, text}: Notice{original, "proposed:" ++ text}

def trigger_pair(pair: Maybe<&2, Check.CandidatePair>, id: U32, +state: S.State) -> Notice:
  match pair:
    case None{}: Notice{state, "rejected"}
    case Some{p}: change(S.trigger(state, Pairs.reference(id, p)), state)

def trigger_numbers(id: Result<&2, &2, J.Access, U32>, index: Result<&2, &2, J.Access, U32>, state: S.State) -> Notice:
  match id index state:
    case Done{+id} Done{i} S.State{+ls, +qs, +fs, +r, +at, +next, +gen, +cap}:
      trigger_pair(Check.get_stream(ls, id, U32.to_nat(i)), id, S.State{ls, qs, fs, r, at, next, gen, cap})
    case _ _ s: Notice{s, "rejected"}

def complete_numbers(token: Result<&2, &2, J.Access, U32>, generation: Result<&2, &2, J.Access, U32>, success: Bool, +state: S.State) -> Notice:
  match token generation:
    case Done{t} Done{g}: changed(S.complete(state, t, g, success), state)
    case _ _: Notice{state, "rejected"}

def role_numbers(control: Bool, high: Result<&2, &2, J.Access, U32>, low: Result<&2, &2, J.Access, U32>, +state: S.State) -> Notice:
  match high low:
    case Done{h} Done{l}: changed(S.switch_role(state, role(control, h, l)), state)
    case _ _: Notice{state, "rejected"}

def repair_numbers(token: Result<&2, &2, J.Access, U32>, generation: Result<&2, &2, J.Access, U32>,
                   high: Result<&2, &2, J.Access, U32>, low: Result<&2, &2, J.Access, U32>, +state: S.State) -> Notice:
  match token generation high low:
    case Done{t} Done{g} Done{h} Done{l}: change(S.repair_conflict(state, t, g, h, l), state)
    case _ _ _ _: Notice{state, "rejected"}

def insert_numbers(id: Result<&2, &2, J.Access, U32>, local: Maybe<&2, C.Local>, remote: Maybe<&2, C.Candidate>, +state: S.State) -> Notice:
  match id local remote:
    case Done{id} Some{ls} Some{r}: change(S.insert_triggered(state, id, ls, r), state)
    case _ _ _: Notice{state, "rejected"}

# Snapshot-only allocator injection exercises the U32 exhaustion boundary.
def allocator(value: Result<&2, &2, J.Access, U32>, state: S.State) -> Notice:
  match value state:
    case Done{n} S.State{ls, qs, fs, r, at, _, g, cap}: Notice{S.State{ls, qs, fs, r, at, U32.to_nat(n), g, cap}, "changed"}
    case _ s: Notice{s, "rejected"}

def action(step: J.Json, +state: S.State) -> Notice:
  match step:
    case J.JArr{[J.JStr{"select"}]}: selected(S.select(state), state)
    case J.JArr{[J.JStr{"propose"}]}: proposed(selected(S.select(state), state), state)
    case J.JArr{[J.JStr{"trigger"}, id, index]}: trigger_numbers(J.u32(id), J.u32(index), state)
    case J.JArr{[J.JStr{"complete"}, token, gen, J.JBool{ok}]}: complete_numbers(J.u32(token), J.u32(gen), ok, state)
    case J.JArr{[J.JStr{"role"}, J.JBool{control}, high, low]}: role_numbers(control, J.u32(high), J.u32(low), state)
    case J.JArr{[J.JStr{"repair"}, token, gen, high, low]}: repair_numbers(J.u32(token), J.u32(gen), J.u32(high), J.u32(low), state)
    case J.JArr{[J.JStr{"insert"}, id, local, remote]}: insert_numbers(J.u32(id), Model.local(local), Model.candidate(remote), state)
    case J.JArr{[J.JStr{"allocator"}, next]}: allocator(J.u32(next), state)
    case _: Notice{state, "rejected"}

def show_refs(refs: List<&2, Pairs.Ref>) -> IO(Unit):
  match refs:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{r, tail}:
      do IO<Unit>:
        x : Unit <- IO.print("queued:" ++ ref_text(r))
        show_refs(tail)

def show_queues(values: List<&2, S.Queue>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{S.Queue{id, refs}, tail}:
      do IO<Unit>:
        x : Unit <- IO.print("queue:" ++ U32.show(id))
        y : Unit <- show_refs(refs)
        show_queues(tail)

def show_flights(values: List<&2, S.Flight>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{S.Flight{token, ref, r}, tail}:
      do IO<Unit>:
        x : Unit <- IO.print("flight:" ++ U32.show(token) ++ ":" ++ ref_text(ref) ++ ":" ++ role_text(r))
        show_flights(tail)

def snapshot(+state: S.State) -> IO(S.State):
  match state:
    case S.State{+ls, +qs, +fs, +r, +at, +next, +gen, +cap}:
      do IO<S.State>:
        a : Unit <- IO.print("state:" ++ role_text(r) ++ ":" ++ Nat.show(at) ++ ":" ++ Nat.show(next) ++ ":" ++ U32.show(gen) ++ ":" ++ U32.show(cap))
        b : Unit <- Model.show_lists(ls)
        c : Unit <- show_queues(qs)
        d : Unit <- show_flights(fs)
        IO.pure(S.State, S.State{ls, qs, fs, r, at, next, gen, cap})

def acted(value: Notice, again: S.State -> IO(Unit)) -> IO(Unit):
  match value:
    case Notice{s, text}:
      do IO<Unit>:
        x : Unit <- IO.print(text)
        next : S.State <- snapshot(s)
        again(next)

def actions(fuel: Nat, steps: List<&2, J.Json>, state: S.State) -> IO(Unit):
  match fuel steps:
    case _ Nil{}: IO.pure(Unit, Unit{})
    case 0n _: IO.print("invalid")
    case 1n+p Con{step, tail}: acted(action(step, state), next => actions(p, tail, next))

def created(value: Maybe<&2, S.State>, steps: List<&2, J.Json>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{s}:
      do IO<Unit>:
        state : S.State <- snapshot(s)
        actions(1024n, steps, state)

def parsed(streams: Maybe<&2, List<&2, Check.Stream>>, control: Bool,
           cap: Result<&2, &2, J.Access, U32>, gen: Result<&2, &2, J.Access, U32>, steps: List<&2, J.Json>) -> IO(Unit):
  match streams cap gen:
    case Some{s} Done{cap} Done{gen}: created(S.create(s, role(control, 1, 2), cap, gen), steps)
    case _ _ _: IO.print("invalid")

def decoded(value: Result<&2, &2, J.Error, J.Json>) -> IO(Unit):
  match value:
    case Done{J.JArr{[J.JBool{control}, cap, gen, J.JArr{streams}, J.JArr{steps}]}}:
      parsed(Model.streams(18n, streams, []), control, J.u32(cap), J.u32(gen), steps)
    case _: IO.print("invalid")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [path]:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        decoded(J.parse_bytes(bytes))
    case _: IO.die(Unit, 2, "usage: ice_scheduler <fixture.json>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
