import Base
import ../ice_nomination.bend as N
import ../ice_valid.bend as V
import ../ice_session.bend as Session
import ../ice_attempts.bend as A
import ../ice_scheduler.bend as S
import ../ice_registry.bend as R
import ../ice_checklist.bend as Check
import ../ice_incoming.bend as Incoming
import ../ice_binding.bend as Ice
import ../ice_transactions.bend as Tx
import ../ice_pairs.bend as Pairs
import ../stun.bend as Stun
import ../stun_auth.bend as Auth
import ./ice_valid.bend as Example
import ./ice_valid_output.bend as ValidOutput
import ./ice_session_output.bend as Output
import ./ice_scheduler.bend as Scheduler
import ./ice_model.bend as Model
import ./ice_accept.bend as Format
import ../../crypto/bytes.bend as B
import ../../json/json.bend as J
import ../../io/io.bend as Io

type Fixture is Data:
  Fixture{state: N.State, saved: Maybe<&2, Session.Notice>}

type Turn is Data:
  Turn{fixture: Fixture, events: List<&2, Session.Notice>, valid: List<&2, V.Notice>,
       nomination: List<&2, N.Notice>, text: String}

def changed(step: N.Step, saved: Maybe<&2, Session.Notice>, text: String) -> Turn:
  match step:
    case N.Step{state, +events, valid, nomination}:
      Turn{Fixture{state, Example.send(events, saved)}, events, valid, nomination, text}

def adapted(turn: Example.Turn, state: N.State) -> Turn:
  match turn:
    case Example.Turn{Example.Fixture{v, saved}, events, valid, text}:
      changed(N.advance(V.Step{v, events, valid}, state), saved, text)

def request_text(request: Incoming.Request) -> String:
  match request:
    case Incoming.Request{tx, fragment, priority, role, nominate, mode}:
      B.hex(tx) ++ ":" ++ fragment ++ ":" ++ U32.show(priority) ++ ":" ++ Format.role(role) ++ ":" ++
      Format.flag(nominate) ++ ":" ++ Format.mode(mode)

def resolved_text(path: Maybe<&2, V.Path>) -> String:
  match path:
    case None{}: "none"
    case Some{p}: ValidOutput.path_text(p)

def resolved(path: Maybe<&2, V.Path>, reference: Pairs.Ref) -> IO(Unit):
  IO.print("resolved:" ++ Scheduler.ref_text(reference) ++ ":" ++ resolved_text(path))

def links(values: List<&2, N.Link>, +state: N.State) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{N.Link{+r, gen, path}, tail}:
      do IO<Unit>:
        a : Unit <- IO.print("association:" ++ U32.show(gen) ++ ":" ++ Scheduler.ref_text(r) ++ ":" ++ ValidOutput.path_text(path))
        b : Unit <- resolved(N.path_for(state, r), r)
        links(tail, state)

def intents(values: List<&2, N.Intent>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{N.Intent{r, gen, request}, tail}:
      do IO<Unit>:
        a : Unit <- IO.print("intent:" ++ U32.show(gen) ++ ":" ++ Scheduler.ref_text(r) ++ ":" ++ request_text(request))
        intents(tail)

def bindings(values: List<&2, N.Binding>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{N.Binding{record, request}, tail}:
      do IO<Unit>:
        a : Unit <- IO.print("intent-binding:" ++ Output.record(record) ++ ":" ++ request_text(request))
        bindings(tail)


def notice(value: N.Notice) -> IO(Unit):
  match value:
    case N.Mapped{record, request, path, late}:
      IO.print("intent-map:" ++ Format.flag(late) ++ ":" ++ Output.record(record) ++ ":" ++ request_text(request) ++ ":" ++ ValidOutput.path_text(path))
    case N.Outcome{+record, request, event}:
      do IO<Unit>:
        a : Unit <- IO.print("intent-outcome:" ++ Output.record(record) ++ ":" ++ request_text(request))
        Output.event(Session.Attempt{A.Transaction{Some{record}, event}})
    case N.NonSymmetric{record, request, observed, failed}:
      IO.print("intent-non-symmetric:" ++ Format.flag(failed) ++ ":" ++ Output.record(record) ++ ":" ++ request_text(request) ++ ":" ++ Scheduler.ref_text(observed))

def notices(values: List<&2, N.Notice>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{head, tail}:
      do IO<Unit>:
        a : Unit <- notice(head)
        notices(tail)

def current(state: N.State, saved: Maybe<&2, Session.Notice>) -> Bool:
  match saved:
    case Some{notice}: N.current_send(state, notice)
    case _: False{}

def snapshot(fixture: Fixture) -> IO(Fixture):
  match fixture:
    case Fixture{N.State{+v, +ls, +qs, +bs, +limit, +failed}, +saved}:
      +owner : N.State = N.State{v, ls, qs, bs, limit, failed}
      do IO<Fixture>:
        a : Unit <- IO.print("queued-send:" ++ Format.flag(current(owner, saved)))
        next : V.State <- ValidOutput.snapshot(v)
        b : Unit <- IO.print("nomination-fault:" ++ Format.flag(failed))
        c : Unit <- links(ls, owner)
        d : Unit <- intents(qs)
        e : Unit <- bindings(bs)
        IO.pure(Fixture, Fixture{N.State{next, ls, qs, bs, limit, failed}, saved})

def lookup_action(id: Result<&2, &2, J.Access, U32>, component: Result<&2, &2, J.Access, U32>, base: Maybe<&2, Stun.IPv4>, peer: Maybe<&2, Stun.IPv4>, +fixture: Fixture) -> IO(Turn):
  match id component base peer fixture:
    case Done{i} Done{c} Some{b} Some{p} Fixture{state, _}:
      IO.pure(Turn, Turn{fixture, [], [], [], "changed\nlookup:" ++ resolved_text(N.path_for(state, Pairs.Ref{i, c, b, p}))})
    case _ _ _ _ f: IO.pure(Turn, Turn{f, [], [], [], "rejected"})

def recreated(value: Maybe<&2, N.State>, fixture: Fixture) -> Turn:
  match value:
    case None{}: Turn{fixture, [], [], [], "rejected"}
    case Some{state}: Turn{Fixture{state, None{}}, [], [], [], "changed"}

def new_generation(value: Maybe<&2, V.State>, +fixture: Fixture) -> Turn:
  match value fixture:
    case Some{v} Fixture{state, saved}: changed(N.advance(V.Step{v, [], []}, state), saved, "changed")
    case _ f: Turn{f, [], [], [], "rejected"}

# Replacing the core is a synthetic ownership test, not a public ICE restart.
def generation_action(value: Result<&2, &2, J.Access, U32>, +fixture: Fixture) -> Turn:
  match value fixture:
    case Done{g} Fixture{N.State{V.State{Session.State{A.State{S.State{_, _, _, role, _, _, _, limit}, Tx.State{_, _, capacity, _, _}, _, _}, R.State{streams, _, _, _}, secret, _, _, mode}, _, _, _, valid_limit, _}, _, _, _, _, _}, _}:
      new_generation(V.from_session(Session.create(streams, role, secret, mode, limit, capacity, g), valid_limit), fixture)
    case _ f: Turn{f, [], [], [], "rejected"}

# Deliberately keep old flights/listeners/records to verify that the evidence
# owner guards generation independently of core cleanup. This is not restart.
def retained_generation(value: Result<&2, &2, J.Access, U32>, +fixture: Fixture) -> Turn:
  match value fixture:
    case Done{g} Fixture{N.State{V.State{Session.State{A.State{S.State{ls, qs, fs, role, cursor, token, _, cap}, engine, records, policies}, registry, secret, peer, pending, mode}, locals, names, paths, limit, faulted}, _, _, _, _, _}, _}:
      new_generation(Some{V.State{Session.State{A.State{S.State{ls, qs, fs, role, cursor, token, g, cap}, engine, records, policies}, registry, secret, peer, pending, mode}, locals, names, paths, limit, faulted}}, fixture)
    case _ f: Turn{f, [], [], [], "rejected"}

def recreate_action(+fixture: Fixture) -> IO(Turn):
  match fixture:
    case Fixture{state, _}: IO.pure(Turn, recreated(N.create(N.core(state)), fixture))

# Keep owner-state matching separate from recursive JSON alternatives. Combining
# them in one pattern matrix expands thousands of native compiler continuations.
def ordinary_action(step: J.Json, +fixture: Fixture) -> IO(Turn):
  match fixture:
    case Fixture{N.State{_, _, _, _, _, True{}}, _}: IO.pure(Turn, Turn{fixture, [], [], [], "rejected"})
    case Fixture{+state, saved}: IO.pure(Turn, adapted(Example.action(step, Example.Fixture{N.core(state), saved}), state))

def action(step: J.Json, fixture: Fixture) -> IO(Turn):
  match step:
    case J.JArr{[J.JStr{"lookup"}, id, component, base, peer]}:
      lookup_action(J.u32(id), J.u32(component), Model.address(base), Model.address(peer), fixture)
    case J.JArr{[J.JStr{"recreate"}]}: recreate_action(fixture)
    case J.JArr{[J.JStr{"synthetic-generation"}, gen]}: IO.pure(Turn, generation_action(J.u32(gen), fixture))
    case J.JArr{[J.JStr{"synthetic-retained-generation"}, gen]}: IO.pure(Turn, retained_generation(J.u32(gen), fixture))
    case s: ordinary_action(s, fixture)

def acted(turn: Turn, again: Fixture -> IO(Unit)) -> IO(Unit):
  match turn:
    case Turn{f, events, valid, nomination, text}:
      do IO<Unit>:
        a : Unit <- IO.print(text)
        b : Unit <- Output.events(events)
        c : Unit <- ValidOutput.notices(valid)
        d : Unit <- notices(nomination)
        next : Fixture <- snapshot(f)
        again(next)

def actions(fuel: Nat, values: List<&2, J.Json>, fixture: Fixture) -> IO(Unit):
  match fuel values:
    case _ Nil{}: IO.pure(Unit, Unit{})
    case 0n _: IO.print("invalid")
    case 1n+p Con{head, tail}:
      do IO<Unit>:
        turn : Turn <- action(head, fixture)
        acted(turn, next => actions(p, tail, next))

def owned(value: Maybe<&2, N.State>, steps: List<&2, J.Json>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{state}:
      do IO<Unit>:
        f : Fixture <- snapshot(Fixture{state, None{}})
        actions(1024n, steps, f)

def created(value: Maybe<&2, V.State>, steps: List<&2, J.Json>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{v}: owned(N.create(v), steps)

def parsed(streams: Maybe<&2, List<&2, Check.Stream>>, mode: Maybe<&2, Auth.Mode>, capacity: Result<&2, &2, J.Access, U32>, limit: Result<&2, &2, J.Access, U32>, valid_limit: Result<&2, &2, J.Access, U32>, steps: List<&2, J.Json>) -> IO(Unit):
  match streams mode capacity limit valid_limit:
    case Some{s} Some{m} Done{c} Done{l} Done{v}:
      created(V.from_session(Session.create(s, Ice.Controlling{0, 1}, Incoming.Secret{"localFrag", "LocalFixturePassword123456"}, m, l, c, 7), v), steps)
    case _ _ _ _ _: IO.print("invalid")

def decoded(value: Result<&2, &2, J.Error, J.Json>) -> IO(Unit):
  match value:
    case Done{J.JArr{[J.JArr{streams}, J.JStr{mode}, capacity, limit, valid_limit, J.JArr{steps}]}}:
      parsed(Model.streams(18n, streams, []), Example.mode(mode), J.u32(capacity), J.u32(limit), J.u32(valid_limit), steps)
    case _: IO.print("invalid")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [path]:
      do IO<Unit>:
        raw : List<&2, U32> <- Io.read_bytes(path)
        decoded(J.parse_bytes(raw))
    case _: IO.die(Unit, 2, "usage: ice_nomination_evidence <fixture.json>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
