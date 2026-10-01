import Base
import ./ice_agent_output.bend as Shared
import ../ice_agent.bend as Agent
import ../ice_nomination.bend as N
import ../ice_valid.bend as V
import ../ice_session.bend as Session
import ../ice_checklist.bend as Check
import ../ice_binding.bend as Ice
import ../ice_incoming.bend as Incoming
import ../ice_pairs.bend as Pairs
import ../stun.bend as Stun
import ../stun_auth.bend as Auth
import ../stun_retry.bend as Retry
import ../stun_client.bend as Discovery
import ./ice_valid.bend as Example
import ./ice_nomination_evidence.bend as Evidence
import ./ice_valid_output.bend as ValidOutput
import ./ice_session_output.bend as Output
import ./ice_scheduler.bend as Scheduler
import ./ice_model.bend as Model
import ./ice_accept.bend as Format
import ../../json/json.bend as J
import ../../io/io.bend as Io

type Fixture is Data:
  Fixture{state: Agent.State, saved: Maybe<&2, Session.Notice>, now: Nat}

type Turn is Data:
  Turn{fixture: Fixture, step: Agent.Step, text: String}

def changed(step: Agent.Step, saved: Maybe<&2, Session.Notice>, now: Nat) -> Turn:
  match step:
    case Agent.Step{+state, +events, +valid, +nom, +life}:
      Turn{Fixture{state, Example.send(events, saved), now}, Agent.Step{state, events, valid, nom, life}, "changed"}

def rejected(+fixture: Fixture) -> Turn:
  match fixture:
    case Fixture{state, _, _}: Turn{fixture, Agent.empty(state), "rejected"}

def maybe_changed(value: Maybe<&2, Agent.Step>, +fixture: Fixture) -> Turn:
  match value fixture:
    case Some{s} Fixture{_, saved, now}: changed(s, saved, now)
    case _ _: rejected(fixture)

def status_text(status: Agent.Status) -> String:
  Shared.status_text(status)

def numbers(values: List<&2, U32>) -> String:
  match values:
    case Nil{}: ""
    case Con{head, tail}: U32.show(head) ++ "," ++ numbers(tail)

def pac_text(pac: Agent.Pac) -> String:
  match pac:
    case Agent.Dormant{advertised}: "dormant:" ++ Format.flag(advertised)
    case Agent.Started{deadline}: "started:" ++ Nat.show(deadline)
    case Agent.Elapsed{}: "elapsed"

def plans(values: List<&2, Agent.Plan>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{Agent.Plan{path, ref, gen, attempt}, tail}:
      do IO<Unit>:
        a : Unit <- IO.print("plan:" ++ U32.show(gen) ++ ":" ++ Scheduler.ref_text(ref) ++ ":" ++ Output.maybe_record(attempt) ++ ":" ++ ValidOutput.path_text(path))
        plans(tail)

def selected(values: List<&2, U32>, +id: U32, +state: Agent.State) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{+comp, tail}:
      do IO<Unit>:
        a : Unit <- IO.print("selected:" ++ U32.show(id) ++ ":" ++ U32.show(comp) ++ ":" ++ Evidence.resolved_text(Agent.selected(state, id, comp)))
        selected(tail, id, state)

def streams(values: List<&2, Agent.Stream>, +state: Agent.State) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{Agent.Stream{+id, +req, failed, status}, tail}:
      do IO<Unit>:
        a : Unit <- IO.print("stream-status:" ++ U32.show(id) ++ ":" ++ status_text(status) ++ ":" ++ numbers(req) ++ ":" ++ numbers(failed))
        b : Unit <- selected(req, id, state)
        streams(tail, state)

def lifecycle(values: List<&2, Agent.Notice>) -> IO(Unit):
  Shared.lifecycle(values)

def snapshot(+fixture: Fixture) -> IO(Fixture):
  match fixture:
    case Fixture{Agent.State{+e, +ps, +ds, +ss, +pac, +cfg, +faulted}, +saved, +now}:
      +state : Agent.State = Agent.State{e, ps, ds, ss, pac, cfg, faulted}
      do IO<Fixture>:
        a : Unit <- IO.print("agent-status:" ++ status_text(Agent.status(state)))
        b : Unit <- IO.print("pac:" ++ pac_text(pac))
        c : Unit <- IO.print("agent-timeout:" ++ U32.show(Agent.timeout(state, now, 60000)))
        d : Unit <- plans(ps)
        f : Unit <- streams(ss, state)
        ef : Evidence.Fixture <- Evidence.snapshot(Evidence.Fixture{e, saved})
        IO.pure(Fixture, fixture)

def start_numbers(now: Result<&2, &2, J.Access, U32>, tx: Result<&2, &2, J.Access, U32>, count: Result<&2, &2, J.Access, U32>, fixture: Fixture) -> Turn:
  match now tx count fixture:
    case Done{+n} Done{t} Done{c} Fixture{state, saved, _}:
      changed(Agent.start(state, Discovery.transaction(t, 2, 3), Retry.Policy{500, c, 1}, U32.to_nat(n)), saved, U32.to_nat(n))
    case _ _ _ f: rejected(f)

def tick_number(now: Result<&2, &2, J.Access, U32>, fixture: Fixture) -> Turn:
  match now fixture:
    case Done{+n} Fixture{state, saved, _}: changed(Agent.tick(state, U32.to_nat(n)), saved, U32.to_nat(n))
    case _ f: rejected(f)

def signal_number(now: Result<&2, &2, J.Access, U32>, fixture: Fixture) -> Turn:
  match now fixture:
    case Done{+n} Fixture{state, saved, _}: changed(Agent.local_signaled(state, U32.to_nat(n)), saved, U32.to_nat(n))
    case _ f: rejected(f)

def nominate_numbers(id: Result<&2, &2, J.Access, U32>, comp: Result<&2, &2, J.Access, U32>, +fixture: Fixture) -> Turn:
  match id comp fixture:
    case Done{i} Done{c} Fixture{state, _, _}: maybe_changed(Agent.nominate_best(state, i, c), fixture)
    case _ _ f: rejected(f)

def receive_numbers(now: Result<&2, &2, J.Access, U32>, id: Result<&2, &2, J.Access, U32>, comp: Result<&2, &2, J.Access, U32>,
                    base: Maybe<&2, Stun.IPv4>, source: Maybe<&2, Stun.IPv4>, raw: Maybe<&2, List<&2, U32>>, fixture: Fixture) -> Turn:
  match now id comp base source raw fixture:
    case Done{+n} Done{i} Done{c} Some{b} Some{s} Some{r} Fixture{state, saved, _}:
      changed(Agent.receive(state, Pairs.Ref{i, c, b, s}, r, U32.to_nat(n)), saved, U32.to_nat(n))
    case _ _ _ _ _ _ f: rejected(f)

def bind_action(local: String, remote: String, password: String, +fixture: Fixture) -> Turn:
  match fixture:
    case Fixture{state, _, now}: maybe_changed(Agent.bind(state, Ice.Credentials{local, remote, password}, now), fixture)

def acknowledge(now: Result<&2, &2, J.Access, U32>, fixture: Fixture) -> Turn:
  match now fixture:
    case Done{+n} Fixture{state, Some{+notice}, _}:
      changed(Agent.acknowledge(state, notice, U32.to_nat(n)), Some{notice}, U32.to_nat(n))
    case _ f: rejected(f)

def failed_numbers(token: Result<&2, &2, J.Access, U32>, code: Result<&2, &2, J.Access, U32>, fixture: Fixture) -> Turn:
  match token code fixture:
    case Done{t} Done{c} Fixture{state, saved, +now}: changed(Agent.failed(state, t, c, now), saved, now)
    case _ _ f: rejected(f)

def repair_numbers(token: Result<&2, &2, J.Access, U32>, gen: Result<&2, &2, J.Access, U32>, high: Result<&2, &2, J.Access, U32>, low: Result<&2, &2, J.Access, U32>, +fixture: Fixture) -> Turn:
  match token gen high low fixture:
    case Done{t} Done{g} Done{h} Done{l} Fixture{state, _, now}: maybe_changed(Agent.repair(state, t, g, h, l, now), fixture)
    case _ _ _ _ f: rejected(f)

# Keep JSON dispatch separate from owner-state patterns to bound generated code.
def action(step: J.Json, fixture: Fixture) -> Turn:
  match step:
    case J.JArr{[J.JStr{"start"}, n, tx, count]}: start_numbers(J.u32(n), J.u32(tx), J.u32(count), fixture)
    case J.JArr{[J.JStr{"tick"}, n]}: tick_number(J.u32(n), fixture)
    case J.JArr{[J.JStr{"signal"}, n]}: signal_number(J.u32(n), fixture)
    case J.JArr{[J.JStr{"nominate"}, id, comp]}: nominate_numbers(J.u32(id), J.u32(comp), fixture)
    case J.JArr{[J.JStr{"receive"}, n, id, comp, b, s, J.JArr{raw}]}:
      receive_numbers(J.u32(n), J.u32(id), J.u32(comp), Model.address(b), Model.address(s), Example.bytes(65557n, raw, []), fixture)
    case J.JArr{[J.JStr{"bind"}, J.JStr{l}, J.JStr{r}, J.JStr{p}]}: bind_action(l, r, p, fixture)
    case J.JArr{[J.JStr{"ack"}, n]}: acknowledge(J.u32(n), fixture)
    case J.JArr{[J.JStr{"fail"}, t, c]}: failed_numbers(J.u32(t), J.u32(c), fixture)
    case J.JArr{[J.JStr{"repair"}, t, g, h, l]}: repair_numbers(J.u32(t), J.u32(g), J.u32(h), J.u32(l), fixture)
    case _: rejected(fixture)

def acted(turn: Turn, again: Fixture -> IO(Unit)) -> IO(Unit):
  match turn:
    case Turn{f, Agent.Step{_, events, valid, nom, life}, text}:
      do IO<Unit>:
        a : Unit <- IO.print(text)
        b : Unit <- Output.events(events)
        c : Unit <- ValidOutput.notices(valid)
        d : Unit <- Evidence.notices(nom)
        e : Unit <- lifecycle(life)
        next : Fixture <- snapshot(f)
        again(next)

def actions(fuel: Nat, values: List<&2, J.Json>, fixture: Fixture) -> IO(Unit):
  match fuel values:
    case _ Nil{}: IO.pure(Unit, Unit{})
    case 0n _: IO.print("invalid")
    case 1n+p Con{head, tail}: acted(action(head, fixture), next => actions(p, tail, next))

def owned(value: Maybe<&2, Agent.State>, steps: List<&2, J.Json>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{state}:
      do IO<Unit>:
        f : Fixture <- snapshot(Fixture{state, None{}, 0n})
        actions(1024n, steps, f)

def created(value: Maybe<&2, V.State>, config: Agent.Config, steps: List<&2, J.Json>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{v}: owned(Agent.create(v, config), steps)

def parsed(ss: Maybe<&2, List<&2, Check.Stream>>, mode: Maybe<&2, Auth.Mode>, capacity: Result<&2, &2, J.Access, U32>, limit: Result<&2, &2, J.Access, U32>,
           valid_limit: Result<&2, &2, J.Access, U32>, pac: Result<&2, &2, J.Access, U32>, automatic: Result<&2, &2, J.Access, Bool>, steps: List<&2, J.Json>) -> IO(Unit):
  match ss mode capacity limit valid_limit pac automatic:
    case Some{s} Some{m} Done{c} Done{l} Done{v} Done{p} Done{a}:
      created(V.from_session(Session.create(s, Ice.Controlling{0, 1}, Incoming.Secret{"localFrag", "LocalFixturePassword123456"}, m, l, c, 7), v), Agent.Config{p, a}, steps)
    case _ _ _ _ _ _ _: IO.print("invalid")

def decoded(value: Result<&2, &2, J.Error, J.Json>) -> IO(Unit):
  match value:
    case Done{J.JArr{[J.JArr{ss}, J.JStr{m}, c, l, v, p, a, J.JArr{steps}]}}:
      parsed(Model.streams(18n, ss, []), Example.mode(m), J.u32(c), J.u32(l), J.u32(v), J.u32(p), J.bool(a), steps)
    case _: IO.print("invalid")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [path]:
      do IO<Unit>:
        raw : List<&2, U32> <- Io.read_bytes(path)
        decoded(J.parse_bytes(raw))
    case _: IO.print("invalid")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args
    dispatch(args)
