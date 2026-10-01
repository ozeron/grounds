import Base
import ../ice_checklist.bend as Check
import ../ice_transactions.bend as Tx
import ../ice_session.bend as Session
import ../ice_valid.bend as V
import ../ice_attempts.bend as A
import ../ice_binding.bend as Ice
import ../ice_incoming.bend as Incoming
import ../ice_pairs.bend as Pairs
import ../stun.bend as Stun
import ../stun_retry.bend as Retry
import ../stun_auth.bend as Auth
import ../stun_client.bend as Discovery
import ./ice_model.bend as Model
import ./ice_session_output.bend as Output
import ./ice_valid_output.bend as ValidOutput
import ./ice_accept.bend as Format
import ../../json/json.bend as J
import ../../io/io.bend as Io

type Fixture is Data:
  Fixture{state: V.State, saved: Maybe<&2, Session.Notice>}

type Turn is Data:
  Turn{fixture: Fixture, events: List<&2, Session.Notice>, valid: List<&2, V.Notice>, text: String}

def send(values: List<&2, Session.Notice>, previous: Maybe<&2, Session.Notice>) -> Maybe<&2, Session.Notice>:
  match values:
    case Nil{}: previous
    case Con{Session.Attempt{A.Transaction{r, Tx.Send{token, host, port, bytes, fresh}}}, tail}:
      send(tail, Some{Session.Attempt{A.Transaction{r, Tx.Send{token, host, port, bytes, fresh}}}})
    case Con{_, tail}: send(tail, previous)

def changed(step: V.Step, saved: Maybe<&2, Session.Notice>) -> Turn:
  match step:
    case V.Step{state, +events, valid}: Turn{Fixture{state, send(events, saved)}, events, valid, "changed"}

def maybe_changed(step: Maybe<&2, V.Step>, old: Fixture) -> Turn:
  match step old:
    case None{} f: Turn{f, [], [], "rejected"}
    case Some{s} Fixture{_, saved}: changed(s, saved)

def parsed_byte(value: Result<&2, &2, J.Access, U32>, rev: List<&2, U32>, again: List<&2, U32> -> Maybe<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  match value:
    case Done{v}: again(Con{v, rev})
    case _: None{}

def bytes(fuel: Nat, values: List<&2, J.Json>, rev: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match fuel values:
    case 0n _: None{}
    case 1n+_ Nil{}: Some{List.reverse(&2, U32, rev)}
    case 1n+p Con{head, tail}: parsed_byte(J.u32(head), rev, r => bytes(p, tail, r))

def receive_numbers(now: Result<&2, &2, J.Access, U32>, id: Result<&2, &2, J.Access, U32>, component: Result<&2, &2, J.Access, U32>,
                    base: Maybe<&2, Stun.IPv4>, source: Maybe<&2, Stun.IPv4>, raw: Maybe<&2, List<&2, U32>>, fixture: Fixture) -> Turn:
  match now id component base source raw fixture:
    case Done{n} Done{i} Done{c} Some{b} Some{s} Some{r} Fixture{state, saved}:
      changed(V.receive(state, Pairs.Ref{i, c, b, s}, r, U32.to_nat(n)), saved)
    case _ _ _ _ _ _ f: Turn{f, [], [], "rejected"}

def start_numbers(now: Result<&2, &2, J.Access, U32>, transaction: Result<&2, &2, J.Access, U32>, requests: Result<&2, &2, J.Access, U32>, fixture: Fixture) -> Turn:
  match now transaction requests fixture:
    case Done{n} Done{tx} Done{rc} Fixture{state, saved}:
      changed(V.start(state, Discovery.transaction(tx, 2, 3), Retry.Policy{500, rc, 1}, U32.to_nat(n)), saved)
    case _ _ _ f: Turn{f, [], [], "rejected"}

def tick_number(now: Result<&2, &2, J.Access, U32>, fixture: Fixture) -> Turn:
  match now fixture:
    case Done{n} Fixture{state, saved}: changed(V.tick(state, U32.to_nat(n)), saved)
    case _ f: Turn{f, [], [], "rejected"}

def repair_numbers(token: Result<&2, &2, J.Access, U32>, gen: Result<&2, &2, J.Access, U32>, high: Result<&2, &2, J.Access, U32>, low: Result<&2, &2, J.Access, U32>, +fixture: Fixture) -> Turn:
  match token gen high low fixture:
    case Done{t} Done{g} Done{h} Done{l} Fixture{state, _}: maybe_changed(V.repair(state, t, g, h, l), fixture)
    case _ _ _ _ f: Turn{f, [], [], "rejected"}

def failed_numbers(token: Result<&2, &2, J.Access, U32>, code: Result<&2, &2, J.Access, U32>, fixture: Fixture) -> Turn:
  match token code fixture:
    case Done{t} Done{c} Fixture{state, saved}: changed(V.failed(state, t, c), saved)
    case _ _ f: Turn{f, [], [], "rejected"}

def acknowledge(now: Result<&2, &2, J.Access, U32>, fixture: Fixture) -> Turn:
  match now fixture:
    case Done{n} Fixture{state, Some{+notice}}: changed(V.acknowledge(state, notice, U32.to_nat(n)), Some{notice})
    case _ f: Turn{f, [], [], "rejected"}

def action(step: J.Json, +fixture: Fixture) -> Turn:
  match step fixture:
    case J.JArr{[J.JStr{"bind"}, J.JStr{local}, J.JStr{remote}, J.JStr{password}]} Fixture{state, _}:
      maybe_changed(V.bind(state, Ice.Credentials{local, remote, password}), fixture)
    case J.JArr{[J.JStr{"start"}, now, tx, rc]} f: start_numbers(J.u32(now), J.u32(tx), J.u32(rc), f)
    case J.JArr{[J.JStr{"tick"}, now]} f: tick_number(J.u32(now), f)
    case J.JArr{[J.JStr{"receive"}, now, id, component, base, source, J.JArr{raw}]} f:
      receive_numbers(J.u32(now), J.u32(id), J.u32(component), Model.address(base), Model.address(source), bytes(65556n, raw, []), f)
    case J.JArr{[J.JStr{"repair"}, token, gen, high, low]} f: repair_numbers(J.u32(token), J.u32(gen), J.u32(high), J.u32(low), f)
    case J.JArr{[J.JStr{"fail"}, token, code]} f: failed_numbers(J.u32(token), J.u32(code), f)
    case J.JArr{[J.JStr{"ack"}, now]} f: acknowledge(J.u32(now), f)
    case J.JArr{[J.JStr{"drain"}]} Fixture{state, saved}: changed(V.drain(state), saved)
    case _ f: Turn{f, [], [], "rejected"}

def current(state: V.State, value: Maybe<&2, Session.Notice>) -> Bool:
  match value:
    case None{}: False{}
    case Some{notice}: V.current_send(state, notice)

def snapshot(fixture: Fixture) -> IO(Fixture):
  match fixture:
    case Fixture{+state, +saved}:
      do IO<Fixture>:
        x : Unit <- IO.print("queued-send:" ++ Format.flag(current(state, saved)))
        next : V.State <- ValidOutput.snapshot(state)
        IO.pure(Fixture, Fixture{next, saved})

def acted(turn: Turn, again: Fixture -> IO(Unit)) -> IO(Unit):
  match turn:
    case Turn{f, events, valid, text}:
      do IO<Unit>:
        a : Unit <- IO.print(text)
        b : Unit <- Output.events(events)
        c : Unit <- ValidOutput.notices(valid)
        next : Fixture <- snapshot(f)
        again(next)

def actions(fuel: Nat, steps: List<&2, J.Json>, fixture: Fixture) -> IO(Unit):
  match fuel steps:
    case _ Nil{}: IO.pure(Unit, Unit{})
    case 0n _: IO.print("invalid")
    case 1n+p Con{step, tail}: acted(action(step, fixture), next => actions(p, tail, next))

def created(value: Maybe<&2, V.State>, steps: List<&2, J.Json>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{state}:
      do IO<Unit>:
        f : Fixture <- snapshot(Fixture{state, None{}})
        actions(1024n, steps, f)

def parsed(streams: Maybe<&2, List<&2, Check.Stream>>, mode: Maybe<&2, Auth.Mode>, capacity: Result<&2, &2, J.Access, U32>,
           limit: Result<&2, &2, J.Access, U32>, valid_limit: Result<&2, &2, J.Access, U32>, steps: List<&2, J.Json>) -> IO(Unit):
  match streams mode capacity limit valid_limit:
    case Some{s} Some{m} Done{c} Done{l} Done{v}:
      created(V.from_session(Session.create(s, Ice.Controlling{0, 1}, Incoming.Secret{"localFrag", "LocalFixturePassword123456"}, m, l, c, 7), v), steps)
    case _ _ _ _ _: IO.print("invalid")

def mode(name: String) -> Maybe<&2, Auth.Mode>:
  match name:
    case "legacy": Some{Auth.Legacy{}}
    case "sha256": Some{Auth.Sha256{}}
    case "dual": Some{Auth.Dual{}}
    case _: None{}

def decoded(value: Result<&2, &2, J.Error, J.Json>) -> IO(Unit):
  match value:
    case Done{J.JArr{[J.JArr{streams}, J.JStr{name}, capacity, limit, valid_limit, J.JArr{steps}]}}:
      parsed(Model.streams(18n, streams, []), mode(name), J.u32(capacity), J.u32(limit), J.u32(valid_limit), steps)
    case _: IO.print("invalid")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [path]:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        decoded(J.parse_bytes(bytes))
    case _: IO.die(Unit, 2, "usage: ice_session <fixture.json>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
