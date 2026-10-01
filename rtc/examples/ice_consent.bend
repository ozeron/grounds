import Base
import ../ice_consent.bend as Consent
import ../ice_binding.bend as Ice
import ../ice_pairs.bend as Pairs
import ../stun.bend as Stun
import ../stun_auth.bend as Auth
import ../stun_client.bend as Discovery
import ./ice_model.bend as Model
import ./ice_valid.bend as Parse
import ../../crypto/bytes.bend as B
import ../../json/json.bend as J
import ../../io/io.bend as Io

# Deterministic entropy is confined to this local synthetic test interface.
type Fixture is Data:
  Fixture{state: Consent.State, saved: Maybe<&2, Consent.Notice>, now: Nat}

type Turn is Data:
  Turn{fixture: Fixture, events: List<&2, Consent.Notice>, text: String}

def status(status: Consent.Status) -> String:
  match status:
    case Consent.Awaiting{}: "awaiting"
    case Consent.Granted{}: "granted"
    case Consent.Expired{}: "expired"
    case Consent.Revoked{}: "revoked"
    case Consent.Closed{}: "closed"

def mode(mode: Auth.Mode) -> String:
  match mode:
    case Auth.Legacy{}: "legacy"
    case Auth.Sha256{}: "sha256"
    case Auth.Dual{}: "dual"

def flag(value: Bool) -> String:
  match value:
    case True{}: "1"
    case False{}: "0"

def saved(values: List<&2, Consent.Notice>, previous: Maybe<&2, Consent.Notice>) -> Maybe<&2, Consent.Notice>:
  match values:
    case Nil{}: previous
    case Con{Consent.Send{ref, gen, token, bytes}, tail}: saved(tail, Some{Consent.Send{ref, gen, token, bytes}})
    case Con{_, tail}: saved(tail, previous)

def changed(step: Consent.Step, previous: Maybe<&2, Consent.Notice>, now: Nat, text: String) -> Turn:
  match step:
    case Consent.Step{state, +events}: Turn{Fixture{state, saved(events, previous), now}, events, text}

def started(start: Consent.Start, previous: Maybe<&2, Consent.Notice>, now: Nat) -> Turn:
  match start:
    case Consent.Ready{step}: changed(step, previous, now, "ready")
    case Consent.Later{step, at}: changed(step, previous, now, "later:" ++ Nat.show(at))
    case Consent.Rejected{step}: changed(step, previous, now, "rejected")

def rejected(+fixture: Fixture) -> Turn:
  Turn{fixture, [], "rejected"}

def event(event: Consent.Notice) -> IO(Unit):
  match event:
    case Consent.Send{_, gen, token, bytes}: IO.print("send:" ++ U32.show(gen) ++ ":" ++ U32.show(token) ++ ":" ++ B.hex(bytes))
    case Consent.Sent{token}: IO.print("sent:" ++ U32.show(token))
    case Consent.Renewed{token, expires}: IO.print("renewed:" ++ U32.show(token) ++ ":" ++ Nat.show(expires))
    case Consent.TimedOut{token}: IO.print("timedout:" ++ U32.show(token))
    case Consent.Error{token, code}: IO.print("error:" ++ U32.show(token) ++ ":" ++ U32.show(code))
    case Consent.Invalid{token}: IO.print("invalid-response:" ++ U32.show(token))
    case Consent.TransportError{token, code}: IO.print("transport-error:" ++ U32.show(token) ++ ":" ++ U32.show(code))
    case Consent.Changed{s}: IO.print("status-changed:" ++ status(s))

def events(values: List<&2, Consent.Notice>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{head, tail}:
      do IO<Unit>:
        x : Unit <- event(head)
        events(tail)

def sent_text(sent: Maybe<&2, Nat>) -> String:
  match sent:
    case None{}: "pending"
    case Some{now}: Nat.show(now)

def probes(values: List<&2, Consent.Probe>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{Consent.Probe{token, tx, _, algo, sent, deadline, interval}, tail}:
      do IO<Unit>:
        x : Unit <- IO.print("probe:" ++ U32.show(token) ++ ":" ++ B.hex(tx) ++ ":" ++ mode(algo) ++ ":" ++ sent_text(sent) ++ ":" ++ Nat.show(deadline) ++ ":" ++ U32.show(interval))
        probes(tail)

def current(saved: Maybe<&2, Consent.Notice>, state: Consent.State, now: Nat) -> String:
  match saved:
    case None{}: "0"
    case Some{notice}: flag(Consent.current_send(state, notice, now))

def snapshot(+fixture: Fixture) -> IO(Fixture):
  match fixture:
    case Fixture{Consent.State{Consent.Route{+ref, +gen, creds, check, +algo}, Consent.Clock{+s, +expires, +next, +rto, +mean, +variation}, +ps, +recent, +token}, +saved, +now}:
      +state : Consent.State = Consent.State{Consent.Route{ref, gen, creds, check, algo}, Consent.Clock{s, expires, next, rto, mean, variation}, ps, recent, token}
      do IO<Fixture>:
        a : Unit <- IO.print("status:" ++ status(s))
        b : Unit <- IO.print("clock:" ++ Nat.show(expires) ++ ":" ++ Nat.show(next) ++ ":" ++ U32.show(rto) ++ ":" ++ Nat.show(mean) ++ ":" ++ Nat.show(variation))
        c : Unit <- IO.print("allowed:" ++ flag(Consent.allowed(state, ref, gen, now)))
        d : Unit <- IO.print("current-send:" ++ current(saved, state, now))
        e : Unit <- IO.print("timeout:" ++ U32.show(Consent.timeout(state, now, 60000)))
        f : Unit <- IO.print("algorithm:" ++ mode(algo))
        g : Unit <- IO.print("history:" ++ Nat.show(List.length(&2, List<&2, U32>, recent)))
        h : Unit <- probes(ps)
        IO.pure(Fixture, fixture)

def start_numbers(n: Result<&2, &2, J.Access, U32>, t: Result<&2, &2, J.Access, U32>, j: Result<&2, &2, J.Access, U32>, gate: Result<&2, &2, J.Access, U32>, fixture: Fixture) -> Turn:
  match n t j gate fixture:
    case Done{+now} Done{tx} Done{jitter} Done{at} Fixture{state, previous, _}:
      started(Consent.start(state, Discovery.transaction(tx, 2, 3), jitter, U32.to_nat(now), U32.to_nat(at)), previous, U32.to_nat(now))
    case _ _ _ _ f: rejected(f)

def tick_number(n: Result<&2, &2, J.Access, U32>, fixture: Fixture) -> Turn:
  match n fixture:
    case Done{+now} Fixture{state, previous, _}: changed(Consent.tick(state, U32.to_nat(now)), previous, U32.to_nat(now), "changed")
    case _ f: rejected(f)

def ack_number(n: Result<&2, &2, J.Access, U32>, fixture: Fixture) -> Turn:
  match n fixture:
    case Done{+now} Fixture{state, Some{+previous}, _}: changed(Consent.acknowledge(state, previous, U32.to_nat(now)), Some{previous}, U32.to_nat(now), "changed")
    case _ f: rejected(f)

def receive_numbers(n: Result<&2, &2, J.Access, U32>, base: Maybe<&2, Stun.IPv4>, peer: Maybe<&2, Stun.IPv4>, g: Result<&2, &2, J.Access, U32>, raw: Maybe<&2, List<&2, U32>>, fixture: Fixture) -> Turn:
  match n base peer g raw fixture:
    case Done{+now} Some{b} Some{p} Done{gen} Some{bytes} Fixture{state, previous, _}:
      changed(Consent.receive(state, Pairs.Ref{1, 1, b, p}, gen, bytes, U32.to_nat(now)), previous, U32.to_nat(now), "changed")
    case _ _ _ _ _ f: rejected(f)

def fail_numbers(t: Result<&2, &2, J.Access, U32>, c: Result<&2, &2, J.Access, U32>, fixture: Fixture) -> Turn:
  match t c fixture:
    case Done{token} Done{code} Fixture{state, previous, now}: changed(Consent.failed(state, token, code), previous, now, "changed")
    case _ _ f: rejected(f)

def gate_numbers(n: Result<&2, &2, J.Access, U32>, sid: Result<&2, &2, J.Access, U32>, comp: Result<&2, &2, J.Access, U32>, base: Maybe<&2, Stun.IPv4>, peer: Maybe<&2, Stun.IPv4>, gen: Result<&2, &2, J.Access, U32>, +fixture: Fixture) -> Turn:
  match n sid comp base peer gen fixture:
    case Done{now} Done{id} Done{component} Some{b} Some{p} Done{g} Fixture{state, _, _}:
      Turn{fixture, [], "gate:" ++ flag(Consent.allowed(state, Pairs.Ref{id, component, b, p}, g, U32.to_nat(now)))}
    case _ _ _ _ _ _ f: rejected(f)

def closing(fixture: Fixture) -> Turn:
  match fixture:
    case Fixture{state, previous, now}: changed(Consent.close(state), previous, now, "changed")

def action(step: J.Json, fixture: Fixture) -> Turn:
  match step:
    case J.JArr{[J.JStr{"start"}, n, t, j, gate]}: start_numbers(J.u32(n), J.u32(t), J.u32(j), J.u32(gate), fixture)
    case J.JArr{[J.JStr{"tick"}, n]}: tick_number(J.u32(n), fixture)
    case J.JArr{[J.JStr{"ack"}, n]}: ack_number(J.u32(n), fixture)
    case J.JArr{[J.JStr{"receive"}, n, b, p, g, J.JArr{raw}]}:
      receive_numbers(J.u32(n), Model.address(b), Model.address(p), J.u32(g), Parse.bytes(65557n, raw, []), fixture)
    case J.JArr{[J.JStr{"fail"}, t, c]}: fail_numbers(J.u32(t), J.u32(c), fixture)
    case J.JArr{[J.JStr{"gate"}, n, sid, comp, b, p, g]}:
      gate_numbers(J.u32(n), J.u32(sid), J.u32(comp), Model.address(b), Model.address(p), J.u32(g), fixture)
    case J.JArr{[J.JStr{"close"}]}: closing(fixture)
    case _: rejected(fixture)

def acted(turn: Turn, again: Fixture -> IO(Unit)) -> IO(Unit):
  match turn:
    case Turn{fixture, notices, text}:
      do IO<Unit>:
        a : Unit <- IO.print(text)
        b : Unit <- events(notices)
        next : Fixture <- snapshot(fixture)
        again(next)

def actions(fuel: Nat, values: List<&2, J.Json>, fixture: Fixture) -> IO(Unit):
  match fuel values:
    case _ Nil{}: IO.pure(Unit, Unit{})
    case 0n _: IO.print("invalid")
    case 1n+p Con{head, tail}: acted(action(head, fixture), f => actions(p, tail, f))

def created(value: Maybe<&2, Consent.State>, steps: List<&2, J.Json>, now: Nat) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{state}:
      do IO<Unit>:
        f : Fixture <- snapshot(Fixture{state, None{}, now})
        actions(4096n, steps, f)

def parsed(mode: Maybe<&2, Auth.Mode>, rto: Result<&2, &2, J.Access, U32>, n: Result<&2, &2, J.Access, U32>, steps: List<&2, J.Json>) -> IO(Unit):
  match mode rto n:
    case Some{m} Done{r} Done{+now}:
      created(Consent.create(Consent.Route{Pairs.Ref{1, 1, Stun.IPv4{127, 0, 0, 1, 10001}, Stun.IPv4{127, 0, 0, 1, 20001}}, 7,
        Ice.Credentials{"localFrag", "remoteFrag", "SyntheticPassword123456789"}, Ice.Check{1845494271, Ice.Controlling{0, 1}}, m}, r, U32.to_nat(now)), steps, U32.to_nat(now))
    case _ _ _: IO.print("invalid")

def decoded(value: Result<&2, &2, J.Error, J.Json>) -> IO(Unit):
  match value:
    case Done{J.JArr{[J.JStr{m}, rto, now, J.JArr{steps}]}}: parsed(Parse.mode(m), J.u32(rto), J.u32(now), steps)
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
    args : List<String> <- IO.args()
    dispatch(args)
