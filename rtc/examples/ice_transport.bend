import Base
import ../ice_transport.bend as T
import ../ice_agent.bend as Agent
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
import ./ice_model.bend as Model
import ./ice_valid.bend as Parse
import ./ice_transport_output.bend as Output
import ./ice_scheduler.bend as Scheduler
import ./ice_consent.bend as Probe
import ../../json/json.bend as J
import ../../io/io.bend as Io

type Action is Data:
  Invalid{}
  Start{now: Nat, transaction: U32, count: U32}
  Tick{now: Nat}
  Signal{now: Nat}
  Bind{local: String, remote: String, password: String}
  Receive{now: Nat, reference: Pairs.Ref, bytes: List<&2, U32>}
  Probe{now: Nat, transaction: U32, jitter: U32, generation: U32, reference: Pairs.Ref}
  Ack{now: Nat, index: Nat}
  SendFailure{now: Nat, index: Nat, code: U32}
  Current{now: Nat, index: Nat}
  Gate{now: Nat, generation: U32, reference: Pairs.Ref}
  Route{now: Nat, id: U32, component: U32}
  Restart{now: Nat, secret: Incoming.Secret, streams: List<&2, Check.Stream>}
  Repair{now: Nat, token: U32, generation: U32, high: U32, low: U32}
  Nominate{now: Nat, reference: Pairs.Ref}
  Closing{}

type Fixture is Data:
  Fixture{state: T.State, saved: List<&2, T.Packet>, now: Nat}

type Turn is Data:
  Turn{fixture: Fixture, events: List<&2, T.Notice>, text: String}

def limited(fuel: Nat, values: List<&2, T.Packet>) -> List<&2, T.Packet>:
  match fuel values:
    case 0n _: []
    case _ Nil{}: []
    case 1n+p Con{head, tail}: Con{head, limited(p, tail)}

def saved(values: List<&2, T.Notice>, previous: List<&2, T.Packet>) -> List<&2, T.Packet>:
  match values:
    case Nil{}: limited(128n, previous)
    case Con{T.Transmit{packet}, tail}: saved(tail, Con{packet, previous})
    case Con{_, tail}: saved(tail, previous)

def get(values: List<&2, T.Packet>, index: Nat) -> Maybe<&2, T.Packet>:
  match values index:
    case Con{head, _} 0n: Some{head}
    case Con{_, tail} 1n+p: get(tail, p)
    case _ _: None{}

def changed(step: T.Step, previous: List<&2, T.Packet>, now: Nat) -> Turn:
  match step:
    case T.Step{state, +events}: Turn{Fixture{state, saved(events, previous), now}, events, "changed"}

def rejected(fixture: Fixture) -> Turn:
  Turn{fixture, [], "invalid-action"}

def packet_action(value: Action, got: Maybe<&2, T.Packet>, +fixture: Fixture) -> Turn:
  match value got fixture:
    case Ack{+now, _} Some{packet} Fixture{state, previous, _}: changed(T.acknowledge(state, packet, now), previous, now)
    case SendFailure{+now, _, code} Some{packet} Fixture{state, previous, _}: changed(T.failed(state, packet, code, now), previous, now)
    case Current{now, _} Some{packet} Fixture{state, _, _}: Turn{fixture, [], "current:" ++ Probe.flag(T.current_send(state, packet, now))}
    case _ _ f: rejected(f)

def route_text(value: Maybe<&2, T.Route>) -> String:
  match value:
    case None{}: "none"
    case Some{T.Route{ref, gen}}: U32.show(gen) ++ ":" ++ Scheduler.ref_text(ref)

# State mutation consumes typed actions; JSON decoding is kept separate.
def act(+value: Action, +fixture: Fixture) -> Turn:
  match value fixture:
    case Start{+now, tx, count} Fixture{state, previous, _}: changed(T.start(state, Discovery.transaction(tx, 2, 3), Retry.Policy{500, count, 1}, now), previous, now)
    case Tick{+now} Fixture{state, previous, _}: changed(T.tick(state, now), previous, now)
    case Signal{+now} Fixture{state, previous, _}: changed(T.local_signaled(state, now), previous, now)
    case Bind{local, remote, password} Fixture{state, previous, +now}: changed(T.bind(state, Ice.Credentials{local, remote, password}, now), previous, now)
    case Receive{+now, ref, raw} Fixture{state, previous, _}: changed(T.receive(state, ref, raw, now), previous, now)
    case Probe{+now, tx, jitter, gen, ref} Fixture{state, previous, _}: changed(T.probe(state, ref, gen, Discovery.transaction(tx, 2, 3), jitter, now), previous, now)
    case Ack{_, index} Fixture{_, previous, _}: packet_action(value, get(previous, index), fixture)
    case SendFailure{_, index, _} Fixture{_, previous, _}: packet_action(value, get(previous, index), fixture)
    case Current{_, index} Fixture{_, previous, _}: packet_action(value, get(previous, index), fixture)
    case Gate{now, gen, ref} Fixture{state, _, _}: Turn{fixture, [], "gate:" ++ Probe.flag(T.allowed(state, ref, gen, now))}
    case Route{now, id, comp} Fixture{state, _, _}: Turn{fixture, [], "route:" ++ route_text(T.route(state, id, comp, now))}
    case Restart{+now, secret, streams} Fixture{state, previous, _}: changed(T.restart(state, streams, secret, now), previous, now)
    case Repair{+now, token, gen, high, low} Fixture{state, previous, _}: changed(T.repair(state, token, gen, high, low, now), previous, now)
    case Nominate{+now, ref} Fixture{state, previous, _}: changed(T.nominate(state, ref, now), previous, now)
    case Closing{} Fixture{state, previous, now}: changed(T.close(state), previous, now)
    case _ f: rejected(f)

def reference_parts(id: Result<&2, &2, J.Access, U32>, comp: Result<&2, &2, J.Access, U32>, base: Maybe<&2, Stun.IPv4>, peer: Maybe<&2, Stun.IPv4>) -> Maybe<&2, Pairs.Ref>:
  match id comp base peer:
    case Done{i} Done{c} Some{b} Some{p}: Some{Pairs.Ref{i, c, b, p}}
    case _ _ _ _: None{}

def reference(value: J.Json) -> Maybe<&2, Pairs.Ref>:
  match value:
    case J.JArr{[id, comp, base, peer]}: reference_parts(J.u32(id), J.u32(comp), Model.address(base), Model.address(peer))
    case _: None{}

def with_ref(value: Maybe<&2, Pairs.Ref>, next: Pairs.Ref -> Action) -> Action:
  match value:
    case Some{ref}: next(ref)
    case None{}: Invalid{}

def with_bytes(value: Maybe<&2, List<&2, U32>>, next: List<&2, U32> -> Action) -> Action:
  match value:
    case Some{bytes}: next(bytes)
    case None{}: Invalid{}

def with_streams(value: Maybe<&2, List<&2, Check.Stream>>, next: List<&2, Check.Stream> -> Action) -> Action:
  match value:
    case Some{streams}: next(streams)
    case None{}: Invalid{}

def nums1(x0: Result<&2, &2, J.Access, U32>, next: U32 -> Action) -> Action:
  match x0:
    case Done{x0}: next(x0)
    case _: Invalid{}

def nums2(x0: Result<&2, &2, J.Access, U32>, x1: Result<&2, &2, J.Access, U32>, next: U32 -> U32 -> Action) -> Action:
  match x0 x1:
    case Done{x0} Done{x1}: next(x0, x1)
    case _ _: Invalid{}

def nums3(x0: Result<&2, &2, J.Access, U32>, x1: Result<&2, &2, J.Access, U32>, x2: Result<&2, &2, J.Access, U32>, next: U32 -> U32 -> U32 -> Action) -> Action:
  match x0 x1 x2:
    case Done{x0} Done{x1} Done{x2}: next(x0, x1, x2)
    case _ _ _: Invalid{}

def nums4(x0: Result<&2, &2, J.Access, U32>, x1: Result<&2, &2, J.Access, U32>, x2: Result<&2, &2, J.Access, U32>, x3: Result<&2, &2, J.Access, U32>, next: U32 -> U32 -> U32 -> U32 -> Action) -> Action:
  match x0 x1 x2 x3:
    case Done{x0} Done{x1} Done{x2} Done{x3}: next(x0, x1, x2, x3)
    case _ _ _ _: Invalid{}

def nums5(x0: Result<&2, &2, J.Access, U32>, x1: Result<&2, &2, J.Access, U32>, x2: Result<&2, &2, J.Access, U32>, x3: Result<&2, &2, J.Access, U32>, x4: Result<&2, &2, J.Access, U32>, next: U32 -> U32 -> U32 -> U32 -> U32 -> Action) -> Action:
  match x0 x1 x2 x3 x4:
    case Done{x0} Done{x1} Done{x2} Done{x3} Done{x4}: next(x0, x1, x2, x3, x4)
    case _ _ _ _ _: Invalid{}


def action(value: J.Json) -> Action:
  match value:
    case J.JArr{[J.JStr{"start"}, n, t, c]}: nums3(J.u32(n), J.u32(t), J.u32(c), now => tx => count => Start{U32.to_nat(now), tx, count})
    case J.JArr{[J.JStr{"tick"}, n]}: nums1(J.u32(n), now => Tick{U32.to_nat(now)})
    case J.JArr{[J.JStr{"signal"}, n]}: nums1(J.u32(n), now => Signal{U32.to_nat(now)})
    case J.JArr{[J.JStr{"bind"}, J.JStr{l}, J.JStr{r}, J.JStr{p}]}: Bind{l, r, p}
    case J.JArr{[J.JStr{"receive"}, n, ref, J.JArr{raw}]}:
      nums1(J.u32(n), now => with_ref(reference(ref), r => with_bytes(Parse.bytes(65557n, raw, []), bytes => Receive{U32.to_nat(now), r, bytes})))
    case J.JArr{[J.JStr{"probe"}, n, t, j, g, ref]}:
      nums4(J.u32(n), J.u32(t), J.u32(j), J.u32(g), now => tx => jitter => gen => with_ref(reference(ref), r => Probe{U32.to_nat(now), tx, jitter, gen, r}))
    case J.JArr{[J.JStr{"ack"}, n, i]}: nums2(J.u32(n), J.u32(i), now => index => Ack{U32.to_nat(now), U32.to_nat(index)})
    case J.JArr{[J.JStr{"fail"}, n, i, c]}: nums3(J.u32(n), J.u32(i), J.u32(c), now => index => code => SendFailure{U32.to_nat(now), U32.to_nat(index), code})
    case J.JArr{[J.JStr{"current"}, n, i]}: nums2(J.u32(n), J.u32(i), now => index => Current{U32.to_nat(now), U32.to_nat(index)})
    case J.JArr{[J.JStr{"gate"}, n, g, ref]}: nums2(J.u32(n), J.u32(g), now => gen => with_ref(reference(ref), r => Gate{U32.to_nat(now), gen, r}))
    case J.JArr{[J.JStr{"route"}, n, id, comp]}: nums3(J.u32(n), J.u32(id), J.u32(comp), now => sid => c => Route{U32.to_nat(now), sid, c})
    case J.JArr{[J.JStr{"restart"}, n, J.JStr{l}, J.JStr{p}, J.JArr{ss}]}:
      nums1(J.u32(n), now => with_streams(Model.streams(18n, ss, []), streams => Restart{U32.to_nat(now), Incoming.Secret{l, p}, streams}))
    case J.JArr{[J.JStr{"repair"}, n, t, g, h, l]}: nums5(J.u32(n), J.u32(t), J.u32(g), J.u32(h), J.u32(l), now => token => gen => hi => lo => Repair{U32.to_nat(now), token, gen, hi, lo})
    case J.JArr{[J.JStr{"nominate"}, n, ref]}: nums1(J.u32(n), now => with_ref(reference(ref), r => Nominate{U32.to_nat(now), r}))
    case J.JArr{[J.JStr{"close"}]}: Closing{}
    case _: Invalid{}

def acted(turn: Turn, next: Fixture -> IO(Unit)) -> IO(Unit):
  match turn:
    case Turn{Fixture{+state, +previous, +now}, events, text}:
      do IO<Unit>:
        a : Unit <- IO.print("frame")
        b : Unit <- IO.print(text)
        c : Unit <- Output.events(events)
        d : Unit <- Output.snapshot(state, now)
        next(Fixture{state, previous, now})

def actions(fuel: Nat, values: List<&2, J.Json>, fixture: Fixture) -> IO(Unit):
  match fuel values:
    case _ Nil{}: IO.pure(Unit, Unit{})
    case 0n _: IO.print("invalid")
    case 1n+p Con{head, tail}: acted(act(action(head), fixture), next => actions(p, tail, next))

def owned(value: Maybe<&2, T.State>, steps: List<&2, J.Json>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{+state}:
      do IO<Unit>:
        a : Unit <- IO.print("frame")
        b : Unit <- Output.snapshot(state, 0n)
        actions(4096n, steps, Fixture{state, [], 0n})

def created(value: Maybe<&2, Agent.State>, config: T.Config, steps: List<&2, J.Json>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{agent}: owned(T.create(agent, config), steps)

def valid(value: Maybe<&2, V.State>, config: Agent.Config, owner: T.Config, steps: List<&2, J.Json>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{v}: created(Agent.create(v, config), owner, steps)

def parsed(ss: Maybe<&2, List<&2, Check.Stream>>, mode: Maybe<&2, Auth.Mode>, pac: Result<&2, &2, J.Access, U32>, automatic: Result<&2, &2, J.Access, Bool>, slots: Result<&2, &2, J.Access, U32>, steps: List<&2, J.Json>) -> IO(Unit):
  match ss mode pac automatic slots:
    case Some{streams} Some{m} Done{p} Done{a} Done{s}:
      valid(V.from_session(Session.create(streams, Ice.Controlling{0, 1}, Incoming.Secret{"localFrag", "LocalFixturePassword123456"}, m, 100, 8, 7), 100), Agent.Config{p, a}, T.Config{500, s}, steps)
    case _ _ _ _ _: IO.print("invalid")

def decoded(value: Result<&2, &2, J.Error, J.Json>) -> IO(Unit):
  match value:
    case Done{J.JArr{[J.JArr{ss}, J.JStr{m}, p, a, s, J.JArr{steps}]}}: parsed(Model.streams(18n, ss, []), Parse.mode(m), J.u32(p), J.bool(a), J.u32(s), steps)
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
