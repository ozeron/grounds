import Base
import ./ice_agent.bend as Agent
import ./ice_consent.bend as Consent
import ./ice_consent_server.bend as Server
import ./ice_nomination.bend as N
import ./ice_valid.bend as V
import ./ice_session.bend as Session
import ./ice_attempts.bend as A
import ./ice_registry.bend as R
import ./ice_scheduler.bend as S
import ./ice_checklist.bend as Check
import ./ice_candidates.bend as C
import ./ice_pairs.bend as Pairs
import ./ice_binding.bend as Ice
import ./ice_incoming.bend as Incoming
import ./ice_roles.bend as Roles
import ./ice_transactions.bend as Tx
import ./stun.bend as Stun
import ./stun_auth.bend as Auth
import ./stun_retry.bend as Retry
import ../utf8/utf8.bend as U

type Config is Data:
  Config{rto: U32, slots: U32}

type Slot is Data:
  Slot{consent: Consent.State, secret: Incoming.Secret, aliases: List<&2, Pairs.Ref>}

type Stamp is Data:
  Stamp{secret: Incoming.Secret, peer: Maybe<&2, Ice.Credentials>, generation: U32, recent: List<&2, List<&2, U32>>}

type Source is Data:
  Check{notice: Session.Notice}
  Probe{notice: Consent.Notice}

type Packet is Data:
  Packet{ticket: Nat, generation: U32, reference: Pairs.Ref, bytes: List<&2, U32>, source: Source}

# Pending is the one authoritative request directive. Replies are separate:
# they may be served while a request is waiting for actual OS send completion.
type State is Data:
  State{agent: Agent.State, slots: List<&2, Slot>, previous: List<&2, Slot>,
        gate: Nat, pending: Maybe<&2, Packet>, ticket: Nat, history: List<&2, Stamp>, config: Config, closed: Bool}

type Notice is Data:
  AgentEvent{event: Session.Notice}
  Lifecycle{event: Agent.Notice}
  ConsentEvent{reference: Pairs.Ref, generation: U32, event: Consent.Notice}
  Transmit{packet: Packet}
  Reply{reference: Pairs.Ref, generation: U32, bytes: List<&2, U32>, code: U32}
  Selected{reference: Pairs.Ref, generation: U32}
  Restarted{generation: U32}
  Waiting{at: Nat}
  Rejected{}
  Exhausted{}
  Closed{}

type Step is Data:
  Step{state: State, events: List<&2, Notice>}

type Route is Data:
  Route{reference: Pairs.Ref, generation: U32}

type Wanted is Data:
  Wanted{reference: Pairs.Ref, priority: U32}

def defaults() -> Config:
  Config{500, 256}

def physical(a: Pairs.Ref, b: Pairs.Ref) -> Bool:
  match a b:
    case Pairs.Ref{_, _, local, peer} Pairs.Ref{_, _, other, remote}:
      Bool.and(C.address_same(local, other), C.address_same(peer, remote))

def logical(a: Pairs.Ref, b: Pairs.Ref) -> Bool:
  match a b:
    case Pairs.Ref{id, comp, _, _} Pairs.Ref{sid, component, _, _}:
      Bool.and(U32.is_eq(id, sid), U32.is_eq(comp, component))

def slot_reference(slot: Slot) -> Pairs.Ref:
  match slot:
    case Slot{Consent.State{Consent.Route{ref, _, _, _, _}, _, _, _, _}, _, _}: ref

def slot_generation(slot: Slot) -> U32:
  match slot:
    case Slot{Consent.State{Consent.Route{_, gen, _, _, _}, _, _, _, _}, _, _}: gen

def alias_exists(aliases: List<&2, Pairs.Ref>, +wanted: Pairs.Ref, found: Bool) -> Bool:
  match aliases:
    case Nil{}: found
    case Con{got, tail}: alias_exists(tail, wanted, Bool.or(found, Pairs.same(got, wanted)))

def logical_exists(aliases: List<&2, Pairs.Ref>, +wanted: Pairs.Ref, found: Bool) -> Bool:
  match aliases:
    case Nil{}: found
    case Con{got, tail}: logical_exists(tail, wanted, Bool.or(found, logical(got, wanted)))

def aliases_added(+aliases: List<&2, Pairs.Ref>, +reference: Pairs.Ref) -> List<&2, Pairs.Ref>:
  Bool.pick(List<&2, Pairs.Ref>, alias_exists(aliases, reference, False{}), aliases, Con{reference, aliases})

def selection(path: Maybe<&2, V.Path>) -> Maybe<&2, Wanted>:
  match path:
    case None{}: None{}
    case Some{V.Path{id, +local, C.Candidate{comp, _, _, _, peer}, _, _, _}}:
      Some{Wanted{Pairs.Ref{id, comp, V.base(local), peer}, V.priority(local)}}

def wanted_added(value: Maybe<&2, Wanted>, rev: List<&2, Wanted>) -> List<&2, Wanted>:
  match value:
    case None{}: rev
    case Some{w}: Con{w, rev}

def components(values: List<&2, U32>, +id: U32, +agent: Agent.State, rev: List<&2, Wanted>) -> List<&2, Wanted>:
  match values:
    case Nil{}: rev
    case Con{comp, tail}: components(tail, id, agent, wanted_added(selection(Agent.selected(agent, id, comp)), rev))

def selected_streams(values: List<&2, Agent.Stream>, +agent: Agent.State, rev: List<&2, Wanted>) -> List<&2, Wanted>:
  match values:
    case Nil{}: List.reverse(&2, Wanted, rev)
    case Con{Agent.Stream{id, required, _, _}, tail}: selected_streams(tail, agent, components(required, id, agent, rev))

def wanted(+agent: Agent.State) -> List<&2, Wanted>:
  match agent:
    case Agent.State{_, _, _, streams, _, _, _}: selected_streams(streams, agent, [])

def current_stamp(session: Session.State, generation: U32) -> Stamp:
  match session:
    case Session.State{_, _, secret, peer, _, _}: Stamp{secret, peer, generation, []}

def engine_gate(session: Session.State) -> Nat:
  match session:
    case Session.State{A.State{_, Tx.State{_, _, _, _, at}, _, _}, _, _, _, _, _}: at

def created(ok: Bool, +agent: Agent.State, config: Config) -> Maybe<&2, State>:
  match ok:
    case False{}: None{}
    case True{}: Some{State{agent, [], [], engine_gate(Agent.session(agent)), None{}, 1n, [current_stamp(Agent.session(agent), Agent.generation(agent))], config, False{}}}

def create(+agent: Agent.State, +config: Config) -> Maybe<&2, State>:
  match config:
    case Config{+rto, +limit}:
      created(Bool.and(Bool.and(U32.is_le(500, rto), U32.is_le(rto, 60000)),
        Bool.and(Bool.and(U32.is_le(1, limit), U32.is_le(limit, 256)), Bool.and(Bool.not(Agent.same_status(Agent.status(agent), Agent.Faulted{})), Bool.not(Agent.same_status(Agent.status(agent), Agent.Failed{}))))),
        agent, Config{rto, limit})

def empty(state: State) -> Step:
  Step{state, []}

def join(previous: List<&2, Notice>, step: Step) -> Step:
  match step:
    case Step{state, events}: Step{state, List.reverse.go(&2, Notice, List.reverse(&2, Notice, previous), events)}

def reset_aliases(slots: List<&2, Slot>, +role: Ice.Role, rev: List<&2, Slot>) -> List<&2, Slot>:
  match slots:
    case Nil{}: List.reverse(&2, Slot, rev)
    case Con{Slot{Consent.State{Consent.Route{ref, gen, creds, Ice.Check{priority, _}, mode}, clock, probes, recent, token}, secret, _}, tail}:
      reset_aliases(tail, role, Con{Slot{Consent.State{Consent.Route{ref, gen, creds, Ice.Check{priority, role}, mode}, clock, probes, recent, token}, secret, []}, rev})

def lookup(slots: List<&2, Slot>, +reference: Pairs.Ref, +gen: U32) -> Maybe<&2, Slot>:
  match slots:
    case Nil{}: None{}
    case Con{+slot, tail}:
      Bool.pick(Maybe<&2, Slot>, Bool.and(U32.is_eq(slot_generation(slot), gen), physical(slot_reference(slot), reference)), Some{slot}, lookup(tail, reference, gen))

def replaced(slots: List<&2, Slot>, +replacement: Slot, rev: List<&2, Slot>) -> List<&2, Slot>:
  match slots:
    case Nil{}: List.reverse(&2, Slot, rev)
    case Con{+slot, tail}:
      replaced(tail, replacement, Con{Bool.pick(Slot,
        Bool.and(U32.is_eq(slot_generation(slot), slot_generation(replacement)), physical(slot_reference(slot), slot_reference(replacement))), replacement, slot), rev})

def new_slot(value: Maybe<&2, Consent.State>, secret: Incoming.Secret, reference: Pairs.Ref) -> Maybe<&2, Slot>:
  match value:
    case None{}: None{}
    case Some{consent}: Some{Slot{consent, secret, [reference]}}

def slot_credentials(peer: Maybe<&2, Ice.Credentials>, secret: Incoming.Secret, mode: Auth.Mode, policies: List<&2, A.PeerMode>, +reference: Pairs.Ref,
                     priority: U32, role: Ice.Role, gen: U32, rto: U32, now: Nat) -> Maybe<&2, Slot>:
  match peer reference:
    case Some{creds} Pairs.Ref{id, comp, +base, +remote}:
      new_slot(Consent.create(Consent.Route{Pairs.Ref{id, comp, base, remote}, gen, creds, Ice.Check{priority, role}, A.peer_mode(policies, remote, mode)}, rto, now),
        secret, Pairs.Ref{id, comp, base, remote})
    case _ _: None{}

def make_slot(session: Session.State, reference: Pairs.Ref, priority: U32, role: Ice.Role, gen: U32, rto: U32, now: Nat) -> Maybe<&2, Slot>:
  match session:
    case Session.State{A.State{_, _, _, policies}, _, secret, peer, _, mode}:
      slot_credentials(peer, secret, mode, policies, reference, priority, role, gen, rto, now)

def closed_slot(step: Consent.Step, secret: Incoming.Secret, aliases: List<&2, Pairs.Ref>) -> Slot:
  match step:
    case Consent.Step{state, _}: Slot{state, secret, aliases}

def closed_slots(slots: List<&2, Slot>, rev: List<&2, Slot>) -> List<&2, Slot>:
  match slots:
    case Nil{}: List.reverse(&2, Slot, rev)
    case Con{Slot{consent, secret, aliases}, tail}:
      closed_slots(tail, Con{closed_slot(Consent.close(consent), secret, aliases), rev})

def close(state: State) -> Step:
  match state:
    case State{agent, slots, previous, gate, _, ticket, history, config, False{}}:
      Step{State{agent, closed_slots(slots, []), closed_slots(previous, []), gate, None{}, ticket, history, config, True{}}, [Closed{}]}
    case s: empty(s)

def healthy(+agent: Agent.State) -> Bool:
  Bool.not(Bool.or(Agent.same_status(Agent.status(agent), Agent.Failed{}), Agent.same_status(Agent.status(agent), Agent.Faulted{})))

def step_state(step: Step) -> State:
  match step:
    case Step{state, _}: state

def guarded(+step: Step) -> Step:
  match step:
    case Step{State{+agent, _, _, _, _, _, _, _, _}, events}:
      Bool.pick(Step, healthy(agent), step, join(events, close(step_state(step))))

def slot_added(value: Maybe<&2, Slot>, step: Step) -> Step:
  match value step:
    case Some{+slot} Step{State{agent, slots, previous, gate, pending, ticket, history, config, +closed}, events}:
      Step{State{agent, List.reverse.go(&2, Slot, List.reverse(&2, Slot, slots), [slot]), previous, gate, pending, ticket, history, config, closed},
        List.reverse.go(&2, Notice, List.reverse(&2, Notice, events), [Selected{slot_reference(slot), slot_generation(slot)}])}
    case None{} Step{state, events}: join(List.reverse.go(&2, Notice, List.reverse(&2, Notice, events), [Exhausted{}]), close(state))

def path_owned(found: Maybe<&2, Slot>, +reference: Pairs.Ref, priority: U32, step: Step, now: Nat) -> Step:
  match found step:
    case Some{Slot{consent, secret, aliases}} Step{State{agent, slots, previous, gate, pending, ticket, history, config, +closed}, events}:
      Step{State{agent, replaced(slots, Slot{consent, secret, aliases_added(aliases, reference)}, []), previous, gate, pending, ticket, history, config, closed}, events}
    case None{} Step{State{+agent, +slots, +previous, gate, pending, ticket, history, Config{+rto, +limit}, +closed}, events}:
      slot_added(Bool.pick(Maybe<&2, Slot>, Nat.is_lt(Nat.add(List.length(&2, Slot, slots), List.length(&2, Slot, previous)), U32.to_nat(limit)),
        make_slot(Agent.session(agent), reference, priority, Agent.role(agent), Agent.generation(agent), rto, now), None{}),
        Step{State{agent, slots, previous, gate, pending, ticket, history, Config{rto, limit}, closed}, events})

def own_paths(paths: List<&2, Wanted>, +step: Step, +now: Nat) -> Step:
  match paths step:
    case Nil{} s: s
    case _ Step{State{_, _, _, _, _, _, _, _, True{}}, _}: step
    case Con{Wanted{+reference, priority}, tail} Step{State{+agent, +slots, previous, gate, pending, ticket, history, config, +closed}, events}:
      own_paths(tail, path_owned(lookup(slots, reference, Agent.generation(agent)), reference, priority,
        Step{State{agent, slots, previous, gate, pending, ticket, history, config, closed}, events}, now), now)

def synchronize(+state: State, now: Nat) -> Step:
  match state:
    case State{+agent, slots, previous, gate, pending, ticket, history, config, +closed}:
      own_paths(wanted(agent), empty(State{agent, reset_aliases(slots, Agent.role(agent), []), previous, gate, pending, ticket, history, config, closed}), now)

def covered(paths: List<&2, Wanted>, +reference: Pairs.Ref) -> Bool:
  match paths:
    case Nil{}: False{}
    case Con{Wanted{ref, _}, tail}: Bool.or(logical(ref, reference), covered(tail, reference))

def retained_aliases(aliases: List<&2, Pairs.Ref>, +paths: List<&2, Wanted>, +rev: List<&2, Pairs.Ref>) -> List<&2, Pairs.Ref>:
  match aliases:
    case Nil{}: List.reverse(&2, Pairs.Ref, rev)
    case Con{+ref, tail}:
      retained_aliases(tail, paths, Bool.pick(List<&2, Pairs.Ref>, covered(paths, ref), rev, Con{ref, rev}))

def previous_kept(slot: Slot, tail: List<&2, Slot>, rev: List<&2, Slot>, again: List<&2, Slot> -> List<&2, Slot> -> List<&2, Slot>) -> List<&2, Slot>:
  match slot:
    case Slot{_, _, Nil{}}: again(tail, rev)
    case Slot{consent, secret, aliases}: again(tail, Con{Slot{consent, secret, aliases}, rev})

def previous_retired(previous: List<&2, Slot>, +paths: List<&2, Wanted>, rev: List<&2, Slot>) -> List<&2, Slot>:
  match previous:
    case Nil{}: List.reverse(&2, Slot, rev)
    case Con{Slot{consent, secret, aliases}, +tail}:
      previous_kept(Slot{consent, secret, retained_aliases(aliases, paths, [])}, tail, rev, rest => kept => previous_retired(tail, paths, kept))

def retire_previous(+state: State) -> State:
  match state:
    case State{+agent, slots, previous, gate, pending, ticket, history, config, closed}:
      State{agent, slots, previous_retired(previous, wanted(agent), []), gate, pending, ticket, history, config, closed}

def sources_same(a: Source, b: Source) -> Bool:
  match a b:
    case Check{_} Check{_}: True{}
    case Probe{_} Probe{_}: True{}
    case _ _: False{}

def packets_same(a: Packet, b: Packet) -> Bool:
  match a b:
    case Packet{x, g, r, bytes, source} Packet{y, h, s, raw, other}:
      Bool.and(sources_same(source, other), Bool.and(Bool.and(Nat.is_eq(x, y), U32.is_eq(g, h)), Bool.and(Pairs.same(r, s), Stun.same(bytes, raw, True{}))))

def queue_available(pending: Maybe<&2, Packet>) -> Bool:
  match pending:
    case None{}: True{}
    case Some{_}: False{}

def issued_history(history: List<&2, Stamp>, +gen: U32, +transaction: List<&2, U32>, rev: List<&2, Stamp>) -> List<&2, Stamp>:
  match history:
    case Nil{}: List.reverse(&2, Stamp, rev)
    case Con{Stamp{secret, peer, +got, +recent}, tail}:
      issued_history(tail, gen, transaction, Con{Stamp{secret, peer, got,
        Bool.pick(List<&2, List<&2, U32>>, Bool.and(U32.is_eq(got, gen), Bool.not(Consent.used(recent, transaction))), Consent.history(64n, Con{transaction, recent}), recent)}, rev})

def packet_history(parsed: Maybe<&2, Stun.Packet>, history: List<&2, Stamp>, gen: U32) -> List<&2, Stamp>:
  match parsed:
    case Some{Stun.Packet{1, tx, _}}: issued_history(history, gen, tx, [])
    case _: history

def queued(reference: Pairs.Ref, +gen: U32, +bytes: List<&2, U32>, +source: Source, state: State) -> Step:
  match state:
    case State{agent, slots, previous, gate, None{}, +ticket, history, config, +closed}:
      +packet : Packet = Packet{ticket, gen, reference, bytes, source}
      Step{State{agent, slots, previous, gate, Some{packet}, Nat.add(ticket, 1n), packet_history(Stun.parse(bytes), history, gen), config, closed}, [Transmit{packet}]}
    case s: empty(s)

def lifecycle(values: List<&2, Agent.Notice>, rev: List<&2, Notice>) -> List<&2, Notice>:
  match values:
    case Nil{}: List.reverse(&2, Notice, rev)
    case Con{event, tail}: lifecycle(tail, Con{Lifecycle{event}, rev})

def agent_event(+event: Session.Notice, +state: State) -> Step:
  match event:
    case Session.Attempt{A.Transaction{Some{A.Record{S.Flight{_, +ref, _}, +gen, _, _}}, Tx.Send{_, _, _, +bytes, _}}}:
      queued(ref, gen, bytes, Check{event}, state)
    case Session.Reply{ref, bytes, code}:
      match state:
        case State{+agent, _, _, _, _, _, _, _, +closed}: Step{state, [Reply{ref, Agent.generation(agent), bytes, code}]}
    case e: Step{state, [AgentEvent{e}]}

def agent_events(values: List<&2, Session.Notice>, +step: Step) -> Step:
  match values step:
    case Nil{} s: s
    case Con{event, tail} Step{state, previous}:
      agent_events(tail, join(previous, agent_event(event, state)))

def agent_step(step: Agent.Step, state: State, now: Nat) -> Step:
  match step state:
    case Agent.Step{agent, events, _, _, life} State{_, slots, previous, gate, pending, ticket, history, config, +closed}:
      guarded(join(lifecycle(life, []), agent_events(events, synchronize(retire_previous(State{agent, slots, previous, gate, pending, ticket, history, config, closed}), now))))

def slot_live(slot: Slot, +now: Nat) -> Bool:
  match slot:
    case Slot{Consent.State{_, Consent.Clock{status, expires, _, _, _, _}, _, _, _}, _, _}:
      Bool.and(Consent.live(status), Nat.is_lt(now, expires))

def aliases_present(aliases: List<&2, Pairs.Ref>) -> Bool:
  match aliases:
    case Nil{}: False{}
    case Con{_, _}: True{}

def tuple_lost(value: Maybe<&2, Slot>, now: Nat) -> Bool:
  match value:
    case None{}: False{}
    case Some{slot}: Bool.not(slot_live(slot, now))

def probe_current(found: Maybe<&2, Slot>, notice: Consent.Notice, now: Nat) -> Bool:
  match found:
    case None{}: False{}
    case Some{Slot{consent, _, aliases}}:
      Bool.and(aliases_present(aliases), Consent.current_send(consent, notice, now))

def fallback(found: Maybe<&2, Slot>, other: Maybe<&2, Slot>) -> Maybe<&2, Slot>:
  match found:
    case Some{slot}: Some{slot}
    case None{}: other

def lease_expired(entries: List<&2, Tx.Entry>, +token: U32, +now: Nat) -> Bool:
  match entries:
    case Nil{}: False{}
    case Con{Tx.Entry{id, _, deadline, _, _}, tail}:
      Bool.or(Bool.and(U32.is_eq(id, token), Nat.is_le(deadline, now)), lease_expired(tail, token, now))
    case Con{_, tail}: lease_expired(tail, token, now)

def check_lease(session: Session.State, token: U32, now: Nat) -> Bool:
  match session:
    case Session.State{A.State{_, Tx.State{entries, _, _, _, _}, _, _}, _, _, _, _, _}: lease_expired(entries, token, now)

def check_send_live(+agent: Agent.State, +notice: Session.Notice, +now: Nat) -> Bool:
  match notice:
    case Session.Attempt{A.Transaction{_, Tx.Send{token, _, _, _, _}}}:
      Bool.and(Agent.current_send(agent, notice), Bool.not(check_lease(Agent.session(agent), token, now)))
    case _: False{}

def source_current(source: Source, +reference: Pairs.Ref, +gen: U32, +agent: Agent.State, +slots: List<&2, Slot>, previous: List<&2, Slot>, +now: Nat) -> Bool:
  match source:
    case Check{notice}:
      Bool.and(Bool.and(U32.is_eq(gen, Agent.generation(agent)), check_send_live(agent, notice, now)), Bool.not(tuple_lost(lookup(slots, reference, gen), now)))
    case Probe{notice}:
      probe_current(fallback(lookup(slots, reference, gen), lookup(previous, reference, gen)), notice, now)

def current_send(state: State, +packet: Packet, +now: Nat) -> Bool:
  match state packet:
    case State{agent, slots, previous, gate, Some{got}, _, _, _, closed} Packet{_, +gen, +ref, _, source}:
      Bool.and(Bool.and(Bool.not(closed), Nat.is_le(gate, now)), Bool.and(packets_same(got, packet), source_current(source, ref, gen, agent, slots, previous, now)))
    case _ _: False{}

def pending_valid(pending: Maybe<&2, Packet>, agent: Agent.State, slots: List<&2, Slot>, previous: List<&2, Slot>, now: Nat) -> Maybe<&2, Packet>:
  match pending:
    case None{}: None{}
    case Some{Packet{+ticket, +gen, +ref, +bytes, +source}}:
      Bool.pick(Maybe<&2, Packet>, source_current(source, ref, gen, agent, slots, previous, now), Some{Packet{ticket, gen, ref, bytes, source}}, None{})

def cleaned(state: State, now: Nat) -> State:
  match state:
    case State{+agent, +slots, +previous, gate, pending, ticket, history, config, closed}:
      State{agent, slots, previous, gate, pending_valid(pending, agent, slots, previous, now), ticket, history, config, closed}

def slot_events(values: List<&2, Consent.Notice>, +ref: Pairs.Ref, +gen: U32, rev: List<&2, Notice>) -> List<&2, Notice>:
  match values:
    case Nil{}: List.reverse(&2, Notice, rev)
    case Con{event, tail}: slot_events(tail, ref, gen, Con{ConsentEvent{ref, gen, event}, rev})

def slot_step(step: Consent.Step, secret: Incoming.Secret, aliases: List<&2, Pairs.Ref>) -> Slot & List<&2, Notice>:
  match step:
    case Consent.Step{Consent.State{Consent.Route{+ref, +gen, creds, check, mode}, clock, probes, recent, token}, events}:
      (Slot{Consent.State{Consent.Route{ref, gen, creds, check, mode}, clock, probes, recent, token}, secret, aliases}, slot_events(events, ref, gen, []))

def tick_slots_added(result: Slot & List<&2, Notice>, tail: List<&2, Slot>, rev: List<&2, Slot>, events: List<&2, Notice>, again: List<&2, Slot> -> List<&2, Slot> -> List<&2, Notice> -> List<&2, Slot> & List<&2, Notice>) -> List<&2, Slot> & List<&2, Notice>:
  (slot, notices) = result
  again(tail, Con{slot, rev}, List.reverse.go(&2, Notice, notices, events))

def tick_slots(slots: List<&2, Slot>, +now: Nat, rev: List<&2, Slot>, events: List<&2, Notice>) -> List<&2, Slot> & List<&2, Notice>:
  match slots:
    case Nil{}: (List.reverse(&2, Slot, rev), List.reverse(&2, Notice, events))
    case Con{Slot{consent, secret, aliases}, +tail}:
      tick_slots_added(slot_step(Consent.tick(consent, now), secret, aliases), tail, rev, events, rest => kept => notices => tick_slots(tail, now, kept, notices))

def clocked_previous(result: List<&2, Slot> & List<&2, Notice>, +state: State, +now: Nat, events: List<&2, Notice>) -> Step:
  (previous, notices) = result
  match state:
    case State{+agent, slots, _, +gate, +pending, ticket, history, config, closed}:
      +at = Bool.pick(Nat, queue_available(pending), gate, Tx.later(gate, Nat.add(now, 1n)))
      join(List.reverse.go(&2, Notice, List.reverse(&2, Notice, events), notices),
        agent_step(Agent.tick(Agent.send_gate(agent, at), now), State{agent, slots, previous, gate, pending, ticket, history, config, closed}, now))

def clocked_slots(result: List<&2, Slot> & List<&2, Notice>, state: State, +now: Nat) -> Step:
  (slots, events) = result
  match state:
    case State{agent, _, +previous, gate, pending, ticket, history, config, closed}:
      clocked_previous(tick_slots(previous, now, [], []), cleaned(State{agent, slots, previous, gate, pending, ticket, history, config, closed}, now), now, events)

def leased(+state: State, +now: Nat) -> Step:
  match state:
    case State{+agent, slots, previous, gate, Some{Packet{_, _, _, _, Check{Session.Attempt{A.Transaction{_, Tx.Send{+token, _, _, _, _}}}}}}, ticket, history, config, False{}}:
      Bool.pick(Step, check_lease(Agent.session(agent), token, now),
        agent_step(Agent.failed(agent, token, 60, now), State{agent, slots, previous, gate, None{}, ticket, history, config, False{}}, now), empty(state))
    case s: empty(s)

def tick_leased(step: Step, +now: Nat) -> Step:
  match step:
    case Step{State{_, _, _, _, _, _, _, _, True{}}, _}: step
    case Step{State{agent, +slots, previous, gate, pending, ticket, history, config, closed}, events}:
      join(events, clocked_slots(tick_slots(slots, now, [], []), State{agent, slots, previous, gate, pending, ticket, history, config, closed}, now))

# An unexecuted ICE directive has a bounded IO lease: its current response
# window. Suppressing retries while IO is pending must never extend that lease.
def tick(state: State, +now: Nat) -> Step:
  tick_leased(leased(state, now), now)

def record_reserved(records: List<&2, A.Record>, +transaction: List<&2, U32>) -> Bool:
  match records:
    case Nil{}: False{}
    case Con{A.Record{_, _, tx, _}, tail}: Bool.or(Stun.same(tx, transaction, True{}), record_reserved(tail, transaction))

def slots_reserved(slots: List<&2, Slot>, +transaction: List<&2, U32>) -> Bool:
  match slots:
    case Nil{}: False{}
    case Con{Slot{Consent.State{_, _, _, recent, _}, _, _}, tail}:
      Bool.or(Consent.used(recent, transaction), slots_reserved(tail, transaction))

def session_reserved(session: Session.State, transaction: List<&2, U32>) -> Bool:
  match session:
    case Session.State{A.State{_, _, records, _}, _, _, _, _, _}: record_reserved(records, transaction)

def stamps_reserved(history: List<&2, Stamp>, +transaction: List<&2, U32>) -> Bool:
  match history:
    case Nil{}: False{}
    case Con{Stamp{_, _, _, recent}, tail}: Bool.or(Consent.used(recent, transaction), stamps_reserved(tail, transaction))

def reserved(state: State, +transaction: List<&2, U32>) -> Bool:
  match state:
    case State{agent, slots, previous, _, _, _, history, _, _}:
      Bool.or(stamps_reserved(history, transaction), Bool.or(session_reserved(Agent.session(agent), transaction), Bool.or(slots_reserved(slots, transaction), slots_reserved(previous, transaction))))

def start_checked(available: Bool, +step: Step, transaction: List<&2, U32>, policy: Retry.Policy, +now: Nat) -> Step:
  match available step:
    case False{} s: s
    case True{} Step{State{+agent, slots, previous, +gate, pending, ticket, history, config, closed}, events}:
      join(events, agent_step(Agent.start(Agent.send_gate(agent, gate), transaction, policy, now), State{agent, slots, previous, gate, pending, ticket, history, config, closed}, now))

def start_ticked(+step: Step, +transaction: List<&2, U32>, policy: Retry.Policy, now: Nat) -> Step:
  match step:
    case Step{+state, _}:
      match state:
        case State{_, _, _, _, pending, _, _, _, closed}:
          start_checked(Bool.and(Bool.and(Bool.not(closed), queue_available(pending)), Bool.not(reserved(state, transaction))), step, transaction, policy, now)

def start(state: State, transaction: List<&2, U32>, policy: Retry.Policy, +now: Nat) -> Step:
  start_ticked(tick(state, now), transaction, policy, now)

def consent_packet(notices: List<&2, Consent.Notice>, +state: State) -> Step:
  match notices:
    case Nil{}: empty(state)
    case Con{Consent.Send{+ref, +gen, +token, +bytes}, _}: queued(ref, gen, bytes, Probe{Consent.Send{ref, gen, token, bytes}}, state)
    case Con{_, tail}: consent_packet(tail, state)

def consent_updated(step: Consent.Step, slot: Slot, +state: State) -> Step:
  match step slot state:
    case Consent.Step{consent, +notices} Slot{_, secret, aliases} State{+agent, +slots, +previous, gate, pending, ticket, history, config, closed}:
      +replacement : Slot = Slot{consent, secret, aliases}
      +ref = slot_reference(replacement)
      +gen = slot_generation(replacement)
      join(slot_events(notices, ref, gen, []), consent_packet(notices,
        State{agent, Bool.pick(List<&2, Slot>, U32.is_eq(gen, Agent.generation(agent)), replaced(slots, replacement, []), slots),
          Bool.pick(List<&2, Slot>, U32.is_eq(gen, Agent.generation(agent)), previous, replaced(previous, replacement, [])), gate, pending, ticket, history, config, closed}))

def consent_started(start: Consent.Start, slot: Slot, state: State) -> Step:
  match start:
    case Consent.Ready{step}: consent_updated(step, slot, state)
    case Consent.Later{step, at}: join([Waiting{at}], consent_updated(step, slot, state))
    case Consent.Rejected{step}: join([Rejected{}], consent_updated(step, slot, state))

def probe_aliases(ok: Bool, +slot: Slot, +state: State, transaction: List<&2, U32>, jitter: U32, +now: Nat) -> Step:
  match ok slot state:
    case True{} Slot{+consent, +secret, +aliases} State{agent, slots, previous, +gate, pending, ticket, history, config, closed}:
      consent_started(Consent.start_binding(consent, transaction, jitter, now, gate), Slot{consent, secret, aliases}, State{agent, slots, previous, gate, pending, ticket, history, config, closed})
    case _ _ s: Step{s, [Rejected{}]}

def probe_owned(found: Maybe<&2, Slot>, +state: State, transaction: List<&2, U32>, jitter: U32, +now: Nat) -> Step:
  match found state:
    case Some{Slot{+consent, +secret, +aliases}} State{agent, slots, previous, +gate, pending, ticket, history, config, closed}:
      probe_aliases(aliases_present(aliases), Slot{consent, secret, aliases}, State{agent, slots, previous, gate, pending, ticket, history, config, closed}, transaction, jitter, now)
    case None{} s: Step{s, [Rejected{}]}

def probe_checked(ok: Bool, +step: Step, +reference: Pairs.Ref, +gen: U32, transaction: List<&2, U32>, jitter: U32, now: Nat) -> Step:
  match ok step:
    case False{} Step{s, events}: join(events, Step{s, [Rejected{}]})
    case True{} Step{State{+agent, +slots, +previous, gate, pending, ticket, history, config, closed}, events}:
      join(events, probe_owned(fallback(lookup(slots, reference, gen), lookup(previous, reference, gen)),
        State{agent, slots, previous, gate, pending, ticket, history, config, closed}, transaction, jitter, now))

def probe_ticked(+step: Step, reference: Pairs.Ref, gen: U32, +transaction: List<&2, U32>, jitter: U32, now: Nat) -> Step:
  match step:
    case Step{+state, _}:
      match state:
        case State{_, _, _, _, pending, _, _, _, closed}:
          probe_checked(Bool.and(Bool.and(Bool.not(closed), queue_available(pending)), Bool.not(reserved(state, transaction))), step, reference, gen, transaction, jitter, now)

def probe(state: State, reference: Pairs.Ref, gen: U32, transaction: List<&2, U32>, jitter: U32, +now: Nat) -> Step:
  probe_ticked(tick(state, now), reference, gen, transaction, jitter, now)

def released(pending: Maybe<&2, Packet>, +packet: Packet) -> Maybe<&2, Packet>:
  match pending:
    case None{}: None{}
    case Some{+got}: Bool.pick(Maybe<&2, Packet>, packets_same(got, packet), None{}, Some{got})

def sent_gate(state: State, packet: Packet, +now: Nat) -> State:
  match state:
    case State{+agent, slots, previous, +gate, pending, ticket, history, config, closed}:
      +at = Tx.later(gate, Nat.add(now, 5n))
      State{Agent.send_gate(agent, at), slots, previous, at, released(pending, packet), ticket, history, config, closed}

def probe_ack(found: Maybe<&2, Slot>, notice: Consent.Notice, state: State, now: Nat) -> Step:
  match found:
    case None{}: empty(state)
    case Some{Slot{+consent, +secret, +aliases}}:
      consent_updated(Consent.acknowledge(consent, notice, now), Slot{consent, secret, aliases}, state)

def source_ack(source: Source, +reference: Pairs.Ref, +gen: U32, +state: State, +now: Nat) -> Step:
  match source state:
    case Check{notice} State{+agent, slots, previous, gate, pending, ticket, history, config, closed}:
      Bool.pick(Step, U32.is_eq(gen, Agent.generation(agent)),
        agent_step(Agent.acknowledge(agent, notice, now), State{agent, slots, previous, gate, pending, ticket, history, config, closed}, now), empty(state))
    case Probe{notice} State{agent, +slots, +previous, gate, pending, ticket, history, config, closed}:
      probe_ack(fallback(lookup(slots, reference, gen), lookup(previous, reference, gen)), notice,
        State{agent, slots, previous, gate, pending, ticket, history, config, closed}, now)

def acknowledged(issued: Bool, +state: State, +packet: Packet, +now: Nat) -> Step:
  match issued packet:
    case False{} _: empty(state)
    case True{} Packet{_, gen, ref, _, source}: source_ack(source, ref, gen, sent_gate(state, packet, now), now)

# This callback affirms actual successful IO, including an old in-flight send
# whose generation was replaced while the OS operation was pending. It always
# shares that real completion time, but only its retained source can be acked.
def acknowledge_live(+state: State, +packet: Packet, +now: Nat) -> Step:
  match state packet:
    case State{_, _, _, _, _, next, _, _, closed} Packet{ticket, _, _, _, _}:
      acknowledged(Bool.and(Bool.not(closed), Bool.and(Nat.is_le(1n, ticket), Nat.is_lt(ticket, next))), state, packet, now)

def acknowledge_ticked(step: Step, packet: Packet, now: Nat) -> Step:
  match step:
    case Step{state, events}: join(events, acknowledge_live(state, packet, now))

def acknowledge(state: State, packet: Packet, +now: Nat) -> Step:
  acknowledge_ticked(tick(state, now), packet, now)

def logical_slot(slots: List<&2, Slot>, +id: U32, +component: U32) -> Maybe<&2, Slot>:
  match slots:
    case Nil{}: None{}
    case Con{Slot{+consent, +secret, +aliases}, tail}:
      Bool.pick(Maybe<&2, Slot>, logical_exists(aliases, Pairs.Ref{id, component, Stun.IPv4{0, 0, 0, 0, 1}, Stun.IPv4{0, 0, 0, 0, 1}}, False{}),
        Some{Slot{consent, secret, aliases}}, logical_slot(tail, id, component))

def allowed_slot(slot: Maybe<&2, Slot>, +now: Nat) -> Bool:
  match slot:
    case None{}: False{}
    case Some{Slot{Consent.State{Consent.Route{+ref, +gen, creds, check, mode}, clock, probes, recent, token}, _, _}}:
      Consent.allowed(Consent.State{Consent.Route{ref, gen, creds, check, mode}, clock, probes, recent, token}, ref, gen, now)

def owned_alias(slots: List<&2, Slot>, +reference: Pairs.Ref, +gen: U32) -> Maybe<&2, Slot>:
  match slots:
    case Nil{}: None{}
    case Con{+slot, tail}:
      match slot:
        case Slot{_, _, aliases}:
          Bool.pick(Maybe<&2, Slot>, Bool.and(U32.is_eq(slot_generation(slot), gen), alias_exists(aliases, reference, False{})), Some{slot}, owned_alias(tail, reference, gen))

def allowed(+state: State, +reference: Pairs.Ref, +gen: U32, now: Nat) -> Bool:
  match state:
    case State{+agent, +slots, +previous, _, _, _, _, _, closed}:
      Bool.and(Bool.and(Bool.not(closed), healthy(agent)), allowed_slot(Bool.pick(Maybe<&2, Slot>, U32.is_eq(gen, Agent.generation(agent)),
        owned_alias(slots, reference, gen), owned_alias(previous, reference, gen)), now))

def route_alias(aliases: List<&2, Pairs.Ref>, +id: U32, +component: U32, +gen: U32) -> Maybe<&2, Route>:
  match aliases:
    case Nil{}: None{}
    case Con{+ref, tail}:
      match ref:
        case Pairs.Ref{sid, comp, _, _}:
          Bool.pick(Maybe<&2, Route>, Bool.and(U32.is_eq(sid, id), U32.is_eq(comp, component)), Some{Route{ref, gen}}, route_alias(tail, id, component, gen))

def routed(found: Maybe<&2, Slot>, id: U32, component: U32, +now: Nat) -> Maybe<&2, Route>:
  match found:
    case None{}: None{}
    case Some{+slot}:
      match slot:
        case Slot{_, _, aliases}: Bool.pick(Maybe<&2, Route>, allowed_slot(Some{slot}, now), route_alias(aliases, id, component, slot_generation(slot)), None{})

# New completed selections retire the old logical route immediately, even while
# their fresh consent is Awaiting. A missing new consent cannot expose old data.
def route(state: State, +id: U32, +component: U32, now: Nat) -> Maybe<&2, Route>:
  match state:
    case State{+agent, slots, previous, _, _, _, _, _, closed}:
      Bool.pick(Maybe<&2, Route>, Bool.and(Bool.not(closed), healthy(agent)),
        routed(fallback(logical_slot(slots, id, component), logical_slot(previous, id, component)), id, component, now), None{})

def response_slot(slot: Slot, +reference: Pairs.Ref, raw: List<&2, U32>, now: Nat) -> Slot & List<&2, Notice>:
  match slot:
    case Slot{Consent.State{Consent.Route{+ref, +gen, creds, check, mode}, clock, probes, recent, token}, secret, aliases}:
      slot_step(Consent.receive(Consent.State{Consent.Route{ref, gen, creds, check, mode}, clock, probes, recent, token},
        Bool.pick(Pairs.Ref, physical(ref, reference), ref, reference), gen, raw, now), secret, aliases)

def responses_added(result: Slot & List<&2, Notice>, tail: List<&2, Slot>, rev: List<&2, Slot>, events: List<&2, Notice>,
                    again: List<&2, Slot> -> List<&2, Slot> -> List<&2, Notice> -> List<&2, Slot> & List<&2, Notice>) -> List<&2, Slot> & List<&2, Notice>:
  (slot, notices) = result
  again(tail, Con{slot, rev}, List.reverse.go(&2, Notice, notices, events))

def responses(slots: List<&2, Slot>, +reference: Pairs.Ref, +raw: List<&2, U32>, +now: Nat, rev: List<&2, Slot>, events: List<&2, Notice>) -> List<&2, Slot> & List<&2, Notice>:
  match slots:
    case Nil{}: (List.reverse(&2, Slot, rev), List.reverse(&2, Notice, events))
    case Con{slot, +tail}:
      responses_added(response_slot(slot, reference, raw, now), tail, rev, events, rest => kept => notices => responses(tail, reference, raw, now, kept, notices))

def response_reference(records: List<&2, A.Record>, +transaction: List<&2, U32>, +observed: Pairs.Ref) -> Pairs.Ref:
  match records:
    case Nil{}: observed
    case Con{A.Record{S.Flight{_, Pairs.Ref{id, comp, _, _}, _}, _, tx, _}, tail}:
      match observed:
        case Pairs.Ref{sid, component, +base, +peer}:
          Bool.pick(Pairs.Ref, Stun.same(tx, transaction, True{}), Pairs.Ref{id, comp, base, peer}, response_reference(tail, transaction, Pairs.Ref{sid, component, base, peer}))

def resolved_response(packet: Maybe<&2, Stun.Packet>, session: Session.State, observed: Pairs.Ref) -> Pairs.Ref:
  match packet session:
    case Some{Stun.Packet{_, tx, _}} Session.State{A.State{_, _, records, _}, _, _, _, _, _}: response_reference(records, tx, observed)
    case _ _: observed

def responses_previous(result: List<&2, Slot> & List<&2, Notice>, +state: State, reference: Pairs.Ref, +raw: List<&2, U32>, +now: Nat, events: List<&2, Notice>) -> Step:
  (previous, notices) = result
  match state:
    case State{+agent, slots, _, gate, pending, ticket, history, config, closed}:
      join(List.reverse.go(&2, Notice, List.reverse(&2, Notice, events), notices),
        agent_step(Agent.receive(agent, resolved_response(Stun.parse(raw), Agent.session(agent), reference), raw, now), State{agent, slots, previous, gate, pending, ticket, history, config, closed}, now))

def responses_current(result: List<&2, Slot> & List<&2, Notice>, state: State, +reference: Pairs.Ref, +raw: List<&2, U32>, +now: Nat) -> Step:
  (slots, events) = result
  match state:
    case State{agent, _, +previous, gate, pending, ticket, history, config, closed}:
      responses_previous(responses(previous, reference, raw, now, [], []), State{agent, slots, previous, gate, pending, ticket, history, config, closed}, reference, raw, now, events)

def request_layout(value: Maybe<&2, Auth.Layout>) -> Maybe<&2, List<&2, U32>>:
  match value:
    case Some{Auth.Layout{_, _, attrs, _}}: Incoming.first(attrs, 6)
    case None{}: None{}

def request_fragment(packet: Maybe<&2, Stun.Packet>) -> Maybe<&2, List<&2, U32>>:
  match packet:
    case Some{Stun.Packet{1, _, attrs}}:
      request_layout(Auth.layout(attrs, 0n, 0, Auth.Missing{}, Auth.Missing{}, []))
    case _: None{}

def name_matches(remote: Maybe<&2, String>) -> Bool:
  match remote:
    case None{}: False{}
    case Some{_}: True{}

def slot_names(slot: Slot, reference: Pairs.Ref, username: List<&2, U32>) -> Bool:
  match slot:
    case Slot{Consent.State{Consent.Route{ref, _, _, _, _}, _, _, _, _}, Incoming.Secret{local, _}, aliases}:
      Bool.and(physical(ref, reference), name_matches(Incoming.username_parts(username, U.encode(local), [])))

def request_context(slots: List<&2, Slot>, +reference: Pairs.Ref, +username: List<&2, U32>) -> Maybe<&2, Slot>:
  match slots:
    case Nil{}: None{}
    case Con{+slot, tail}:
      Bool.pick(Maybe<&2, Slot>, slot_names(slot, reference, username), Some{slot}, request_context(tail, reference, username))

def old_decision(decision: Incoming.Decision, reference: Pairs.Ref, gen: U32, state: State) -> Step:
  match decision:
    case Incoming.Accepted{bytes, _, _, _}: Step{state, [Reply{reference, gen, bytes, 0}]}
    case Incoming.Rejected{bytes, code, _}: Step{state, [Reply{reference, gen, bytes, code}]}
    case _: empty(state)

def actual_peer(reference: Pairs.Ref) -> Stun.IPv4:
  match reference:
    case Pairs.Ref{_, _, _, peer}: peer

def request_pass(slot: Slot, +reference: Pairs.Ref, +raw: List<&2, U32>, +state: State, +now: Nat) -> Step:
  match slot state:
    case Slot{Consent.State{Consent.Route{_, +gen, _, Ice.Check{_, role}, _}, _, _, _, _}, secret, _}
         State{+agent, slots, previous, gate, pending, ticket, history, config, closed}:
      Bool.pick(Step, U32.is_eq(gen, Agent.generation(agent)),
        agent_step(Agent.receive(agent, reference, raw, now), State{agent, slots, previous, gate, pending, ticket, history, config, closed}, now),
        old_decision(Incoming.receive(raw, secret, role, actual_peer(reference)), reference, gen, state))

def request_decided(decision: Server.Decision, +slot: Slot, +reference: Pairs.Ref, raw: List<&2, U32>, state: State, now: Nat) -> Step:
  match decision:
    case Server.Pass{}: request_pass(slot, reference, raw, state, now)
    case Server.Ignored{}: empty(state)
    case Server.Reply{bytes, code, _, _}: Step{state, [Reply{reference, slot_generation(slot), bytes, code}]}

def request_live(live: Bool, +slot: Slot, +reference: Pairs.Ref, +raw: List<&2, U32>, state: State, now: Nat) -> Step:
  match live slot:
    case False{} _: empty(state)
    case True{} Slot{Consent.State{Consent.Route{+ref, gen, Ice.Credentials{_, remote, _}, _, _}, _, _, _, _}, +secret, _}:
      request_decided(Server.receive(raw, Server.Context{secret, remote, ref, gen}, ref), slot, reference, raw, state, now)

def serving(+slot: Slot, now: Nat) -> Bool:
  match slot:
    case Slot{_, _, aliases}: Bool.and(aliases_present(aliases), slot_live(slot, now))

def request_owned(found: Maybe<&2, Slot>, +reference: Pairs.Ref, +raw: List<&2, U32>, +state: State, +now: Nat) -> Step:
  match found state:
    case Some{+slot} _: request_live(serving(slot, now), slot, reference, raw, state, now)
    case None{} State{+agent, slots, previous, gate, pending, ticket, history, config, closed}:
      agent_step(Agent.receive(agent, reference, raw, now), State{agent, slots, previous, gate, pending, ticket, history, config, closed}, now)

def historical_name(history: List<&2, Stamp>, +username: List<&2, U32>, +current: U32) -> Bool:
  match history:
    case Nil{}: False{}
    case Con{Stamp{Incoming.Secret{local, _}, _, gen, _}, tail}:
      Bool.or(Bool.and(Bool.not(U32.is_eq(gen, current)), name_matches(Incoming.username_parts(username, U.encode(local), []))), historical_name(tail, username, current))

def request_historical(found: Maybe<&2, Slot>, old: Bool, reference: Pairs.Ref, raw: List<&2, U32>, state: State, now: Nat) -> Step:
  match found old:
    case None{} True{}: empty(state)
    case value _: request_owned(value, reference, raw, state, now)

def request_named(name: Maybe<&2, List<&2, U32>>, +state: State, +reference: Pairs.Ref, raw: List<&2, U32>, now: Nat) -> Step:
  match name state:
    case Some{+username} State{+agent, +slots, +previous, gate, pending, ticket, +history, config, closed}:
      request_historical(fallback(request_context(slots, reference, username), request_context(previous, reference, username)), historical_name(history, username, Agent.generation(agent)), reference, raw,
        State{agent, slots, previous, gate, pending, ticket, history, config, closed}, now)
    case None{} s: request_owned(None{}, reference, raw, s, now)

def received_kind(packet: Maybe<&2, Stun.Packet>, +state: State, +reference: Pairs.Ref, +raw: List<&2, U32>, +now: Nat) -> Step:
  match packet state:
    case Some{Stun.Packet{1, _, _}} State{agent, +slots, +previous, gate, pending, ticket, history, config, closed}:
      request_named(request_fragment(Stun.parse(raw)), State{agent, slots, previous, gate, pending, ticket, history, config, closed}, reference, raw, now)
    case _ State{agent, +slots, previous, gate, pending, ticket, history, config, closed}:
      responses_current(responses(slots, reference, raw, now, [], []), State{agent, slots, previous, gate, pending, ticket, history, config, closed}, reference, raw, now)

def receive_ticked(+step: Step, +reference: Pairs.Ref, +raw: List<&2, U32>, +now: Nat) -> Step:
  match step:
    case Step{State{_, _, _, _, _, _, _, _, True{}}, _}: step
    case Step{state, events}: join(events, received_kind(Stun.parse(raw), state, reference, raw, now))

def receive(state: State, reference: Pairs.Ref, raw: List<&2, U32>, +now: Nat) -> Step:
  receive_ticked(tick(state, now), reference, raw, now)

# Credential history is bounded, and never silently forgets a revoked namespace.
# Reaching 64 generations requires disposing this owner and creating a session
# with new credentials; the signaling owner must not revive the old identity.
def local_fresh(history: List<&2, Stamp>, +secret: Incoming.Secret) -> Bool:
  match history secret:
    case Nil{} _: True{}
    case Con{Stamp{Incoming.Secret{ufrag, password}, _, _, _}, tail} Incoming.Secret{+local, +key}:
      Bool.and(Bool.and(Bool.not(String.eq(ufrag, local)), Bool.not(String.eq(password, key))), local_fresh(tail, Incoming.Secret{local, key}))

def peer_fresh(history: List<&2, Stamp>, +credentials: Ice.Credentials, +generation: U32) -> Bool:
  match history credentials:
    case Nil{} _: True{}
    case Con{Stamp{_, Some{Ice.Credentials{_, fragment, password}}, gen, _}, tail} Ice.Credentials{local, +remote, +key}:
      Bool.and(Bool.or(U32.is_eq(gen, generation), Bool.and(Bool.not(String.eq(fragment, remote)), Bool.not(String.eq(password, key)))),
        peer_fresh(tail, Ice.Credentials{local, remote, key}, generation))
    case Con{_, tail} creds: peer_fresh(tail, creds, generation)

def stamp_updated(history: List<&2, Stamp>, +replacement: Stamp, rev: List<&2, Stamp>) -> List<&2, Stamp>:
  match history replacement:
    case Nil{} _: List.reverse(&2, Stamp, rev)
    case Con{Stamp{+secret, +peer, +gen, +recent}, tail} Stamp{+other, +bound, +current, +newrecent}:
      stamp_updated(tail, Stamp{other, bound, current, newrecent}, Con{Bool.pick(Stamp, U32.is_eq(gen, current), Stamp{other, bound, current, recent}, Stamp{secret, peer, gen, recent}), rev})

def remembered(state: State) -> State:
  match state:
    case State{+agent, slots, previous, gate, pending, ticket, history, config, closed}:
      State{agent, slots, previous, gate, pending, ticket, stamp_updated(history, current_stamp(Agent.session(agent), Agent.generation(agent)), []), config, closed}

def maybe_agent(value: Maybe<&2, Agent.Step>, state: State, now: Nat) -> Step:
  match value:
    case None{}: Step{state, [Rejected{}]}
    case Some{step}: agent_step(step, state, now)

def bound_step(step: Step) -> Step:
  match step:
    case Step{state, events}: Step{remembered(state), events}

def bind_ticked(+step: Step, +credentials: Ice.Credentials, +now: Nat) -> Step:
  match step:
    case Step{State{_, _, _, _, _, _, _, _, True{}}, _}: step
    case Step{State{+agent, slots, previous, gate, pending, ticket, +history, config, closed}, events}:
      join(events, Bool.pick(Step, peer_fresh(history, credentials, Agent.generation(agent)),
        bound_step(maybe_agent(Agent.bind(agent, credentials, now), State{agent, slots, previous, gate, pending, ticket, history, config, closed}, now)),
        Step{State{agent, slots, previous, gate, pending, ticket, history, config, closed}, [Rejected{}]}))

def bind(state: State, credentials: Ice.Credentials, +now: Nat) -> Step:
  bind_ticked(tick(state, now), credentials, now)

def signaled_ticked(step: Step, +now: Nat) -> Step:
  match step:
    case Step{State{+agent, slots, previous, gate, pending, ticket, history, config, False{}}, events}:
      join(events, agent_step(Agent.local_signaled(agent, now), State{agent, slots, previous, gate, pending, ticket, history, config, False{}}, now))
    case s: s

def local_signaled(state: State, +now: Nat) -> Step:
  signaled_ticked(tick(state, now), now)

def repair_ticked(step: Step, token: U32, generation: U32, high: U32, low: U32, +now: Nat) -> Step:
  match step:
    case Step{State{+agent, slots, previous, gate, pending, ticket, history, config, False{}}, events}:
      join(events, maybe_agent(Agent.repair(agent, token, generation, high, low, now), State{agent, slots, previous, gate, pending, ticket, history, config, False{}}, now))
    case s: s

def repair(state: State, token: U32, generation: U32, high: U32, low: U32, +now: Nat) -> Step:
  repair_ticked(tick(state, now), token, generation, high, low, now)

def nominate_ticked(step: Step, reference: Pairs.Ref, +now: Nat) -> Step:
  match step:
    case Step{State{+agent, slots, previous, gate, pending, ticket, history, config, False{}}, events}:
      join(events, maybe_agent(Agent.nominate(agent, reference), State{agent, slots, previous, gate, pending, ticket, history, config, False{}}, now))
    case s: s

def nominate(state: State, reference: Pairs.Ref, +now: Nat) -> Step:
  nominate_ticked(tick(state, now), reference, now)

def rebuilt_valid(value: Maybe<&2, V.State>, config: Agent.Config) -> Maybe<&2, Agent.State>:
  match value:
    case None{}: None{}
    case Some{v}: Agent.create(v, config)

def rebuilt_session(session: Session.State, values: List<&2, Check.Stream>, secret: Incoming.Secret, role: Ice.Role,
                    generation: U32, limit: U32, config: Agent.Config) -> Maybe<&2, Agent.State>:
  match session:
    case Session.State{A.State{S.State{_, _, _, _, _, _, _, pairs}, Tx.State{_, _, capacity, _, _}, _, _}, _, _, _, _, mode}:
      rebuilt_valid(V.from_session(Session.create(values, role, secret, mode, pairs, capacity, generation), limit), config)

def rebuilt(+agent: Agent.State, values: List<&2, Check.Stream>, secret: Incoming.Secret, generation: U32) -> Maybe<&2, Agent.State>:
  match agent:
    case Agent.State{N.State{V.State{_, _, _, _, limit, _}, _, _, _, _, _}, _, _, _, _, config, _}:
      rebuilt_session(Agent.session(agent), values, secret, Agent.role(agent), generation, limit, config)

def active_slots(slots: List<&2, Slot>, rev: List<&2, Slot>) -> List<&2, Slot>:
  match slots:
    case Nil{}: List.reverse(&2, Slot, rev)
    case Con{Slot{_, _, Nil{}}, tail}: active_slots(tail, rev)
    case Con{slot, tail}: active_slots(tail, Con{slot, rev})

def required_alias(streams: List<&2, Agent.Stream>, +ref: Pairs.Ref) -> Bool:
  match streams ref:
    case Nil{} _: False{}
    case Con{Agent.Stream{id, required, _, _}, tail} Pairs.Ref{+sid, +comp, base, peer}:
      Bool.or(Bool.and(U32.is_eq(id, sid), Agent.number_exists(required, comp, False{})), required_alias(tail, Pairs.Ref{sid, comp, base, peer}))

def required_aliases(aliases: List<&2, Pairs.Ref>, +streams: List<&2, Agent.Stream>, +rev: List<&2, Pairs.Ref>) -> List<&2, Pairs.Ref>:
  match aliases:
    case Nil{}: List.reverse(&2, Pairs.Ref, rev)
    case Con{+ref, tail}: required_aliases(tail, streams, Bool.pick(List<&2, Pairs.Ref>, required_alias(streams, ref), Con{ref, rev}, rev))

def previous_required(slots: List<&2, Slot>, +streams: List<&2, Agent.Stream>, rev: List<&2, Slot>) -> List<&2, Slot>:
  match slots:
    case Nil{}: active_slots(List.reverse(&2, Slot, rev), [])
    case Con{Slot{consent, secret, aliases}, tail}: previous_required(tail, streams, Con{Slot{consent, secret, required_aliases(aliases, streams, [])}, rev})

def old_selected(+state: State, streams: List<&2, Agent.Stream>) -> List<&2, Slot>:
  match state:
    case State{+agent, slots, previous, _, _, _, _, _, _}:
      previous_required(List.reverse.go(&2, Slot, List.reverse(&2, Slot, active_slots(slots, [])), previous_retired(previous, wanted(agent), [])), streams, [])

def restarted_slots(+slots: List<&2, Slot>, +agent: Agent.State, +state: State, now: Nat) -> Step:
  match state:
    case State{_, _, _, +gate, _, ticket, history, +config, +closed}:
      match config:
        case Config{_, limit}:
          Bool.pick(Step, Nat.is_le(List.length(&2, Slot, slots), U32.to_nat(limit)),
            Step{State{Agent.send_gate(agent, gate), [], slots, gate, None{}, ticket,
              Con{current_stamp(Agent.session(agent), Agent.generation(agent)), history}, config, closed}, [Restarted{Agent.generation(agent)}]},
            Step{state, [Exhausted{}]})

def restarted(value: Maybe<&2, Agent.State>, +state: State, now: Nat) -> Step:
  match value:
    case None{}: Step{state, [Rejected{}]}
    case Some{+agent}:
      match agent:
        case Agent.State{_, _, _, streams, _, _, _}: restarted_slots(old_selected(state, streams), agent, state, now)

def restart_ticked(+step: Step, values: List<&2, Check.Stream>, +secret: Incoming.Secret, +now: Nat) -> Step:
  match step:
    case Step{State{_, _, _, _, _, _, _, _, True{}}, _}: step
    case Step{State{+agent, slots, previous, gate, pending, ticket, +history, config, closed}, events}:
      join(events, Bool.pick(Step, Bool.and(Bool.and(U32.is_lt(Agent.generation(agent), 4294967295), Nat.is_lt(List.length(&2, Stamp, history), 64n)), local_fresh(history, secret)),
        restarted(rebuilt(agent, values, secret, U32.add(Agent.generation(agent), 1)), State{agent, slots, previous, gate, pending, ticket, history, config, closed}, now),
        Step{State{agent, slots, previous, gate, pending, ticket, history, config, closed}, [Rejected{}]}))

# Full/full restart reconstructs all ICE layers from candidate configuration.
# Only selected consent/server slots survive. Role direction and shared actual
# send pacing survive; old queued requests and ICE evidence cannot survive.
def restart(state: State, values: List<&2, Check.Stream>, secret: Incoming.Secret, +now: Nat) -> Step:
  restart_ticked(tick(state, now), values, secret, now)

def probe_failed(found: Maybe<&2, Slot>, notice: Consent.Notice, state: State, code: U32) -> Step:
  match found notice:
    case Some{Slot{+consent, +secret, +aliases}} Consent.Send{_, _, token, _}:
      consent_updated(Consent.failed(consent, token, code), Slot{consent, secret, aliases}, state)
    case _ _: empty(state)

def source_failed(source: Source, +reference: Pairs.Ref, +gen: U32, +state: State, code: U32, +now: Nat) -> Step:
  match source state:
    case Check{Session.Attempt{A.Transaction{_, Tx.Send{token, _, _, _, _}}}} State{+agent, slots, previous, gate, pending, ticket, history, config, closed}:
      Bool.pick(Step, U32.is_eq(gen, Agent.generation(agent)),
        agent_step(Agent.failed(agent, token, code, now), State{agent, slots, previous, gate, pending, ticket, history, config, closed}, now), empty(state))
    case Probe{notice} State{agent, +slots, +previous, gate, pending, ticket, history, config, closed}:
      probe_failed(fallback(lookup(slots, reference, gen), lookup(previous, reference, gen)), notice,
        State{agent, slots, previous, gate, pending, ticket, history, config, closed}, code)
    case _ _: empty(state)

def failed_issued(ok: Bool, +packet: Packet, +state: State, code: U32, now: Nat) -> Step:
  match ok packet state:
    case True{} Packet{_, gen, ref, _, source} State{agent, slots, previous, gate, pending, ticket, history, config, closed}:
      source_failed(source, ref, gen, State{agent, slots, previous, gate, released(pending, packet), ticket, history, config, closed}, code, now)
    case _ _ s: empty(s)

# A failed OS send releases only its directive and never advances actual pacing.
def failed(+state: State, +packet: Packet, code: U32, now: Nat) -> Step:
  match state packet:
    case State{_, _, _, _, _, next, _, _, closed} Packet{ticket, _, _, _, _}:
      failed_issued(Bool.and(Bool.not(closed), Bool.and(Nat.is_le(1n, ticket), Nat.is_lt(ticket, next))), packet, state, code, now)

def timeouts(slots: List<&2, Slot>, +now: Nat, +cap: U32) -> U32:
  match slots:
    case Nil{}: cap
    case Con{Slot{consent, _, aliases}, tail}:
      timeouts(tail, now, Bool.pick(U32, aliases_present(aliases), Consent.timeout(consent, now, cap), cap))

def timeout(+state: State, +now: Nat, cap: U32) -> U32:
  match state:
    case State{agent, slots, previous, _, _, _, _, _, False{}}:
      timeouts(previous, now, timeouts(slots, now, Agent.timeout(agent, now, cap)))
    case _: cap

def registered(session: Session.State, reference: Pairs.Ref) -> Bool:
  match session reference:
    case Session.State{_, R.State{streams, _, _, _}, _, _, _, _} Pairs.Ref{id, comp, base, _}:
      Maybe.is_some(&2, C.Local, R.local(streams, id, comp, base))

def reply_slot(found: Maybe<&2, Slot>, now: Nat) -> Bool:
  match found:
    case None{}: False{}
    case Some{slot}: serving(slot, now)

# Replies are not paced requests. Recheck immediately before IO so queued old
# replies cannot keep a retired credential namespace alive after replacement.
def current_reply(state: State, notice: Notice, +now: Nat) -> Bool:
  match state notice:
    case State{+agent, +slots, previous, _, _, _, _, _, False{}} Reply{+ref, +gen, _, _}:
      Bool.pick(Bool, U32.is_eq(gen, Agent.generation(agent)),
        Bool.and(registered(Agent.session(agent), ref), Bool.not(tuple_lost(lookup(slots, ref, gen), now))), reply_slot(lookup(previous, ref, gen), now))
    case _ _: False{}

def due_slot(slots: List<&2, Slot>, +now: Nat) -> Maybe<&2, Route>:
  match slots:
    case Nil{}: None{}
    case Con{Slot{Consent.State{Consent.Route{+ref, +gen, _, _, _}, Consent.Clock{status, expires, next, _, _, _}, _, _, _}, _, aliases}, tail}:
      Bool.pick(Maybe<&2, Route>, Bool.and(Bool.and(Consent.live(status), aliases_present(aliases)), Bool.and(Nat.is_lt(now, expires), Nat.is_le(next, now))),
        Some{Route{ref, gen}}, due_slot(tail, now))

def route_fallback(first: Maybe<&2, Route>, other: Maybe<&2, Route>) -> Maybe<&2, Route>:
  match first:
    case Some{value}: Some{value}
    case None{}: other

def probe_due(state: State, +now: Nat) -> Maybe<&2, Route>:
  match state:
    case State{agent, slots, previous, gate, pending, _, _, _, closed}:
      Bool.pick(Maybe<&2, Route>, Bool.and(Bool.not(closed), Bool.and(queue_available(pending), Nat.is_le(gate, now))),
        route_fallback(due_slot(slots, now), due_slot(previous, now)), None{})
