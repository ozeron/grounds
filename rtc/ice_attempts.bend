import Base
import ./ice_scheduler.bend as S
import ./ice_pairs.bend as Pairs
import ./ice_binding.bend as Ice
import ./ice_candidates.bend as C
import ./ice_transactions.bend as Tx
import ./ice_reliable.bend as Reliable
import ./ice_response.bend as Response
import ./stun_auth.bend as Auth
import ./stun_retry.bend as Retry
import ./stun.bend as Stun

# Current scheduler flights and retained response listeners have separate lives.
# A conflict record survives its finished engine entry until host RNG repairs it.
type Record is Data:
  Record{flight: S.Flight, generation: U32, transaction: List<&2, U32>, conflict: Bool}

type PeerMode is Data:
  PeerMode{address: Stun.IPv4, algorithm: Auth.Mode}

type State is Data:
  State{schedule: S.State, engine: Tx.State, records: List<&2, Record>, policies: List<&2, PeerMode>}

type Notice is Data:
  Transaction{record: Maybe<&2, Record>, event: Tx.Notice}
  Waiting{at: Nat}
  AtCapacity{}
  Idle{}
  Invalid{}

type Step is Data:
  Step{state: State, events: List<&2, Notice>}

def generation(schedule: S.State) -> U32:
  match schedule:
    case S.State{_, _, _, _, _, _, gen, _}: gen

def created(ok: Bool, schedule: S.State, ta: U32, capacity: U32) -> Maybe<&2, State>:
  match ok:
    case False{}: None{}
    case True{}: Some{State{schedule, Tx.State{[], ta, capacity, 0n, 0n}, [], []}}

# The caller supplies a freshly created scheduler; Ta negotiation is external.
def create(schedule: S.State, +ta: U32, +capacity: U32) -> Maybe<&2, State>:
  created(Bool.and(Bool.and(U32.is_le(5, ta), U32.is_le(ta, 60000)),
    Bool.and(U32.is_le(1, capacity), U32.is_le(capacity, 256))), schedule, ta, capacity)

def get(records: List<&2, Record>, +token: U32) -> Maybe<&2, Record>:
  match records:
    case Nil{}: None{}
    case Con{Record{S.Flight{+got, +ref, +role}, +gen, +tx, +conflict}, tail}:
      Bool.pick(Maybe<&2, Record>, U32.is_eq(got, token), Some{Record{S.Flight{got, ref, role}, gen, tx, conflict}}, get(tail, token))

def remove(records: List<&2, Record>, +token: U32, +rev: List<&2, Record>) -> List<&2, Record>:
  match records:
    case Nil{}: List.reverse(&2, Record, rev)
    case Con{Record{S.Flight{+got, +ref, +role}, +gen, +tx, +conflict}, tail}:
      remove(tail, token, Bool.pick(List<&2, Record>, U32.is_eq(got, token), rev,
        Con{Record{S.Flight{got, ref, role}, gen, tx, conflict}, rev}))

def mark(records: List<&2, Record>, +token: U32, rev: List<&2, Record>) -> List<&2, Record>:
  match records:
    case Nil{}: List.reverse(&2, Record, rev)
    case Con{Record{S.Flight{+got, ref, role}, gen, tx, conflict}, tail}:
      mark(tail, token, Con{Record{S.Flight{got, ref, role}, gen, tx, Bool.or(conflict, U32.is_eq(got, token))}, rev})

def keep(value: Maybe<&2, S.State>, original: S.State) -> S.State:
  match value:
    case None{}: original
    case Some{s}: s

def succeeded(outcome: Reliable.Outcome) -> Bool:
  match outcome:
    case Reliable.Received{Response.Success{_}, _}: True{}
    case _: False{}

def conflict(outcome: Reliable.Outcome) -> Bool:
  match outcome:
    case Reliable.Received{Response.Error{487}, _}: True{}
    case _: False{}

def peer_mode(values: List<&2, PeerMode>, +address: Stun.IPv4, +fallback: Auth.Mode) -> Auth.Mode:
  match values:
    case Nil{}: fallback
    case Con{PeerMode{got, mode}, tail}:
      Bool.pick(Auth.Mode, C.address_same(got, address), mode, peer_mode(tail, address, fallback))

def mode_exists(values: List<&2, PeerMode>, +address: Stun.IPv4, found: Bool) -> Bool:
  match values:
    case Nil{}: found
    case Con{PeerMode{got, _}, tail}: mode_exists(tail, address, Bool.or(found, C.address_same(got, address)))

def remember(+values: List<&2, PeerMode>, +address: Stun.IPv4, algorithm: Auth.Mode) -> List<&2, PeerMode>:
  Bool.pick(List<&2, PeerMode>, mode_exists(values, address, False{}), values, Con{PeerMode{address, algorithm}, values})

def response_mode(outcome: Reliable.Outcome) -> Maybe<&2, Auth.Mode>:
  match outcome:
    case Reliable.Received{_, mode}: Some{mode}
    case _: None{}

def negotiated(record: Maybe<&2, Record>, mode: Maybe<&2, Auth.Mode>, state: State) -> State:
  match record mode state:
    case Some{Record{S.Flight{_, Pairs.Ref{_, _, _, remote}, _}, _, _, _}} Some{algorithm} State{s, engine, records, policies}:
      State{s, engine, records, remember(policies, remote, algorithm)}
    case _ _ s: s

def finished_record(record: Maybe<&2, Record>, +state: State, +token: U32, +outcome: Reliable.Outcome) -> State:
  match record state:
    case Some{Record{_, gen, _, _}} State{+schedule, engine, +records, +policies}:
      Bool.pick(State, conflict(outcome), State{schedule, engine, mark(records, token, []), policies},
        State{keep(S.complete(schedule, token, gen, succeeded(outcome)), schedule), engine, remove(records, token, []), policies})
    case None{} s: s

def notice_token(event: Tx.Notice) -> Maybe<&2, U32>:
  match event:
    case Tx.Send{token, _, _, _, _}: Some{token}
    case Tx.Sent{token}: Some{token}
    case Tx.Finished{token, _}: Some{token}
    case Tx.Cancelled{token}: Some{token}
    case Tx.Stopped{token}: Some{token}
    case Tx.LateResponse{token, _, _}: Some{token}
    case Tx.Retired{token}: Some{token}
    case _: None{}

def notice_record(token: Maybe<&2, U32>, records: List<&2, Record>) -> Maybe<&2, Record>:
  match token:
    case None{}: None{}
    case Some{t}: get(records, t)

def retire(state: State, token: U32) -> State:
  match state:
    case State{schedule, engine, records, +policies}: State{schedule, engine, remove(records, token, []), policies}

def applied(+event: Tx.Notice, +state: State, +record: Maybe<&2, Record>, rev: List<&2, Notice>,
            again: State -> List<&2, Notice> -> Step) -> Step:
  match event:
    case Tx.Finished{token, outcome}:
      again(finished_record(record, negotiated(record, response_mode(outcome), state), token, outcome), Con{Transaction{record, event}, rev})
    case Tx.LateResponse{token, _, mode}: again(retire(negotiated(record, Some{mode}, state), token), Con{Transaction{record, event}, rev})
    case Tx.Retired{token}: again(retire(state, token), Con{Transaction{record, event}, rev})
    case Tx.Cancelled{token}: again(retire(state, token), Con{Transaction{record, event}, rev})
    case _: again(state, Con{Transaction{record, event}, rev})

def events(fuel: Nat, values: List<&2, Tx.Notice>, +state: State, rev: List<&2, Notice>) -> Step:
  match fuel values state:
    case _ Nil{} s: Step{s, List.reverse(&2, Notice, rev)}
    case 0n _ s: Step{s, List.reverse(&2, Notice, Con{Invalid{}, rev})}
    case 1n+p Con{+head, tail} State{+schedule, +engine, +records, +policies}:
      applied(head, State{schedule, engine, records, policies}, notice_record(notice_token(head), records), rev,
        s => r => events(p, tail, s, r))

def engine_step(step: Tx.Step, schedule: S.State, records: List<&2, Record>, policies: List<&2, PeerMode>) -> Step:
  match step:
    case Tx.Step{engine, +notices}: events(Nat.add(List.length(&2, Tx.Notice, notices), 1n), notices, State{schedule, engine, records, policies}, [])

def at_capacity(engine: Tx.State) -> Bool:
  match engine:
    case Tx.State{entries, _, capacity, _, _}: Nat.is_le(U32.to_nat(capacity), Tx.count(entries, 0n))

def started(result: Tx.Start, old: State, +selected: S.State, reference: Pairs.Ref, token: U32, role: Ice.Role,
            transaction: List<&2, U32>) -> Step:
  match result old:
    case Tx.Ready{step} State{_, _, records, +policies}:
      engine_step(step, selected, Con{Record{S.Flight{token, reference, role}, generation(selected), transaction, False{}}, records}, policies)
    case Tx.Later{at} s: Step{s, [Waiting{at}]}
    case Tx.Rejected{} State{+schedule, +engine, +records, +policies}:
      Step{State{schedule, engine, records, policies}, [Bool.pick(Notice, at_capacity(engine), AtCapacity{}, Invalid{})]}

def selected(choice: S.Choice, +old: State, +transaction: List<&2, U32>, policy: Retry.Policy,
             credentials: Ice.Credentials, priority: U32, mode: Auth.Mode, now: Nat) -> Step:
  match choice old:
    case S.Selected{schedule, Pairs.Ref{+id, +component, +base, +remote}, +token, +role} State{+previous, +engine, +records, +policies}:
      started(Tx.start(engine, token, C.host(remote), C.port(remote), transaction, policy, credentials, Ice.Check{priority, role}, peer_mode(policies, remote, mode), now),
        State{previous, engine, records, policies}, schedule, Pairs.Ref{id, component, base, remote}, token, role, transaction)
    case S.Idle{schedule} State{_, engine, records, +policies}: Step{State{schedule, engine, records, policies}, [Idle{}]}
    case S.Rejected{} s: Step{s, [Invalid{}]}

# Credentials/PRIORITY must belong to the selected pair's registered local base
# and peer. The session layer binds these; RNG supplies a fresh 96-bit ID.
def start(+state: State, transaction: List<&2, U32>, policy: Retry.Policy, credentials: Ice.Credentials,
          priority: U32, mode: Auth.Mode, now: Nat) -> Step:
  match state:
    case State{+schedule, +engine, +records, +policies}:
      selected(S.select(schedule), State{schedule, engine, records, policies}, transaction, policy, credentials, priority, mode, now)

def stopped(token: Maybe<&2, U32>, state: State) -> Step:
  match token state:
    case None{} s: Step{s, []}
    case Some{t} State{schedule, engine, records, +policies}: engine_step(Tx.stop_retries(engine, t), schedule, records, policies)

def triggered(value: Maybe<&2, S.Change>, engine: Tx.State, records: List<&2, Record>, policies: List<&2, PeerMode>) -> Maybe<&2, Step>:
  match value:
    case None{}: None{}
    case Some{S.Change{schedule, token}}: Some{stopped(token, State{schedule, engine, records, policies})}

def trigger(state: State, reference: Pairs.Ref) -> Maybe<&2, Step>:
  match state:
    case State{schedule, engine, records, +policies}: triggered(S.trigger(schedule, reference), engine, records, policies)

def insert_triggered(state: State, id: U32, local: C.Local, remote: C.Candidate) -> Maybe<&2, Step>:
  match state:
    case State{schedule, engine, records, +policies}: triggered(S.insert_triggered(schedule, id, local, remote), engine, records, policies)

def switched(value: Maybe<&2, S.State>, engine: Tx.State, records: List<&2, Record>, policies: List<&2, PeerMode>) -> Maybe<&2, State>:
  match value:
    case None{}: None{}
    case Some{s}: Some{State{s, engine, records, policies}}

def switch_role(state: State, role: Ice.Role) -> Maybe<&2, State>:
  match state:
    case State{s, engine, records, +policies}: switched(S.switch_role(s, role), engine, records, policies)

def repaired(value: Maybe<&2, S.Change>, engine: Tx.State, records: List<&2, Record>, token: U32, policies: List<&2, PeerMode>) -> Maybe<&2, Step>:
  match value:
    case None{}: None{}
    case Some{S.Change{schedule, _}}: Some{Step{State{schedule, engine, remove(records, token, []), policies}, []}}

def repair_record(record: Maybe<&2, Record>, state: State, +token: U32, +gen: U32, high: U32, low: U32) -> Maybe<&2, Step>:
  match record state:
    case Some{Record{_, +current, _, True{}}} State{schedule, engine, records, +policies}:
      Bool.pick(Maybe<&2, Step>, U32.is_eq(current, gen), repaired(S.repair_conflict(schedule, token, gen, high, low), engine, records, token, policies), None{})
    case _ _: None{}

# Only an authenticated current 487 creates a repairable record. Equal RNG
# values can be retried without resurrecting the finished network transaction.
def repair(+state: State, +token: U32, gen: U32, high: U32, low: U32) -> Maybe<&2, Step>:
  match state:
    case State{+schedule, +engine, +records, +policies}:
      repair_record(get(records, token), State{schedule, engine, records, policies}, token, gen, high, low)

def matches(records: List<&2, Record>, +observed: Pairs.Ref, +transaction: List<&2, U32>, found: Bool) -> Bool:
  match records:
    case Nil{}: found
    case Con{Record{S.Flight{_, ref, _}, _, got, conflict}, tail}:
      matches(tail, observed, transaction, Bool.or(found, Bool.and(Bool.not(conflict), Bool.and(Pairs.same(ref, observed), Stun.same(got, transaction, True{})))))

def received_allowed(allowed: Bool, state: State, observed: Pairs.Ref, raw: List<&2, U32>, now: Nat) -> Step:
  match allowed state observed:
    case True{} State{schedule, engine, records, +policies} Pairs.Ref{_, _, _, +remote}:
      engine_step(Tx.receive(engine, C.host(remote), C.port(remote), raw, now), schedule, records, policies)
    case False{} s Pairs.Ref{_, _, _, +remote}: Step{s, [Transaction{None{}, Tx.Datagram{C.host(remote), C.port(remote), raw}}]}

def received_packet(packet: Maybe<&2, Stun.Packet>, +state: State, +observed: Pairs.Ref, raw: List<&2, U32>, now: Nat) -> Step:
  match packet state:
    case Some{Stun.Packet{+kind, transaction, _}} State{+schedule, +engine, +records, +policies}:
      received_allowed(Bool.and(Bool.or(U32.is_eq(kind, 257), U32.is_eq(kind, 273)), matches(records, observed, transaction, False{})),
        State{schedule, engine, records, policies}, observed, raw, now)
    case None{} s: received_allowed(False{}, s, observed, raw, now)

# observed contains the actual receiving local base and OS/relay peer source;
# matching remote source/ID alone cannot complete a check on another local base.
def receive(state: State, observed: Pairs.Ref, +raw: List<&2, U32>, now: Nat) -> Step:
  received_packet(Stun.parse(raw), state, observed, raw, now)

def tick(state: State, now: Nat) -> Step:
  match state:
    case State{s, engine, records, +policies}: engine_step(Tx.tick(engine, now), s, records, policies)

def failed(state: State, token: U32, code: U32) -> Step:
  match state:
    case State{s, engine, records, +policies}: engine_step(Tx.failed(engine, token, code), s, records, policies)

def current_send(state: State, notice: Notice) -> Bool:
  match state notice:
    case State{_, engine, _, +policies} Transaction{Some{_}, Tx.Send{token, host, port, bytes, fresh}}:
      Tx.current_send(engine, Tx.Send{token, host, port, bytes, fresh})
    case _ _: False{}

def acknowledged(ok: Bool, state: State, event: Tx.Notice, now: Nat) -> Step:
  match ok state event:
    case True{} State{s, engine, records, +policies} Tx.Send{token, _, _, _, fresh}:
      engine_step(Tx.Step{Tx.sent(engine, now, fresh), [Tx.Sent{token}]}, s, records, policies)
    case _ s _: Step{s, []}

# Call only after the OS successfully executes the exact current Send directive.
def acknowledge(+state: State, +notice: Notice, now: Nat) -> Step:
  match notice:
    case Transaction{record, +event}: acknowledged(current_send(state, Transaction{record, event}), state, event, now)
    case _: Step{state, []}

def timeout(state: State, now: Nat, cap: U32) -> U32:
  match state:
    case State{_, engine, _, +policies}: Tx.timeout(engine, now, cap)
