import Base
import ./ice_binding.bend as Ice
import ./ice_roles.bend as Roles
import ./ice_candidates.bend as C
import ./ice_checklist.bend as Check
import ./ice_pairs.bend as Pairs

# Pure scheduling and current-attempt ownership. The agent commits a proposed
# selection only after its paced transaction engine accepts the new check.
type Queue is Data:
  Queue{stream: U32, pairs: List<&2, Pairs.Ref>}

type Flight is Data:
  Flight{token: U32, reference: Pairs.Ref, role: Ice.Role}

type State is Data:
  State{lists: List<&2, Check.Checklist>, queues: List<&2, Queue>, flights: List<&2, Flight>,
        role: Ice.Role, cursor: Nat, next_token: Nat, generation: U32, limit: U32}

type Change is Data:
  Change{state: State, interrupted: Maybe<&2, U32>}

type Choice is Data:
  Selected{state: State, reference: Pairs.Ref, token: U32, role: Ice.Role}
  Idle{state: State}
  Rejected{}

type Offer is Data:
  Offer{lists: List<&2, Check.Checklist>, reference: Maybe<&2, Pairs.Ref>}

def queues(lists: List<&2, Check.Checklist>, reversed: List<&2, Queue>) -> List<&2, Queue>:
  match lists:
    case Nil{}: List.reverse(&2, Queue, reversed)
    case Con{Check.Checklist{id, _}, tail}: queues(tail, Con{Queue{id, []}, reversed})

def identifiable(pairs: List<&2, Check.CandidatePair>, +id: U32, +lists: List<&2, Check.Checklist>, ok: Bool) -> Bool:
  match pairs:
    case Nil{}: ok
    case Con{p, tail}:
      identifiable(tail, id, lists, Bool.and(ok, Maybe.is_some(&2, Pairs.Position, Pairs.lookup(lists, Pairs.reference(id, p)))))

def identifiable_lists(lists: List<&2, Check.Checklist>, +whole: List<&2, Check.Checklist>, ok: Bool) -> Bool:
  match lists:
    case Nil{}: ok
    case Con{Check.Checklist{id, pairs}, tail}: identifiable_lists(tail, whole, identifiable(pairs, id, whole, ok))

def created_valid(ok: Bool, +lists: List<&2, Check.Checklist>, role: Ice.Role, generation: U32, limit: U32) -> Maybe<&2, State>:
  match ok:
    case False{}: None{}
    case True{}: Some{State{lists, queues(lists, []), [], role, 0n, 0n, generation, limit}}

def created(lists: Maybe<&2, List<&2, Check.Checklist>>, role: Ice.Role, generation: U32, limit: U32) -> Maybe<&2, State>:
  match lists:
    case None{}: None{}
    case Some{+ls}: created_valid(identifiable_lists(ls, ls, True{}), ls, role, generation, limit)

# Input bounds are Check.build's. Endpoint aliases must be resolved by gathering
# or signaling before creation; they cannot be targeted by an unambiguous ref.
def create(streams: List<&2, Check.Stream>, +role: Ice.Role, +limit: U32, generation: U32) -> Maybe<&2, State>:
  created(Check.build(streams, Roles.controlling(role), limit), role, generation, limit)

def stream(reference: Pairs.Ref) -> U32:
  match reference:
    case Pairs.Ref{id, _, _, _}: id

def contains(values: List<&2, Pairs.Ref>, +wanted: Pairs.Ref, found: Bool) -> Bool:
  match values:
    case Nil{}: found
    case Con{r, tail}: contains(tail, wanted, Bool.or(found, Pairs.same(r, wanted)))

def enqueue(+values: List<&2, Pairs.Ref>, +wanted: Pairs.Ref) -> List<&2, Pairs.Ref>:
  Bool.pick(List<&2, Pairs.Ref>, contains(values, wanted, False{}), values,
    List.reverse.go(&2, Pairs.Ref, List.reverse(&2, Pairs.Ref, values), [wanted]))

def queued(values: List<&2, Queue>, +wanted: Pairs.Ref, reversed: List<&2, Queue>) -> List<&2, Queue>:
  match values:
    case Nil{}: List.reverse(&2, Queue, reversed)
    case Con{Queue{+id, +refs}, tail}:
      queued(tail, wanted, Con{Queue{id, Bool.pick(List<&2, Pairs.Ref>, U32.is_eq(id, stream(wanted)), enqueue(refs, wanted), refs)}, reversed})

def queue_at(values: List<&2, Queue>, +id: U32) -> List<&2, Pairs.Ref>:
  match values:
    case Nil{}: []
    case Con{Queue{+got, +refs}, tail}: Bool.pick(List<&2, Pairs.Ref>, U32.is_eq(id, got), refs, queue_at(tail, id))

def replace_queue(values: List<&2, Queue>, +id: U32, +refs: List<&2, Pairs.Ref>, reversed: List<&2, Queue>) -> List<&2, Queue>:
  match values:
    case Nil{}: List.reverse(&2, Queue, reversed)
    case Con{Queue{+got, +old}, tail}:
      replace_queue(tail, id, refs, Con{Queue{got, Bool.pick(List<&2, Pairs.Ref>, U32.is_eq(id, got), refs, old)}, reversed})

def dequeue(values: List<&2, Pairs.Ref>) -> List<&2, Pairs.Ref>:
  match values:
    case Nil{}: []
    case Con{_, tail}: tail

def flight_at(flights: List<&2, Flight>, +wanted: Pairs.Ref) -> Maybe<&2, U32>:
  match flights:
    case Nil{}: None{}
    case Con{Flight{token, +reference, _}, tail}:
      Bool.pick(Maybe<&2, U32>, Pairs.same(reference, wanted), Some{token}, flight_at(tail, wanted))

def by_token(flights: List<&2, Flight>, +token: U32) -> Maybe<&2, Flight>:
  match flights:
    case Nil{}: None{}
    case Con{Flight{+id, +ref, +role}, tail}:
      Bool.pick(Maybe<&2, Flight>, U32.is_eq(id, token), Some{Flight{id, ref, role}}, by_token(tail, token))

def without(flights: List<&2, Flight>, +wanted: Pairs.Ref, +reversed: List<&2, Flight>) -> List<&2, Flight>:
  match flights:
    case Nil{}: List.reverse(&2, Flight, reversed)
    case Con{Flight{+token, +ref, +role}, tail}:
      without(tail, wanted, Bool.pick(List<&2, Flight>, Pairs.same(ref, wanted), reversed, Con{Flight{token, ref, role}, reversed}))

def triggered(position: Maybe<&2, Pairs.Position>, state: State, +wanted: Pairs.Ref) -> Maybe<&2, Change>:
  match position state:
    case None{} _: None{}
    case Some{Pairs.Position{_, _, Check.CandidatePair{_, _, _, Check.Succeeded{}}}} s: Some{Change{s, None{}}}
    case Some{Pairs.Position{+id, index, _}} State{lists, qs, +flights, role, cursor, next, generation, limit}:
      Some{Change{State{Check.replace_stream(lists, id, index, Check.Waiting{}, []), queued(qs, wanted, []),
        without(flights, wanted, []), role, cursor, next, generation, limit}, flight_at(flights, wanted)}}

# Only use for accepted/authenticated incoming work bound to this generation.
# The enclosing agent executes an interruption with Tx.stop_retries.
def trigger(+state: State, +wanted: Pairs.Ref) -> Maybe<&2, Change>:
  match state:
    case State{+lists, +qs, +fs, +role, +cursor, +next, +generation, +limit}:
      triggered(Pairs.lookup(lists, wanted), State{lists, qs, fs, role, cursor, next, generation, limit}, wanted)

def active_pairs(pairs: List<&2, Check.CandidatePair>, +target: Check.CandidatePair, found: Bool) -> Bool:
  match pairs:
    case Nil{}: found
    case Con{Check.CandidatePair{+local, +remote, +rank, +state}, tail}:
      active_pairs(tail, target, Bool.or(found, Bool.and(
        Bool.or(U32.is_eq(Check.state_code(state), 1), U32.is_eq(Check.state_code(state), 2)),
        Check.foundation_same(Check.CandidatePair{local, remote, rank, state}, target))))

def active_foundation(lists: List<&2, Check.Checklist>, +target: Check.CandidatePair, found: Bool) -> Bool:
  match lists:
    case Nil{}: found
    case Con{Check.Checklist{_, pairs}, tail}: active_foundation(tail, target, active_pairs(pairs, target, found))

def thaw(pairs: List<&2, Check.CandidatePair>, +id: U32, +index: Nat, +lists: List<&2, Check.Checklist>) -> List<&2, Check.Checklist>:
  match pairs:
    case Nil{}: lists
    case Con{Check.CandidatePair{+local, +remote, +rank, +state}, tail}:
      thaw(tail, id, Nat.add(index, 1n), Bool.pick(List<&2, Check.Checklist>,
        Bool.and(U32.is_eq(Check.state_code(state), 0), Bool.not(active_foundation(lists, Check.CandidatePair{local, remote, rank, state}, False{}))),
        Check.replace_stream(lists, id, index, Check.Waiting{}, []), lists))

def better(+a: Check.CandidatePair, +b: Check.CandidatePair) -> Bool:
  Bool.or(Check.higher(a, b), Bool.and(Bool.and(Bool.not(Check.higher(a, b)), Bool.not(Check.higher(b, a))),
    U32.is_lt(Check.component(a), Check.component(b))))

def best(yes: Bool, +candidate: Check.CandidatePair, previous: Maybe<&2, Check.CandidatePair>) -> Maybe<&2, Check.CandidatePair>:
  match yes previous:
    case False{} p: p
    case True{} None{}: Some{candidate}
    case True{} Some{+old}: Bool.pick(Maybe<&2, Check.CandidatePair>, better(candidate, old), Some{candidate}, Some{old})

def waiting(pairs: List<&2, Check.CandidatePair>, previous: Maybe<&2, Check.CandidatePair>) -> Maybe<&2, Check.CandidatePair>:
  match pairs:
    case Nil{}: previous
    case Con{Check.CandidatePair{+local, +remote, +rank, +state}, tail}:
      waiting(tail, best(U32.is_eq(Check.state_code(state), 1), Check.CandidatePair{local, remote, rank, state}, previous))

def list_at(lists: List<&2, Check.Checklist>, +id: U32) -> List<&2, Check.CandidatePair>:
  match lists:
    case Nil{}: []
    case Con{Check.Checklist{+got, +pairs}, tail}: Bool.pick(List<&2, Check.CandidatePair>, U32.is_eq(id, got), pairs, list_at(tail, id))

def offered(pair: Maybe<&2, Check.CandidatePair>, id: U32, lists: List<&2, Check.Checklist>) -> Offer:
  match pair:
    case None{}: Offer{lists, None{}}
    case Some{p}: Offer{lists, Some{Pairs.reference(id, p)}}

def thawed(+lists: List<&2, Check.Checklist>, +id: U32) -> Offer:
  offered(waiting(list_at(lists, id), None{}), id, lists)

def ordinary(pair: Maybe<&2, Check.CandidatePair>, +id: U32, +pairs: List<&2, Check.CandidatePair>, +lists: List<&2, Check.Checklist>) -> Offer:
  match pair:
    case Some{p}: Offer{lists, Some{Pairs.reference(id, p)}}
    case None{}:
      # Re-read after sequential thawing: only one pair per free foundation.
      thawed(thaw(pairs, id, 0n, lists), id)

def offer(refs: List<&2, Pairs.Ref>, +id: U32, +lists: List<&2, Check.Checklist>) -> Offer:
  match refs:
    case Con{head, _}: Offer{lists, Some{head}}
    case Nil{}: ordinary(waiting(list_at(lists, id), None{}), id, list_at(lists, id), lists)

def stream_at(lists: List<&2, Check.Checklist>, index: Nat) -> Maybe<&2, U32>:
  match lists index:
    case Nil{} _: None{}
    case Con{Check.Checklist{id, _}, _} 0n: Some{id}
    case Con{_, tail} 1n+p: stream_at(tail, p)

def selected(lists: Maybe<&2, List<&2, Check.Checklist>>, +wanted: Pairs.Ref, +qs: List<&2, Queue>, fs: List<&2, Flight>,
             +role: Ice.Role, cursor: Nat, +next: Nat, generation: U32, limit: U32) -> Choice:
  match lists:
    case None{}: Rejected{}
    case Some{ls}: Selected{State{ls, replace_queue(qs, stream(wanted), dequeue(queue_at(qs, stream(wanted))), []),
      Con{Flight{U32.from_nat(next), wanted, role}, fs}, role, cursor, Nat.add(next, 1n), generation, limit}, wanted, U32.from_nat(next), role}

def choice_offered(result: Offer, qs: List<&2, Queue>, fs: List<&2, Flight>, role: Ice.Role,
                   cursor: Nat, next: Nat, generation: U32, limit: U32,
                   again: List<&2, Check.Checklist> -> Nat -> Choice) -> Choice:
  match result:
    case Offer{+lists, Some{+ref}}: selected(Pairs.begin(lists, ref), ref, qs, fs, role, cursor, next, generation, limit)
    case Offer{lists, None{}}: again(lists, cursor)

def choice_stream(id: Maybe<&2, U32>, lists: List<&2, Check.Checklist>, +qs: List<&2, Queue>, fs: List<&2, Flight>, role: Ice.Role,
                  cursor: Nat, next: Nat, generation: U32, limit: U32,
                  again: List<&2, Check.Checklist> -> Nat -> Choice) -> Choice:
  match id:
    case None{}: Rejected{}
    case Some{+id}: choice_offered(offer(queue_at(qs, id), id, lists), qs, fs, role, cursor, next, generation, limit, again)

def select_go(fuel: Nat, +lists: List<&2, Check.Checklist>, +qs: List<&2, Queue>, +fs: List<&2, Flight>, +role: Ice.Role,
              +cursor: Nat, +next: Nat, +generation: U32, +limit: U32, +count: Nat) -> Choice:
  match fuel:
    case 0n: Idle{State{lists, qs, fs, role, cursor, next, generation, limit}}
    case 1n+p:
      choice_stream(stream_at(lists, cursor), lists, qs, fs, role, Nat.mod(Nat.add(cursor, 1n), count), next, generation, limit,
        ls => at => select_go(p, ls, qs, fs, role, at, next, generation, limit, count))

def select_valid(ok: Bool, lists: List<&2, Check.Checklist>, qs: List<&2, Queue>, fs: List<&2, Flight>, role: Ice.Role,
                 +cursor: Nat, next: Nat, generation: U32, limit: U32, +count: Nat) -> Choice:
  match ok:
    case False{}: Rejected{}
    case True{}:
      Bool.pick(Choice, Bool.and(Nat.is_lt(cursor, count), Nat.is_le(count, 16n)),
        select_go(count, lists, qs, fs, role, cursor, next, generation, limit, count), Rejected{})

# One FIFO triggered check wins within the chosen stream; otherwise thaw only
# free foundations and pick the highest Waiting rank. Skip idle streams without
# consuming another Ta opportunity. Tokens never repeat within a generation.
def select(state: State) -> Choice:
  match state:
    case State{+lists, qs, fs, role, cursor, +next, generation, limit}:
      select_valid(Nat.is_le(next, 4294967295n), lists, qs, fs, role, cursor, next, generation, limit, List.length(&2, Check.Checklist, lists))

def completed(lists: Maybe<&2, List<&2, Check.Checklist>>, wanted: Pairs.Ref, qs: List<&2, Queue>, fs: List<&2, Flight>,
              role: Ice.Role, cursor: Nat, next: Nat, generation: U32, limit: U32) -> Maybe<&2, State>:
  match lists:
    case None{}: None{}
    case Some{ls}: Some{State{ls, qs, without(fs, wanted, []), role, cursor, next, generation, limit}}

def complete_valid(ok: Bool, +lists: List<&2, Check.Checklist>, +wanted: Pairs.Ref, qs: List<&2, Queue>, fs: List<&2, Flight>,
                   role: Ice.Role, cursor: Nat, next: Nat, generation: U32, limit: U32, success: Bool) -> Maybe<&2, State>:
  match ok:
    case False{}: None{}
    case True{}: completed(Pairs.finish_check(lists, wanted, success), wanted, qs, fs, role, cursor, next, generation, limit)

def complete_flight(flight: Maybe<&2, Flight>, state: State, success: Bool, generation: U32) -> Maybe<&2, State>:
  match flight state:
    case None{} _: None{}
    case Some{Flight{_, +wanted, _}} State{+lists, qs, fs, role, cursor, next, +current, limit}:
      complete_valid(U32.is_eq(current, generation), lists, wanted, qs, fs, role, cursor, next, current, limit, success)

def complete(+state: State, token: U32, generation: U32, success: Bool) -> Maybe<&2, State>:
  match state:
    case State{+lists, +qs, +fs, +role, +cursor, +next, +current, +limit}:
      complete_flight(by_token(fs, token), State{lists, qs, fs, role, cursor, next, current, limit}, success, generation)

def unqueued(values: List<&2, Pairs.Ref>, +wanted: Pairs.Ref, +rev: List<&2, Pairs.Ref>) -> List<&2, Pairs.Ref>:
  match values:
    case Nil{}: List.reverse(&2, Pairs.Ref, rev)
    case Con{+head, tail}:
      unqueued(tail, wanted, Bool.pick(List<&2, Pairs.Ref>, Pairs.same(head, wanted), rev, Con{head, rev}))

def validated_position(position: Maybe<&2, Pairs.Position>, state: State) -> Maybe<&2, Change>:
  match position state:
    case Some{Pairs.Position{+id, +index, +pair}} State{+lists, +qs, +fs, role, cursor, next, gen, limit}:
      +wanted = Pairs.reference(id, pair)
      Some{Change{State{Check.thaw_all(Check.replace_stream(lists, id, index, Check.Succeeded{}, []), pair, []),
        replace_queue(qs, id, unqueued(queue_at(qs, id), wanted, []), []), without(fs, wanted, []), role, cursor, next, gen, limit}, flight_at(fs, wanted)}}
    case _ _: None{}

# The owner calls this only after authenticated current-attempt path construction.
# Unlike complete, a represented pair can be in any state. Stop its retry engine
# separately and preserve response correlation until the original deadline.
def validated(+state: State, mapped: Pairs.Ref, generation: U32) -> Maybe<&2, Change>:
  match state:
    case State{+lists, +qs, +fs, +role, +cursor, +next, +current, +limit}:
      Bool.pick(Maybe<&2, Change>, U32.is_eq(current, generation),
        validated_position(Pairs.lookup_mapped(lists, mapped), State{lists, qs, fs, role, cursor, next, current, limit}), None{})

def role_changed(lists: Maybe<&2, List<&2, Check.Checklist>>, qs: List<&2, Queue>, fs: List<&2, Flight>,
                 role: Ice.Role, cursor: Nat, next: Nat, generation: U32, limit: U32) -> Maybe<&2, State>:
  match lists:
    case None{}: None{}
    case Some{ls}: Some{State{ls, qs, fs, role, cursor, next, generation, limit}}

# Server-side switches preserve old attempts' sent roles and all queue identities.
def switch_role(state: State, +role: Ice.Role) -> Maybe<&2, State>:
  match state:
    case State{lists, qs, fs, _, cursor, next, generation, limit}:
      role_changed(Pairs.reorder(lists, Roles.controlling(role)), qs, fs, role, cursor, next, generation, limit)

def total(lists: List<&2, Check.Checklist>, +n: Nat) -> Nat:
  match lists:
    case Nil{}: n
    case Con{Check.Checklist{_, pairs}, tail}: total(tail, Nat.add(n, Check.length_pairs(pairs, 0n)))

def stream_exists(lists: List<&2, Check.Checklist>, +wanted: U32, found: Bool) -> Bool:
  match lists:
    case Nil{}: found
    case Con{Check.Checklist{id, _}, tail}: stream_exists(tail, wanted, Bool.or(found, U32.is_eq(id, wanted)))

def inserted(lists: List<&2, Check.Checklist>, +id: U32, +pair: Check.CandidatePair, reversed: List<&2, Check.Checklist>) -> List<&2, Check.Checklist>:
  match lists:
    case Nil{}: List.reverse(&2, Check.Checklist, reversed)
    case Con{Check.Checklist{+got, +pairs}, tail}:
      inserted(tail, id, pair, Con{Check.Checklist{got, Bool.pick(List<&2, Check.CandidatePair>, U32.is_eq(id, got),
        Check.insert(Nat.add(Check.length_pairs(pairs, 0n), 1n), pairs, pair, []), pairs)}, reversed})

def inserted_rank(rank: Maybe<&2, C.Priority>, +id: U32, +local: C.Local, +remote: C.Candidate, state: State) -> Maybe<&2, Change>:
  match rank state:
    case None{} _: None{}
    case Some{+p} State{+lists, +qs, +fs, +role, +cursor, +next, +generation, +limit}:
      trigger(State{inserted(lists, id, Check.CandidatePair{local, remote, p, Check.Waiting{}}, []), qs, fs, role, cursor, next, generation, limit},
        Pairs.reference(id, Check.CandidatePair{local, remote, p, Check.Waiting{}}))

def insertion_capacity(ok: Bool, id: U32, local: C.Local, remote: C.Candidate, state: State) -> Maybe<&2, Change>:
  match ok local remote state:
    case False{} _ _ _: None{}
    case True{} C.Local{C.Candidate{+c, +p, +f, +k, +a}, +base} C.Candidate{+rc, +rp, +rf, +rk, +ra}
                State{+lists, +qs, +fs, +role, +cursor, +next, +generation, +limit}:
      inserted_rank(Bool.pick(Maybe<&2, C.Priority>, Roles.controlling(role), C.pair_priority(p, rp), C.pair_priority(rp, p)), id,
        C.Local{C.Candidate{c, p, f, k, a}, base}, C.Candidate{rc, rp, rf, rk, ra}, State{lists, qs, fs, role, cursor, next, generation, limit})

def insertion_found(found: Pairs.Search, +state: State, +id: U32, local: C.Local, remote: C.Candidate, reference: Pairs.Ref) -> Maybe<&2, Change>:
  match found state:
    case Pairs.Search{1n, _} s: trigger(s, reference)
    case Pairs.Search{0n, _} State{+lists, +qs, +fs, +role, +cursor, +next, +generation, +limit}:
      insertion_capacity(Bool.and(stream_exists(lists, id, False{}), Nat.is_lt(total(lists, 0n), U32.to_nat(limit))),
        id, local, remote, State{lists, qs, fs, role, cursor, next, generation, limit})
    case _ _: None{}

def insertion_valid(ok: Bool, +state: State, +id: U32, +local: C.Local, +remote: C.Candidate) -> Maybe<&2, Change>:
  match ok state:
    case False{} _: None{}
    case True{} State{+lists, +qs, +fs, +role, +cursor, +next, +generation, +limit}:
      insertion_found(Pairs.find_streams(lists, Pairs.reference(id, Check.CandidatePair{local, remote, C.Priority{0, 0}, Check.Waiting{}}), Pairs.Search{0n, None{}}),
        State{lists, qs, fs, role, cursor, next, generation, limit}, id, local, remote,
        Pairs.reference(id, Check.CandidatePair{local, remote, C.Priority{0, 0}, Check.Waiting{}}))

# Add ONLY the pair from an authenticated observed local base/remote source;
# never form cross-products with other locals for a learned peer-reflexive peer.
# Capacity rejection is atomic: the caller retains bounded deferred work.
def insert_triggered(+state: State, id: U32, +local: C.Local, +remote: C.Candidate) -> Maybe<&2, Change>:
  match local:
    case C.Local{C.Candidate{+c, +p, +f, +k, +a}, +base}:
      insertion_valid(Bool.and(Bool.and(C.local_valid(C.Local{C.Candidate{c, p, f, k, a}, base}), C.valid(remote)),
        Bool.and(Bool.not(C.reflexive(k)), Check.same_component(C.Local{C.Candidate{c, p, f, k, a}, base}, remote))),
        state, id, C.Local{C.Candidate{c, p, f, k, a}, base}, remote)

def tie(role: Ice.Role, +high: U32, low: U32) -> Bool:
  match role:
    case Ice.Controlling{h, l}: Bool.and(U32.is_eq(h, high), U32.is_eq(l, low))
    case Ice.Controlled{h, l}: Bool.and(U32.is_eq(h, high), U32.is_eq(l, low))

def repaired(state: Maybe<&2, State>, reference: Pairs.Ref) -> Maybe<&2, Change>:
  match state:
    case None{}: None{}
    case Some{s}: trigger(s, reference)

def repair_valid(ok: Bool, state: State, reference: Pairs.Ref, role: Ice.Role) -> Maybe<&2, Change>:
  match ok:
    case False{}: None{}
    case True{}: repaired(switch_role(state, role), reference)

def repair_flight(flight: Maybe<&2, Flight>, state: State, generation: U32, +high: U32, +low: U32) -> Maybe<&2, Change>:
  match flight state:
    case None{} _: None{}
    case Some{Flight{_, ref, +sent}} State{+lists, +qs, +fs, +role, +cursor, +next, +current, +limit}:
      repair_valid(Bool.and(U32.is_eq(current, generation), Bool.and(Bool.not(tie(sent, high, low)), Bool.not(tie(role, high, low)))),
        State{lists, qs, fs, role, cursor, next, current, limit}, ref,
        Bool.pick(Ice.Role, Roles.controlling(sent), Ice.Controlled{high, low}, Ice.Controlling{high, low}))

# Only for a current authenticated 487. Flip the role SENT by that attempt,
# generate a different tie-breaker through host RNG, reorder, then requeue it.
def repair_conflict(+state: State, token: U32, generation: U32, high: U32, low: U32) -> Maybe<&2, Change>:
  match state:
    case State{+lists, +qs, +fs, +role, +cursor, +next, +current, +limit}:
      repair_flight(by_token(fs, token), State{lists, qs, fs, role, cursor, next, current, limit}, generation, high, low)
