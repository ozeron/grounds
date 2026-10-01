import Base
import ./ice_valid.bend as V
import ./ice_session.bend as Session
import ./ice_attempts.bend as A
import ./ice_scheduler.bend as S
import ./ice_pairs.bend as Pairs
import ./ice_candidates.bend as C
import ./ice_checklist.bend as Check
import ./ice_binding.bend as Ice
import ./ice_incoming.bend as Incoming
import ./ice_roles.bend as Roles
import ./ice_transactions.bend as Tx
import ./stun_retry.bend as Retry

# Nomination evidence belongs to the generation and the actual authenticated
# requests. A late mapping can enter V's valid list, but cannot replace the
# successful check associated with a current Succeeded checklist reference.
type Link is Data:
  Link{reference: Pairs.Ref, generation: U32, path: V.Path}

type Intent is Data:
  Intent{reference: Pairs.Ref, generation: U32, request: Incoming.Request}

type Binding is Data:
  Binding{record: A.Record, request: Incoming.Request}

type State is Data:
  State{valid: V.State, links: List<&2, Link>, intents: List<&2, Intent>,
        bindings: List<&2, Binding>, limit: U32, faulted: Bool}

type Notice is Data:
  Mapped{record: A.Record, request: Incoming.Request, path: V.Path, late: Bool}
  Outcome{record: A.Record, request: Incoming.Request, event: Tx.Notice}
  NonSymmetric{record: A.Record, request: Incoming.Request, observed: Pairs.Ref, failed: Bool}

type Step is Data:
  Step{state: State, events: List<&2, Session.Notice>, valid: List<&2, V.Notice>,
       nomination: List<&2, Notice>}

def core(state: State) -> V.State:
  match state:
    case State{v, _, _, _, _, _}: v

def schedule(state: V.State) -> S.State:
  match state:
    case V.State{Session.State{A.State{s, _, _, _}, _, _, _, _, _}, _, _, _, _, _}: s

def generation(state: V.State) -> U32:
  A.generation(schedule(state))

def lists(state: V.State) -> List<&2, Check.Checklist>:
  match state:
    case V.State{Session.State{A.State{S.State{ls, _, _, _, _, _, _, _}, _, _, _}, _, _, _, _, _}, _, _, _, _, _}: ls

def succeeded(position: Maybe<&2, Pairs.Position>) -> Bool:
  match position:
    case Some{Pairs.Position{_, _, Check.CandidatePair{_, _, _, Check.Succeeded{}}}}: True{}
    case _: False{}

def reference_live(+state: V.State, reference: Pairs.Ref, gen: U32) -> Bool:
  Bool.and(U32.is_eq(generation(state), gen), succeeded(Pairs.lookup(lists(state), reference)))

def paths(state: V.State) -> List<&2, V.Path>:
  match state:
    case V.State{_, _, _, ps, _, _}: ps

def linked_path(stored: Maybe<&2, V.Path>, origin: A.Record) -> Maybe<&2, V.Path>:
  match stored:
    case Some{V.Path{id, local, remote, rank, _, nominated}}:
      Some{V.Path{id, local, remote, rank, origin, nominated}}
    case _: None{}

# Return the stored path's current rank/metadata with the generating check from
# this association. A duplicate valid path may retain an older V.Path.origin.
def live_path(+valid: V.State, reference: Pairs.Ref, gen: U32, +path: V.Path) -> Maybe<&2, V.Path>:
  match path:
    case V.Path{_, _, _, _, origin, _}:
      Bool.pick(Maybe<&2, V.Path>, reference_live(valid, reference, gen),
        linked_path(V.stored_path(paths(valid), path), origin), None{})

def find_link(values: List<&2, Link>, +valid: V.State, +reference: Pairs.Ref) -> Maybe<&2, V.Path>:
  match values:
    case Nil{}: None{}
    case Con{Link{+r, gen, path}, tail}:
      Bool.pick(Maybe<&2, V.Path>, Pairs.same(r, reference), live_path(valid, r, gen, path), find_link(tail, valid, reference))

def path_for(state: State, reference: Pairs.Ref) -> Maybe<&2, V.Path>:
  match state:
    case State{_, _, _, _, _, True{}}: None{}
    case State{V.State{_, _, _, _, _, True{}}, _, _, _, _, _}: None{}
    case State{v, links, _, _, _, _}: find_link(links, v, reference)

def keep_links(values: List<&2, Link>, +valid: V.State, +rev: List<&2, Link>) -> List<&2, Link>:
  match values:
    case Nil{}: List.reverse(&2, Link, rev)
    case Con{Link{+r, +gen, +path}, tail}:
      keep_links(tail, valid, Bool.pick(List<&2, Link>, Maybe.is_some(&2, V.Path, live_path(valid, r, gen, path)),
        Con{Link{r, gen, path}, rev}, rev))

def remove_link(values: List<&2, Link>, +reference: Pairs.Ref, +rev: List<&2, Link>) -> List<&2, Link>:
  match values:
    case Nil{}: List.reverse(&2, Link, rev)
    case Con{Link{+r, gen, path}, tail}:
      remove_link(tail, reference, Bool.pick(List<&2, Link>, Pairs.same(r, reference), rev, Con{Link{r, gen, path}, rev}))

def fault(state: State) -> State:
  match state:
    case State{v, ls, intents, bs, limit, _}: State{v, ls, intents, bs, limit, True{}}

def added_link(ok: Bool, state: State, reference: Pairs.Ref, gen: U32, path: V.Path) -> State:
  match ok state:
    case True{} State{v, ls, intents, bs, limit, failed}: State{v, Con{Link{reference, gen, path}, ls}, intents, bs, limit, failed}
    case False{} s: fault(s)

def replace_link(+state: State, +reference: Pairs.Ref, gen: U32, path: V.Path) -> State:
  match state:
    case State{v, ls, intents, bs, +limit, failed}:
      +rest = remove_link(ls, reference, [])
      added_link(Nat.is_lt(List.length(&2, Link, rest), U32.to_nat(limit)),
        State{v, rest, intents, bs, limit, failed}, reference, gen, path)

def associate_live(ok: Bool, state: State, reference: Pairs.Ref, gen: U32, path: V.Path) -> State:
  match ok:
    case True{}: replace_link(state, reference, gen, path)
    case False{}: state

def associate(+state: State, +reference: Pairs.Ref, +gen: U32, path: V.Path) -> State:
  associate_live(reference_live(core(state), reference, gen), state, reference, gen, path)

def counterpart(position: Maybe<&2, Pairs.Position>, state: State, gen: U32, path: V.Path) -> State:
  match position:
    case Some{Pairs.Position{id, _, pair}}: associate(state, Pairs.reference(id, pair), gen, path)
    case _: state

def associated(+state: State, +path: V.Path) -> State:
  match path:
    case V.Path{id, +local, C.Candidate{comp, _, _, _, remote}, _, A.Record{S.Flight{_, reference, _}, +gen, _, _}, _}:
      counterpart(Pairs.lookup_mapped(lists(core(state)), Pairs.Ref{id, comp, V.address(local), remote}),
        associate(state, reference, gen, path), gen, path)

def binding_for(values: List<&2, Binding>, +record: A.Record) -> Maybe<&2, Incoming.Request>:
  match values:
    case Nil{}: None{}
    case Con{Binding{got, request}, tail}:
      Bool.pick(Maybe<&2, Incoming.Request>, V.record_same(got, record), Some{request}, binding_for(tail, record))

def mapped_notice(request: Maybe<&2, Incoming.Request>, record: A.Record, path: V.Path, late: Bool, rev: List<&2, Notice>) -> List<&2, Notice>:
  match request:
    case Some{q}: Con{Mapped{record, q, path, late}, rev}
    case _: rev

def mapped(values: List<&2, V.Notice>, +old_bindings: List<&2, Binding>, +state: State, rev: List<&2, Notice>) -> State & List<&2, Notice>:
  match values:
    case Nil{}: (state, rev)
    case Con{V.Validated{+path, _, +late}, tail}:
      match path:
        case V.Path{_, _, _, _, +record, _}:
          mapped(tail, old_bindings, Bool.pick(State, late, state, associated(state, path)),
            mapped_notice(binding_for(old_bindings, record), record, path, late, rev))
    case Con{_, tail}: mapped(tail, old_bindings, state, rev)

def pending(state: V.State) -> List<&2, Session.Pending>:
  match state:
    case V.State{Session.State{_, _, _, _, waiting, _}, _, _, _, _, _}: waiting

# Combine actual prior pending requests with actually accepted packets using
# Session's own merge rule. Applied alone is not enough to reconstruct intent.
def accepted(values: List<&2, Session.Notice>, waiting: List<&2, Session.Pending>) -> List<&2, Session.Pending>:
  match values:
    case Nil{}: waiting
    case Con{Session.Accepted{r, q, _}, tail}:
      accepted(tail, Session.pending_merge(waiting, Session.Pending{r, q}, False{}, []))
    case Con{_, tail}: accepted(tail, waiting)

def bound_peer(valid: V.State, request: Incoming.Request) -> Bool:
  match valid:
    case V.State{Session.State{_, _, _, Some{Ice.Credentials{_, remote, _}}, _, _}, _, _, _, _, _}:
      String.eq(remote, Session.fragment(request))
    case _: False{}

def nomination(request: Incoming.Request) -> Bool:
  match request:
    case Incoming.Request{_, _, _, Ice.Controlling{_, _}, True{}, _}: True{}
    case _: False{}

def qualified(+valid: V.State, +request: Incoming.Request) -> Bool:
  Bool.and(Bool.not(Roles.controlling(V.role(V.core(valid)))), Bool.and(bound_peer(valid, request), nomination(request)))

def request_for(values: List<&2, Session.Pending>, +valid: V.State, +reference: Pairs.Ref) -> Maybe<&2, Incoming.Request>:
  match values:
    case Nil{}: None{}
    case Con{Session.Pending{r, +q}, tail}:
      Bool.pick(Maybe<&2, Incoming.Request>, Bool.and(Pairs.same(r, reference), bound_peer(valid, q)), Some{q}, request_for(tail, valid, reference))

def remove_intent(values: List<&2, Intent>, +reference: Pairs.Ref, +rev: List<&2, Intent>) -> List<&2, Intent>:
  match values:
    case Nil{}: List.reverse(&2, Intent, rev)
    case Con{Intent{+r, gen, q}, tail}:
      remove_intent(tail, reference, Bool.pick(List<&2, Intent>, Pairs.same(r, reference), rev, Con{Intent{r, gen, q}, rev}))

def keep_intents(values: List<&2, Intent>, +valid: V.State, +rev: List<&2, Intent>) -> List<&2, Intent>:
  match values:
    case Nil{}: List.reverse(&2, Intent, rev)
    case Con{Intent{r, +gen, +q}, tail}:
      keep_intents(tail, valid, Bool.pick(List<&2, Intent>, Bool.and(U32.is_eq(gen, generation(valid)), qualified(valid, q)),
        Con{Intent{r, gen, q}, rev}, rev))

def intent_added(ok: Bool, state: State, reference: Pairs.Ref, request: Incoming.Request) -> State:
  match ok state:
    case True{} State{+v, ls, intents, bs, limit, failed}:
      State{v, ls, Con{Intent{reference, generation(v), request}, intents}, bs, limit, failed}
    case False{} s: fault(s)

def intent_request(ok: Bool, state: State, reference: Pairs.Ref, request: Incoming.Request) -> State:
  match ok state:
    case True{} State{v, ls, +intents, bs, +limit, failed}:
      intent_added(Nat.is_lt(List.length(&2, Intent, intents), U32.to_nat(limit)), State{v, ls, intents, bs, limit, failed}, reference, request)
    case False{} s: s

def materialized(request: Maybe<&2, Incoming.Request>, +state: State, reference: Pairs.Ref) -> State:
  match request:
    case Some{+q}: intent_request(qualified(core(state), q), state, reference, q)
    case _: state

def applied(values: List<&2, Session.Notice>, +waiting: List<&2, Session.Pending>, state: State) -> State:
  match values state:
    case Nil{} s: s
    case Con{Session.Applied{+r}, tail} State{+v, ls, intents, bs, limit, failed}:
      applied(tail, waiting, materialized(request_for(waiting, v, r),
        State{v, ls, remove_intent(intents, r, []), bs, limit, failed}, r))
    case Con{_, tail} s: applied(tail, waiting, s)

def intent_for(values: List<&2, Intent>, +reference: Pairs.Ref, +gen: U32) -> Maybe<&2, Incoming.Request>:
  match values:
    case Nil{}: None{}
    case Con{Intent{r, got, q}, tail}:
      Bool.pick(Maybe<&2, Incoming.Request>, Bool.and(Pairs.same(r, reference), U32.is_eq(gen, got)), Some{q}, intent_for(tail, reference, gen))

def record_matches(value: Maybe<&2, A.Record>, record: A.Record) -> Bool:
  match value:
    case Some{got}: V.record_same(got, record)
    case _: False{}

def kept_record(valid: V.State, +record: A.Record) -> Bool:
  match valid record:
    case V.State{Session.State{A.State{S.State{_, _, _, _, _, _, current, _}, _, records, _}, _, _, _, _, _}, _, _, _, _, _} A.Record{S.Flight{token, _, _}, gen, _, _}:
      Bool.and(U32.is_eq(current, gen), record_matches(A.get(records, token), record))

def keep_bindings(values: List<&2, Binding>, +valid: V.State, +rev: List<&2, Binding>) -> List<&2, Binding>:
  match values:
    case Nil{}: List.reverse(&2, Binding, rev)
    case Con{Binding{+record, +request}, tail}:
      keep_bindings(tail, valid, Bool.pick(List<&2, Binding>, Bool.and(kept_record(valid, record), bound_peer(valid, request)),
        Con{Binding{record, request}, rev}, rev))

# Entries include response-only listeners; authenticated 487 repair records can
# additionally survive without an engine entry, one per checklist reference.
def binding_limit(valid: V.State) -> U32:
  match valid:
    case V.State{Session.State{A.State{S.State{_, _, _, _, _, _, _, limit}, Tx.State{_, _, capacity, _, _}, _, _}, _, _, _, _, _}, _, _, _, _, _}:
      (limit + capacity : U32)

def bind_added(ok: Bool, state: State, record: A.Record, request: Incoming.Request) -> State:
  match ok state record:
    case True{} State{v, ls, intents, bs, limit, failed} A.Record{S.Flight{+token, +reference, +role}, +gen, +tx, +conflict}:
      State{v, ls, remove_intent(intents, reference, []), Con{Binding{A.Record{S.Flight{token, reference, role}, gen, tx, conflict}, request}, bs}, limit, failed}
    case False{} s _: fault(s)

def bind_request(request: Maybe<&2, Incoming.Request>, +state: State, +record: A.Record) -> State:
  match request state:
    case Some{q} State{+v, ls, intents, +bs, limit, failed}:
      bind_added(Nat.is_lt(List.length(&2, Binding, bs), U32.to_nat(binding_limit(v))), State{v, ls, intents, bs, limit, failed}, record, q)
    case _ s: s

def bind_record(record: A.Record, +state: State) -> State:
  match record state:
    case A.Record{S.Flight{+token, +reference, Ice.Controlled{+high, +low}}, +gen, +tx, +conflict} State{+v, +ls, +intents, +bs, +limit, +failed}:
      bind_request(Bool.pick(Maybe<&2, Incoming.Request>, kept_record(v, A.Record{S.Flight{token, reference, Ice.Controlled{high, low}}, gen, tx, conflict}),
        intent_for(intents, reference, gen), None{}), State{v, ls, intents, bs, limit, failed},
        A.Record{S.Flight{token, reference, Ice.Controlled{high, low}}, gen, tx, conflict})
    case _ s: s

def sent(values: List<&2, Session.Notice>, state: State) -> State:
  match values:
    case Nil{}: state
    case Con{Session.Attempt{A.Transaction{Some{record}, Tx.Send{_, _, _, _, True{}}}}, tail}:
      sent(tail, bind_record(record, state))
    case Con{_, tail}: sent(tail, state)

def outcome(event: Tx.Notice) -> Bool:
  match event:
    case Tx.Finished{_, _}: True{}
    case Tx.LateResponse{_, _, _}: True{}
    case Tx.Retired{_}: True{}
    case Tx.Cancelled{_}: True{}
    case _: False{}

def outcome_notice(request: Maybe<&2, Incoming.Request>, record: A.Record, event: Tx.Notice, rev: List<&2, Notice>) -> List<&2, Notice>:
  match request:
    case Some{q}: Con{Outcome{record, q, event}, rev}
    case _: rev

def non_symmetric(request: Maybe<&2, Incoming.Request>, record: A.Record, observed: Pairs.Ref, failed: Bool, rev: List<&2, Notice>) -> List<&2, Notice>:
  match request:
    case Some{q}: Con{NonSymmetric{record, q, observed, failed}, rev}
    case _: rev

def outcomes(values: List<&2, Session.Notice>, +bindings: List<&2, Binding>, rev: List<&2, Notice>) -> List<&2, Notice>:
  match values:
    case Nil{}: rev
    case Con{Session.Attempt{A.Transaction{Some{+record}, +event}}, tail}:
      outcomes(tail, bindings, outcome_notice(Bool.pick(Maybe<&2, Incoming.Request>, outcome(event), binding_for(bindings, record), None{}), record, event, rev))
    case Con{Session.Attempt{A.NonSymmetric{+record, observed, failed}}, tail}:
      outcomes(tail, bindings, non_symmetric(binding_for(bindings, record), record, observed, failed, rev))
    case Con{_, tail}: outcomes(tail, bindings, rev)

def advanced(result: State & List<&2, Notice>, events: List<&2, Session.Notice>, valid: List<&2, V.Notice>) -> Step:
  (state, rev) = result
  Step{state, events, valid, List.reverse(&2, Notice, rev)}

def advance(step: V.Step, old: State) -> Step:
  match step old:
    case V.Step{+v, +events, +valid} State{previous, links, intents, +bindings, limit, failed}:
      advanced(mapped(valid, bindings,
        sent(events, applied(events, accepted(events, pending(previous)),
          State{v, keep_links(links, v, []), keep_intents(intents, v, []), keep_bindings(bindings, v, []), limit, failed})),
        outcomes(events, bindings, [])), events, valid)

# This owner starts with a fresh unbound session, before accepted packets or
# checks. Importing a running session would lose already materialized intent.
def created(ok: Bool, valid: V.State, limit: U32) -> Maybe<&2, State>:
  match ok:
    case True{}: Some{State{valid, [], [], [], limit, False{}}}
    case False{}: None{}

def fresh(valid: V.State) -> Bool:
  match valid:
    case V.State{Session.State{A.State{S.State{_, _, Nil{}, _, _, 0n, _, _}, Tx.State{Nil{}, _, _, _, _}, Nil{}, _}, _, _, None{}, Nil{}, _}, Nil{}, Nil{}, Nil{}, _, False{}}: True{}
    case _: False{}

def create(+valid: V.State) -> Maybe<&2, State>:
  match valid:
    case V.State{Session.State{A.State{S.State{_, _, _, _, _, _, _, limit}, _, _, _}, _, _, _, _, _}, _, _, _, _, _}:
      created(Bool.and(fresh(valid), Bool.and(U32.is_le(1, limit), U32.is_le(limit, 256))), valid, limit)

def maybe_advance(step: Maybe<&2, V.Step>, old: State) -> Maybe<&2, Step>:
  match step:
    case None{}: None{}
    case Some{s}: Some{advance(s, old)}

def bind(+state: State, credentials: Ice.Credentials) -> Maybe<&2, Step>:
  match state:
    case State{_, _, _, _, _, True{}}: None{}
    case _: maybe_advance(V.bind(core(state), credentials), state)

def start(+state: State, tx: List<&2, U32>, policy: Retry.Policy, now: Nat) -> Step:
  match state:
    case State{_, _, _, _, _, True{}}: Step{state, [], [], []}
    case _: advance(V.start(core(state), tx, policy, now), state)

def receive(+state: State, reference: Pairs.Ref, raw: List<&2, U32>, now: Nat) -> Step:
  match state:
    case State{_, _, _, _, _, True{}}: Step{state, [], [], []}
    case _: advance(V.receive(core(state), reference, raw, now), state)

def tick(+state: State, now: Nat) -> Step:
  match state:
    case State{_, _, _, _, _, True{}}: Step{state, [], [], []}
    case _: advance(V.tick(core(state), now), state)

def drain(+state: State) -> Step:
  match state:
    case State{_, _, _, _, _, True{}}: Step{state, [], [], []}
    case _: advance(V.drain(core(state)), state)

def repair(+state: State, token: U32, gen: U32, high: U32, low: U32) -> Maybe<&2, Step>:
  match state:
    case State{_, _, _, _, _, True{}}: None{}
    case _: maybe_advance(V.repair(core(state), token, gen, high, low), state)

def acknowledge(+state: State, notice: Session.Notice, now: Nat) -> Step:
  advance(V.acknowledge(core(state), notice, now), state)

def failed(+state: State, token: U32, code: U32) -> Step:
  advance(V.failed(core(state), token, code), state)

def current_send(state: State, notice: Session.Notice) -> Bool:
  match state:
    case State{v, _, _, _, _, failed}: Bool.and(Bool.not(failed), V.current_send(v, notice))

def timeout(state: State, now: Nat, cap: U32) -> U32:
  V.timeout(core(state), now, cap)
