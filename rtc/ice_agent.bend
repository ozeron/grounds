import Base
import ./ice_nomination.bend as N
import ./ice_valid.bend as V
import ./ice_session.bend as Session
import ./ice_attempts.bend as A
import ./ice_scheduler.bend as S
import ./ice_checklist.bend as Check
import ./ice_candidates.bend as C
import ./ice_pairs.bend as Pairs
import ./ice_binding.bend as Ice
import ./ice_incoming.bend as Incoming
import ./ice_roles.bend as Roles
import ./ice_transactions.bend as Tx
import ./ice_reliable.bend as Reliable
import ./ice_response.bend as Response
import ./stun_retry.bend as Retry

# One UDP/IPv4 generation. Session/V/N remain compatible foundation APIs; this
# owner alone decides nomination, selected paths, component cleanup and PAC.
type Status is Data:
  Running{}
  Completed{}
  Failed{}
  Faulted{}

type Config is Data:
  Config{pac_ms: U32, automatic: Bool}

type Pac is Data:
  Dormant{advertised: Bool}
  Started{deadline: Nat}
  Elapsed{}

type Stream is Data:
  Stream{id: U32, required: List<&2, U32>, failed: List<&2, U32>, status: Status}

type Plan is Data:
  Plan{path: V.Path, reference: Pairs.Ref, generation: U32, attempt: Maybe<&2, A.Record>}

type Decision is Data:
  Decision{path: V.Path, reference: Pairs.Ref, generation: U32}

type State is Data:
  State{evidence: N.State, plans: List<&2, Plan>, decisions: List<&2, Decision>,
        streams: List<&2, Stream>, pac: Pac, config: Config, faulted: Bool}

type Notice is Data:
  Nominated{path: V.Path, reference: Pairs.Ref, attempt: Maybe<&2, A.Record>}
  NominationFailed{record: A.Record, path: Maybe<&2, V.Path>}
  StreamChanged{id: U32, status: Status}
  SessionChanged{status: Status}
  PacStarted{deadline: Nat}
  PacExpired{}

type Step is Data:
  Step{state: State, events: List<&2, Session.Notice>, valid: List<&2, V.Notice>,
       nomination: List<&2, N.Notice>, lifecycle: List<&2, Notice>}

def defaults() -> Config:
  Config{39500, True{}}

def core(state: State) -> N.State:
  match state:
    case State{e, _, _, _, _, _, _}: e

def valid(state: State) -> V.State:
  N.core(core(state))

def session(state: State) -> Session.State:
  V.core(valid(state))

def role(state: State) -> Ice.Role:
  V.role(session(state))

def generation(state: State) -> U32:
  N.generation(valid(state))

def number_exists(values: List<&2, U32>, +wanted: U32, found: Bool) -> Bool:
  match values:
    case Nil{}: found
    case Con{head, tail}: number_exists(tail, wanted, Bool.or(found, U32.is_eq(head, wanted)))

def required(locals: List<&2, C.Local>, +rev: List<&2, U32>) -> List<&2, U32>:
  match locals:
    case Nil{}: List.reverse(&2, U32, rev)
    case Con{local, tail}:
      +comp = V.component(local)
      required(tail, Bool.pick(List<&2, U32>, number_exists(rev, comp, False{}), rev, Con{comp, rev}))

def streams(values: List<&2, Check.Stream>, rev: List<&2, Stream>) -> List<&2, Stream>:
  match values:
    case Nil{}: List.reverse(&2, Stream, rev)
    case Con{Check.Stream{id, locals, _}, tail}: streams(tail, Con{Stream{id, required(locals, []), [], Running{}}, rev})

def created(value: Maybe<&2, N.State>, config: Config) -> Maybe<&2, State>:
  match value:
    case None{}: None{}
    case Some{+e}: Some{State{e, [], [], streams(V.streams(V.core(N.core(e))), []), Dormant{False{}}, config, False{}}}

def configured(values: List<&2, Check.Stream>, ok: Bool) -> Bool:
  match values:
    case Nil{}: ok
    case Con{Check.Stream{_, Nil{}, _}, tail}: configured(tail, False{})
    case Con{_, tail}: configured(tail, ok)

def create(+v: V.State, +config: Config) -> Maybe<&2, State>:
  match config:
    case Config{ms, _}:
      Bool.pick(Maybe<&2, State>, Bool.and(configured(V.streams(V.core(v)), True{}),
        Bool.and(U32.is_le(1, ms), U32.is_le(ms, 2147483647))), created(N.create(v), config), None{})

def statuses(values: List<&2, Stream>, +complete: Bool, +failed: Bool) -> Status:
  match values:
    case Nil{}: Bool.pick(Status, failed, Failed{}, Bool.pick(Status, complete, Completed{}, Running{}))
    case Con{Stream{_, _, _, Completed{}}, tail}: statuses(tail, complete, failed)
    case Con{Stream{_, _, _, Failed{}}, tail}: statuses(tail, False{}, True{})
    case Con{_, tail}: statuses(tail, False{}, failed)

def status(state: State) -> Status:
  match state:
    case State{N.State{V.State{_, _, _, _, _, False{}}, _, _, _, _, False{}}, _, _, ss, _, _, False{}}: statuses(ss, True{}, False{})
    case _: Faulted{}

def same_status(a: Status, b: Status) -> Bool:
  match a b:
    case Running{} Running{}: True{}
    case Completed{} Completed{}: True{}
    case Failed{} Failed{}: True{}
    case Faulted{} Faulted{}: True{}
    case _ _: False{}

def terminal(status: Status) -> Bool:
  match status:
    case Failed{}: True{}
    case Faulted{}: True{}
    case _: False{}

def running(values: List<&2, Stream>, +id: U32, +comp: U32) -> Bool:
  match values:
    case Nil{}: False{}
    case Con{Stream{got, required, _, Running{}}, tail}:
      Bool.pick(Bool, U32.is_eq(got, id), number_exists(required, comp, False{}), running(tail, id, comp))
    case Con{_, tail}: running(tail, id, comp)

def path_component(path: V.Path, id: U32, comp: U32) -> Bool:
  match path:
    case V.Path{got, local, _, _, _, _}: Bool.and(U32.is_eq(got, id), U32.is_eq(V.component(local), comp))

def better_path(old: Maybe<&2, V.Path>, +path: V.Path) -> Maybe<&2, V.Path>:
  match old:
    case None{}: Some{path}
    case Some{+p}: Some{Bool.pick(V.Path, V.higher(path, p), path, p)}

def better_owned(candidate: Maybe<&2, V.Path>, old: Maybe<&2, V.Path>) -> Maybe<&2, V.Path>:
  match candidate:
    case None{}: old
    case Some{path}: better_path(old, path)

def best_path(values: List<&2, V.Path>, +id: U32, +comp: U32, +nominated: Bool, +found: Maybe<&2, V.Path>) -> Maybe<&2, V.Path>:
  match values:
    case Nil{}: found
    case Con{V.Path{+sid, +l, +r, +rank, +origin, +flag}, tail}:
      +path : V.Path = V.Path{sid, l, r, rank, origin, flag}
      best_path(tail, id, comp, nominated,
        Bool.pick(Maybe<&2, V.Path>, Bool.and(path_component(path, id, comp), Bool.or(Bool.not(nominated), flag)),
          better_path(found, path), found))

def selected_stream(values: List<&2, Stream>, +paths: List<&2, V.Path>, +id: U32, +comp: U32) -> Maybe<&2, V.Path>:
  match values:
    case Nil{}: None{}
    case Con{Stream{got, +req, _, Completed{}}, tail}:
      Bool.pick(Maybe<&2, V.Path>, U32.is_eq(got, id),
        Bool.pick(Maybe<&2, V.Path>, number_exists(req, comp, False{}), best_path(paths, id, comp, True{}, None{}), None{}),
        selected_stream(tail, paths, id, comp))
    case Con{_, tail}: selected_stream(tail, paths, id, comp)

def selected(+state: State, id: U32, comp: U32) -> Maybe<&2, V.Path>:
  match state:
    case State{_, _, _, ss, _, _, False{}}:
      Bool.pick(Maybe<&2, V.Path>, terminal(status(state)), None{}, selected_stream(ss, N.paths(valid(state)), id, comp))
    case _: None{}

def replace_evidence(state: State, e: N.State) -> State:
  match state:
    case State{_, ps, ds, ss, pac, cfg, failed}: State{e, ps, ds, ss, pac, cfg, failed}

def session_step(+state: State, step: Session.Step) -> N.Step:
  N.advance(V.advance(step, valid(state)), core(state))

def planned(values: List<&2, Plan>, +id: U32, +comp: U32) -> Bool:
  match values:
    case Nil{}: False{}
    case Con{Plan{path, _, _, _}, tail}: Bool.or(path_component(path, id, comp), planned(tail, id, comp))

def targets(values: List<&2, Plan>, rev: List<&2, Pairs.Ref>) -> List<&2, Pairs.Ref>:
  match values:
    case Nil{}: List.reverse(&2, Pairs.Ref, rev)
    case Con{Plan{_, r, _, _}, tail}: targets(tail, Con{r, rev})

def eligible(+state: State, path: V.Path) -> Bool:
  match state path:
    case State{_, plans, _, ss, _, _, False{}} V.Path{+id, local, _, _, _, False{}}:
      +comp = V.component(local)
      Bool.and(Bool.not(terminal(status(state))), Bool.and(Roles.controlling(role(state)), Bool.and(running(ss, id, comp),
        Bool.and(Bool.not(planned(plans, id, comp)), Bool.not(Maybe.is_some(&2, V.Path, best_path(N.paths(valid(state)), id, comp, True{}, None{})))))))
    case _ _: False{}

def planned_step(step: N.Step, state: State, path: V.Path, reference: Pairs.Ref, gen: U32) -> Maybe<&2, Step>:
  match step state:
    case N.Step{e, events, notices, nom} State{_, plans, ds, ss, pac, cfg, failed}:
      Some{Step{State{e, Con{Plan{path, reference, gen, None{}}, plans}, ds, ss, pac, cfg, failed}, events, notices, nom, []}}

def plan_queued(step: Maybe<&2, Session.Step>, +state: State, path: V.Path, reference: Pairs.Ref, gen: U32) -> Maybe<&2, Step>:
  match step:
    case Some{s}: planned_step(session_step(state, s), state, path, reference, gen)
    case _: None{}

def plan_path(path: Maybe<&2, V.Path>, +state: State) -> Maybe<&2, Step>:
  match path:
    case Some{+path}:
      match path:
        case V.Path{_, _, _, _, A.Record{S.Flight{_, +ref, _}, +gen, _, _}, _}:
          Bool.pick(Maybe<&2, Step>, eligible(state, path), plan_queued(Session.queue_nomination(session(state), ref, gen), state, path, ref, gen), None{})
    case _: None{}

# Resolve the current owned association. A copied Path.origin can be older than
# the check that most recently generated the stored valid identity.
def nominate(+state: State, reference: Pairs.Ref) -> Maybe<&2, Step>:
  plan_path(N.path_for(core(state), reference), state)

def nominate_paths(values: List<&2, N.Link>, +state: State, +id: U32, +comp: U32, +found: Maybe<&2, V.Path>) -> Maybe<&2, V.Path>:
  match values:
    case Nil{}: found
    case Con{N.Link{+ref, _, path}, tail}:
      nominate_paths(tail, state, id, comp,
        Bool.pick(Maybe<&2, V.Path>, path_component(path, id, comp),
          better_owned(N.path_for(core(state), ref), found), found))

def nominate_core(evidence: N.State, +state: State, id: U32, comp: U32) -> Maybe<&2, Step>:
  match evidence:
    case N.State{_, links, _, _, _, _}: plan_path(nominate_paths(links, state, id, comp, None{}), state)

def nominate_best(+state: State, id: U32, comp: U32) -> Maybe<&2, Step>:
  nominate_core(core(state), state, id, comp)

def mark_paths(values: List<&2, V.Path>, +wanted: V.Path, rev: List<&2, V.Path>) -> List<&2, V.Path>:
  match values:
    case Nil{}: List.reverse(&2, V.Path, rev)
    case Con{V.Path{+id, +l, +r, +rank, +origin, +flag}, tail}:
      mark_paths(tail, wanted, Con{V.Path{id, l, r, rank, origin,
        Bool.or(flag, V.same_path(V.Path{id, l, r, rank, origin, flag}, wanted))}, rev})

def marked(state: N.State, path: V.Path) -> N.State:
  match state:
    case N.State{V.State{s, ls, fs, ps, limit, failed}, links, qs, bs, cap, faulted}:
      N.State{V.State{s, ls, fs, mark_paths(ps, path, []), limit, failed}, links, qs, bs, cap, faulted}

def remove_plans(values: List<&2, Plan>, +id: U32, +comp: U32, +rev: List<&2, Plan>) -> List<&2, Plan>:
  match values:
    case Nil{}: List.reverse(&2, Plan, rev)
    case Con{Plan{+path, +ref, +gen, +attempt}, tail}:
      remove_plans(tail, id, comp, Bool.pick(List<&2, Plan>, path_component(path, id, comp), rev, Con{Plan{path, ref, gen, attempt}, rev}))

def nomination_done(path: Maybe<&2, V.Path>, +state: State, +reference: Pairs.Ref, attempt: Maybe<&2, A.Record>, rev: List<&2, Notice>) -> State & List<&2, Notice>:
  match path state:
    case Some{V.Path{+id, +l, +r, +rank, +origin, False{}}} State{e, plans, ds, ss, pac, cfg, failed}:
      +path : V.Path = V.Path{id, l, r, rank, origin, True{}}
      (State{marked(e, path), remove_plans(plans, id, V.component(l), []), Con{Decision{path, reference, generation(state)}, ds}, ss, pac, cfg, failed},
        Con{Nominated{path, reference, attempt}, rev})
    case _ s: (s, rev)

def nominate_valid(+state: State, path: V.Path, reference: Pairs.Ref, attempt: Maybe<&2, A.Record>, rev: List<&2, Notice>) -> State & List<&2, Notice>:
  nomination_done(V.stored_path(N.paths(valid(state)), path), state, reference, attempt, rev)

def flights(schedule: S.State) -> List<&2, S.Flight>:
  match schedule:
    case S.State{_, _, fs, _, _, _, _, _}: fs

def record_current(+state: State, record: A.Record) -> Bool:
  match record:
    case A.Record{S.Flight{token, _, +sent}, gen, _, _}:
      Bool.and(U32.is_eq(generation(state), gen), Bool.and(V.role_same(role(state), sent),
        Maybe.is_some(&2, S.Flight, S.by_token(flights(N.schedule(valid(state))), token))))

def continued(T: Type, result: State & List<&2, Notice>, again: State -> List<&2, Notice> -> T) -> T:
  (state, notices) = result
  again(state, notices)

def outgoing_plan(values: List<&2, Plan>, +record: A.Record) -> Bool:
  match values record:
    case Nil{} _: False{}
    case Con{Plan{_, ref, gen, _}, tail} A.Record{S.Flight{_, +got, _}, +current, +tx, +conflict}:
      Bool.or(Bool.and(Pairs.same(ref, got), U32.is_eq(gen, current)), outgoing_plan(tail, record))

def outgoing_attempt(attempt: Maybe<&2, V.Attempt>) -> Bool:
  match attempt:
    case Some{V.Attempt{A.Record{S.Flight{_, _, Ice.Controlling{_, _}}, _, _, _}, _, _, _, True{}}}: True{}
    case _: False{}

def controlling_valid(values: List<&2, V.Notice>, +previous: State, +state: State, +rev: List<&2, Notice>) -> State & List<&2, Notice>:
  match values:
    case Nil{}: (state, rev)
    case Con{V.Validated{+path, _, _}, tail}:
      match path:
        case V.Path{_, _, _, _, +record, _}:
          match record:
            case A.Record{S.Flight{_, +ref, +sent}, +gen, _, _}:
              match state:
                case State{_, plans, _, _, _, _, _}:
                  +ok = Bool.and(U32.is_eq(gen, generation(state)), Bool.and(V.role_same(sent, role(state)),
                    Bool.and(outgoing_plan(plans, record), outgoing_attempt(V.attempt(session(previous), record)))))
                  continued(State & List<&2, Notice>, Bool.pick(State & List<&2, Notice>, ok, nominate_valid(state, path, ref, Some{record}, rev), (state, rev)),
                    next => notices => controlling_valid(tail, previous, next, notices))
    case Con{_, tail}: controlling_valid(tail, previous, state, rev)

def controlled_valid(values: List<&2, N.Notice>, +state: State, +rev: List<&2, Notice>) -> State & List<&2, Notice>:
  match values:
    case Nil{}: (state, rev)
    case Con{N.Mapped{+record, +request, path, _}, tail}:
      match record:
        case A.Record{S.Flight{_, +ref, sent}, gen, _, _}:
          +ok = Bool.and(U32.is_eq(gen, generation(state)), Bool.and(V.role_same(sent, role(state)), N.qualified(valid(state), request)))
          continued(State & List<&2, Notice>, Bool.pick(State & List<&2, Notice>, ok, nominate_valid(state, path, ref, Some{record}, rev), (state, rev)),
            next => notices => controlled_valid(tail, next, notices))
    case Con{_, tail}: controlled_valid(tail, state, rev)

def accepted_intents(values: List<&2, N.Intent>, +state: State, +rev: List<&2, Notice>) -> State & List<&2, Notice>:
  match values:
    case Nil{}: (state, rev)
    case Con{N.Intent{+ref, gen, +request}, tail}:
      +ok = Bool.and(U32.is_eq(gen, generation(state)), N.qualified(valid(state), request))
      continued(State & List<&2, Notice>, Bool.pick(State & List<&2, Notice>, ok,
        nomination_done(N.path_for(core(state), ref), state, ref, None{}, rev), (state, rev)),
        next => notices => accepted_intents(tail, next, notices))

def bound_plan(values: List<&2, Plan>, +record: A.Record, rev: List<&2, Plan>) -> List<&2, Plan>:
  match values record:
    case Nil{} _: List.reverse(&2, Plan, rev)
    case Con{Plan{path, +ref, +gen, +attempt}, tail} A.Record{S.Flight{_, +got, _}, +current, _, _}:
      bound_plan(tail, record, Con{Plan{path, ref, gen,
        Bool.pick(Maybe<&2, A.Record>, Bool.and(Pairs.same(ref, got), U32.is_eq(gen, current)), Some{record}, attempt)}, rev})

def sent(values: List<&2, Session.Notice>, +state: State) -> State:
  match values state:
    case Nil{} s: s
    case Con{Session.Attempt{A.Transaction{Some{+record}, Tx.Send{_, _, _, _, True{}}}}, tail} State{e, plans, ds, ss, pac, cfg, failed}:
      sent(tail, State{e, Bool.pick(List<&2, Plan>, outgoing_attempt(V.attempt(session(state), record)), bound_plan(plans, record, []), plans), ds, ss, pac, cfg, failed})
    case Con{_, tail} s: sent(tail, s)

def failed_outcome(value: Reliable.Outcome) -> Bool:
  match value:
    case Reliable.Received{Response.Error{487}, _}: False{}
    case Reliable.Received{Response.Success{_}, _}: False{}
    case _: True{}

def current_plan(values: List<&2, Plan>, +record: A.Record) -> Maybe<&2, V.Path>:
  match values:
    case Nil{}: None{}
    case Con{Plan{path, _, _, Some{got}}, tail}:
      Bool.pick(Maybe<&2, V.Path>, V.record_same(got, record), Some{path}, current_plan(tail, record))
    case Con{_, tail}: current_plan(tail, record)

def remove_path(values: List<&2, V.Path>, +wanted: V.Path, +rev: List<&2, V.Path>) -> List<&2, V.Path>:
  match values:
    case Nil{}: List.reverse(&2, V.Path, rev)
    case Con{+path, tail}: remove_path(tail, wanted, Bool.pick(List<&2, V.Path>, V.same_path(path, wanted), rev, Con{path, rev}))

def removed_path(state: N.State, p: V.Path) -> N.State:
  match state:
    case N.State{V.State{s, ls, fs, paths, limit, failed}, links, qs, bs, cap, faulted}:
      N.State{V.State{s, ls, fs, remove_path(paths, p, []), limit, failed}, links, qs, bs, cap, faulted}

def without_path(state: N.State, wanted: Maybe<&2, V.Path>) -> N.State:
  match wanted:
    case Some{p}: removed_path(state, p)
    case _: state

def failed_component(values: List<&2, Stream>, +id: U32, +comp: U32, rev: List<&2, Stream>) -> List<&2, Stream>:
  match values:
    case Nil{}: List.reverse(&2, Stream, rev)
    case Con{Stream{+got, req, +failed, status}, tail}:
      failed_component(tail, id, comp, Con{Stream{got, req,
        Bool.pick(List<&2, U32>, Bool.and(U32.is_eq(id, got), Bool.not(number_exists(failed, comp, False{}))), Con{comp, failed}, failed), status}, rev})

def nomination_failed(+state: State, record: A.Record, +path: Maybe<&2, V.Path>, rev: List<&2, Notice>) -> State & List<&2, Notice>:
  match state record:
    case State{e, plans, ds, ss, pac, cfg, failed} A.Record{S.Flight{_, Pairs.Ref{+id, +comp, _, _}, _}, _, _, _}:
      (State{without_path(e, path), remove_plans(plans, id, comp, []), ds, failed_component(ss, id, comp, []), pac, cfg, failed},
        Con{NominationFailed{record, path}, rev})

def failed_record(ok: Bool, +previous: State, +state: State, +record: A.Record, controlled: Bool, +rev: List<&2, Notice>) -> State & List<&2, Notice>:
  match previous:
    case State{_, plans, _, _, _, _, _}:
      +path = current_plan(plans, record)
      Bool.pick(State & List<&2, Notice>, Bool.and(ok, Bool.and(record_current(previous, record),
        Bool.or(controlled, Maybe.is_some(&2, V.Path, path)))), nomination_failed(state, record, path, rev), (state, rev))

def controlling_failures(values: List<&2, Session.Notice>, +previous: State, state: State, rev: List<&2, Notice>) -> State & List<&2, Notice>:
  match values:
    case Nil{}: (state, rev)
    case Con{Session.Attempt{A.Transaction{Some{record}, Tx.Finished{_, outcome}}}, tail}:
      continued(State & List<&2, Notice>, failed_record(failed_outcome(outcome), previous, state, record, False{}, rev),
        next => notices => controlling_failures(tail, previous, next, notices))
    case Con{Session.Attempt{A.NonSymmetric{record, _, failed}}, tail}:
      continued(State & List<&2, Notice>, failed_record(failed, previous, state, record, False{}, rev),
        next => notices => controlling_failures(tail, previous, next, notices))
    case Con{_, tail}: controlling_failures(tail, previous, state, rev)

def controlled_failures(values: List<&2, N.Notice>, +previous: State, state: State, rev: List<&2, Notice>) -> State & List<&2, Notice>:
  match values:
    case Nil{}: (state, rev)
    case Con{N.Outcome{record, request, Tx.Finished{_, outcome}}, tail}:
      continued(State & List<&2, Notice>, failed_record(Bool.and(failed_outcome(outcome), N.qualified(valid(previous), request)), previous, state, record, True{}, rev),
        next => notices => controlled_failures(tail, previous, next, notices))
    case Con{N.NonSymmetric{record, request, _, failed}, tail}:
      continued(State & List<&2, Notice>, failed_record(Bool.and(failed, N.qualified(valid(previous), request)), previous, state, record, True{}, rev),
        next => notices => controlled_failures(tail, previous, next, notices))
    case Con{_, tail}: controlled_failures(tail, previous, state, rev)

def all_paths(required: List<&2, U32>, +paths: List<&2, V.Path>, +id: U32, +nominated: Bool, ok: Bool) -> Bool:
  match required:
    case Nil{}: ok
    case Con{comp, tail}: all_paths(tail, paths, id, nominated, Bool.and(ok, Maybe.is_some(&2, V.Path, best_path(paths, id, comp, nominated, None{}))))

def active_pairs(values: List<&2, Check.CandidatePair>, active: Bool) -> Bool:
  match values:
    case Nil{}: active
    case Con{Check.CandidatePair{_, _, _, Check.Failed{}}, tail}: active_pairs(tail, active)
    case Con{Check.CandidatePair{_, _, _, Check.Succeeded{}}, tail}: active_pairs(tail, active)
    case Con{_, tail}: active_pairs(tail, True{})

def active(values: List<&2, Check.Checklist>, +id: U32) -> Bool:
  match values:
    case Nil{}: False{}
    case Con{Check.Checklist{got, pairs}, tail}: Bool.pick(Bool, U32.is_eq(got, id), active_pairs(pairs, False{}), active(tail, id))

def pac_elapsed(pac: Pac) -> Bool:
  match pac:
    case Elapsed{}: True{}
    case _: False{}

def no_failures(values: List<&2, U32>) -> Bool:
  match values:
    case Nil{}: True{}
    case _: False{}

def stream_status(old: Status, +required: List<&2, U32>, failed: List<&2, U32>, +paths: List<&2, V.Path>, +id: U32, +lists: List<&2, Check.Checklist>, pac: Pac) -> Status:
  match old:
    case Failed{}: Failed{}
    case _:
      Bool.pick(Status, all_paths(required, paths, id, True{}, True{}), Completed{},
        Bool.pick(Status, Bool.and(pac_elapsed(pac), Bool.or(Bool.not(no_failures(failed)),
          Bool.and(Bool.not(active(lists, id)), Bool.not(all_paths(required, paths, id, False{}, True{}))))), Failed{}, Running{}))

def update_streams(values: List<&2, Stream>, +paths: List<&2, V.Path>, +lists: List<&2, Check.Checklist>, +pac: Pac,
                   rev: List<&2, Stream>, +notices: List<&2, Notice>) -> List<&2, Stream> & List<&2, Notice>:
  match values:
    case Nil{}: (List.reverse(&2, Stream, rev), notices)
    case Con{Stream{+id, +req, +failed, +old}, tail}:
      +next = stream_status(old, req, failed, paths, id, lists, pac)
      update_streams(tail, paths, lists, pac, Con{Stream{id, req, failed, next}, rev},
        Bool.pick(List<&2, Notice>, same_status(old, next), notices, Con{StreamChanged{id, next}, notices}))

def pac_update(pac: Pac, bound: Bool, ms: U32, +now: Nat, +rev: List<&2, Notice>) -> Pac & List<&2, Notice>:
  match pac:
    case Dormant{True{}}:
      +deadline = Nat.add(now, U32.to_nat(ms))
      Bool.pick(Pac & List<&2, Notice>, bound, (Started{deadline}, Con{PacStarted{deadline}, rev}), (Dormant{True{}}, rev))
    case Started{+deadline}: Bool.pick(Pac & List<&2, Notice>, Nat.is_le(deadline, now), (Elapsed{}, Con{PacExpired{}, rev}), (Started{deadline}, rev))
    case p: (p, rev)

def bound_session(state: Session.State) -> Bool:
  match state:
    case Session.State{_, _, _, Some{_}, _, _}: True{}
    case _: False{}

def bound(state: State) -> Bool:
  bound_session(session(state))

def refreshed_streams(result: List<&2, Stream> & List<&2, Notice>, +state: State, next_pac: Pac) -> State & List<&2, Notice>:
  (next_streams, +notices) = result
  match state:
    case State{e, plans, ds, _, _, cfg, failed}:
      +next : State = State{e, plans, ds, next_streams, next_pac, cfg, failed}
      (next, Bool.pick(List<&2, Notice>, same_status(status(state), status(next)), notices, Con{SessionChanged{status(next)}, notices}))

def refreshed_pac(result: Pac & List<&2, Notice>, +state: State) -> State & List<&2, Notice>:
  (+next_pac, notices) = result
  match state:
    case State{_, _, _, ss, _, _, _}:
      refreshed_streams(update_streams(ss, N.paths(valid(state)), N.lists(valid(state)), next_pac, [], notices), state, next_pac)

def refreshed(+state: State, now: Nat, rev: List<&2, Notice>) -> State & List<&2, Notice>:
  match state:
    case State{_, _, _, _, pac, Config{ms, _}, _}: refreshed_pac(pac_update(pac, bound(state), ms, now, rev), state)

def cleanup_advanced(step: N.Step, state: State, events: List<&2, Session.Notice>) -> State & List<&2, Session.Notice>:
  match step:
    case N.Step{e, extra, _, _}: (replace_evidence(state, e), List.reverse.go(&2, Session.Notice, List.reverse(&2, Session.Notice, events), extra))

def cleanup_step(value: Maybe<&2, Session.Step>, +state: State, events: List<&2, Session.Notice>) -> State & List<&2, Session.Notice>:
  match value:
    case None{}: (state, events)
    case Some{s}: cleanup_advanced(session_step(state, s), state, events)

def cleanup_next(result: State & List<&2, Session.Notice>, again: State -> List<&2, Session.Notice> -> State & List<&2, Session.Notice>) -> State & List<&2, Session.Notice>:
  (state, events) = result
  again(state, events)

def clear_intents(values: List<&2, N.Intent>, +id: U32, +comp: U32, +rev: List<&2, N.Intent>) -> List<&2, N.Intent>:
  match values:
    case Nil{}: List.reverse(&2, N.Intent, rev)
    case Con{N.Intent{+ref, +gen, +q}, tail}:
      clear_intents(tail, id, comp, Bool.pick(List<&2, N.Intent>, S.component_ref(ref, id, comp), rev, Con{N.Intent{ref, gen, q}, rev}))

def clear_component(state: State, id: U32, comp: U32) -> State:
  match state:
    case State{N.State{v, ls, qs, bs, cap, faulted}, ps, ds, ss, pac, cfg, failed}:
      State{N.State{v, ls, clear_intents(qs, id, comp, []), bs, cap, faulted}, ps, ds, ss, pac, cfg, failed}

def conclude_component(+state: State, +id: U32, +comp: U32, events: List<&2, Session.Notice>) -> State & List<&2, Session.Notice>:
  cleanup_step(Session.conclude(session(state), id, comp, generation(state)), clear_component(state, id, comp), events)

def conclude_components(values: List<&2, U32>, +id: U32, +state: State, events: List<&2, Session.Notice>) -> State & List<&2, Session.Notice>:
  match values:
    case Nil{}: (state, events)
    case Con{comp, tail}:
      cleanup_next(conclude_component(state, id, comp, events), next => es => conclude_components(tail, id, next, es))

def conclude_stream(values: List<&2, Stream>, +id: U32, +state: State, +events: List<&2, Session.Notice>) -> State & List<&2, Session.Notice>:
  match values:
    case Nil{}: (state, events)
    case Con{Stream{got, req, _, _}, tail}:
      Bool.pick(State & List<&2, Session.Notice>, U32.is_eq(id, got), conclude_components(req, id, state, events), conclude_stream(tail, id, state, events))

def conclude_all(values: List<&2, Stream>, state: State, events: List<&2, Session.Notice>) -> State & List<&2, Session.Notice>:
  match values:
    case Nil{}: (state, events)
    case Con{Stream{id, req, _, _}, tail}:
      cleanup_next(conclude_components(req, id, state, events), next => es => conclude_all(tail, next, es))

def invalidate_path(path: Maybe<&2, V.Path>, +state: State, events: List<&2, Session.Notice>) -> State & List<&2, Session.Notice>:
  match path:
    case None{}: (state, events)
    case Some{V.Path{id, +local, C.Candidate{comp, _, _, _, remote}, _, _, _}}:
      cleanup_step(Session.invalidated(session(state), Pairs.Ref{id, comp, V.address(local), remote}, generation(state)), state, events)

def cleanup(values: List<&2, Notice>, +state: State, events: List<&2, Session.Notice>) -> State & List<&2, Session.Notice>:
  match values:
    case Nil{}: (state, events)
    case Con{Nominated{V.Path{id, local, _, _, _, _}, _, _}, tail}:
      cleanup_next(conclude_component(state, id, V.component(local), events),
        next => es => cleanup(tail, next, es))
    case Con{NominationFailed{_, path}, tail}:
      cleanup_next(invalidate_path(path, state, events), next => es => cleanup(tail, next, es))
    case Con{StreamChanged{id, Failed{}}, tail}:
      match state:
        case State{_, _, _, ss, _, _, _}:
          cleanup_next(conclude_stream(ss, id, state, events), next => es => cleanup(tail, next, es))
    case Con{SessionChanged{Failed{}}, tail}:
      match state:
        case State{_, _, _, ss, _, _, _}:
          cleanup_next(conclude_all(ss, state, events), next => es => cleanup(tail, next, es))
    case Con{SessionChanged{Faulted{}}, tail}:
      match state:
        case State{_, _, _, ss, _, _, _}:
          cleanup_next(conclude_all(ss, state, events), next => es => cleanup(tail, next, es))
    case Con{_, tail}: cleanup(tail, state, events)

def cleaned(result: State & List<&2, Session.Notice>, valid: List<&2, V.Notice>, nomination: List<&2, N.Notice>, lifecycle: List<&2, Notice>) -> Step:
  (next, es) = result
  Step{next, es, valid, nomination, lifecycle}

def advanced(result: State & List<&2, Notice>, events: List<&2, Session.Notice>, valid: List<&2, V.Notice>, nomination: List<&2, N.Notice>) -> Step:
  (state, +rev) = result
  cleaned(cleanup(rev, state, events), valid, nomination, List.reverse(&2, Notice, rev))

def finished_intents(e: N.State, +state: State, now: Nat, rev: List<&2, Notice>, events: List<&2, Session.Notice>, notices: List<&2, V.Notice>, nom: List<&2, N.Notice>) -> Step:
  match e:
    case N.State{_, _, intents, _, _, _}:
      continued(Step, accepted_intents(intents, state, rev), s => ns => advanced(refreshed(s, now, ns), events, notices, nom))

def session_notice(values: List<&2, Notice>, found: Bool) -> Bool:
  match values:
    case Nil{}: found
    case Con{SessionChanged{_}, tail}: session_notice(tail, True{})
    case Con{_, tail}: session_notice(tail, found)

# A core fault is an owner abort, not an ICE Failed transition before PAC. It
# must still notify the caller and stop all retries, even when V/N faulted first.
def checked_status(step: Step, previous: Status) -> Step:
  match step:
    case Step{+state, +events, +valid, +nomination, +life}:
      +current = status(state)
      Bool.pick(Step, Bool.or(same_status(previous, current), session_notice(life, False{})),
        Step{state, events, valid, nomination, life},
        cleaned(cleanup([SessionChanged{current}], state, events), valid, nomination,
          List.reverse.go(&2, Notice, List.reverse(&2, Notice, life), [SessionChanged{current}])))

def advance(step: N.Step, +previous: State, now: Nat) -> Step:
  match step previous:
    case N.Step{+e, +events, +notices, +nom} State{_, +plans, ds, ss, pac, cfg, failed}:
      +state = sent(events, State{e, Bool.pick(List<&2, Plan>, V.role_same(role(previous), V.role(V.core(N.core(e)))), plans, []), ds, ss, pac, cfg, failed})
      checked_status(continued(Step, controlling_failures(events, previous, state, []), s => ns =>
        continued(Step, controlled_failures(nom, previous, s, ns), s => ns =>
          continued(Step, controlling_valid(notices, previous, s, ns), s => ns =>
            continued(Step, controlled_valid(nom, s, ns), +s => ns => finished_intents(core(s), s, now, ns, events, notices, nom))))), status(previous))

def empty(state: State) -> Step:
  Step{state, [], [], [], []}

def merge(first: Step, second: Step) -> Step:
  match first second:
    case Step{_, e1, v1, n1, l1} Step{state, e2, v2, n2, l2}:
      Step{state, List.reverse.go(&2, Session.Notice, List.reverse(&2, Session.Notice, e1), e2),
        List.reverse.go(&2, V.Notice, List.reverse(&2, V.Notice, v1), v2),
        List.reverse.go(&2, N.Notice, List.reverse(&2, N.Notice, n1), n2),
        List.reverse.go(&2, Notice, List.reverse(&2, Notice, l1), l2)}

def auto_chosen(value: Maybe<&2, Step>, +prior: Step) -> Step:
  match value:
    case Some{s}: merge(prior, s)
    case None{}: prior

def automatic_components(values: List<&2, U32>, +id: U32, +step: Step) -> Step:
  match values step:
    case Nil{} s: s
    case Con{comp, tail} Step{+state, _, _, _, _}:
      automatic_components(tail, id, auto_chosen(nominate_best(state, id, comp), step))

def automatic_streams(values: List<&2, Stream>, step: Step) -> Step:
  match values:
    case Nil{}: step
    case Con{Stream{id, required, _, Running{}}, tail}: automatic_streams(tail, automatic_components(required, id, step))
    case Con{_, tail}: automatic_streams(tail, step)

def automatic(+step: Step) -> Step:
  match step:
    case Step{State{_, _, _, ss, _, Config{_, True{}}, _}, _, _, _, _}: automatic_streams(ss, step)
    case _: step

def started(step: Step, tx: List<&2, U32>, policy: Retry.Policy, +now: Nat) -> Step:
  match step:
    case Step{+state, +events, +notices, +nom, +life}:
      match state:
        case State{_, plans, _, _, _, _, _}:
          Bool.pick(Step, terminal(status(state)), Step{state, events, notices, nom, life},
            merge(Step{state, events, notices, nom, life},
              advance(session_step(state, Session.start_intents(session(state), tx, policy, targets(plans, []), now)), state, now)))

# First-highest-current-valid is the automatic policy. Only the repeat of its
# actual generating reference is marked; admission/pacing does not consume it.
def start(+state: State, tx: List<&2, U32>, policy: Retry.Policy, +now: Nat) -> Step:
  Bool.pick(Step, terminal(status(state)), empty(state), started(automatic(advance(N.drain(core(state)), state, now)), tx, policy, now))

def decision_allows(values: List<&2, Decision>, +reference: Pairs.Ref, +gen: U32, allowed: Bool) -> Bool:
  match values:
    case Nil{}: allowed
    case Con{Decision{V.Path{+id, +local, C.Candidate{+comp, _, _, _, +remote}, _, _, _}, +ref, got}, tail}:
      decision_allows(tail, reference, gen, Bool.or(allowed, Bool.and(U32.is_eq(got, gen),
        Bool.or(Pairs.same(ref, reference), Pairs.same(Pairs.Ref{id, comp, V.base(local), remote}, reference)))))

def concluded_component(paths: List<&2, V.Path>, reference: Pairs.Ref) -> Bool:
  match reference:
    case Pairs.Ref{id, comp, _, _}: Maybe.is_some(&2, V.Path, best_path(paths, id, comp, True{}, None{}))

def receive(+state: State, +reference: Pairs.Ref, +raw: List<&2, U32>, +now: Nat) -> Step:
  match state:
    case State{_, _, ds, _, _, _, _}:
      Bool.pick(Step, same_status(status(state), Faulted{}), empty(state),
      advance(session_step(state, Bool.pick(Session.Step, Bool.or(terminal(status(state)), concluded_component(N.paths(valid(state)), reference)),
        Session.reply_only(session(state), reference, raw, now,
          Bool.and(Bool.not(terminal(status(state))), decision_allows(ds, reference, generation(state), False{}))),
        Session.receive(session(state), reference, raw, now))), state, now))

def tick(+state: State, +now: Nat) -> Step:
  advance(N.tick(core(state), now), state, now)

def bind_result(value: Maybe<&2, N.Step>, state: State, now: Nat) -> Maybe<&2, Step>:
  match value:
    case None{}: None{}
    case Some{s}: Some{advance(s, state, now)}

def bind(+state: State, credentials: Ice.Credentials, now: Nat) -> Maybe<&2, Step>:
  bind_result(N.bind(core(state), credentials), state, now)

# Signaling must call this only once the local credentials have actually been
# sent. Remote credentials may arrive first; either ordering starts PAC once.
def local_signaled(+state: State, now: Nat) -> Step:
  match state:
    case State{e, plans, ds, ss, Dormant{_}, cfg, failed}:
      advanced(refreshed(State{e, plans, ds, ss, Dormant{True{}}, cfg, failed}, now, []), [], [], [])
    case _: advanced(refreshed(state, now, []), [], [], [])

def repair(+state: State, token: U32, gen: U32, high: U32, low: U32, now: Nat) -> Maybe<&2, Step>:
  bind_result(N.repair(core(state), token, gen, high, low), state, now)

def acknowledge(+state: State, notice: Session.Notice, +now: Nat) -> Step:
  advance(N.acknowledge(core(state), notice, now), state, now)

def failed(+state: State, token: U32, code: U32, now: Nat) -> Step:
  advance(N.failed(core(state), token, code), state, now)

def current_send(+state: State, notice: Session.Notice) -> Bool:
  Bool.and(Bool.not(terminal(status(state))), N.current_send(core(state), notice))

def pac_timeout(pac: Pac, +now: Nat, +other: U32) -> U32:
  match pac:
    case Started{+deadline}:
      Bool.pick(U32, Nat.is_le(deadline, now), 0,
        U32.from_nat(Tx.earlier(Nat.sub(deadline, now), U32.to_nat(other))))
    case _: other

def timeout(+state: State, +now: Nat, cap: U32) -> U32:
  match state:
    case State{_, _, _, _, pac, _, _}: pac_timeout(pac, now, N.timeout(core(state), now, cap))

def send_gate(state: State, not_before: Nat) -> State:
  match state:
    case State{evidence, plans, decisions, streams, pac, config, faulted}:
      State{N.send_gate(evidence, not_before), plans, decisions, streams, pac, config, faulted}
