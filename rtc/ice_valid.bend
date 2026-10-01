import Base
import ./ice_session.bend as Session
import ./ice_attempts.bend as A
import ./ice_scheduler.bend as S
import ./ice_registry.bend as R
import ./ice_candidates.bend as C
import ./ice_checklist.bend as Check
import ./ice_pairs.bend as Pairs
import ./ice_binding.bend as Ice
import ./ice_incoming.bend as Incoming
import ./ice_roles.bend as Roles
import ./ice_transactions.bend as Tx
import ./ice_reliable.bend as Reliable
import ./ice_response.bend as Response
import ./stun.bend as Stun
import ./stun_auth.bend as Auth
import ./stun_retry.bend as Retry

# An additive owner for one Session generation. Valid identity includes the
# mapped candidate and its base; a transport reference alone is insufficient.
type Learned is Data:
  Learned{stream: U32, local: C.Local}

type Foundation is Data:
  Foundation{base: Stun.IPv4, peer: Stun.IPv4, name: String}

type RequestFields is Data:
  RequestFields{priority: U32, use_candidate: Bool}

type Attempt is Data:
  Attempt{record: A.Record, local: C.Local, remote: C.Candidate, priority: U32, use_candidate: Bool}

type Path is Data:
  Path{stream: U32, local: C.Local, remote: C.Candidate, rank: C.Priority,
       origin: A.Record, nominated: Bool}

type State is Data:
  State{session: Session.State, learned: List<&2, Learned>, foundations: List<&2, Foundation>,
        paths: List<&2, Path>, limit: U32, faulted: Bool}

type Notice is Data:
  Validated{path: Path, discovered: Bool, late: Bool}
  Exhausted{record: A.Record}
  InvalidMapping{record: A.Record}

type Step is Data:
  Step{state: State, events: List<&2, Session.Notice>, valid: List<&2, Notice>}

def core(state: State) -> Session.State:
  match state:
    case State{s, _, _, _, _, _}: s

def role(session: Session.State) -> Ice.Role:
  match session:
    case Session.State{a, _, _, _, _, _}: Session.role(a)

def streams(session: Session.State) -> List<&2, Check.Stream>:
  match session:
    case Session.State{_, R.State{ss, _, _, _}, _, _, _, _}: ss

def role_same(a: Ice.Role, b: Ice.Role) -> Bool:
  match a b:
    case Ice.Controlling{ah, al} Ice.Controlling{bh, bl}: Bool.and(U32.is_eq(ah, bh), U32.is_eq(al, bl))
    case Ice.Controlled{ah, al} Ice.Controlled{bh, bl}: Bool.and(U32.is_eq(ah, bh), U32.is_eq(al, bl))
    case _ _: False{}

def record_same(a: A.Record, b: A.Record) -> Bool:
  match a b:
    case A.Record{S.Flight{ta, ra, arole}, ga, txa, _} A.Record{S.Flight{tb, rb, brole}, gb, txb, _}:
      Bool.and(Bool.and(U32.is_eq(ta, tb), U32.is_eq(ga, gb)),
        Bool.and(Pairs.same(ra, rb), Bool.and(role_same(arole, brole), Stun.same(txa, txb, True{}))))

def request_fields(packet: Maybe<&2, Stun.Packet>) -> Maybe<&2, RequestFields>:
  match packet:
    case Some{Stun.Packet{1, _, +attrs}}:
      Maybe.bind(&2, U32, RequestFields, Incoming.word(Incoming.first(attrs, 36)),
        p => Maybe.bind(&2, Bool, RequestFields, Incoming.nomination(Incoming.first(attrs, 37)), n => Some{RequestFields{p, n}}))
    case _: None{}

def context_fields(entry: Maybe<&2, Tx.Entry>) -> Maybe<&2, RequestFields>:
  match entry:
    case Some{Tx.Entry{_, Reliable.Context{_, _, _, _, _, raw}, _, _, _}}: request_fields(Stun.parse(raw))
    case Some{Tx.Listening{_, Reliable.Context{_, _, _, _, _, raw}, _}}: request_fields(Stun.parse(raw))
    case _: None{}

def attempt_fields(fields: Maybe<&2, RequestFields>, local: Maybe<&2, C.Local>, remote: Maybe<&2, C.Candidate>, record: A.Record) -> Maybe<&2, Attempt>:
  match fields local remote:
    case Some{RequestFields{p, n}} Some{l} Some{r}: Some{Attempt{record, l, r, p, n}}
    case _ _ _: None{}

def attempt_record(saved: Maybe<&2, A.Record>, +record: A.Record, +session: Session.State) -> Maybe<&2, Attempt>:
  match saved record session:
    case Some{+old} A.Record{S.Flight{+token, Pairs.Ref{+id, +component, +base, +peer}, +sent_role}, +gen, +tx, +conflict}
         Session.State{A.State{_, Tx.State{entries, _, _, _, _}, _, _}, R.State{+ss, _, _, _}, _, _, _, _}:
      Bool.pick(Maybe<&2, Attempt>, record_same(old, A.Record{S.Flight{token, Pairs.Ref{id, component, base, peer}, sent_role}, gen, tx, conflict}),
        attempt_fields(context_fields(A.transaction_entry(entries, token)), R.local(ss, id, component, base), R.remote(ss, id, component, peer),
          A.Record{S.Flight{token, Pairs.Ref{id, component, base, peer}, sent_role}, gen, tx, conflict}), None{})
    case _ _ _: None{}

# The signed request bytes already retained by Tx are authoritative. Read them
# before processing a response removes its entry, including interrupted listeners.
# This metadata is the original request, not a recomputation under the new role.
def attempt(+session: Session.State, +record: A.Record) -> Maybe<&2, Attempt>:
  match session record:
    case Session.State{A.State{+s, +engine, +records, +policies}, +registry, +secret, +peer, +pending, +mode}
         A.Record{S.Flight{+token, +ref, +sent_role}, +gen, +tx, +conflict}:
      attempt_record(A.get(records, token), A.Record{S.Flight{token, ref, sent_role}, gen, tx, conflict},
        Session.State{A.State{s, engine, records, policies}, registry, secret, peer, pending, mode})

def address(local: C.Local) -> Stun.IPv4:
  match local:
    case C.Local{C.Candidate{_, _, _, _, a}, _}: a

def base(local: C.Local) -> Stun.IPv4:
  match local:
    case C.Local{_, C.Candidate{_, _, _, _, a}}: a

def component(local: C.Local) -> U32:
  match local:
    case C.Local{C.Candidate{c, _, _, _, _}, _}: c

def priority(local: C.Local) -> U32:
  match local:
    case C.Local{C.Candidate{_, p, _, _, _}, _}: p

def best(old: Maybe<&2, C.Local>, +local: C.Local) -> Maybe<&2, C.Local>:
  match old:
    case None{}: Some{local}
    case Some{+previous}: Some{Bool.pick(C.Local, U32.is_gt(priority(local), priority(previous)), local, previous)}

def matching(locals: List<&2, C.Local>, +comp: U32, +mapped: Stun.IPv4, +found: Maybe<&2, C.Local>) -> Maybe<&2, C.Local>:
  match locals:
    case Nil{}: found
    case Con{C.Local{+candidate, +base_candidate}, tail}:
      +l : C.Local = C.Local{candidate, base_candidate}
      +bl : C.Local = C.Local{base_candidate, base_candidate}
      +next = Bool.pick(Maybe<&2, C.Local>, Bool.and(U32.is_eq(component(l), comp), C.address_same(address(l), mapped)), best(found, l), found)
      matching(tail, comp, mapped, Bool.pick(Maybe<&2, C.Local>, Bool.and(U32.is_eq(component(bl), comp), C.address_same(address(bl), mapped)), best(next, bl), next))

def known(ss: List<&2, Check.Stream>, +id: U32, +comp: U32, +mapped: Stun.IPv4) -> Maybe<&2, C.Local>:
  match ss:
    case Nil{}: None{}
    case Con{Check.Stream{got, ls, _}, tail}:
      Bool.pick(Maybe<&2, C.Local>, U32.is_eq(id, got), matching(ls, comp, mapped, None{}), known(tail, id, comp, mapped))

def learned_local(ls: List<&2, Learned>, +id: U32, +comp: U32, +mapped: Stun.IPv4, +found: Maybe<&2, C.Local>) -> Maybe<&2, C.Local>:
  match ls:
    case Nil{}: found
    case Con{Learned{got, +l}, tail}:
      learned_local(tail, id, comp, mapped, Bool.pick(Maybe<&2, C.Local>, Bool.and(U32.is_eq(id, got), Bool.and(U32.is_eq(component(l), comp), C.address_same(address(l), mapped))), best(found, l), found))

def foundation_name(fs: List<&2, Foundation>, +b: Stun.IPv4, +peer: Stun.IPv4) -> Maybe<&2, String>:
  match fs:
    case Nil{}: None{}
    case Con{Foundation{got_base, got_peer, name}, tail}:
      Bool.pick(Maybe<&2, String>, Bool.and(String.eq(C.host(b), C.host(got_base)), String.eq(C.host(peer), C.host(got_peer))), Some{name}, foundation_name(tail, b, peer))

def names_locals(ls: List<&2, C.Local>, +name: String, found: Bool) -> Bool:
  match ls:
    case Nil{}: found
    case Con{C.Local{C.Candidate{_, _, f, _, _}, C.Candidate{_, _, bf, _, _}}, tail}:
      names_locals(tail, name, Bool.or(found, Bool.or(String.eq(name, f), String.eq(name, bf))))

def names_streams(ss: List<&2, Check.Stream>, +name: String, found: Bool) -> Bool:
  match ss:
    case Nil{}: found
    case Con{Check.Stream{_, ls, _}, tail}: names_streams(tail, name, names_locals(ls, name, found))

def names_learned(ls: List<&2, Learned>, +name: String, found: Bool) -> Bool:
  match ls:
    case Nil{}: found
    case Con{Learned{_, local}, tail}: names_learned(tail, name, names_locals([local], name, found))

def fresh_name(fuel: Nat, +ss: List<&2, Check.Stream>, +ls: List<&2, Learned>, +index: Nat) -> Maybe<&2, String>:
  match fuel:
    case 0n: None{}
    case 1n+p:
      +name = "v" ++ Nat.show(index)
      Bool.pick(Maybe<&2, String>, names_learned(ls, name, names_streams(ss, name, False{})),
        fresh_name(p, ss, ls, Nat.add(index, 1n)), Some{name})

def chosen_name(existing: Maybe<&2, String>, ss: List<&2, Check.Stream>, ls: List<&2, Learned>) -> Maybe<&2, String>:
  match existing:
    case Some{name}: Some{name}
    case None{}: fresh_name(2561n, ss, ls, 0n)

def same_path(a: Path, b: Path) -> Bool:
  match a b:
    case Path{ai, +al, C.Candidate{ac, _, _, _, ar}, _, _, _} Path{bi, +bl, C.Candidate{bc, _, _, _, br}, _, _, _}:
      Bool.and(Bool.and(U32.is_eq(ai, bi), U32.is_eq(ac, bc)), Bool.and(C.address_same(address(al), address(bl)),
        Bool.and(C.address_same(base(al), base(bl)), C.address_same(ar, br))))

def exists(paths: List<&2, Path>, +path: Path, found: Bool) -> Bool:
  match paths:
    case Nil{}: found
    case Con{other, tail}: exists(tail, path, Bool.or(found, same_path(other, path)))

def higher(a: Path, b: Path) -> Bool:
  match a b:
    case Path{_, _, _, ar, _, _} Path{_, _, _, br, _, _}: C.greater(ar, br)

def inserted(before: Bool, path: Path, head: Path, tail: List<&2, Path>, rev: List<&2, Path>, again: List<&2, Path> -> List<&2, Path>) -> List<&2, Path>:
  match before:
    case True{}: List.reverse.go(&2, Path, rev, Con{path, Con{head, tail}})
    case False{}: again(Con{head, rev})

def insert(paths: List<&2, Path>, +path: Path, rev: List<&2, Path>) -> List<&2, Path>:
  match paths:
    case Nil{}: List.reverse(&2, Path, Con{path, rev})
    case Con{+head, +tail}: inserted(higher(path, head), path, head, tail, rev, r => insert(tail, path, r))

def rerank(paths: List<&2, Path>, +controlling: Bool, sorted: List<&2, Path>) -> List<&2, Path>:
  match paths:
    case Nil{}: sorted
    case Con{Path{id, +local, C.Candidate{+c, +p, +f, +k, +a}, _, origin, nominated}, tail}:
      +lp = priority(local)
      +rank : C.Priority = C.Priority{U32.min(lp, p), (U32.max(lp, p) * 2 + Bool.pick(U32, Bool.pick(Bool, controlling, U32.is_gt(lp, p), U32.is_gt(p, lp)), 1, 0) : U32)}
      rerank(tail, controlling, insert(sorted, Path{id, local, C.Candidate{c, p, f, k, a}, rank, origin, nominated}, []))

def fault(state: State, notice: Notice, +late: Bool) -> State & Notice:
  match state:
    case State{s, ls, fs, ps, limit, failed}: (State{s, ls, fs, ps, limit, Bool.or(failed, Bool.not(late))}, notice)

def retained(+path: Path, state: State, discovered: Bool, +late: Bool) -> State & Notice:
  match state:
    case State{s, ls, fs, +ps, limit, failed}:
      (State{s, ls, fs, Bool.pick(List<&2, Path>, exists(ps, path, False{}), ps, insert(ps, path, [])), limit, failed}, Validated{path, discovered, late})

def ranked(rank: Maybe<&2, C.Priority>, state: State, id: U32, local: C.Local, remote: C.Candidate, +record: A.Record, discovered: Bool, +late: Bool) -> State & Notice:
  match rank:
    case None{}: fault(state, InvalidMapping{record}, late)
    case Some{r}: retained(Path{id, local, remote, r, record, False{}}, state, discovered, late)

def add_path(+state: State, id: U32, +local: C.Local, remote: C.Candidate, record: A.Record, discovered: Bool, +late: Bool) -> State & Notice:
  match state remote:
    case State{+s, +ls, +fs, +ps, +limit, +failed} C.Candidate{+c, +p, +f, +k, +a}:
      ranked(Bool.pick(Maybe<&2, C.Priority>, Roles.controlling(role(s)), C.pair_priority(priority(local), p), C.pair_priority(p, priority(local))),
        State{s, ls, fs, ps, limit, failed}, id, local, C.Candidate{c, p, f, k, a}, record, discovered, late)

def new_local(name: Maybe<&2, String>, state: State, attempt: Attempt, mapped: Stun.IPv4, +late: Bool) -> State & Notice:
  match name state attempt:
    case Some{+name} State{+s, +ls, +fs, +ps, +limit, +failed}
         Attempt{A.Record{S.Flight{+token, Pairs.Ref{+id, +comp, +b, +peer}, +sent_role}, +gen, +tx, +conflict}, C.Local{_, +base_candidate}, +remote, +p, _}:
      +record : A.Record = A.Record{S.Flight{token, Pairs.Ref{id, comp, b, peer}, sent_role}, gen, tx, conflict}
      +l : C.Local = C.Local{C.Candidate{comp, p, name, C.PeerReflexive{}, mapped}, base_candidate}
      add_path(State{s, Con{Learned{id, l}, ls}, Bool.pick(List<&2, Foundation>, Maybe.is_some(&2, String, foundation_name(fs, b, peer)), fs, Con{Foundation{b, peer, name}, fs}), ps, limit, failed}, id, l, remote, record, True{}, late)
    case _ s Attempt{record, _, _, _, _}: fault(s, Exhausted{record}, late)

def resolved(local: Maybe<&2, C.Local>, +state: State, +attempt: Attempt, mapped: Stun.IPv4, +late: Bool) -> State & Notice:
  match local state attempt:
    case Some{l} s Attempt{A.Record{S.Flight{token, Pairs.Ref{+id, comp, b, peer}, sent_role}, gen, tx, conflict}, _, remote, _, _}:
      add_path(s, id, l, remote, A.Record{S.Flight{token, Pairs.Ref{id, comp, b, peer}, sent_role}, gen, tx, conflict}, False{}, late)
    case None{} State{+s, +ls, +fs, +ps, +limit, +failed} Attempt{A.Record{S.Flight{+token, Pairs.Ref{+id, +comp, +b, +peer}, +sent_role}, +gen, +tx, +conflict}, +l, +r, +p, +n}:
      +record : A.Record = A.Record{S.Flight{token, Pairs.Ref{id, comp, b, peer}, sent_role}, gen, tx, conflict}
      Bool.pick(State & Notice, Nat.is_lt(List.length(&2, Learned, ls), U32.to_nat(limit)),
        new_local(chosen_name(foundation_name(fs, b, peer), streams(s), ls), State{s, ls, fs, ps, limit, failed}, Attempt{record, l, r, p, n}, mapped, late),
        fault(State{s, ls, fs, ps, limit, failed}, Exhausted{record}, late))

def room(local: Maybe<&2, C.Local>, attempt: Attempt, +paths: List<&2, Path>, +limit: U32) -> Bool:
  match local attempt:
    case Some{l} Attempt{A.Record{S.Flight{+token, Pairs.Ref{+id, +comp, +b, +peer}, +sent_role}, +gen, +tx, +conflict}, _, remote, _, _}:
      +record : A.Record = A.Record{S.Flight{token, Pairs.Ref{id, comp, b, peer}, sent_role}, gen, tx, conflict}
      Bool.or(Nat.is_lt(List.length(&2, Path, paths), U32.to_nat(limit)), exists(paths, Path{id, l, remote, C.Priority{0, 0}, record, False{}}, False{}))
    case _ _: Nat.is_lt(List.length(&2, Path, paths), U32.to_nat(limit))

def successful(found: Maybe<&2, Attempt>, +state: State, +record: A.Record, +mapped: Stun.IPv4, +late: Bool) -> State & Notice:
  match found state record:
    case Some{+a} State{+s, +ls, +fs, +ps, +limit, +failed} A.Record{S.Flight{_, Pairs.Ref{+id, +comp, _, _}, _}, _, _, _}:
      +local : Maybe<&2, C.Local> = learned_local(ls, id, comp, mapped, known(streams(s), id, comp, mapped))
      Bool.pick(State & Notice, C.address_valid(mapped),
        Bool.pick(State & Notice, room(local, a, ps, limit),
          resolved(local, State{s, ls, fs, ps, limit, failed}, a, mapped, late), fault(State{s, ls, fs, ps, limit, failed}, Exhausted{record}, late)),
        fault(State{s, ls, fs, ps, limit, failed}, InvalidMapping{record}, late))
    case _ s r: fault(s, InvalidMapping{r}, late)

def updated(result: State & Notice, rev: List<&2, Notice>, again: State -> List<&2, Notice> -> Step) -> Step:
  (state, notice) = result
  again(state, Con{notice, rev})

def event(+notice: Session.Notice, +previous: Session.State, state: State, rev: List<&2, Notice>, again: State -> List<&2, Notice> -> Step) -> Step:
  match notice:
    case Session.Attempt{A.Transaction{Some{+record}, Tx.Finished{_, Reliable.Received{Response.Success{mapped}, _}}}}:
      updated(successful(attempt(previous, record), state, record, mapped, False{}), rev, again)
    case Session.Attempt{A.Transaction{Some{+record}, Tx.LateResponse{_, Response.Success{mapped}, _}}}:
      updated(successful(attempt(previous, record), state, record, mapped, True{}), rev, again)
    case _: again(state, rev)

def events(values: List<&2, Session.Notice>, +previous: Session.State, state: State, rev: List<&2, Notice>, +all: List<&2, Session.Notice>) -> Step:
  match values:
    case Nil{}: Step{state, all, List.reverse(&2, Notice, rev)}
    case Con{head, tail}: event(head, previous, state, rev, s => r => events(tail, previous, s, r, all))

def advance(step: Session.Step, old: State) -> Step:
  match step old:
    case Session.Step{+s, +notices} State{previous, ls, fs, ps, limit, failed}:
      events(notices, previous, State{s, ls, fs, rerank(ps, Roles.controlling(role(s)), []), limit, failed}, [], notices)

def maybe_advance(step: Maybe<&2, Session.Step>, old: State) -> Maybe<&2, Step>:
  match step:
    case None{}: None{}
    case Some{s}: Some{advance(s, old)}

def create(session: Session.State, +limit: U32) -> Maybe<&2, State>:
  Bool.pick(Maybe<&2, State>, Bool.and(U32.is_le(1, limit), U32.is_le(limit, 256)), Some{State{session, [], [], [], limit, False{}}}, None{})

def from_session(value: Maybe<&2, Session.State>, limit: U32) -> Maybe<&2, State>:
  match value:
    case None{}: None{}
    case Some{s}: create(s, limit)

def bind(+state: State, credentials: Ice.Credentials) -> Maybe<&2, Step>:
  match state:
    case State{_, _, _, _, _, True{}}: None{}
    case _: maybe_advance(Session.bind(core(state), credentials), state)

def start(+state: State, tx: List<&2, U32>, policy: Retry.Policy, now: Nat) -> Step:
  match state:
    case State{_, _, _, _, _, True{}}: Step{state, [], []}
    case _: advance(Session.start(core(state), tx, policy, now), state)

def receive(+state: State, reference: Pairs.Ref, raw: List<&2, U32>, now: Nat) -> Step:
  match state:
    case State{_, _, _, _, _, True{}}: Step{state, [], []}
    case _: advance(Session.receive(core(state), reference, raw, now), state)

def tick(+state: State, now: Nat) -> Step:
  match state:
    case State{_, _, _, _, _, True{}}: Step{state, [], []}
    case _: advance(Session.tick(core(state), now), state)

def failed(+state: State, token: U32, code: U32) -> Step:
  advance(Session.failed(core(state), token, code), state)

def repair(+state: State, token: U32, generation: U32, high: U32, low: U32) -> Maybe<&2, Step>:
  match state:
    case State{_, _, _, _, _, True{}}: None{}
    case _: maybe_advance(Session.repair(core(state), token, generation, high, low), state)

def acknowledge(+state: State, notice: Session.Notice, now: Nat) -> Step:
  advance(Session.acknowledge(core(state), notice, now), state)

def drain(+state: State) -> Step:
  match state:
    case State{_, _, _, _, _, True{}}: Step{state, [], []}
    case _: advance(Session.drain(core(state)), state)

def current_send(state: State, notice: Session.Notice) -> Bool:
  match state:
    case State{s, _, _, _, _, faulted}: Bool.and(Bool.not(faulted), Session.current_send(s, notice))

def timeout(state: State, now: Nat, cap: U32) -> U32:
  Session.timeout(core(state), now, cap)
