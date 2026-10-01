import Base
import ./ice_transactions.bend as Tx
import ./ice_attempts.bend as A
import ./ice_registry.bend as R
import ./ice_scheduler.bend as S
import ./ice_checklist.bend as Check
import ./ice_pairs.bend as Pairs
import ./ice_binding.bend as Ice
import ./ice_incoming.bend as Incoming
import ./ice_candidates.bend as C
import ./stun.bend as Stun
import ./stun_auth.bend as Auth
import ./stun_retry.bend as Retry

type Pending is Data:
  Pending{reference: Pairs.Ref, request: Incoming.Request}

type State is Data:
  State{attempts: A.State, registry: R.State, secret: Incoming.Secret,
        peer: Maybe<&2, Ice.Credentials>, pending: List<&2, Pending>, mode: Auth.Mode}

type Notice is Data:
  Attempt{event: A.Notice}
  Datagram{reference: Pairs.Ref, bytes: List<&2, U32>}
  Reply{reference: Pairs.Ref, bytes: List<&2, U32>, code: U32}
  Accepted{reference: Pairs.Ref, request: Incoming.Request, switched: Bool}
  Applied{reference: Pairs.Ref}
  Deferred{reference: Pairs.Ref, overloaded: Bool}
  Unbound{reference: Pairs.Ref}
  WaitingCredentials{}
  Invalid{}

type Step is Data:
  Step{state: State, events: List<&2, Notice>}

def registry_limit(registry: R.State) -> U32:
  match registry:
    case R.State{_, _, _, limit}: limit

def fragment(request: Incoming.Request) -> String:
  match request:
    case Incoming.Request{_, remote, _, _, _, _}: remote

def peer_matches(peer: Maybe<&2, Ice.Credentials>, request: Incoming.Request) -> Bool:
  match peer:
    case None{}: True{}
    case Some{Ice.Credentials{_, remote, _}}: String.eq(remote, fragment(request))

def pending_same(a: Pending, b: Pending) -> Bool:
  match a b:
    case Pending{ar, aq} Pending{br, bq}: Bool.and(Pairs.same(ar, br), String.eq(fragment(aq), fragment(bq)))

def pending_exists(values: List<&2, Pending>, +wanted: Pending, found: Bool) -> Bool:
  match values:
    case Nil{}: found
    case Con{head, tail}: pending_exists(tail, wanted, Bool.or(found, pending_same(head, wanted)))

def merged(+old: Pending, +new: Pending) -> Pending:
  match old new:
    case Pending{+r, Incoming.Request{+tx, +f, +p, +role, +nominate, +algorithm}}
         Pending{+nr, Incoming.Request{+ntx, +nf, +np, +nrole, +other, +nalgorithm}}:
      # Preserve an actually authenticated nomination request, not a synthetic
      # combination of a controlled request's role and another request's flag.
      Bool.pick(Pending, Bool.and(Bool.not(nominate), other),
        Pending{nr, Incoming.Request{ntx, nf, np, nrole, other, nalgorithm}},
        Pending{r, Incoming.Request{tx, f, p, role, nominate, algorithm}})

def pending_merge(values: List<&2, Pending>, +wanted: Pending, found: Bool, +rev: List<&2, Pending>) -> List<&2, Pending>:
  match values:
    case Nil{}:
      Bool.pick(List<&2, Pending>, found, List.reverse(&2, Pending, rev), List.reverse(&2, Pending, Con{wanted, rev}))
    case Con{+head, tail}:
      pending_merge(tail, wanted, Bool.or(found, pending_same(head, wanted)),
        Con{Bool.pick(Pending, pending_same(head, wanted), merged(head, wanted), head), rev})

def wrapped(values: List<&2, A.Notice>, rev: List<&2, Notice>) -> List<&2, Notice>:
  match values:
    case Nil{}: List.reverse(&2, Notice, rev)
    case Con{head, tail}: wrapped(tail, Con{Attempt{head}, rev})

def attempt_step(step: A.Step, registry: R.State, secret: Incoming.Secret, peer: Maybe<&2, Ice.Credentials>,
                 pending: List<&2, Pending>, mode: Auth.Mode) -> Step:
  match step:
    case A.Step{a, events}: Step{State{a, registry, secret, peer, pending, mode}, wrapped(events, [])}

def attempt_maybe(step: Maybe<&2, A.Step>, registry: R.State, secret: Incoming.Secret, peer: Maybe<&2, Ice.Credentials>,
                  pending: List<&2, Pending>, mode: Auth.Mode) -> Maybe<&2, Step>:
  match step:
    case None{}: None{}
    case Some{s}: Some{attempt_step(s, registry, secret, peer, pending, mode)}

# Only an authenticated current result may complete a mapped checklist pair.
# Pending incoming requests and signaled candidate metadata remain intact.
def validated(state: State, mapped: Pairs.Ref, generation: U32) -> Maybe<&2, Step>:
  match state:
    case State{a, registry, secret, peer, pending, mode}:
      attempt_maybe(A.validated(a, mapped, generation), registry, secret, peer, pending, mode)

def invalidated(state: State, mapped: Pairs.Ref, generation: U32) -> Maybe<&2, Step>:
  match state:
    case State{a, registry, secret, peer, pending, mode}:
      attempt_maybe(A.invalidated(a, mapped, generation), registry, secret, peer, pending, mode)

def queue_nomination(state: State, reference: Pairs.Ref, generation: U32) -> Maybe<&2, Step>:
  match state:
    case State{a, registry, secret, Some{peer}, pending, mode}:
      attempt_maybe(A.queue_nomination(a, reference, generation), registry, secret, Some{peer}, pending, mode)
    case _: None{}

def component_pending(values: List<&2, Pending>, +id: U32, +component: U32, +rev: List<&2, Pending>) -> List<&2, Pending>:
  match values:
    case Nil{}: List.reverse(&2, Pending, rev)
    case Con{Pending{+ref, +request}, tail}:
      component_pending(tail, id, component, Bool.pick(List<&2, Pending>, S.component_ref(ref, id, component), rev,
        Con{Pending{ref, request}, rev}))

def conclude(state: State, +id: U32, +component: U32, generation: U32) -> Maybe<&2, Step>:
  match state:
    case State{a, registry, secret, peer, pending, mode}:
      attempt_maybe(A.conclude(a, id, component, generation), registry, secret, peer, component_pending(pending, id, component, []), mode)

def materialized(step: Maybe<&2, A.Step>, registry: R.State, secret: Incoming.Secret, peer: Maybe<&2, Ice.Credentials>, mode: Auth.Mode,
                 +reference: Pairs.Ref) -> Maybe<&2, Step>:
  match step:
    case None{}: None{}
    case Some{A.Step{a, events}}: Some{Step{State{a, registry, secret, peer, [], mode},
      Con{Applied{reference}, wrapped(events, [])}}}

def learned(value: Maybe<&2, R.Learned>, state: State, +id: U32, local: C.Local, reference: Pairs.Ref) -> Maybe<&2, Step>:
  match value state:
    case None{} _: None{}
    case Some{R.Learned{registry, candidate}} State{a, _, secret, peer, _, mode}:
      materialized(A.insert_triggered(a, id, local, candidate), registry, secret, peer, mode, reference)

def observed(local: Maybe<&2, C.Local>, pending: Pending, state: State) -> Maybe<&2, Step>:
  match local pending state:
    case Some{l} Pending{Pairs.Ref{+id, +component, +base, +source}, Incoming.Request{_, _, priority, _, _, _}}
                   State{+a, +registry, +secret, +peer, +waiting, +mode}:
      learned(R.learn(registry, id, component, priority, source), State{a, registry, secret, peer, waiting, mode}, id, l, Pairs.Ref{id, component, base, source})
    case _ _ _: None{}

def materialize(+pending: Pending, state: State) -> Maybe<&2, Step>:
  match pending state:
    case Pending{Pairs.Ref{+id, +component, +base, +source}, +request} State{+a, R.State{+streams, +next, +count, +limit}, +secret, +peer, +waiting, +mode}:
      observed(R.local(streams, id, component, base), Pending{Pairs.Ref{id, component, base, source}, request},
        State{a, R.State{streams, next, count, limit}, secret, peer, waiting, mode})

def pending_reference(pending: Pending) -> Pairs.Ref:
  match pending:
    case Pending{reference, _}: reference

def drained_step(result: Maybe<&2, Step>, +old: State, +wanted: Pending, rev: List<&2, Pending>, events: List<&2, Notice>,
                 again: State -> List<&2, Pending> -> List<&2, Notice> -> Step) -> Step:
  match result:
    case None{}: again(old, Con{wanted, rev}, Con{Deferred{pending_reference(wanted), False{}}, events})
    case Some{Step{state, notices}}: again(state, rev, List.reverse.go(&2, Notice, notices, events))

def drain_bound(ok: Bool, +state: State, +wanted: Pending, rev: List<&2, Pending>, events: List<&2, Notice>,
                again: State -> List<&2, Pending> -> List<&2, Notice> -> Step) -> Step:
  match ok wanted:
    case False{} Pending{r, _}: again(state, rev, Con{Unbound{r}, events})
    case True{} p: drained_step(materialize(p, state), state, p, rev, events, again)

def pending_request(pending: Pending) -> Incoming.Request:
  match pending:
    case Pending{_, request}: request

def drain_go(fuel: Nat, values: List<&2, Pending>, state: State, rev: List<&2, Pending>, events: List<&2, Notice>) -> Step:
  match fuel values state:
    case _ Nil{} State{a, registry, secret, peer, _, mode}:
      Step{State{a, registry, secret, peer, List.reverse(&2, Pending, rev), mode}, List.reverse(&2, Notice, events)}
    case 0n rest State{a, registry, secret, peer, _, mode}:
      Step{State{a, registry, secret, peer, List.reverse.go(&2, Pending, rev, rest), mode}, List.reverse(&2, Notice, Con{Invalid{}, events})}
    case 1n+p Con{+head, tail} State{+a, +registry, +secret, +peer, +waiting, +mode}:
      drain_bound(peer_matches(peer, pending_request(head)), State{a, registry, secret, peer, waiting, mode}, head, rev, events,
        s => r => es => drain_go(p, tail, s, r, es))

def drain(+state: State) -> Step:
  match state:
    case State{a, registry, secret, None{}, pending, mode}: Step{State{a, registry, secret, None{}, pending, mode}, []}
    case State{+a, +registry, +secret, Some{+peer}, +pending, +mode}:
      drain_go(257n, pending, State{a, registry, secret, Some{peer}, [], mode}, [], [])

def prefixed(step: Step, prefix: List<&2, Notice>) -> Step:
  match step:
    case Step{state, events}: Step{state, List.reverse.go(&2, Notice, List.reverse(&2, Notice, prefix), events)}

def enqueue_allowed(ok: Bool, state: State, +wanted: Pending, prefix: List<&2, Notice>) -> Step:
  match ok state wanted:
    case False{} s Pending{r, _}: Step{s, List.reverse.go(&2, Notice, List.reverse(&2, Notice, prefix), [Deferred{r, True{}}])}
    case True{} State{a, registry, secret, +peer, waiting, mode} Pending{+r, +q}:
      prefixed(drain(State{a, registry, secret, peer, pending_merge(waiting, Pending{r, q}, False{}, []), mode}),
        List.reverse.go(&2, Notice, List.reverse(&2, Notice, prefix), Bool.pick(List<&2, Notice>, Maybe.is_some(&2, Ice.Credentials, peer), [], [Deferred{r, False{}}])))

def enqueue(+state: State, +wanted: Pending, prefix: List<&2, Notice>) -> Step:
  match state:
    case State{+a, +registry, +secret, +peer, +waiting, +mode}:
      enqueue_allowed(Bool.or(pending_exists(waiting, wanted, False{}), Nat.is_lt(List.length(&2, Pending, waiting), U32.to_nat(registry_limit(registry)))),
        State{a, registry, secret, peer, waiting, mode}, wanted, prefix)

def accepted_role(value: Maybe<&2, A.State>, old: State, +reference: Pairs.Ref, +request: Incoming.Request,
                  reply: List<&2, U32>, switched: Bool) -> Step:
  match value old:
    case None{} s: Step{s, [Invalid{}]}
    case Some{a} State{_, registry, secret, peer, pending, mode}:
      enqueue(State{a, registry, secret, peer, pending, mode}, Pending{reference, request},
        [Reply{reference, reply, 0}, Accepted{reference, request, switched}])

def accepted_bound(ok: Bool, +state: State, +reference: Pairs.Ref, request: Incoming.Request, reply: List<&2, U32>, role: Ice.Role, switched: Bool) -> Step:
  match ok state:
    case False{} s: Step{s, [Reply{reference, reply, 0}, Unbound{reference}]}
    case True{} State{+a, +registry, +secret, +peer, +pending, +mode}:
      accepted_role(A.switch_role(a, role), State{a, registry, secret, peer, pending, mode}, reference, request, reply, switched)

def incoming(decision: Incoming.Decision, +state: State, +reference: Pairs.Ref) -> Step:
  match decision state:
    case Incoming.Accepted{reply, +request, role, switched} State{+a, +registry, +secret, +peer, +pending, +mode}:
      accepted_bound(peer_matches(peer, request), State{a, registry, secret, peer, pending, mode}, reference, request, reply, role, switched)
    case Incoming.Rejected{reply, code, _} s: Step{s, [Reply{reference, reply, code}]}
    case Incoming.Ignored{} s: Step{s, []}
    case Incoming.InvalidInput{} s: Step{s, [Invalid{}]}

def role(attempts: A.State) -> Ice.Role:
  match attempts:
    case A.State{S.State{_, _, _, r, _, _, _, _}, _, _, +policies}: r

def receive_events(values: List<&2, A.Notice>, +reference: Pairs.Ref, rev: List<&2, Notice>) -> List<&2, Notice>:
  match values:
    case Nil{}: List.reverse(&2, Notice, rev)
    case Con{A.Transaction{_, Tx.Datagram{_, _, raw}}, tail}:
      receive_events(tail, reference, Con{Datagram{reference, raw}, rev})
    case Con{event, tail}: receive_events(tail, reference, Con{Attempt{event}, rev})

def receive_step(step: A.Step, registry: R.State, secret: Incoming.Secret, peer: Maybe<&2, Ice.Credentials>,
                 pending: List<&2, Pending>, mode: Auth.Mode, reference: Pairs.Ref) -> Step:
  match step:
    case A.Step{a, events}: Step{State{a, registry, secret, peer, pending, mode}, receive_events(events, reference, [])}

def received_kind(kind: U32, +state: State, +reference: Pairs.Ref, +raw: List<&2, U32>, now: Nat) -> Step:
  match kind state reference:
    case 1 State{+a, +registry, +secret, +peer, +pending, +mode} Pairs.Ref{+id, +component, +base, +source}:
      incoming(Incoming.receive(raw, secret, role(a), source), State{a, registry, secret, peer, pending, mode}, Pairs.Ref{id, component, base, source})
    case _ State{a, registry, secret, peer, pending, mode} +r:
      receive_step(A.receive(a, r, raw, now), registry, secret, peer, pending, mode, r)

def received_packet(packet: Maybe<&2, Stun.Packet>, state: State, reference: Pairs.Ref, raw: List<&2, U32>, now: Nat) -> Step:
  match packet:
    case Some{Stun.Packet{kind, _, _}}: received_kind(kind, state, reference, raw, now)
    case None{}: received_kind(0, state, reference, raw, now)

def received_local(local: Maybe<&2, C.Local>, +state: State, reference: Pairs.Ref, +raw: List<&2, U32>, now: Nat) -> Step:
  match local:
    case None{}: Step{state, [Invalid{}]}
    case Some{_}: received_packet(Stun.parse(raw), state, reference, raw, now)

# A one-peer ICE generation. The IO owner provides the actual registered local
# base and observed OS/relay source, not addresses copied from STUN attributes.
def receive(state: State, +reference: Pairs.Ref, raw: List<&2, U32>, now: Nat) -> Step:
  match state reference:
    case State{a, R.State{+streams, next, count, limit}, secret, peer, pending, mode} Pairs.Ref{+id, +component, +base, +source}:
      received_local(Bool.pick(Maybe<&2, C.Local>, C.address_valid(source), R.local(streams, id, component, base), None{}),
        State{a, R.State{streams, next, count, limit}, secret, peer, pending, mode}, Pairs.Ref{id, component, base, source}, raw, now)

# Concluded components still serve authenticated Binding requests. Admission of
# a new nomination is decided by the lifecycle owner before a success is sent;
# this path never learns candidates, enqueues checks or restores removed pairs.
def reply_role(value: Maybe<&2, A.State>, old: State, +reference: Pairs.Ref, request: Incoming.Request,
               reply: List<&2, U32>, switched: Bool) -> Step:
  match value old:
    case Some{a} State{_, registry, secret, peer, pending, mode}:
      Step{State{a, registry, secret, peer, pending, mode}, [Reply{reference, reply, 0}, Accepted{reference, request, switched}]}
    case _ s: Step{s, [Invalid{}]}

def reply_admitted(ok: Bool, +state: State, +reference: Pairs.Ref, +request: Incoming.Request,
                   reply: List<&2, U32>, role: Ice.Role, switched: Bool) -> Step:
  match ok state request:
    case True{} State{+a, registry, secret, peer, pending, mode} q:
      reply_role(A.switch_role(a, role), State{a, registry, secret, peer, pending, mode}, reference, q, reply, switched)
    case False{} State{a, registry, +secret, peer, pending, mode} Incoming.Request{tx, _, _, _, _, algorithm}:
      incoming(Incoming.reject(tx, 400, [], Incoming.Protected{Incoming.key(secret), algorithm}),
        State{a, registry, secret, peer, pending, mode}, reference)

def reply_bound(ok: Bool, +state: State, +reference: Pairs.Ref, +request: Incoming.Request,
                reply: List<&2, U32>, role: Ice.Role, switched: Bool, allow_nomination: Bool) -> Step:
  match ok request:
    case False{} _: Step{state, [Reply{reference, reply, 0}, Unbound{reference}]}
    case True{} Incoming.Request{tx, remote, priority, sent_role, +nominate, algorithm}:
      reply_admitted(Bool.or(Bool.not(nominate), allow_nomination), state, reference,
        Incoming.Request{tx, remote, priority, sent_role, nominate, algorithm}, reply, role, switched)

def reply_decision(decision: Incoming.Decision, +state: State, +reference: Pairs.Ref, allow_nomination: Bool) -> Step:
  match decision state:
    case Incoming.Accepted{reply, +request, role, switched} State{+a, +registry, +secret, +peer, +pending, +mode}:
      reply_bound(peer_matches(peer, request), State{a, registry, secret, peer, pending, mode}, reference, request, reply, role, switched, allow_nomination)
    case d s: incoming(d, s, reference)

def reply_packet(packet: Maybe<&2, Stun.Packet>, +state: State, +reference: Pairs.Ref, +raw: List<&2, U32>, now: Nat, allow_nomination: Bool) -> Step:
  match packet state reference:
    case Some{Stun.Packet{1, _, _}} State{+a, registry, +secret, peer, pending, mode} Pairs.Ref{+id, +component, +base, +source}:
      reply_decision(Incoming.receive(raw, secret, role(a), source), State{a, registry, secret, peer, pending, mode},
        Pairs.Ref{id, component, base, source}, allow_nomination)
    case _ s r: receive(s, r, raw, now)

def reply_local(local: Maybe<&2, C.Local>, +state: State, reference: Pairs.Ref, +raw: List<&2, U32>, now: Nat, allow_nomination: Bool) -> Step:
  match local:
    case None{}: Step{state, [Invalid{}]}
    case Some{_}: reply_packet(Stun.parse(raw), state, reference, raw, now, allow_nomination)

def reply_only(state: State, +reference: Pairs.Ref, raw: List<&2, U32>, now: Nat, allow_nomination: Bool) -> Step:
  match state reference:
    case State{a, R.State{+streams, next, count, limit}, secret, peer, pending, mode} Pairs.Ref{+id, +component, +base, +source}:
      reply_local(Bool.pick(Maybe<&2, C.Local>, C.address_valid(source), R.local(streams, id, component, base), None{}),
        State{a, R.State{streams, next, count, limit}, secret, peer, pending, mode}, Pairs.Ref{id, component, base, source}, raw, now, allow_nomination)

def peer_same(peer: Maybe<&2, Ice.Credentials>, +credentials: Ice.Credentials) -> Bool:
  match peer credentials:
    case None{} _: True{}
    case Some{Ice.Credentials{a, b, c}} Ice.Credentials{d, e, f}: Bool.and(String.eq(a, d), Bool.and(String.eq(b, e), String.eq(c, f)))

def bind_valid(ok: Bool, state: State, credentials: Ice.Credentials) -> Maybe<&2, Step>:
  match ok state:
    case False{} _: None{}
    case True{} State{a, registry, secret, _, pending, mode}: Some{drain(State{a, registry, secret, Some{credentials}, pending, mode})}

def bind(state: State, +credentials: Ice.Credentials) -> Maybe<&2, Step>:
  match state credentials:
    case State{a, registry, Incoming.Secret{+fragment, +password}, +peer, pending, mode} Ice.Credentials{+local, +remote, +key}:
      bind_valid(Bool.and(Ice.valid(Ice.Credentials{local, remote, key}), Bool.and(String.eq(fragment, local), peer_same(peer, Ice.Credentials{local, remote, key}))),
        State{a, registry, Incoming.Secret{fragment, password}, peer, pending, mode}, Ice.Credentials{local, remote, key})

def starting_priority(priority: Maybe<&2, U32>, state: State, transaction: List<&2, U32>, policy: Retry.Policy, now: Nat) -> Step:
  match priority state:
    case Some{p} State{a, registry, secret, Some{+peer}, pending, +mode}:
      attempt_step(A.start(a, transaction, policy, peer, p, mode, now), registry, secret, Some{peer}, pending, mode)
    case _ s: Step{s, [Invalid{}]}

def selected_local(local: Maybe<&2, C.Local>, state: State, transaction: List<&2, U32>, policy: Retry.Policy, now: Nat) -> Step:
  match local:
    case Some{l}: starting_priority(R.priority(l), state, transaction, policy, now)
    case None{}: Step{state, [Invalid{}]}

def starting_choice(choice: S.Choice, state: State, transaction: List<&2, U32>, policy: Retry.Policy, now: Nat) -> Step:
  match choice state:
    case S.Selected{_, Pairs.Ref{id, component, base, _}, _, _} State{a, R.State{+streams, next, count, limit}, secret, peer, pending, mode}:
      selected_local(R.local(streams, id, component, base), State{a, R.State{streams, next, count, limit}, secret, peer, pending, mode}, transaction, policy, now)
    case S.Idle{schedule} State{A.State{_, engine, records, +policies}, registry, secret, peer, pending, mode}:
      Step{State{A.State{schedule, engine, records, policies}, registry, secret, peer, pending, mode}, [Attempt{A.Idle{}}]}
    case _ s: Step{s, [Invalid{}]}

def start_drained(step: Step, transaction: List<&2, U32>, policy: Retry.Policy, now: Nat) -> Step:
  match step:
    case Step{State{A.State{+schedule, engine, records, +policies}, registry, secret, peer, pending, mode}, prefix}:
      prefixed(starting_choice(S.select(schedule), State{A.State{schedule, engine, records, policies}, registry, secret, peer, pending, mode}, transaction, policy, now), prefix)

# Fresh transaction IDs come from host RNG; retry bytes remain cached by Tx.
def start(+state: State, transaction: List<&2, U32>, policy: Retry.Policy, now: Nat) -> Step:
  match state:
    case State{a, registry, secret, None{}, pending, mode}: Step{State{a, registry, secret, None{}, pending, mode}, [WaitingCredentials{}]}
    case State{a, registry, secret, Some{peer}, pending, mode}:
      start_drained(drain(State{a, registry, secret, Some{peer}, pending, mode}), transaction, policy, now)

def nomination_selected(target: Maybe<&2, Pairs.Ref>, selected: Pairs.Ref) -> Bool:
  match target:
    case None{}: False{}
    case Some{r}: Pairs.same(r, selected)

def intent_priority(priority: Maybe<&2, U32>, state: State, transaction: List<&2, U32>, policy: Retry.Policy, nominate: Bool, now: Nat) -> Step:
  match priority state:
    case Some{p} State{a, registry, secret, Some{+peer}, pending, +mode}:
      attempt_step(A.start_intent(a, transaction, policy, peer, p, nominate, mode, now), registry, secret, Some{peer}, pending, mode)
    case _ s: Step{s, [Invalid{}]}

def intent_local(local: Maybe<&2, C.Local>, state: State, transaction: List<&2, U32>, policy: Retry.Policy, nominate: Bool, now: Nat) -> Step:
  match local:
    case Some{l}: intent_priority(R.priority(l), state, transaction, policy, nominate, now)
    case None{}: Step{state, [Invalid{}]}

def intent_choice(choice: S.Choice, state: State, transaction: List<&2, U32>, policy: Retry.Policy, target: Maybe<&2, Pairs.Ref>, now: Nat) -> Step:
  match choice state:
    case S.Selected{_, Pairs.Ref{+id, +component, +base, +remote}, _, _} State{a, R.State{+ss, next, count, limit}, secret, peer, pending, mode}:
      intent_local(R.local(ss, id, component, base), State{a, R.State{ss, next, count, limit}, secret, peer, pending, mode}, transaction, policy,
        nomination_selected(target, Pairs.Ref{id, component, base, remote}), now)
    case S.Idle{schedule} State{A.State{_, engine, records, +policies}, registry, secret, peer, pending, mode}:
      Step{State{A.State{schedule, engine, records, policies}, registry, secret, peer, pending, mode}, [Attempt{A.Idle{}}]}
    case _ s: Step{s, [Invalid{}]}

def intent_drained(step: Step, transaction: List<&2, U32>, policy: Retry.Policy, target: Maybe<&2, Pairs.Ref>, now: Nat) -> Step:
  match step:
    case Step{State{A.State{+s, engine, records, +policies}, registry, secret, peer, pending, mode}, prefix}:
      prefixed(intent_choice(S.select(s), State{A.State{s, engine, records, policies}, registry, secret, peer, pending, mode}, transaction, policy, target, now), prefix)

# Intent is bound to the actual selected reference after deferred work drains.
# Other selected pairs still send ordinary checks, without USE-CANDIDATE.
def start_intent(state: State, transaction: List<&2, U32>, policy: Retry.Policy, target: Maybe<&2, Pairs.Ref>, now: Nat) -> Step:
  match state:
    case State{a, registry, secret, None{}, pending, mode}: Step{State{a, registry, secret, None{}, pending, mode}, [WaitingCredentials{}]}
    case State{a, registry, secret, Some{peer}, pending, mode}:
      intent_drained(drain(State{a, registry, secret, Some{peer}, pending, mode}), transaction, policy, target, now)

# Multiple components/streams can have a queued regular nomination. Bind the
# flag to whichever reference actually wins after deferred work drains.
def intents_choice(choice: S.Choice, state: State, transaction: List<&2, U32>, policy: Retry.Policy, targets: List<&2, Pairs.Ref>, now: Nat) -> Step:
  match choice state:
    case S.Selected{_, Pairs.Ref{+id, +component, +base, +remote}, _, _} State{a, R.State{+ss, next, count, limit}, secret, peer, pending, mode}:
      intent_local(R.local(ss, id, component, base), State{a, R.State{ss, next, count, limit}, secret, peer, pending, mode}, transaction, policy,
        S.contains(targets, Pairs.Ref{id, component, base, remote}, False{}), now)
    case S.Idle{schedule} State{A.State{_, engine, records, +policies}, registry, secret, peer, pending, mode}:
      Step{State{A.State{schedule, engine, records, policies}, registry, secret, peer, pending, mode}, [Attempt{A.Idle{}}]}
    case _ s: Step{s, [Invalid{}]}

def intents_drained(step: Step, transaction: List<&2, U32>, policy: Retry.Policy, targets: List<&2, Pairs.Ref>, now: Nat) -> Step:
  match step:
    case Step{State{A.State{+s, engine, records, +policies}, registry, secret, peer, pending, mode}, prefix}:
      prefixed(intents_choice(S.select(s), State{A.State{s, engine, records, policies}, registry, secret, peer, pending, mode}, transaction, policy, targets, now), prefix)

def start_intents(state: State, transaction: List<&2, U32>, policy: Retry.Policy, targets: List<&2, Pairs.Ref>, now: Nat) -> Step:
  match state:
    case State{a, registry, secret, None{}, pending, mode}: Step{State{a, registry, secret, None{}, pending, mode}, [WaitingCredentials{}]}
    case State{a, registry, secret, Some{peer}, pending, mode}:
      intents_drained(drain(State{a, registry, secret, Some{peer}, pending, mode}), transaction, policy, targets, now)

def tick(state: State, now: Nat) -> Step:
  match state:
    case State{a, registry, secret, peer, pending, mode}: attempt_step(A.tick(a, now), registry, secret, peer, pending, mode)

def failed(state: State, token: U32, code: U32) -> Step:
  match state:
    case State{a, registry, secret, peer, pending, mode}: attempt_step(A.failed(a, token, code), registry, secret, peer, pending, mode)

def repair(state: State, token: U32, generation: U32, high: U32, low: U32) -> Maybe<&2, Step>:
  match state:
    case State{a, registry, secret, peer, pending, mode}: attempt_maybe(A.repair(a, token, generation, high, low), registry, secret, peer, pending, mode)

def current_send(state: State, notice: Notice) -> Bool:
  match state notice:
    case State{a, _, _, _, _, _} Attempt{event}: A.current_send(a, event)
    case _ _: False{}

def acknowledge(state: State, notice: Notice, now: Nat) -> Step:
  match state notice:
    case State{a, registry, secret, peer, pending, mode} Attempt{event}:
      attempt_step(A.acknowledge(a, event, now), registry, secret, peer, pending, mode)
    case s _: Step{s, []}

def timeout(state: State, now: Nat, cap: U32) -> U32:
  match state:
    case State{a, _, _, _, _, _}: A.timeout(a, now, cap)

def created_attempts(value: Maybe<&2, A.State>, registry: R.State, secret: Incoming.Secret, mode: Auth.Mode) -> Maybe<&2, State>:
  match value:
    case None{}: None{}
    case Some{a}: Some{State{a, registry, secret, None{}, [], mode}}

def created_schedule(value: Maybe<&2, S.State>, streams: List<&2, Check.Stream>, secret: Incoming.Secret, mode: Auth.Mode, limit: U32, capacity: U32) -> Maybe<&2, State>:
  match value:
    case None{}: None{}
    case Some{s}: created_attempts(A.create(s, 50, capacity), R.State{streams, 0n, 0n, limit}, secret, mode)

def create_valid(ok: Bool, +streams: List<&2, Check.Stream>, role: Ice.Role, secret: Incoming.Secret, mode: Auth.Mode,
                 +limit: U32, capacity: U32, generation: U32) -> Maybe<&2, State>:
  match ok:
    case False{}: None{}
    case True{}: created_schedule(S.create(streams, role, limit, generation), streams, secret, mode, limit, capacity)

# Default Ta=50 ms, recommended peer-reflexive type preference 110. Alternate
# priority/Ta policies, forking, nomination and terminal states are later work.
def create(+streams: List<&2, Check.Stream>, role: Ice.Role, +secret: Incoming.Secret, mode: Auth.Mode,
           limit: U32, capacity: U32, generation: U32) -> Maybe<&2, State>:
  create_valid(Bool.and(Incoming.secret_valid(secret), R.valid(streams, True{})), streams, role, secret, mode, limit, capacity, generation)
