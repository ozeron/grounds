import Base
import ./ice_binding.bend as Ice
import ./ice_candidates.bend as C
import ./ice_pairs.bend as Pairs
import ./ice_response.bend as Response
import ./ice_transactions.bend as Tx
import ./stun.bend as Stun
import ./stun_auth.bend as Auth

# One selected UDP/IPv4 transport, owned by trusted protocol code. Selection
# alone never grants consent: a fresh authenticated round trip is required.
# The enclosing socket owner shares its send gate with ICE and other paths.
type Route is Data:
  Route{reference: Pairs.Ref, generation: U32, credentials: Ice.Credentials, check: Ice.Check, mode: Auth.Mode}

type Status is Data:
  Awaiting{}
  Granted{}
  Expired{}
  Revoked{}
  Closed{}

type Clock is Data:
  Clock{status: Status, expires: Nat, next: Nat, rto: U32, mean: Nat, variation: Nat}

type Probe is Data:
  Probe{token: U32, transaction: List<&2, U32>, bytes: List<&2, U32>, mode: Auth.Mode, sent: Maybe<&2, Nat>, deadline: Nat, interval: U32}

type State is Data:
  State{route: Route, clock: Clock, probes: List<&2, Probe>, recent: List<&2, List<&2, U32>>, next_token: Nat}

type Notice is Data:
  Send{reference: Pairs.Ref, generation: U32, token: U32, bytes: List<&2, U32>}
  Sent{token: U32}
  Renewed{token: U32, expires: Nat}
  TimedOut{token: U32}
  Error{token: U32, code: U32}
  Invalid{token: U32}
  TransportError{token: U32, code: U32}
  Changed{status: Status}

type Step is Data:
  Step{state: State, events: List<&2, Notice>}

type Start is Data:
  Ready{step: Step}
  Later{step: Step, at: Nat}
  Rejected{step: Step}

def live(status: Status) -> Bool:
  match status:
    case Awaiting{}: True{}
    case Granted{}: True{}
    case _: False{}

def reference_valid(reference: Pairs.Ref) -> Bool:
  match reference:
    case Pairs.Ref{+id, +component, base, peer}:
      Bool.and(Bool.and(U32.is_le(1, id), U32.is_le(id, 65535)),
        Bool.and(Bool.and(U32.is_le(1, component), U32.is_le(component, 256)),
          Bool.and(C.address_valid(base), C.address_valid(peer))))

def created(ok: Bool, route: Route, rto: U32, +now: Nat) -> Maybe<&2, State>:
  match ok:
    case False{}: None{}
    case True{}: Some{State{route, Clock{Awaiting{}, Nat.add(now, 30000n), now, rto, 0n, 0n}, [], [], 1n}}

# Initial RTO is an owner estimate, bounded like the existing STUN usage.
# Successful samples update it with SRTT + 4*RTTVAR, floored at 500 ms.
def create(+route: Route, +rto: U32, now: Nat) -> Maybe<&2, State>:
  match route:
    case Route{+reference, generation, +credentials, +check, mode}:
      created(Bool.and(Bool.and(reference_valid(reference), Ice.valid(credentials)),
        Bool.and(Ice.priority_ok(check), Bool.and(U32.is_le(500, rto), U32.is_le(rto, 60000)))),
        Route{reference, generation, credentials, check, mode}, rto, now)

def empty(state: State) -> Step:
  Step{state, []}

def ended(state: State, +status: Status) -> Step:
  match state:
    case State{route, Clock{_, expires, next, rto, mean, variation}, _, recent, token}:
      Step{State{route, Clock{status, expires, next, rto, mean, variation}, [], recent, token}, [Changed{status}]}

def aged(probes: List<&2, Probe>, +now: Nat, +kept: List<&2, Probe>, +events: List<&2, Notice>) -> List<&2, Probe> & List<&2, Notice>:
  match probes:
    case Nil{}: (List.reverse(&2, Probe, kept), List.reverse(&2, Notice, events))
    case Con{Probe{+token, +transaction, +bytes, +mode, +sent, +deadline, +interval}, tail}:
      aged(tail, now,
        Bool.pick(List<&2, Probe>, Nat.is_le(deadline, now), kept, Con{Probe{token, transaction, bytes, mode, sent, deadline, interval}, kept}),
        Bool.pick(List<&2, Notice>, Nat.is_le(deadline, now), Con{TimedOut{token}, events}, events))

def tick_aged(result: List<&2, Probe> & List<&2, Notice>, route: Route, clock: Clock, recent: List<&2, List<&2, U32>>, token: Nat) -> Step:
  (probes, events) = result
  Step{State{route, clock, probes, recent, token}, events}

def tick_due(expired: Bool, +state: State, now: Nat) -> Step:
  match expired state:
    case True{} s: ended(s, Expired{})
    case False{} State{route, clock, probes, recent, token}:
      tick_aged(aged(probes, now, [], []), route, clock, recent, token)

def tick(+state: State, +now: Nat) -> Step:
  match state:
    case State{route, Clock{+status, +expires, next, rto, mean, variation}, probes, recent, token}:
      tick_due(Bool.and(live(status), Nat.is_le(expires, now)),
        State{route, Clock{status, expires, next, rto, mean, variation}, probes, recent, token}, now)

def allowed(+state: State, reference: Pairs.Ref, generation: U32, now: Nat) -> Bool:
  match state:
    case State{Route{got, gen, _, _, _}, Clock{Granted{}, expires, _, _, _, _}, _, _, _}:
      Bool.and(Bool.and(Pairs.same(got, reference), U32.is_eq(gen, generation)), Nat.is_lt(now, expires))
    case _: False{}

def pending(probes: List<&2, Probe>) -> Bool:
  match probes:
    case Nil{}: False{}
    case Con{Probe{_, _, _, _, None{}, _, _}, _}: True{}
    case Con{_, tail}: pending(tail)

def used(recent: List<&2, List<&2, U32>>, +transaction: List<&2, U32>) -> Bool:
  match recent:
    case Nil{}: False{}
    case Con{got, tail}: Bool.or(Stun.same(got, transaction, True{}), used(tail, transaction))

def history(fuel: Nat, values: List<&2, List<&2, U32>>) -> List<&2, List<&2, U32>>:
  match fuel values:
    case 0n _: []
    case _ Nil{}: []
    case 1n+p Con{head, tail}: Con{head, history(p, tail)}

def binding_unsigned(ok: Bool, transaction: List<&2, U32>, credentials: Ice.Credentials) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}: None{}
    case True{}: Ice.unsigned_header(Stun.binding_request(transaction), Ice.attribute(6, Ice.username(credentials)))

# RFC 7675 consent is independent of ICE role and candidate priority. Retain
# the original ICE-shaped start API while exposing the role-free usage to the
# integrated selected-transport owner.
def binding_request(transaction: List<&2, U32>, +credentials: Ice.Credentials, mode: Auth.Mode) -> Maybe<&2, List<&2, U32>>:
  Ice.signed(binding_unsigned(Ice.valid(credentials), transaction, credentials), Ice.key(credentials), mode)

def admission_raw(raw: Maybe<&2, List<&2, U32>>, step: Step, +transaction: List<&2, U32>, +interval: U32, +now: Nat) -> Start:
  match raw step:
    case Some{+bytes} Step{State{Route{+ref, +gen, creds, check, +mode}, Clock{status, expires, _, +rto, mean, variation}, probes, recent, +token}, events}:
      Ready{Step{State{Route{ref, gen, creds, check, mode}, Clock{status, expires, Nat.add(now, U32.to_nat(interval)), rto, mean, variation},
        List.reverse.go(&2, Probe, List.reverse(&2, Probe, probes), [Probe{U32.from_nat(token), transaction, bytes, mode, None{}, Nat.add(now, U32.to_nat(rto)), interval}]),
        Con{transaction, history(63n, recent)}, Nat.add(token, 1n)},
        List.reverse.go(&2, Notice, List.reverse(&2, Notice, events), [Send{ref, gen, U32.from_nat(token), bytes}])}}
    case _ s: Rejected{s}

def admission_usage(ok: Bool, +step: Step, +transaction: List<&2, U32>, jitter: U32, now: Nat, binding: Bool) -> Start:
  match ok step:
    case False{} s: Rejected{s}
    case True{} Step{State{Route{ref, gen, +creds, +check, +mode}, clock, probes, recent, token}, events}:
      admission_raw(Bool.pick(Maybe<&2, List<&2, U32>>, binding, binding_request(transaction, creds, mode), Ice.request(transaction, creds, check, mode)),
        Step{State{Route{ref, gen, creds, check, mode}, clock, probes, recent, token}, events}, transaction, (4000 + jitter : U32), now)

def start_due(due: Bool, +step: Step, +transaction: List<&2, U32>, +jitter: U32, +now: Nat, at: Nat, binding: Bool) -> Start:
  match due step:
    case False{} s: Later{s, at}
    case True{} Step{State{route, clock, +probes, +recent, +token}, events}:
      admission_usage(Bool.and(Bool.and(U32.is_le(jitter, 2000), Nat.is_le(token, 4294967295n)),
        Bool.and(Bool.not(used(recent, transaction)), Bool.and(Bool.not(pending(probes)), Nat.is_lt(List.length(&2, Probe, probes), 16n)))),
        Step{State{route, clock, probes, recent, token}, events}, transaction, jitter, now, binding)

def start_live(active: Bool, +step: Step, transaction: List<&2, U32>, jitter: U32, +now: Nat, +at: Nat, binding: Bool) -> Start:
  match active:
    case False{}: Rejected{step}
    case True{}: start_due(Nat.is_le(at, now), step, transaction, jitter, now, at, binding)

def start_ticked(+step: Step, transaction: List<&2, U32>, jitter: U32, +now: Nat, not_before: Nat, binding: Bool) -> Start:
  match step:
    case Step{State{route, Clock{+status, expires, +next, rto, mean, variation}, probes, recent, token}, events}:
      +at = Tx.later(next, not_before)
      start_live(live(status),
        Step{State{route, Clock{status, expires, next, rto, mean, variation}, probes, recent, token}, events}, transaction, jitter, now, at, binding)

# Transaction and jitter must come from trusted OS CSPRNG, never signaling or
# application input. The example JSON fixture is a synthetic test seam only.
# not_before is the shared socket's actual-send pacing gate.
def start(state: State, transaction: List<&2, U32>, jitter: U32, +now: Nat, not_before: Nat) -> Start:
  start_ticked(tick(state, now), transaction, jitter, now, not_before, False{})

def start_binding(state: State, transaction: List<&2, U32>, jitter: U32, +now: Nat, not_before: Nat) -> Start:
  start_ticked(tick(state, now), transaction, jitter, now, not_before, True{})

def current_probe(probes: List<&2, Probe>, +token: U32, +bytes: List<&2, U32>, +now: Nat) -> Bool:
  match probes:
    case Nil{}: False{}
    case Con{Probe{id, _, raw, _, None{}, deadline, _}, tail}:
      Bool.or(Bool.and(Bool.and(U32.is_eq(id, token), Stun.same(bytes, raw, True{})), Nat.is_lt(now, deadline)), current_probe(tail, token, bytes, now))
    case Con{_, tail}: current_probe(tail, token, bytes, now)

def current_send(state: State, notice: Notice, +now: Nat) -> Bool:
  match state notice:
    case State{Route{got, gen, _, _, _}, Clock{status, expires, _, _, _, _}, probes, _, _} Send{ref, g, token, bytes}:
      Bool.and(Bool.and(live(status), Nat.is_lt(now, expires)),
        Bool.and(Bool.and(Pairs.same(got, ref), U32.is_eq(gen, g)), current_probe(probes, token, bytes, now)))
    case _ _: False{}

def ack_tail(result: List<&2, Probe> & U32, probe: Probe) -> List<&2, Probe> & U32:
  (tail, interval) = result
  (Con{probe, tail}, interval)

def ack_probes(probes: List<&2, Probe>, +token: U32, +now: Nat, +rto: U32) -> List<&2, Probe> & U32:
  match probes:
    case Nil{}: ([], 4000)
    case Con{Probe{+id, +tx, +bytes, +mode, +sent, +deadline, +interval}, +tail}:
      Bool.pick(List<&2, Probe> & U32, U32.is_eq(id, token),
        (Con{Probe{id, tx, bytes, mode, Some{now}, Nat.add(now, U32.to_nat(rto)), interval}, tail}, interval),
        ack_tail(ack_probes(tail, token, now, rto), Probe{id, tx, bytes, mode, sent, deadline, interval}))

def acknowledged(result: List<&2, Probe> & U32, state: State, +token: U32, +now: Nat) -> Step:
  (probes, interval) = result
  match state:
    case State{route, Clock{status, expires, _, rto, mean, variation}, _, recent, next_token}:
      Step{State{route, Clock{status, expires, Nat.add(now, U32.to_nat(interval)), rto, mean, variation}, probes, recent, next_token}, [Sent{token}]}

def ack_checked(ok: Bool, notice: Notice, +state: State, +now: Nat) -> Step:
  match ok notice state:
    case True{} Send{_, _, +token, _} State{route, Clock{status, expires, next, +rto, mean, variation}, +probes, recent, next_token}:
      acknowledged(ack_probes(probes, token, now, rto), State{route, Clock{status, expires, next, rto, mean, variation}, probes, recent, next_token}, token, now)
    case _ _ s: empty(s)

def acknowledge(+state: State, +notice: Notice, +now: Nat) -> Step:
  ack_checked(current_send(state, notice, now), notice, state, now)

def failed_go(probes: List<&2, Probe>, +reversed: List<&2, Probe>, +state: State, +token: U32, +code: U32) -> Step:
  match probes:
    case Nil{}: empty(state)
    case Con{Probe{+id, +tx, +bytes, +mode, +sent, +deadline, +interval}, +tail}:
      match state:
        case State{+route, +clock, +all, +recent, +next_token}:
          Bool.pick(Step, U32.is_eq(id, token),
            Step{State{route, clock, List.reverse.go(&2, Probe, reversed, tail), recent, next_token}, [TransportError{token, code}]},
            failed_go(tail, Con{Probe{id, tx, bytes, mode, sent, deadline, interval}, reversed}, State{route, clock, all, recent, next_token}, token, code))

def failed(+state: State, token: U32, code: U32) -> Step:
  match state:
    case State{route, clock, +probes, recent, next_token}:
      failed_go(probes, [], State{route, clock, probes, recent, next_token}, token, code)

def deviation(+a: Nat, +b: Nat) -> Nat:
  Bool.pick(Nat, Nat.is_le(a, b), Nat.sub(b, a), Nat.sub(a, b))

def estimated(clock: Clock, +mean: Nat, +variation: Nat, +now: Nat) -> Clock:
  match clock:
    case Clock{_, _, next, _, _, _}:
      Clock{Granted{}, Nat.add(now, 30000n), next,
        U32.from_nat(Tx.earlier(60000n, Tx.later(500n, Nat.add(mean, Nat.mul(4n, variation))))), mean, variation}

def sample(clock: Clock, +sent: Nat, +now: Nat) -> Clock:
  match clock:
    case Clock{status, expires, next, rto, 0n, variation}:
      +elapsed = Tx.later(1n, Nat.sub(now, sent))
      estimated(Clock{status, expires, next, rto, 0n, variation}, elapsed, Nat.div(elapsed, 2n), now)
    case Clock{status, expires, next, rto, +mean, +variation}:
      +elapsed = Tx.later(1n, Nat.sub(now, sent))
      estimated(Clock{status, expires, next, rto, mean, variation}, Nat.div(Nat.add(Nat.mul(7n, mean), elapsed), 8n),
        Nat.div(Nat.add(Nat.mul(3n, variation), deviation(mean, elapsed)), 4n), now)

def received_response(reply: Response.Reply, probe: Probe, state: State) -> Step:
  match reply probe state:
    case Response.Reply{Response.Error{403}, _} _ s: ended(s, Revoked{})
    case Response.Reply{Response.Error{code}, _} Probe{token, _, _, _, _, _, _} s: Step{s, [Error{token, code}]}
    case _ Probe{token, _, _, _, _, _, _} s: Step{s, [Invalid{token}]}

def pinned(current: Auth.Mode, received: Auth.Mode) -> Auth.Mode:
  match current:
    case Auth.Dual{}: received
    case mode: mode

def received_success(reply: Response.Reply, +probe: Probe, state: State, +now: Nat) -> Step:
  match reply probe state:
    case Response.Reply{Response.Success{_}, mode} Probe{+token, _, _, _, Some{sent}, _, _}
         State{Route{ref, gen, creds, check, old_mode}, clock, probes, recent, next_token}:
      Step{State{Route{ref, gen, creds, check, pinned(old_mode, mode)}, sample(clock, sent, now), probes, recent, next_token}, [Renewed{token, Nat.add(now, 30000n)}]}
    case r p s: received_response(r, p, s)

def receive_parsed(reply: Maybe<&2, Response.Reply>, +probe: Probe, tail: List<&2, Probe>, reversed: List<&2, Probe>,
                   +state: State, +now: Nat, again: List<&2, Probe> -> List<&2, Probe> -> Step) -> Step:
  match reply state:
    case None{} _: again(tail, Con{probe, reversed})
    case Some{r} State{route, clock, _, recent, token}:
      received_success(r, probe, State{route, clock, List.reverse.go(&2, Probe, reversed, tail), recent, token}, now)

def receive_go(probes: List<&2, Probe>, reversed: List<&2, Probe>, +state: State, +raw: List<&2, U32>, +now: Nat, +key: List<&2, U32>, +mode: Auth.Mode) -> Step:
  match probes:
    case Nil{}: empty(state)
    case Con{Probe{+token, +tx, +bytes, +sent_mode, Some{+sent}, +deadline, +interval}, +tail}:
      receive_parsed(Bool.pick(Maybe<&2, Response.Reply>, Nat.is_le(sent, now), Response.parse(raw, tx, key, sent_mode), None{}),
        Probe{token, tx, bytes, sent_mode, Some{sent}, deadline, interval}, tail, reversed, state, now,
        rest => rev => receive_go(tail, rev, state, raw, now, key, mode))
    case Con{head, tail}: receive_go(tail, Con{head, reversed}, state, raw, now, key, mode)

def join(previous: List<&2, Notice>, step: Step) -> Step:
  match step:
    case Step{state, events}: Step{state, List.reverse.go(&2, Notice, List.reverse(&2, Notice, previous), events)}

def receive_ticked(ok: Bool, +step: Step, raw: List<&2, U32>, now: Nat) -> Step:
  match ok step:
    case False{} s: s
    case True{} Step{State{Route{ref, gen, +creds, check, +mode}, clock, +probes, recent, token}, events}:
      join(events, receive_go(probes, [], State{Route{ref, gen, creds, check, mode}, clock, probes, recent, token}, raw, now, Ice.key(creds), mode))

def receive(+state: State, reference: Pairs.Ref, generation: U32, raw: List<&2, U32>, +now: Nat) -> Step:
  match state:
    case State{Route{+ref, +gen, creds, check, mode}, Clock{+status, expires, next, rto, mean, variation}, probes, recent, token}:
      receive_ticked(Bool.and(live(status), Bool.and(Pairs.same(ref, reference), U32.is_eq(gen, generation))),
        tick(State{Route{ref, gen, creds, check, mode}, Clock{status, expires, next, rto, mean, variation}, probes, recent, token}, now), raw, now)

def close(+state: State) -> Step:
  match state:
    case State{_, Clock{Closed{}, _, _, _, _, _}, _, _, _}: empty(state)
    case _: ended(state, Closed{})

def wake(probes: List<&2, Probe>, +deadline: Nat) -> Nat:
  match probes:
    case Nil{}: deadline
    case Con{Probe{_, _, _, _, _, at, _}, tail}: wake(tail, Tx.earlier(at, deadline))

def timeout(state: State, +now: Nat, +cap: U32) -> U32:
  match state:
    case State{_, Clock{+status, +expires, next, _, _, _}, +probes, _, _}:
      U32.from_nat(Nat.sub(Bool.pick(Nat, live(status),
        wake(probes, Tx.earlier(Nat.add(now, U32.to_nat(cap)), Tx.earlier(expires, Bool.pick(Nat, pending(probes), expires, next)))),
        Nat.add(now, U32.to_nat(cap))), now))
