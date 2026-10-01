import Base
import ./ice_binding.bend as Ice
import ./ice_response.bend as Response
import ./ice_reliable.bend as Reliable
import ./stun.bend as Stun
import ./stun_auth.bend as Auth
import ./stun_retry.bend as Retry

# One engine owns all transactions on a bound socket. No socket or clock effects
# appear here; the caller executes Send events and supplies monotonic timestamps.
type Entry is Data:
  Entry{token: U32, context: Reliable.Context, deadline: Nat, next: List<&2, U32>, violated: Bool}
  Listening{token: U32, context: Reliable.Context, deadline: Nat}

type State is Data:
  State{entries: List<&2, Entry>, ta: U32, capacity: U32, next_start: Nat, next_send: Nat}

type Notice is Data:
  Send{token: U32, host: String, port: U32, bytes: List<&2, U32>, fresh: Bool}
  Sent{token: U32}
  Finished{token: U32, outcome: Reliable.Outcome}
  Cancelled{token: U32}
  Stopped{token: U32}
  LateResponse{token: U32, response: Response.Response, algorithm: Auth.Mode}
  Retired{token: U32}
  SocketFailure{code: U32}
  Datagram{host: String, port: U32, bytes: List<&2, U32>}

type Step is Data:
  Step{state: State, events: List<&2, Notice>}

type Start is Data:
  Ready{step: Step}
  Later{at: Nat}
  Rejected{}

def default() -> State:
  State{[], 50, 100, 0n, 0n}

# Base Nat.min/max reconstruct a successor chain on the native target. Clock
# values need only a comparison and selection, independent of uptime size.
def later(+a: Nat, +b: Nat) -> Nat:
  Bool.pick(Nat, Nat.is_le(a, b), b, a)

def earlier(+a: Nat, +b: Nat) -> Nat:
  Bool.pick(Nat, Nat.is_le(a, b), a, b)

def empty(waits: List<&2, U32>) -> Bool:
  match waits:
    case Nil{}: True{}
    case Con{_, _}: False{}

def count(entries: List<&2, Entry>, +n: Nat) -> Nat:
  match entries:
    case Nil{}: n
    case Con{_, tail}: count(tail, Nat.add(n, 1n))

def duplicate(entries: List<&2, Entry>, +token: U32, +transaction: List<&2, U32>, found: Bool) -> Bool:
  match entries:
    case Nil{}: found
    case Con{Entry{+id, Reliable.Context{_, _, got, _, _, _}, _, _, _}, tail}:
      duplicate(tail, token, transaction, Bool.or(found,
        Bool.or(U32.is_eq(id, token), Stun.same(got, transaction, True{}))))
    case Con{Listening{+id, Reliable.Context{_, _, got, _, _, _}, _}, tail}:
      duplicate(tail, token, transaction, Bool.or(found,
        Bool.or(U32.is_eq(id, token), Stun.same(got, transaction, True{}))))

def sending(entry: Entry, fresh: Bool) -> Notice:
  match entry:
    case Entry{token, Reliable.Context{host, port, _, _, _, bytes}, _, _, _}:
      Send{token, host, port, bytes, fresh}
    case Listening{token, _, _}: Retired{token}

def added(+entry: Entry, entries: List<&2, Entry>, +ta: U32, capacity: U32, +now: Nat) -> Start:
  Ready{Step{State{List.reverse.go(&2, Entry, List.reverse(&2, Entry, entries), [entry]),
    ta, capacity, Nat.add(now, U32.to_nat(ta)), Nat.add(now, 5n)}, [sending(entry, True{})]}}

def prepared(ok: Bool, state: State, token: U32, +context: Reliable.Context, +now: Nat,
             waits: List<&2, U32>) -> Start:
  match ok state waits:
    case False{} _ _: Rejected{}
    case True{} State{entries, +ta, capacity, _, _} Con{+interval, tail}:
      added(Entry{token, context, Nat.add(now, U32.to_nat(interval)), tail, False{}}, entries, ta, capacity, now)
    case True{} _ Nil{}: Rejected{}

def start_raw(raw: Maybe<&2, List<&2, U32>>, waits: Maybe<&2, List<&2, U32>>, state: State,
              +token: U32, host: String, port: U32, +transaction: List<&2, U32>, key: List<&2, U32>,
              mode: Auth.Mode, +now: Nat) -> Start:
  match raw waits state:
    case Some{bytes} Some{intervals} State{+entries, +ta, +capacity, +next_start, +next_send}:
      prepared(Bool.and(Bool.and(U32.is_le(5, ta), U32.is_le(ta, 60000)),
        Bool.and(Bool.and(U32.is_le(1, capacity), U32.is_le(capacity, 256)),
          Bool.and(Nat.is_lt(count(entries, 0n), U32.to_nat(capacity)),
            Bool.and(Bool.not(duplicate(entries, token, transaction, False{})), Nat.is_le(now, Nat.mul(65536n, 4294934528n)))))),
        State{entries, ta, capacity, next_start, next_send}, token,
        Reliable.Context{host, port, transaction, key, mode, bytes}, now, intervals)
    case _ _ _: Rejected{}

def start_due(due: Bool, +state: State, token: U32, host: String, port: U32,
              +transaction: List<&2, U32>, policy: Retry.Policy, +credentials: Ice.Credentials,
              check: Ice.Check, +mode: Auth.Mode, now: Nat, at: Nat) -> Start:
  match due:
    case False{}: Later{at}
    case True{}:
      start_raw(Ice.request(transaction, credentials, check, mode), Retry.intervals(policy), state,
        token, host, port, transaction, Ice.key(credentials), mode, now)

def start(+state: State, token: U32, host: String, port: U32, transaction: List<&2, U32>,
          policy: Retry.Policy, credentials: Ice.Credentials, check: Ice.Check, mode: Auth.Mode, +now: Nat) -> Start:
  match state:
    case State{+entries, +ta, +capacity, +next_start, +next_send}:
      +at = later(next_start, next_send)
      start_due(Nat.is_le(at, now), State{entries, ta, capacity, next_start, next_send}, token,
        host, port, transaction, policy, credentials, check, mode, now, at)

def intent_due(due: Bool, +state: State, token: U32, host: String, port: U32,
               +transaction: List<&2, U32>, policy: Retry.Policy, +credentials: Ice.Credentials,
               check: Ice.Check, nominate: Bool, +mode: Auth.Mode, now: Nat, at: Nat) -> Start:
  match due:
    case False{}: Later{at}
    case True{}:
      start_raw(Ice.intent_request(transaction, credentials, check, nominate, mode), Retry.intervals(policy), state,
        token, host, port, transaction, Ice.key(credentials), mode, now)

# Sign nomination intent once; the retained context is authoritative across
# pacing, retries, interruption and role changes, just like ordinary requests.
def start_intent(+state: State, token: U32, host: String, port: U32, transaction: List<&2, U32>,
                 policy: Retry.Policy, credentials: Ice.Credentials, check: Ice.Check, nominate: Bool,
                 mode: Auth.Mode, +now: Nat) -> Start:
  match state:
    case State{+entries, +ta, +capacity, +next_start, +next_send}:
      +at = later(next_start, next_send)
      intent_due(Nat.is_le(at, now), State{entries, ta, capacity, next_start, next_send}, token,
        host, port, transaction, policy, credentials, check, nominate, mode, now, at)

def expired(entry: Entry, +now: Nat) -> Maybe<&2, Entry> & Notice:
  match entry:
    case Listening{token, _, _}: (None{}, Retired{token})
    case Entry{token, _, _, Nil{}, violated}:
      (None{}, Finished{token, Bool.pick(Reliable.Outcome, violated, Reliable.IntegrityViolation{}, Reliable.TimedOut{})})
    case Entry{+token, +context, _, Con{+interval, tail}, violated}:
      (Some{Entry{token, context, Nat.add(now, U32.to_nat(interval)), tail, violated}},
        sending(Entry{token, context, 0n, [], False{}}, False{}))

def expired_step(result: Maybe<&2, Entry> & Notice, tail: List<&2, Entry>, reversed: List<&2, Entry>,
                 ta: U32, capacity: U32, next_start: Nat, next_send: Nat, +now: Nat) -> Step:
  (entry, +event) = result
  match entry:
    case None{}:
      Step{State{List.reverse.go(&2, Entry, reversed, tail), ta, capacity, next_start, next_send}, [event]}
    case Some{e}:
      Step{State{List.reverse.go(&2, Entry, reversed, Con{e, tail}), ta, capacity, next_start, later(next_send, Nat.add(now, 5n))}, [event]}

def tick_entry(due: Bool, +entry: Entry, tail: List<&2, Entry>, reversed: List<&2, Entry>,
               +now: Nat, ta: U32, capacity: U32, next_start: Nat, next_send: Nat,
               again: List<&2, Entry> -> List<&2, Entry> -> Step) -> Step:
  match due:
    case False{}: again(tail, Con{entry, reversed})
    case True{}: expired_step(expired(entry, now), tail, reversed, ta, capacity, next_start, next_send, now)

def tick_go(fuel: Nat, entries: List<&2, Entry>, reversed: List<&2, Entry>, +now: Nat,
            +ta: U32, +capacity: U32, +next_start: Nat, +next_send: Nat) -> Step:
  match fuel entries:
    case 0n _:
      Step{State{List.reverse.go(&2, Entry, reversed, entries), ta, capacity, next_start, next_send}, []}
    case 1n+_ Nil{}:
      Step{State{List.reverse(&2, Entry, reversed), ta, capacity, next_start, next_send}, []}
    case 1n+p Con{Entry{+token, +context, +deadline, +next, +violated}, tail}:
      # Terminal timeouts do not wait for send pacing; retransmissions do.
      tick_entry(Bool.and(Nat.is_le(deadline, now), Bool.or(empty(next), Nat.is_le(next_send, now))),
        Entry{token, context, deadline, next, violated}, tail, reversed, now, ta, capacity, next_start, next_send,
        rest => rev => tick_go(p, rest, rev, now, ta, capacity, next_start, next_send))
    case 1n+p Con{Listening{+token, +context, +deadline}, tail}:
      tick_entry(Nat.is_le(deadline, now), Listening{token, context, deadline}, tail, reversed,
        now, ta, capacity, next_start, next_send,
        rest => rev => tick_go(p, rest, rev, now, ta, capacity, next_start, next_send))

# At most one send per step; caller repeats after >= 5 ms even if several RTOs
# coincide. Initial checks additionally follow Ta (50 ms by default).
def tick(state: State, now: Nat) -> Step:
  match state:
    case State{+entries, ta, capacity, next_start, next_send}:
      tick_go(Nat.add(count(entries, 0n), 1n), entries, [], now, ta, capacity, next_start, next_send)

def response_found(response: Maybe<&2, Response.Reply>, entry: Entry, +raw: List<&2, U32>) -> Maybe<&2, Entry> & List<&2, Notice>:
  match response entry:
    case Some{Response.Reply{r, mode}} Listening{token, _, _}:
      (None{}, [LateResponse{token, r, mode}])
    case None{} Listening{token, Reliable.Context{+host, +port, transaction, key, mode, bytes}, deadline}:
      (Some{Listening{token, Reliable.Context{host, port, transaction, key, mode, bytes}, deadline}}, [Datagram{host, port, raw}])
    case Some{Response.Reply{r, mode}} Entry{token, _, _, _, _}:
      (None{}, [Finished{token, Reliable.Received{r, mode}}])
    case None{} Entry{token, Reliable.Context{+host, +port, +transaction, +key, +mode, +bytes}, deadline, next, violated}:
      (Some{Entry{token, Reliable.Context{host, port, transaction, key, mode, bytes}, deadline, next,
        Bool.or(violated, Response.integrity_failed(raw, transaction, key, mode))}}, [Datagram{host, port, raw}])

def response_timed(expired: Bool, +entry: Entry, +raw: List<&2, U32>) -> Maybe<&2, Entry> & List<&2, Notice>:
  match expired entry:
    case True{} Listening{token, Reliable.Context{host, port, _, _, _, _}, _}:
      (None{}, [Retired{token}, Datagram{host, port, raw}])
    case False{} Listening{+token, Reliable.Context{+host, +port, +transaction, +key, +mode, +bytes}, +deadline}:
      response_found(Response.parse(raw, transaction, key, mode),
        Listening{token, Reliable.Context{host, port, transaction, key, mode, bytes}, deadline}, raw)
    case True{} Entry{token, Reliable.Context{host, port, _, _, _, _}, _, _, violated}:
      (None{}, [Finished{token, Bool.pick(Reliable.Outcome, violated, Reliable.IntegrityViolation{}, Reliable.TimedOut{})}, Datagram{host, port, raw}])
    case False{} Entry{+token, Reliable.Context{+host, +port, +transaction, +key, +mode, +bytes}, +deadline, +next, +violated}:
      response_found(Response.parse(raw, transaction, key, mode),
        Entry{token, Reliable.Context{host, port, transaction, key, mode, bytes}, deadline, next, violated}, raw)

def response_entry(entry: Entry, raw: List<&2, U32>, now: Nat) -> Maybe<&2, Entry> & List<&2, Notice>:
  match entry:
    case Listening{+token, +context, +deadline}:
      response_timed(Nat.is_le(deadline, now), Listening{token, context, deadline}, raw)
    case Entry{+token, +context, +deadline, +next, +violated}:
      response_timed(Bool.and(empty(next), Nat.is_le(deadline, now)), Entry{token, context, deadline, next, violated}, raw)

def routed(result: Maybe<&2, Entry> & List<&2, Notice>, tail: List<&2, Entry>, reversed: List<&2, Entry>,
           ta: U32, capacity: U32, next_start: Nat, next_send: Nat) -> Step:
  (entry, events) = result
  match entry:
    case None{}: Step{State{List.reverse.go(&2, Entry, reversed, tail), ta, capacity, next_start, next_send}, events}
    case Some{e}: Step{State{List.reverse.go(&2, Entry, reversed, Con{e, tail}), ta, capacity, next_start, next_send}, events}

def route_checked(same: Bool, entry: Entry, tail: List<&2, Entry>, reversed: List<&2, Entry>, raw: List<&2, U32>, now: Nat,
                  ta: U32, capacity: U32, next_start: Nat, next_send: Nat,
                  again: List<&2, Entry> -> List<&2, Entry> -> Step) -> Step:
  match same:
    case False{}: again(tail, Con{entry, reversed})
    case True{}: routed(response_entry(entry, raw, now), tail, reversed, ta, capacity, next_start, next_send)

def route_go(fuel: Nat, entries: List<&2, Entry>, reversed: List<&2, Entry>, +host: String, +port: U32,
             +transaction: List<&2, U32>, +raw: List<&2, U32>, +now: Nat, +ta: U32, +capacity: U32,
             +next_start: Nat, +next_send: Nat) -> Step:
  match fuel entries:
    case 0n _:
      Step{State{List.reverse.go(&2, Entry, reversed, entries), ta, capacity, next_start, next_send}, [Datagram{host, port, raw}]}
    case 1n+_ Nil{}:
      Step{State{List.reverse(&2, Entry, reversed), ta, capacity, next_start, next_send}, [Datagram{host, port, raw}]}
    case 1n+p Con{Entry{+token, Reliable.Context{+peer, +peer_port, +got, +key, +mode, +bytes}, +deadline, +next, +violated}, tail}:
      route_checked(Bool.and(Bool.and(String.eq(host, peer), U32.is_eq(port, peer_port)), Stun.same(got, transaction, True{})),
        Entry{token, Reliable.Context{peer, peer_port, got, key, mode, bytes}, deadline, next, violated}, tail, reversed,
        raw, now, ta, capacity, next_start, next_send,
        rest => rev => route_go(p, rest, rev, host, port, transaction, raw, now, ta, capacity, next_start, next_send))
    case 1n+p Con{Listening{+token, Reliable.Context{+peer, +peer_port, +got, +key, +mode, +bytes}, +deadline}, tail}:
      route_checked(Bool.and(Bool.and(String.eq(host, peer), U32.is_eq(port, peer_port)), Stun.same(got, transaction, True{})),
        Listening{token, Reliable.Context{peer, peer_port, got, key, mode, bytes}, deadline}, tail, reversed,
        raw, now, ta, capacity, next_start, next_send,
        rest => rev => route_go(p, rest, rev, host, port, transaction, raw, now, ta, capacity, next_start, next_send))

def packet(packet: Maybe<&2, Stun.Packet>, state: State, host: String, port: U32, raw: List<&2, U32>, now: Nat) -> Step:
  match packet state:
    case Some{Stun.Packet{257, transaction, _}} State{+entries, ta, capacity, next_start, next_send}:
      route_go(Nat.add(count(entries, 0n), 1n), entries, [], host, port, transaction, raw, now, ta, capacity, next_start, next_send)
    case Some{Stun.Packet{273, transaction, _}} State{+entries, ta, capacity, next_start, next_send}:
      route_go(Nat.add(count(entries, 0n), 1n), entries, [], host, port, transaction, raw, now, ta, capacity, next_start, next_send)
    case _ s:
      Step{s, [Datagram{host, port, raw}]}

# Incoming Binding requests, media and unrelated responses are returned intact.
# Datagram is untrusted raw input, never an authenticated ICE request/result.
def receive(state: State, host: String, port: U32, +raw: List<&2, U32>, now: Nat) -> Step:
  packet(Stun.parse(raw), state, host, port, raw, now)

def retirement(event: Notice, token: U32) -> Notice:
  match event:
    case Finished{_, _}: Retired{token}
    case e: e

def remove_go(entries: List<&2, Entry>, +reversed: List<&2, Entry>, +token: U32,
              +ta: U32, +capacity: U32, +next_start: Nat, +next_send: Nat, +event: Notice) -> Step:
  match entries:
    case Nil{}: Step{State{List.reverse(&2, Entry, reversed), ta, capacity, next_start, next_send}, []}
    case Con{Entry{+id, +context, +deadline, +next, +violated}, +tail}:
      Bool.pick(Step, U32.is_eq(id, token),
        Step{State{List.reverse.go(&2, Entry, reversed, tail), ta, capacity, next_start, next_send}, [event]},
        remove_go(tail, Con{Entry{id, context, deadline, next, violated}, reversed}, token, ta, capacity, next_start, next_send, event))
    case Con{Listening{+id, +context, +deadline}, +tail}:
      Bool.pick(Step, U32.is_eq(id, token),
        Step{State{List.reverse.go(&2, Entry, reversed, tail), ta, capacity, next_start, next_send}, [retirement(event, token)]},
        remove_go(tail, Con{Listening{id, context, deadline}, reversed}, token, ta, capacity, next_start, next_send, event))

def cancel(state: State, +token: U32) -> Step:
  match state:
    case State{entries, ta, capacity, next_start, next_send}:
      remove_go(entries, [], token, ta, capacity, next_start, next_send, Cancelled{token})

def failed(state: State, +token: U32, code: U32) -> Step:
  match state:
    case State{entries, ta, capacity, next_start, next_send}:
      remove_go(entries, [], token, ta, capacity, next_start, next_send, Finished{token, Reliable.TransportError{code}})

def final_deadline(waits: List<&2, U32>, deadline: Nat) -> Nat:
  match waits:
    case Nil{}: deadline
    case Con{wait, tail}: final_deadline(tail, Nat.add(deadline, U32.to_nat(wait)))

def stop_go(entries: List<&2, Entry>, +reversed: List<&2, Entry>, +token: U32,
            +ta: U32, +capacity: U32, +next_start: Nat, +next_send: Nat) -> Step:
  match entries:
    case Nil{}: Step{State{List.reverse(&2, Entry, reversed), ta, capacity, next_start, next_send}, []}
    case Con{Entry{+id, +context, +deadline, +waits, +violated}, +tail}:
      Bool.pick(Step, U32.is_eq(id, token),
        Step{State{List.reverse.go(&2, Entry, reversed, Con{Listening{id, context, final_deadline(waits, deadline)}, tail}),
          ta, capacity, next_start, next_send}, [Stopped{token}]},
        stop_go(tail, Con{Entry{id, context, deadline, waits, violated}, reversed}, token, ta, capacity, next_start, next_send))
    case Con{Listening{+id, +context, +deadline}, +tail}:
      Bool.pick(Step, U32.is_eq(id, token),
        Step{State{List.reverse.go(&2, Entry, reversed, Con{Listening{id, context, deadline}, tail}),
          ta, capacity, next_start, next_send}, []},
        stop_go(tail, Con{Listening{id, context, deadline}, reversed}, token, ta, capacity, next_start, next_send))

# RFC 8445 triggered-check interruption. Freeze the remaining response window,
# stop retries/queued sends, reserve identity/capacity and never report failure
# for missing/invalid late traffic. A repeated call cannot extend the window.
def stop_retries(state: State, token: U32) -> Step:
  match state:
    case State{entries, ta, capacity, next_start, next_send}:
      stop_go(entries, [], token, ta, capacity, next_start, next_send)

def current_go(entries: List<&2, Entry>, +token: U32, +host: String, +port: U32, +raw: List<&2, U32>, found: Bool) -> Bool:
  match entries:
    case Nil{}: found
    case Con{Entry{id, Reliable.Context{peer, peer_port, _, _, _, bytes}, _, _, _}, tail}:
      current_go(tail, token, host, port, raw, Bool.or(found, Bool.and(Bool.and(U32.is_eq(id, token), String.eq(peer, host)),
        Bool.and(U32.is_eq(port, peer_port), Stun.same(raw, bytes, True{})))))
    case Con{Listening{_, _, _}, tail}: current_go(tail, token, host, port, raw, found)

# Suppress queued commands invalidated by cancellation/completion before IO.
def current_send(state: State, notice: Notice) -> Bool:
  match state notice:
    case State{entries, _, _, _, _} Send{token, host, port, raw, _}: current_go(entries, token, host, port, raw, False{})
    case _ _: False{}

def wake_go(entries: List<&2, Entry>, +next_send: Nat, +wake: Nat) -> Nat:
  match entries:
    case Nil{}: wake
    case Con{Entry{_, _, +deadline, next, _}, tail}:
      wake_go(tail, next_send, earlier(wake, Bool.pick(Nat, empty(next), deadline, later(deadline, next_send))))
    case Con{Listening{_, _, deadline}, tail}: wake_go(tail, next_send, earlier(wake, deadline))

def timeout(state: State, +now: Nat, cap: U32) -> U32:
  match state:
    case State{entries, _, _, _, next_send}:
      U32.from_nat(Nat.sub(wake_go(entries, next_send, Nat.add(now, U32.to_nat(cap))), now))

# Ack the actual OS send completion time so a delayed send cannot be followed
# immediately by another command. Ta applies to new checks, not retransmits.
def sent(state: State, +now: Nat, fresh: Bool) -> State:
  match state:
    case State{entries, +ta, capacity, +next_start, next_send}:
      State{entries, ta, capacity, Bool.pick(Nat, fresh, later(next_start, Nat.add(now, U32.to_nat(ta))), next_start), later(next_send, Nat.add(now, 5n))}
