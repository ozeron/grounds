import Base
import ../ice_transport.bend as T
import ../ice_agent.bend as Agent
import ../ice_pairs.bend as Pairs
import ../ice_candidates.bend as C
import ../ice_checklist.bend as Check
import ../ice_binding.bend as Ice
import ../ice_incoming.bend as Incoming
import ../ice_consent.bend as Consent
import ../stun.bend as Stun
import ../stun_retry.bend as Retry
import ../stun_client.bend as Discovery
import ./ice_transport_output.bend as Output
import ./ice_entropy.bend as Entropy
import ../../wire/wire.bend as W

# Retained-socket adapter shared by signaling. State decisions remain in T.
# The complete transport owner is a recursive singleton across IO continuations.
# Unpack only for pure state decisions; retain every exact send gate.

type Driver is Data:
  Driver{state: List<&2, T.State>, base: Stun.IPv4, streams: List<&2, Check.Stream>, end: Nat,
         renewals: U32, scenario: String, restarted: Bool}

def Reply() -> Type:
  Socket & Driver

def fatal(socket: Socket, text: String) -> IO(Reply()):
  do IO<Reply()>:
    x : Unit <- Socket.close(socket)
    IO.die(Reply(), 3, text)

def printed(events: List<&2, T.Notice>, driver: Driver) -> IO(Driver):
  do IO<Driver>:
    x : Unit <- Output.events(events)
    IO.pure(Driver, driver)

def updated(step: T.Step, driver: Driver) -> IO(Driver):
  match step driver:
    case T.Step{state, events} Driver{_, base, streams, end, renewals, scenario, restarted}:
      printed(events, Driver{[state], base, streams, end, renewals, scenario, restarted})

def acknowledge_at(now: Nat, socket: Socket, driver: Driver, packet: T.Packet) -> IO(Reply()):
  match driver:
    case Driver{[+state], +base, +streams, +end, +renewals, +scenario, +restarted}:
      IO.bind(Driver, Reply(), updated(T.acknowledge(state, packet, now),
        Driver{[state], base, streams, end, renewals, scenario, restarted}),
        d => IO.pure(Reply(), (socket, d)))
    case _: fatal(socket, "invalid stored transport owner")

def sent_result(result: Result<&1, &1, U32 & String, Unit>, socket: Socket, driver: Driver, packet: Maybe<&2, T.Packet>) -> IO(Reply()):
  match result driver packet:
    case Done{_} d Some{p}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        acknowledge_at(now, socket, d, p)
    case Done{_} d None{}: IO.pure(Reply(), (socket, d))
    case Fail{_} _ _: fatal(socket, "fixture UDP send failed")

def sent(reply: Discovery.RU(), driver: Driver, packet: Maybe<&2, T.Packet>) -> IO(Reply()):
  (socket, result) = reply
  sent_result(result, socket, driver, packet)

def send(current: Bool, socket: Socket, driver: Driver, reference: Pairs.Ref, bytes: List<&2, U32>, packet: Maybe<&2, T.Packet>) -> IO(Reply()):
  match current reference:
    case False{} _: IO.pure(Reply(), (socket, driver))
    case True{} Pairs.Ref{_, _, _, +peer}:
      IO.bind(Discovery.RU(), Reply(), W.wire_udp_send_to(socket, C.host(peer), C.port(peer), bytes, 100), r => sent(r, driver, packet))

def request_now(+now: Nat, socket: Socket, +driver: Driver, +packet: T.Packet) -> IO(Reply()):
  match driver packet:
    case Driver{[state], base, _, _, _, _, _} T.Packet{_, _, +ref, bytes, _}:
      match ref:
        case Pairs.Ref{_, _, local, _}:
          send(Bool.and(C.address_same(base, local), T.current_send(state, packet, now)), socket, driver, ref, bytes, Some{packet})
    case _ _: fatal(socket, "invalid stored transport owner")

def reply_now(+now: Nat, socket: Socket, +driver: Driver, +notice: T.Notice) -> IO(Reply()):
  match driver notice:
    case Driver{[state], base, _, _, _, _, _} T.Reply{+ref, gen, bytes, _}:
      match ref:
        case Pairs.Ref{_, _, local, _}: send(Bool.and(C.address_same(base, local), T.current_reply_route(state, ref, gen, now)), socket, driver, ref, bytes, None{})
    case _ _: IO.pure(Reply(), (socket, driver))

def application_sent(reply: Discovery.RU(), driver: Driver, gen: U32) -> IO(Reply()):
  (socket, result) = reply
  match result:
    case Done{_}:
      do IO<Reply()>:
        x : Unit <- IO.print("application-sent:" ++ U32.show(gen))
        IO.pure(Reply(), (socket, driver))
    case Fail{_}: fatal(socket, "fixture application send failed")

def send_application(ok: Bool, socket: Socket, driver: Driver, +peer: Stun.IPv4, +gen: U32) -> IO(Reply()):
  match ok:
    case False{}:
      do IO<Reply()>:
        x : Unit <- IO.print("application-blocked")
        IO.pure(Reply(), (socket, driver))
    case True{}: IO.bind(Discovery.RU(), Reply(), W.wire_udp_send_to(socket, C.host(peer), C.port(peer), [165, 90, gen, 71, 82, 79, 85, 78, 68, 83], 100), r => application_sent(r, driver, gen))

def application_route(value: Maybe<&2, T.Route>, +now: Nat, socket: Socket, +driver: Driver) -> IO(Reply()):
  match value driver:
    case None{} _:
      do IO<Reply()>:
        x : Unit <- IO.print("application-blocked")
        IO.pure(Reply(), (socket, driver))
    case Some{T.Route{Pairs.Ref{+sid, +comp, +local, +peer}, +gen}} Driver{[+state], base, _, _, _, _, _}:
      send_application(Bool.and(C.address_same(base, local), T.allowed(state, Pairs.Ref{sid, comp, local, peer}, gen, now)), socket, driver, peer, gen)
    case _ _: fatal(socket, "invalid stored transport owner")

def application_now(+now: Nat, socket: Socket, +driver: Driver) -> IO(Reply()):
  match driver:
    case Driver{[state], _, _, _, _, _, _}: application_route(T.route(state, 1, 1, now), now, socket, driver)
    case _: fatal(socket, "invalid stored transport owner")

def application(socket: Socket, +driver: Driver) -> IO(Reply()):
  do IO<Reply()>:
    now : Nat <- IO.now()
    application_now(now, socket, driver)

def restart_bound(step: T.Step, +now: Nat) -> T.Step:
  match step:
    case T.Step{state, events}: T.join(events, T.bind(state, Ice.Credentials{"nextLocal", "nextRemote", "NewRemoteFixturePassword123"}, now))

def restart_signaled(step: T.Step, now: Nat) -> T.Step:
  match step:
    case T.Step{state, events}: T.join(events, T.local_signaled(state, now))

def restart_at(+now: Nat, socket: Socket, driver: Driver) -> IO(Reply()):
  match driver:
    case Driver{[+state], +base, +streams, +end, +renewals, scenario, _}:
      IO.bind(Driver, Reply(), updated(restart_signaled(restart_bound(T.restart(state, streams, Incoming.Secret{"nextLocal", "NewLocalFixturePassword1234"}, now), now), now),
        Driver{[state], base, streams, end, renewals, scenario, True{}}), d => application(socket, d))
    case _: fatal(socket, "invalid stored transport owner")

def restart_after(reply: Reply()) -> IO(Reply()):
  (socket, driver) = reply
  match driver:
    case Driver{state, base, streams, end, renewals, "restart", False{}}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        restart_at(now, socket, Driver{state, base, streams, end, renewals, "restart", False{}})
    case d: IO.pure(Reply(), (socket, d))

def event(+notice: T.Notice, socket: Socket, driver: Driver) -> IO(Reply()):
  match notice driver:
    case T.Transmit{packet} d:
      do IO<Reply()>:
        now : Nat <- IO.now()
        request_now(now, socket, d, packet)
    case T.Reply{_, _, _, _} d:
      do IO<Reply()>:
        now : Nat <- IO.now()
        reply_now(now, socket, d, notice)
    case T.ConsentEvent{_, _, Consent.Renewed{_, _}} Driver{state, base, streams, end, renewals, scenario, restarted}:
      IO.bind(Reply(), Reply(), application(socket, Driver{state, base, streams, end, (renewals + 1 : U32), scenario, restarted}), restart_after)
    case T.Selected{_, _} d: application(socket, d)
    case T.ConsentEvent{_, _, Consent.Changed{_}} d: application(socket, d)
    case _ d: IO.pure(Reply(), (socket, d))

def continued(reply: Reply(), again: Socket -> Driver -> IO(Reply())) -> IO(Reply()):
  (socket, driver) = reply
  again(socket, driver)

def execute(fuel: Nat, values: List<&2, T.Notice>, socket: Socket, driver: Driver) -> IO(Reply()):
  match fuel values:
    case _ Nil{}: IO.pure(Reply(), (socket, driver))
    case 0n _: fatal(socket, "fixture event limit")
    case 1n+p Con{+head, tail}:
      do IO<Reply()>:
        x : Unit <- Output.event(head)
        IO.bind(Reply(), Reply(), event(head, socket, driver), r => continued(r, s => d => execute(p, tail, s, d)))

def execute_step(step: T.Step, socket: Socket, driver: Driver) -> IO(Reply()):
  match step driver:
    case T.Step{state, +events} Driver{_, base, streams, end, renewals, scenario, restarted}:
      execute(Nat.add(List.length(&2, T.Notice, events), 1n), events, socket, Driver{[state], base, streams, end, renewals, scenario, restarted})

def jitter_random(word: Result<&1, &1, U32 & String, U32>, route: T.Route, tx: List<&2, U32>, socket: Socket, driver: Driver, +now: Nat) -> IO(Reply()):
  match word route driver:
    case Done{n} T.Route{ref, gen} Driver{[+state], +base, +streams, +end, +renewals, +scenario, +restarted}:
      execute_step(T.probe(state, ref, gen, tx, U32.from_nat(Nat.mod(U32.to_nat(n), 2001n)), now), socket, Driver{[state], base, streams, end, renewals, scenario, restarted})
    case _ _ _: fatal(socket, "fixture host RNG failed")

def random_route(route: Maybe<&2, T.Route>, +tx: List<&2, U32>, socket: Socket, +driver: Driver, +now: Nat) -> IO(Reply()):
  match route driver:
    case Some{r} _:
      IO.bind(Result<&1, &1, U32 & String, U32>, Reply(), IO.random_u32(), word => jitter_random(word, r, tx, socket, driver, now))
    case None{} Driver{[+state], +base, +streams, +end, +renewals, +scenario, +restarted}:
      execute_step(T.start(state, tx, Retry.default(), now), socket, Driver{[state], base, streams, end, renewals, scenario, restarted})
    case _ _: fatal(socket, "invalid stored transport owner")

def start_random(entropy: Entropy.Entropy(), socket: Socket, +driver: Driver, +now: Nat) -> IO(Reply()):
  match entropy driver:
    case Done{(a, (b, c))} Driver{[+state], base, streams, end, renewals, scenario, restarted}:
      random_route(T.probe_due(state, now), Discovery.transaction(a, b, c), socket, Driver{[state], base, streams, end, renewals, scenario, restarted}, now)
    case Done{_} _: fatal(socket, "invalid stored transport owner")
    case Fail{_} _: fatal(socket, "fixture host RNG failed")

def admission(+state: T.State, +now: Nat) -> Bool:
  match state:
    case T.State{+agent, _, _, _, _, _, _, _, closed}:
      Bool.and(Bool.not(closed), Bool.or(Agent.same_status(Agent.status(agent), Agent.Running{}), Maybe.is_some(&2, T.Route, T.probe_due(state, now))))

def begin_allowed(ok: Bool, socket: Socket, driver: Driver, now: Nat) -> IO(Reply()):
  match ok:
    case True{}: IO.bind(Entropy.Entropy(), Reply(), Entropy.random(), e => start_random(e, socket, driver, now))
    case False{}: IO.pure(Reply(), (socket, driver))

def begin_due(+now: Nat, socket: Socket, +driver: Driver) -> IO(Reply()):
  match driver:
    case Driver{[state], _, _, _, _, _, _}:
      begin_allowed(admission(state, now), socket, driver, now)
    case _: fatal(socket, "invalid stored transport owner")
