import Base
import ../ice_transport.bend as T
import ../ice_agent.bend as Agent
import ../ice_valid.bend as V
import ../ice_session.bend as Session
import ../ice_pairs.bend as Pairs
import ../ice_candidates.bend as C
import ../ice_checklist.bend as Check
import ../ice_binding.bend as Ice
import ../ice_incoming.bend as Incoming
import ../ice_consent.bend as Consent
import ../stun.bend as Stun
import ../stun_auth.bend as Auth
import ../stun_retry.bend as Retry
import ../stun_client.bend as Discovery
import ./ice_transport_output.bend as Output
import ./ice_consent.bend as Format
import ./ice_session_udp.bend as Entropy
import ../../wire/wire.bend as W

# Trusted OS adapter on one retained actual socket. Packet decisions, credential
# restart, nomination, incoming service and every data gate are owned by Bend.
type Driver is Data:
  Driver{state: T.State, base: Stun.IPv4, streams: List<&2, Check.Stream>, end: Nat,
         renewals: U32, scenario: String, restarted: Bool}

def Reply() -> Type:
  Socket & Driver

def fatal(socket: Socket, text: String) -> IO(Reply()):
  do IO<Reply()>:
    x : Unit <- Socket.close(socket)
    IO.die(Reply(), 3, text)

def updated(step: T.Step, driver: Driver) -> IO(Driver):
  match step driver:
    case T.Step{state, events} Driver{_, base, streams, end, renewals, scenario, restarted}:
      do IO<Driver>:
        x : Unit <- Output.events(events)
        IO.pure(Driver, Driver{state, base, streams, end, renewals, scenario, restarted})

def sent_result(result: Result<&1, &1, U32 & String, Unit>, socket: Socket, driver: Driver, packet: Maybe<&2, T.Packet>) -> IO(Reply()):
  match result driver packet:
    case Done{_} Driver{+state, +base, +streams, +end, +renewals, +scenario, +restarted} Some{p}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        d : Driver <- updated(T.acknowledge(state, p, now), Driver{state, base, streams, end, renewals, scenario, restarted})
        IO.pure(Reply(), (socket, d))
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
    case Driver{state, base, _, _, _, _, _} T.Packet{_, _, +ref, bytes, _}:
      match ref:
        case Pairs.Ref{_, _, local, _}:
          send(Bool.and(C.address_same(base, local), T.current_send(state, packet, now)), socket, driver, ref, bytes, Some{packet})

def reply_now(+now: Nat, socket: Socket, +driver: Driver, +notice: T.Notice) -> IO(Reply()):
  match driver notice:
    case Driver{state, base, _, _, _, _, _} T.Reply{+ref, _, bytes, _}:
      match ref:
        case Pairs.Ref{_, _, local, _}: send(Bool.and(C.address_same(base, local), T.current_reply(state, notice, now)), socket, driver, ref, bytes, None{})
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
    case Some{T.Route{Pairs.Ref{+sid, +comp, +local, +peer}, +gen}} Driver{+state, base, _, _, _, _, _}:
      send_application(Bool.and(C.address_same(base, local), T.allowed(state, Pairs.Ref{sid, comp, local, peer}, gen, now)), socket, driver, peer, gen)


def application_now(+now: Nat, socket: Socket, +driver: Driver) -> IO(Reply()):
  match driver:
    case Driver{state, _, _, _, _, _, _}: application_route(T.route(state, 1, 1, now), now, socket, driver)

def application(socket: Socket, +driver: Driver) -> IO(Reply()):
  match driver:
    case Driver{+state, _, _, _, _, _, _}:
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
    case Driver{+state, +base, +streams, +end, +renewals, scenario, _}:
      do IO<Reply()>:
        d : Driver <- updated(restart_signaled(restart_bound(T.restart(state, streams, Incoming.Secret{"nextLocal", "NewLocalFixturePassword1234"}, now), now), now),
          Driver{state, base, streams, end, renewals, scenario, True{}})
        application(socket, d)

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
      execute(Nat.add(List.length(&2, T.Notice, events), 1n), events, socket, Driver{state, base, streams, end, renewals, scenario, restarted})

def received_source(source: Maybe<&2, Stun.IPv4>, raw: List<&2, U32>, socket: Socket, driver: Driver) -> IO(Reply()):
  match source driver:
    case Some{peer} Driver{+state, +base, +streams, +end, +renewals, +scenario, +restarted}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        execute_step(T.receive(state, Pairs.Ref{1, 1, base, peer}, raw, now), socket, Driver{state, base, streams, end, renewals, scenario, restarted})
    case None{} d: IO.pure(Reply(), (socket, d))

def received_result(result: Result<&1, &1, U32 & String, Maybe<&1, String & U32 & List<&2, U32>>>, socket: Socket, driver: Driver) -> IO(Reply()):
  match result:
    case Done{Some{(host, (port, raw))}}: received_source(C.address_read(host, port), raw, socket, driver)
    case Done{None{}}: IO.pure(Reply(), (socket, driver))
    case Fail{_}: fatal(socket, "fixture UDP receive failed")

def received(reply: Discovery.RD(), driver: Driver) -> IO(Reply()):
  (socket, result) = reply
  received_result(result, socket, driver)

def poll(reply: Reply()) -> IO(Reply()):
  (socket, +driver) = reply
  match driver:
    case Driver{+state, _, _, _, _, _, _}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        IO.bind(Discovery.RD(), Reply(), W.wire_udp_recv_from_timeout(socket, 65535, T.timeout(state, now, 20)), r => received(r, driver))

def jitter_random(word: Result<&1, &1, U32 & String, U32>, route: T.Route, tx: List<&2, U32>, socket: Socket, driver: Driver, +now: Nat) -> IO(Reply()):
  match word route driver:
    case Done{n} T.Route{ref, gen} Driver{+state, +base, +streams, +end, +renewals, +scenario, +restarted}:
      execute_step(T.probe(state, ref, gen, tx, U32.from_nat(Nat.mod(U32.to_nat(n), 2001n)), now), socket, Driver{state, base, streams, end, renewals, scenario, restarted})
    case _ _ _: fatal(socket, "fixture host RNG failed")

def random_route(route: Maybe<&2, T.Route>, +tx: List<&2, U32>, socket: Socket, +driver: Driver, +now: Nat) -> IO(Reply()):
  match route driver:
    case Some{r} _:
      IO.bind(Result<&1, &1, U32 & String, U32>, Reply(), IO.random_u32(), word => jitter_random(word, r, tx, socket, driver, now))
    case None{} Driver{+state, +base, +streams, +end, +renewals, +scenario, +restarted}:
      execute_step(T.start(state, tx, Retry.default(), now), socket, Driver{state, base, streams, end, renewals, scenario, restarted})

def start_random(entropy: Entropy.Entropy(), socket: Socket, +driver: Driver, +now: Nat) -> IO(Reply()):
  match entropy driver:
    case Done{(a, (b, c))} Driver{+state, base, streams, end, renewals, scenario, restarted}:
      random_route(T.probe_due(state, now), Discovery.transaction(a, b, c), socket, Driver{state, base, streams, end, renewals, scenario, restarted}, now)
    case Fail{_} _: fatal(socket, "fixture host RNG failed")


def driver_state(driver: Driver) -> T.State:
  match driver:
    case Driver{state, _, _, _, _, _, _}: state


def begin_allowed(ok: Bool, socket: Socket, driver: Driver, now: Nat) -> IO(Reply()):
  match ok:
    case True{}: IO.bind(Entropy.Entropy(), Reply(), Entropy.random(), e => start_random(e, socket, driver, now))
    case False{}: IO.pure(Reply(), (socket, driver))

def begin_due(+now: Nat, socket: Socket, +driver: Driver) -> IO(Reply()):
  match driver:
    case Driver{T.State{+agent, _, _, _, _, _, _, _, closed}, _, _, _, _, _, _}:
      begin_allowed(Bool.and(Bool.not(closed), Bool.or(Agent.same_status(Agent.status(agent), Agent.Running{}), Maybe.is_some(&2, T.Route, T.probe_due(driver_state(driver), now)))), socket, driver, now)


def begin(reply: Reply()) -> IO(Reply()):
  (socket, +driver) = reply
  do IO<Reply()>:
    now : Nat <- IO.now()
    begin_due(now, socket, driver)


def selected_lost(slots: List<&2, T.Slot>, found: Bool, lost: Bool) -> Bool:
  match slots:
    case Nil{}: Bool.and(found, lost)
    case Con{T.Slot{Consent.State{_, Consent.Clock{status, _, _, _, _, _}, _, _, _}, _, +aliases}, tail}:
      selected_lost(tail, Bool.or(found, T.aliases_present(aliases)), Bool.and(lost, Bool.or(Bool.not(T.aliases_present(aliases)), Bool.not(Consent.live(status)))))

def selected_granted(slots: List<&2, T.Slot>, +gen: U32) -> Bool:
  match slots:
    case Nil{}: False{}
    case Con{T.Slot{Consent.State{Consent.Route{_, got, _, _, _}, Consent.Clock{Consent.Granted{}, _, _, _, _, _}, _, _, _}, _, aliases}, tail}:
      Bool.or(Bool.and(U32.is_eq(gen, got), T.aliases_present(aliases)), selected_granted(tail, gen))
    case Con{_, tail}: selected_granted(tail, gen)

def done(state: T.State, renewals: U32, scenario: String) -> Bool:
  match state scenario:
    case T.State{_, _, _, _, _, _, _, _, True{}} _: True{}
    case T.State{_, slots, _, _, _, _, _, _, _} "expiry": selected_lost(slots, False{}, True{})
    case T.State{_, slots, _, _, _, _, _, _, _} "revoke": selected_lost(slots, False{}, True{})
    case T.State{agent, slots, _, _, _, _, _, _, _} "restart": selected_granted(slots, Agent.generation(agent))
    case _ "first": U32.is_le(1, renewals)
    case _ _: U32.is_le(2, renewals)

def finish(socket: Socket, driver: Driver, now: Nat, text: String) -> IO(Unit):
  match driver:
    case Driver{+state, _, _, _, renewals, _, _}:
      do IO<Unit>:
        x : Unit <- Socket.close(socket)
        y : Unit <- IO.print(text)
        z : Unit <- IO.print("renewals:" ++ U32.show(renewals))
        f : Unit <- Output.snapshot(state, now)
        IO.print("done")

def loop_reply(reply: Reply(), again: Socket -> Driver -> IO(Unit)) -> IO(Unit):
  (socket, driver) = reply
  again(socket, driver)

def timed(finished: Bool, socket: Socket, driver: Driver, +now: Nat, again: Socket -> Driver -> IO(Unit)) -> IO(Unit):
  match finished driver:
    case True{} d: finish(socket, d, now, "terminal")
    case False{} Driver{+state, base, streams, end, renewals, scenario, restarted}:
      IO.bind(Reply(), Unit, IO.bind(Reply(), Reply(), IO.bind(Reply(), Reply(), execute_step(T.tick(state, now), socket, Driver{state, base, streams, end, renewals, scenario, restarted}), begin), poll), r => loop_reply(r, again))

def at_now(+now: Nat, socket: Socket, +driver: Driver, again: Socket -> Driver -> IO(Unit)) -> IO(Unit):
  match driver:
    case Driver{+state, +base, +streams, +end, +renewals, +scenario, +restarted}:
      timed(Bool.or(done(state, renewals, scenario), Nat.is_le(end, now)), socket, driver, now, again)

def loop(fuel: Nat, socket: Socket, driver: Driver) -> IO(Unit):
  match fuel:
    case 0n: finish(socket, driver, 0n, "fixture-fuel")
    case 1n+p:
      do IO<Unit>:
        now : Nat <- IO.now()
        at_now(now, socket, driver, s => d => loop(p, s, d))

def signaled(step: T.Step, socket: Socket, base: Stun.IPv4, streams: List<&2, Check.Stream>, +now: Nat, scenario: String) -> IO(Unit):
  match step:
    case T.Step{state, _}:
      do IO<Unit>:
        x : Unit <- IO.print("ready")
        loop(16384n, socket, Driver{state, base, streams, Nat.add(now, 35000n), 0, scenario, False{}})

def owned(value: Maybe<&2, T.State>, socket: Socket, base: Stun.IPv4, streams: List<&2, Check.Stream>, +now: Nat, scenario: String) -> IO(Unit):
  match value:
    case None{}:
      do IO<Unit>:
        x : Unit <- Socket.close(socket)
        IO.die(Unit, 3, "fixture owner creation failed")
    case Some{state}:
      signaled(restart_signaled(T.bind(state, Ice.Credentials{"localFrag", "remoteFrag", "SyntheticPassword123456789"}, now), now), socket, base, streams, now, scenario)

def created(value: Maybe<&2, Agent.State>, socket: Socket, base: Stun.IPv4, streams: List<&2, Check.Stream>, scenario: String) -> IO(Unit):
  match value:
    case None{}:
      do IO<Unit>:
        x : Unit <- Socket.close(socket)
        IO.die(Unit, 3, "fixture agent creation failed")
    case Some{agent}:
      do IO<Unit>:
        now : Nat <- IO.now()
        owned(T.create(agent, T.defaults()), socket, base, streams, now, scenario)

def local_address(+base: Stun.IPv4, socket: Socket, peer: U32, mode: Auth.Mode, scenario: String) -> IO(Unit):
  +local : C.Candidate = C.Candidate{1, 2130706431, "host", C.Host{}, base}
  +streams : List<&2, Check.Stream> = [Check.Stream{1, [C.Local{local, local}], [C.Candidate{1, 2100000000, "remote", C.Host{}, Stun.IPv4{127, 0, 0, 1, peer}}]}]
  created(Maybe.bind(&2, V.State, Agent.State, V.from_session(Session.create(streams, Ice.Controlling{0, 1}, Incoming.Secret{"localFrag", "LocalFixturePassword123456"}, mode, 100, 4, 7), 100), v => Agent.create(v, Agent.defaults())), socket, base, streams, scenario)

def named_result(result: Result<&1, &1, U32 & String, String & U32>, socket: Socket, peer: U32, mode: Auth.Mode, scenario: String) -> IO(Unit):
  match result:
    case Done{(host, +port)}:
      do IO<Unit>:
        x : Unit <- IO.print("base:" ++ host ++ "/" ++ U32.show(port))
        local_address(Stun.IPv4{127, 0, 0, 1, port}, socket, peer, mode, scenario)
    case Fail{_}:
      do IO<Unit>:
        x : Unit <- Socket.close(socket)
        IO.die(Unit, 3, "fixture local address failed")

def named(reply: Socket & Result<&1, &1, U32 & String, String & U32>, peer: U32, mode: Auth.Mode, scenario: String) -> IO(Unit):
  (socket, result) = reply
  named_result(result, socket, peer, mode, scenario)

def bound(result: Result<&1, &1, U32 & String, Socket>, peer: U32, mode: Auth.Mode, scenario: String) -> IO(Unit):
  match result:
    case Done{socket}: IO.bind(Socket & Result<&1, &1, U32 & String, String & U32>, Unit, W.wire_udp_local_address(socket), r => named(r, peer, mode, scenario))
    case Fail{_}: IO.die(Unit, 3, "fixture UDP bind failed")

def configured(peer: U32, +mode: String, scenario: String) -> IO(Unit):
  IO.bind(Result<&1, &1, U32 & String, Socket>, Unit, W.wire_udp_bind("127.0.0.1", 0), r => bound(r, peer, Bool.pick(Auth.Mode, String.eq(mode, "legacy"), Auth.Legacy{}, Bool.pick(Auth.Mode, String.eq(mode, "sha256"), Auth.Sha256{}, Auth.Dual{})), scenario))

def parsed(peer: Maybe<&2, U32>, mode: String, scenario: String) -> IO(Unit):
  match peer:
    case Some{p}: configured(p, mode, scenario)
    case None{}: IO.die(Unit, 2, "bad fixture arguments")


def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [port, mode, scenario]: parsed(U32.read(port), mode, scenario)
    case _: IO.die(Unit, 2, "usage: ice_transport_udp <port> <mode> <first|renew|expiry|revoke|restart>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
