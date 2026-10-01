import Base
import ../ice_consent.bend as Consent
import ../ice_binding.bend as Ice
import ../ice_candidates.bend as C
import ../ice_pairs.bend as Pairs
import ../stun.bend as Stun
import ../stun_auth.bend as Auth
import ../stun_client.bend as Discovery
import ./ice_consent.bend as Format
import ./ice_session_udp.bend as Entropy
import ../../wire/wire.bend as W

# Local synthetic selected-route fixture. Effects perform RNG, timestamps and
# UDP only; consent construction, authentication and the data gate are Bend.
type Driver is Data:
  Driver{state: Consent.State, base: Stun.IPv4, end: Nat, renewals: U32, scenario: String}

def Reply() -> Type:
  Socket & Driver

def fatal(socket: Socket, text: String) -> IO(Reply()):
  do IO<Reply()>:
    x : Unit <- Socket.close(socket)
    IO.die(Reply(), 3, text)

def application_sent(reply: Discovery.RU(), driver: Driver) -> IO(Reply()):
  (socket, result) = reply
  match result:
    case Done{_}:
      do IO<Reply()>:
        x : Unit <- IO.print("application-sent")
        IO.pure(Reply(), (socket, driver))
    case Fail{_}: fatal(socket, "fixture application send failed")

def application_due(allowed: Bool, socket: Socket, driver: Driver, +peer: Stun.IPv4) -> IO(Reply()):
  match allowed:
    case False{}:
      do IO<Reply()>:
        x : Unit <- IO.print("application-blocked")
        IO.pure(Reply(), (socket, driver))
    case True{}: IO.bind(Discovery.RU(), Reply(), W.wire_udp_send_to(socket, C.host(peer), C.port(peer), [165, 90, 71, 82, 79, 85, 78, 68, 83], 1000),
      r => application_sent(r, driver))

def application_route(ref: Pairs.Ref, gen: U32, +state: Consent.State, socket: Socket, base: Stun.IPv4, end: Nat, renewals: U32, scenario: String, now: Nat) -> IO(Reply()):
  match ref:
    case Pairs.Ref{sid, component, local, +peer}:
      application_due(Consent.allowed(state, Pairs.Ref{sid, component, local, peer}, gen, now), socket, Driver{state, base, end, renewals, scenario}, peer)

def application_now(+now: Nat, socket: Socket, driver: Driver) -> IO(Reply()):
  match driver:
    case Driver{Consent.State{Consent.Route{+ref, +gen, creds, check, mode}, clock, probes, recent, token}, base, end, renewals, scenario}:
      application_route(ref, gen, Consent.State{Consent.Route{ref, gen, creds, check, mode}, clock, probes, recent, token}, socket, base, end, renewals, scenario, now)

def acknowledged(step: Consent.Step, socket: Socket, driver: Driver) -> IO(Reply()):
  match step driver:
    case Consent.Step{changed, events} Driver{_, base, end, renewals, scenario}:
      do IO<Reply()>:
        x : Unit <- Format.events(events)
        IO.pure(Reply(), (socket, Driver{changed, base, end, renewals, scenario}))

def sent_result(result: Result<&1, &1, U32 & String, Unit>, socket: Socket, driver: Driver, notice: Consent.Notice) -> IO(Reply()):
  match result driver notice:
    case Done{_} Driver{+state, base, end, renewals, scenario} n:
      do IO<Reply()>:
        now : Nat <- IO.now()
        acknowledged(Consent.acknowledge(state, n, now), socket, Driver{state, base, end, renewals, scenario})
    case Fail{(code, _)} Driver{state, base, end, renewals, scenario} Consent.Send{_, _, token, _}:
      fatal(socket, "fixture UDP send failed")
    case _ _ _: fatal(socket, "invalid send acknowledgement")

def sent(reply: Discovery.RU(), driver: Driver, notice: Consent.Notice) -> IO(Reply()):
  (socket, result) = reply
  sent_result(result, socket, driver, notice)

def send_due(current: Bool, socket: Socket, driver: Driver, notice: Consent.Notice) -> IO(Reply()):
  match current notice:
    case False{} _: IO.pure(Reply(), (socket, driver))
    case True{} Consent.Send{Pairs.Ref{sid, component, base, +peer}, gen, token, +bytes}:
      IO.bind(Discovery.RU(), Reply(), W.wire_udp_send_to(socket, C.host(peer), C.port(peer), bytes, 1000),
        r => sent(r, driver, Consent.Send{Pairs.Ref{sid, component, base, peer}, gen, token, bytes}))
    case _ _: IO.pure(Reply(), (socket, driver))

def send_now(+now: Nat, socket: Socket, +driver: Driver, +notice: Consent.Notice) -> IO(Reply()):
  match driver:
    case Driver{+state, base, end, renewals, scenario}:
      send_due(Consent.current_send(state, notice, now), socket, Driver{state, base, end, renewals, scenario}, notice)

def event(+notice: Consent.Notice, socket: Socket, driver: Driver) -> IO(Reply()):
  match notice driver:
    case Consent.Send{_, _, _, _} d:
      do IO<Reply()>:
        now : Nat <- IO.now()
        send_now(now, socket, d, notice)
    case Consent.Renewed{_, _} Driver{state, base, end, renewals, scenario}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        application_now(now, socket, Driver{state, base, end, (renewals + 1 : U32), scenario})
    case Consent.Changed{_} d:
      do IO<Reply()>:
        now : Nat <- IO.now()
        application_now(now, socket, d)
    case _ d: IO.pure(Reply(), (socket, d))

def continued(reply: Reply(), tail: List<&2, Consent.Notice>, again: Socket -> Driver -> List<&2, Consent.Notice> -> IO(Reply())) -> IO(Reply()):
  (socket, driver) = reply
  again(socket, driver, tail)

def execute(fuel: Nat, socket: Socket, driver: Driver, values: List<&2, Consent.Notice>) -> IO(Reply()):
  match fuel values:
    case _ Nil{}: IO.pure(Reply(), (socket, driver))
    case 0n _: fatal(socket, "fixture directive fuel")
    case 1n+p Con{+head, tail}:
      do IO<Reply()>:
        x : Unit <- Format.event(head)
        IO.bind(Reply(), Reply(), event(head, socket, driver), r => continued(r, tail, s => d => rest => execute(p, s, d, rest)))

def execute_step(step: Consent.Step, socket: Socket, driver: Driver) -> IO(Reply()):
  match step driver:
    case Consent.Step{state, events} Driver{_, base, end, renewals, scenario}:
      execute(32n, socket, Driver{state, base, end, renewals, scenario}, events)

def started(start: Consent.Start, socket: Socket, driver: Driver) -> IO(Reply()):
  match start:
    case Consent.Ready{step}: execute_step(step, socket, driver)
    case Consent.Later{step, _}: execute_step(step, socket, driver)
    case Consent.Rejected{step}: execute_step(step, socket, driver)

def jitter_random(value: Result<&1, &1, U32 & String, U32>, socket: Socket, driver: Driver, tx: List<&2, U32>, +now: Nat) -> IO(Reply()):
  match value driver:
    case Done{+word} Driver{+state, base, end, renewals, scenario}:
      started(Consent.start(state, tx, U32.from_nat(Nat.mod(U32.to_nat(word), 2001n)), now, now), socket, Driver{state, base, end, renewals, scenario})
    case Fail{_} _: fatal(socket, "host RNG failed")

def start_random(value: Entropy.Entropy(), socket: Socket, driver: Driver, now: Nat) -> IO(Reply()):
  match value:
    case Done{(a, (b, c))}:
      IO.bind(Result<&1, &1, U32 & String, U32>, Reply(), IO.random_u32(), word => jitter_random(word, socket, driver, Discovery.transaction(a, b, c), now))
    case Fail{_}: fatal(socket, "host RNG failed")

def begin(reply: Reply()) -> IO(Reply()):
  (socket, driver) = reply
  do IO<Reply()>:
    now : Nat <- IO.now()
    IO.bind(Entropy.Entropy(), Reply(), Entropy.random(), e => start_random(e, socket, driver, now))

def observed(source: Maybe<&2, Stun.IPv4>, socket: Socket, driver: Driver, raw: List<&2, U32>, now: Nat) -> IO(Reply()):
  match source driver:
    case None{} d: IO.pure(Reply(), (socket, d))
    case Some{peer} Driver{+state, +base, end, renewals, scenario}:
      execute_step(Consent.receive(state, Pairs.Ref{1, 1, base, peer}, 7, raw, now), socket, Driver{state, base, end, renewals, scenario})

def received_result(result: Result<&1, &1, U32 & String, Maybe<&1, String & U32 & List<&2, U32>>>, socket: Socket, driver: Driver, now: Nat) -> IO(Reply()):
  match result driver:
    case Done{None{}} d: IO.pure(Reply(), (socket, d))
    case Done{Some{(host, (port, raw))}} d: observed(C.address_read(host, port), socket, d, raw, now)
    case Fail{_} _: fatal(socket, "fixture UDP receive failed")

def received(reply: Discovery.RD(), driver: Driver) -> IO(Reply()):
  (socket, result) = reply
  do IO<Reply()>:
    now : Nat <- IO.now()
    received_result(result, socket, driver, now)

def poll(reply: Reply()) -> IO(Reply()):
  (socket, driver) = reply
  match driver:
    case Driver{+state, base, end, renewals, scenario}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        IO.bind(Discovery.RD(), Reply(), W.wire_udp_recv_from_timeout(socket, 65535, Consent.timeout(state, now, 20)),
          r => received(r, Driver{state, base, end, renewals, scenario}))

def done(status: Consent.Status, renewals: U32, scenario: String) -> Bool:
  match status scenario:
    case Consent.Expired{} _: True{}
    case Consent.Revoked{} _: True{}
    case Consent.Closed{} _: True{}
    case _ "renew": U32.is_le(2, renewals)
    case _ "first": U32.is_le(1, renewals)
    case _ _: False{}

def finish_state(+state: Consent.State, socket: Socket, renewals: U32, now: Nat, text: String) -> IO(Unit):
  match state:
    case Consent.State{Consent.Route{+ref, +gen, _, _, _}, Consent.Clock{status, _, _, _, _, _}, _, _, _}:
      do IO<Unit>:
        a : Unit <- Socket.close(socket)
        b : Unit <- IO.print(text)
        c : Unit <- IO.print("status:" ++ Format.status(status))
        d : Unit <- IO.print("allowed:" ++ Format.flag(Consent.allowed(state, ref, gen, now)))
        e : Unit <- IO.print("renewals:" ++ U32.show(renewals))
        IO.print("done")

def finish(socket: Socket, driver: Driver, now: Nat, text: String) -> IO(Unit):
  match driver:
    case Driver{state, _, _, renewals, _}: finish_state(state, socket, renewals, now, text)

def loop_reply(reply: Reply(), again: Socket -> Driver -> IO(Unit)) -> IO(Unit):
  (socket, driver) = reply
  again(socket, driver)

def timed(finished: Bool, expired: Bool, socket: Socket, driver: Driver, +now: Nat, again: Socket -> Driver -> IO(Unit)) -> IO(Unit):
  match finished expired driver:
    case True{} _ d: finish(socket, d, now, "terminal")
    case False{} True{} d: finish(socket, d, now, "fixture-expired")
    case False{} False{} Driver{+state, base, end, renewals, scenario}:
      IO.bind(Reply(), Unit, IO.bind(Reply(), Reply(), IO.bind(Reply(), Reply(),
        execute_step(Consent.tick(state, now), socket, Driver{state, base, end, renewals, scenario}), begin), poll), r => loop_reply(r, again))

def at_now(+now: Nat, socket: Socket, driver: Driver, again: Socket -> Driver -> IO(Unit)) -> IO(Unit):
  match driver:
    case Driver{Consent.State{route, Consent.Clock{+status, expires, next, rto, mean, variation}, probes, recent, token}, base, +end, +renewals, +scenario}:
      timed(done(status, renewals, scenario), Nat.is_le(end, now), socket,
        Driver{Consent.State{route, Consent.Clock{status, expires, next, rto, mean, variation}, probes, recent, token}, base, end, renewals, scenario}, now, again)

def loop(fuel: Nat, socket: Socket, driver: Driver) -> IO(Unit):
  match fuel:
    case 0n: finish(socket, driver, 0n, "fixture-fuel")
    case 1n+p:
      do IO<Unit>:
        now : Nat <- IO.now()
        at_now(now, socket, driver, s => d => loop(p, s, d))

def created(value: Maybe<&2, Consent.State>, socket: Socket, base: Stun.IPv4, +now: Nat, scenario: String) -> IO(Unit):
  match value:
    case None{}:
      do IO<Unit>:
        x : Unit <- Socket.close(socket)
        IO.die(Unit, 3, "fixture route failed")
    case Some{state}:
      do IO<Unit>:
        x : Unit <- IO.print("ready")
        loop(8192n, socket, Driver{state, base, Nat.add(now, 35000n), 0, scenario})

def located(+base: Stun.IPv4, socket: Socket, peer: U32, mode: Auth.Mode, scenario: String, +now: Nat) -> IO(Unit):
  created(Consent.create(Consent.Route{Pairs.Ref{1, 1, base, Stun.IPv4{127, 0, 0, 1, peer}}, 7,
    Ice.Credentials{"localFrag", "remoteFrag", "SyntheticPassword123456789"}, Ice.Check{1845494271, Ice.Controlling{0, 1}}, mode}, 500, now), socket, base, now, scenario)

def named_result(result: Result<&1, &1, U32 & String, String & U32>, socket: Socket, peer: U32, mode: Auth.Mode, scenario: String) -> IO(Unit):
  match result:
    case Done{(host, +port)}:
      do IO<Unit>:
        x : Unit <- IO.print("base:" ++ host ++ "/" ++ U32.show(port))
        now : Nat <- IO.now()
        located(Stun.IPv4{127, 0, 0, 1, port}, socket, peer, mode, scenario, now)
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

def configured(peer: U32, mode: Auth.Mode, scenario: String) -> IO(Unit):
  IO.bind(Result<&1, &1, U32 & String, Socket>, Unit, W.wire_udp_bind("127.0.0.1", 0), r => bound(r, peer, mode, scenario))

def parsed(peer: Maybe<&2, U32>, mode: String, scenario: String) -> IO(Unit):
  match peer mode:
    case Some{p} "legacy": configured(p, Auth.Legacy{}, scenario)
    case Some{p} "sha256": configured(p, Auth.Sha256{}, scenario)
    case Some{p} "dual": configured(p, Auth.Dual{}, scenario)
    case _ _: IO.die(Unit, 2, "bad fixture arguments")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [peer, mode, scenario]: parsed(U32.read(peer), mode, scenario)
    case _: IO.die(Unit, 2, "usage: ice_consent_udp <port> <mode> <expiry|renew|revoke|first>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
