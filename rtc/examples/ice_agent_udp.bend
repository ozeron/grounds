import Base
import ../ice_agent.bend as Agent
import ../ice_valid.bend as V
import ../ice_session.bend as Session
import ../ice_attempts.bend as A
import ../ice_scheduler.bend as S
import ../ice_pairs.bend as Pairs
import ../ice_candidates.bend as C
import ../ice_checklist.bend as Check
import ../ice_binding.bend as Ice
import ../ice_incoming.bend as Incoming
import ../ice_transactions.bend as Tx
import ../stun.bend as Stun
import ../stun_auth.bend as Auth
import ../stun_retry.bend as Retry
import ../stun_client.bend as Discovery
import ./ice_session_output.bend as Output
import ./ice_valid_output.bend as ValidOutput
import ./ice_agent.bend as Format
import ./ice_session_udp.bend as Entropy
import ../../wire/wire.bend as W

# OS effects only. All packet construction, authentication, nomination and
# lifecycle decisions run through Agent on this one retained actual UDP socket.
type Driver is Data:
  Driver{state: Agent.State, base: Stun.IPv4, end: Nat, finished_at: Maybe<&2, Nat>}

def Reply() -> Type:
  Socket & Driver

def fatal(socket: Socket, message: String) -> IO(Reply()):
  do IO<Reply()>:
    x : Unit <- Socket.close(socket)
    IO.die(Reply(), 3, message)

def updated(step: Agent.Step, driver: Driver) -> IO(Driver):
  match step driver:
    case Agent.Step{state, events, valid, _, life} Driver{_, base, end, at}:
      do IO<Driver>:
        x : Unit <- Output.events(events)
        y : Unit <- ValidOutput.notices(valid)
        z : Unit <- Format.lifecycle(life)
        IO.pure(Driver, Driver{state, base, end, at})

def sent_result(result: Result<&1, &1, U32 & String, Unit>, socket: Socket, driver: Driver, notice: Session.Notice) -> IO(Reply()):
  match result driver:
    case Done{_} Driver{+state, +base, +end, +at}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        d : Driver <- updated(Agent.acknowledge(state, notice, now), Driver{state, base, end, at})
        IO.pure(Reply(), (socket, d))
    case Fail{_} _: fatal(socket, "fixture UDP send failed")

def sent(reply: Discovery.RU(), driver: Driver, notice: Session.Notice) -> IO(Reply()):
  (socket, result) = reply
  sent_result(result, socket, driver, notice)

def send(current: Bool, socket: Socket, driver: Driver, reference: Pairs.Ref, bytes: List<&2, U32>, notice: Session.Notice) -> IO(Reply()):
  match current reference:
    case False{} _: IO.pure(Reply(), (socket, driver))
    case True{} Pairs.Ref{_, _, _, +peer}:
      IO.bind(Discovery.RU(), Reply(), W.wire_udp_send_to(socket, C.host(peer), C.port(peer), bytes, 1000), r => sent(r, driver, notice))

def event(+notice: Session.Notice, socket: Socket, +driver: Driver) -> IO(Reply()):
  match notice driver:
    case Session.Attempt{A.Transaction{Some{A.Record{S.Flight{_, ref, _}, _, _, _}}, Tx.Send{_, _, _, bytes, _}}} Driver{state, _, _, _}:
      send(Agent.current_send(state, notice), socket, driver, ref, bytes, notice)
    case Session.Reply{ref, bytes, _} _: send(True{}, socket, driver, ref, bytes, notice)
    case _ _: IO.pure(Reply(), (socket, driver))

def continued(reply: Reply(), again: Socket -> Driver -> IO(Reply())) -> IO(Reply()):
  (socket, driver) = reply
  again(socket, driver)

def execute(fuel: Nat, values: List<&2, Session.Notice>, socket: Socket, driver: Driver) -> IO(Reply()):
  match fuel values:
    case _ Nil{}: IO.pure(Reply(), (socket, driver))
    case 0n _: fatal(socket, "fixture event limit")
    case 1n+p Con{+head, tail}:
      do IO<Reply()>:
        x : Unit <- Output.event(head)
        IO.bind(Reply(), Reply(), event(head, socket, driver), r => continued(r, s => d => execute(p, tail, s, d)))

def execute_step(step: Agent.Step, socket: Socket, driver: Driver) -> IO(Reply()):
  match step driver:
    case Agent.Step{state, +events, valid, _, life} Driver{_, base, end, at}:
      do IO<Reply()>:
        x : Unit <- ValidOutput.notices(valid)
        y : Unit <- Format.lifecycle(life)
        execute(Nat.add(List.length(&2, Session.Notice, events), 1n), events, socket, Driver{state, base, end, at})

def received_source(source: Maybe<&2, Stun.IPv4>, raw: List<&2, U32>, socket: Socket, driver: Driver) -> IO(Reply()):
  match source driver:
    case Some{peer} Driver{+state, +base, +end, +at}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        execute_step(Agent.receive(state, Pairs.Ref{1, 1, base, peer}, raw, now), socket, Driver{state, base, end, at})
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
    case Driver{+state, _, _, _}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        IO.bind(Discovery.RD(), Reply(), W.wire_udp_recv_from_timeout(socket, 65535, Agent.timeout(state, now, 10)), r => received(r, driver))

def start_random(entropy: Entropy.Entropy(), socket: Socket, driver: Driver, now: Nat) -> IO(Reply()):
  match entropy driver:
    case Done{(a, (b, c))} Driver{+state, +base, +end, +at}:
      execute_step(Agent.start(state, Discovery.transaction(a, b, c), Retry.Policy{500, 2, 1}, now), socket, Driver{state, base, end, at})
    case Fail{_} _: fatal(socket, "fixture host RNG failed")

def begin(reply: Reply()) -> IO(Reply()):
  (socket, driver) = reply
  do IO<Reply()>:
    now : Nat <- IO.now()
    IO.bind(Entropy.Entropy(), Reply(), Entropy.random(), e => start_random(e, socket, driver, now))

def finish(socket: Socket, driver: Driver, text: String) -> IO(Unit):
  match driver:
    case Driver{+state, _, _, _}:
      do IO<Unit>:
        x : Unit <- Socket.close(socket)
        y : Unit <- IO.print(text)
        z : Unit <- IO.print("agent-status:" ++ Format.status_text(Agent.status(state)))
        v : V.State <- ValidOutput.snapshot(Agent.valid(state))
        s : Unit <- IO.print("selected:" ++ Format.status_text(Agent.status(state)))
        f : Unit <- Format.selected([1], 1, state)
        IO.print("done")

def stopped_due(at: Maybe<&2, Nat>, now: Nat) -> Bool:
  match at:
    case None{}: False{}
    case Some{deadline}: Nat.is_le(deadline, now)

def terminal_at(at: Maybe<&2, Nat>, +status: Agent.Status, now: Nat) -> Maybe<&2, Nat>:
  match at:
    case Some{d}: Some{d}
    case None{}:
      Bool.pick(Maybe<&2, Nat>, Agent.same_status(status, Agent.Running{}), None{}, Some{Nat.add(now, 800n)})

def loop_reply(reply: Reply(), again: Socket -> Driver -> IO(Unit)) -> IO(Unit):
  (socket, driver) = reply
  again(socket, driver)

def timed(expired: Bool, stopped: Bool, +now: Nat, socket: Socket, driver: Driver, again: Socket -> Driver -> IO(Unit)) -> IO(Unit):
  match expired stopped driver:
    case True{} _ d: finish(socket, d, "fixture-expired")
    case False{} True{} d: finish(socket, d, "terminal")
    case False{} False{} Driver{+state, +base, +end, +at}:
      IO.bind(Reply(), Unit,
        IO.bind(Reply(), Reply(), IO.bind(Reply(), Reply(), execute_step(Agent.tick(state, now), socket,
          Driver{state, base, end, terminal_at(at, Agent.status(state), now)}), begin), poll),
        r => loop_reply(r, again))

def at_now(+now: Nat, socket: Socket, driver: Driver, again: Socket -> Driver -> IO(Unit)) -> IO(Unit):
  match driver:
    case Driver{state, base, +end, +at}:
      timed(Nat.is_le(end, now), stopped_due(at, now), now, socket, Driver{state, base, end, at}, again)

def loop(fuel: Nat, socket: Socket, driver: Driver) -> IO(Unit):
  match fuel:
    case 0n: finish(socket, driver, "fixture-fuel")
    case 1n+p:
      do IO<Unit>:
        now : Nat <- IO.now()
        at_now(now, socket, driver, s => d => loop(p, s, d))

def bound_peer(value: Maybe<&2, Agent.Step>, socket: Socket, base: Stun.IPv4, +now: Nat) -> IO(Unit):
  match value:
    case None{}:
      do IO<Unit>:
        x : Unit <- Socket.close(socket)
        IO.die(Unit, 3, "fixture credentials failed")
    case Some{Agent.Step{state, _, _, _, _}}:
      do IO<Unit>:
        x : Unit <- IO.print("ready")
        loop(16384n, socket, Driver{state, base, Nat.add(now, 8000n), None{}})

def signaled(step: Agent.Step, socket: Socket, base: Stun.IPv4, +now: Nat) -> IO(Unit):
  match step:
    case Agent.Step{state, _, _, _, _}:
      bound_peer(Agent.bind(state, Ice.Credentials{"localFrag", "remoteFrag", "SyntheticPassword123456789"}, now), socket, base, now)

def signal_now(+now: Nat, state: Agent.State, socket: Socket, base: Stun.IPv4) -> IO(Unit):
  signaled(Agent.local_signaled(state, now), socket, base, now)

def created(value: Maybe<&2, Agent.State>, socket: Socket, base: Stun.IPv4) -> IO(Unit):
  match value:
    case None{}:
      do IO<Unit>:
        x : Unit <- Socket.close(socket)
        IO.die(Unit, 3, "fixture agent creation failed")
    case Some{state}:
      do IO<Unit>:
        now : Nat <- IO.now()
        signal_now(now, state, socket, base)

def local_address(+base: Stun.IPv4, socket: Socket, peer: U32, mode: Auth.Mode, controlled: Bool) -> IO(Unit):
  +local : C.Candidate = C.Candidate{1, 2130706431, "host", C.Host{}, base}
  +streams : List<&2, Check.Stream> = [Check.Stream{1, [C.Local{local, local}], [C.Candidate{1, 2100000000, "remote", C.Host{}, Stun.IPv4{127, 0, 0, 1, peer}}]}]
  created(Maybe.bind(&2, V.State, Agent.State,
    V.from_session(Session.create(streams, Bool.pick(Ice.Role, controlled, Ice.Controlled{0, 1}, Ice.Controlling{0, 1}),
      Incoming.Secret{"localFrag", "LocalFixturePassword123456"}, mode, 100, 4, 7), 100), v => Agent.create(v, Agent.Config{1200, True{}})), socket, base)

def named_result(result: Result<&1, &1, U32 & String, String & U32>, socket: Socket, peer: U32, mode: Auth.Mode, controlled: Bool) -> IO(Unit):
  match result:
    case Done{(host, +port)}:
      do IO<Unit>:
        x : Unit <- IO.print("base:" ++ host ++ "/" ++ U32.show(port))
        local_address(Stun.IPv4{127, 0, 0, 1, port}, socket, peer, mode, controlled)
    case Fail{_}:
      do IO<Unit>:
        x : Unit <- Socket.close(socket)
        IO.die(Unit, 3, "fixture local address failed")

def named(reply: Socket & Result<&1, &1, U32 & String, String & U32>, peer: U32, mode: Auth.Mode, controlled: Bool) -> IO(Unit):
  (socket, result) = reply
  named_result(result, socket, peer, mode, controlled)

def bound(result: Result<&1, &1, U32 & String, Socket>, peer: U32, mode: Auth.Mode, controlled: Bool) -> IO(Unit):
  match result:
    case Done{socket}: IO.bind(Socket & Result<&1, &1, U32 & String, String & U32>, Unit, W.wire_udp_local_address(socket), r => named(r, peer, mode, controlled))
    case Fail{_}: IO.die(Unit, 3, "fixture UDP bind failed")

def configured(peer: U32, mode: Auth.Mode, controlled: Bool) -> IO(Unit):
  IO.bind(Result<&1, &1, U32 & String, Socket>, Unit, W.wire_udp_bind("127.0.0.1", 0), r => bound(r, peer, mode, controlled))

def parsed(peer: Maybe<&2, U32>, mode: String, scenario: String) -> IO(Unit):
  match peer mode scenario:
    case Some{p} "legacy" s: configured(p, Auth.Legacy{}, String.eq(s, "controlled"))
    case Some{p} "sha256" s: configured(p, Auth.Sha256{}, String.eq(s, "controlled"))
    case Some{p} "dual" s: configured(p, Auth.Dual{}, String.eq(s, "controlled"))
    case _ _ _: IO.die(Unit, 2, "bad fixture arguments")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [port, mode, scenario]: parsed(U32.read(port), mode, scenario)
    case _: IO.die(Unit, 2, "usage: ice_agent_udp <port> <mode> <controlling|controlled>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
