import Base
import ../ice_scheduler.bend as S
import ../ice_session.bend as Session
import ../ice_attempts.bend as A
import ../ice_binding.bend as Ice
import ../ice_incoming.bend as Incoming
import ../ice_candidates.bend as C
import ../ice_checklist.bend as Check
import ../ice_pairs.bend as Pairs
import ../ice_transactions.bend as Tx
import ../ice_reliable.bend as Reliable
import ../ice_response.bend as Response
import ../stun.bend as Stun
import ../stun_auth.bend as Auth
import ../stun_retry.bend as Retry
import ../stun_client.bend as Discovery
import ./ice_session_output.bend as Output
import ../../wire/wire.bend as W

type Driver is Data:
  Driver{state: Session.State, first: Stun.IPv4, second: Stun.IPv4, bind_at: Nat, end: Nat, bound: Bool, next: Bool}

def Reply() -> Type:
  Socket & Socket & Driver

def Entropy() -> Type:
  Result<&1, &1, U32 & String, U32 & U32 & U32>

def random_third(c: Result<&1, &1, U32 & String, U32>, a: U32, b: U32) -> IO(Entropy()):
  match c:
    case Done{c}: IO.pure(Entropy(), Done{(a, (b, c))})
    case Fail{error}: IO.pure(Entropy(), Fail{error})

def random_second(b: Result<&1, &1, U32 & String, U32>, a: U32) -> IO(Entropy()):
  match b:
    case Done{b}: IO.bind(Result<&1, &1, U32 & String, U32>, Entropy(), IO.random_u32(), c => random_third(c, a, b))
    case Fail{error}: IO.pure(Entropy(), Fail{error})

def random_first(a: Result<&1, &1, U32 & String, U32>) -> IO(Entropy()):
  match a:
    case Done{a}: IO.bind(Result<&1, &1, U32 & String, U32>, Entropy(), IO.random_u32(), b => random_second(b, a))
    case Fail{error}: IO.pure(Entropy(), Fail{error})

def random() -> IO(Entropy()):
  IO.bind(Result<&1, &1, U32 & String, U32>, Entropy(), IO.random_u32(), a => random_first(a))

def fatal(a: Socket, b: Socket, message: String) -> IO(Reply()):
  do IO<Reply()>:
    x : Unit <- Socket.close(a)
    y : Unit <- Socket.close(b)
    IO.die(Reply(), 3, message)

def position(first: Bool, socket: Socket, other: Socket, driver: Driver) -> Reply():
  match first:
    case True{}: (socket, (other, driver))
    case False{}: (other, (socket, driver))

def updated(step: Session.Step, driver: Driver) -> IO(Driver):
  match step driver:
    case Session.Step{state, events} Driver{_, first, second, bind_at, end, bound, next}:
      do IO<Driver>:
        x : Unit <- Output.events(events)
        IO.pure(Driver, Driver{state, first, second, bind_at, end, bound, next})

def sent_result(result: Result<&1, &1, U32 & String, Unit>, socket: Socket, other: Socket, first: Bool,
                driver: Driver, notice: Session.Notice) -> IO(Reply()):
  match result driver:
    case Done{_} Driver{+state, +base, +second, +bind_at, +end, +bound, +next}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        changed : Driver <- updated(Session.acknowledge(state, notice, now), Driver{state, base, second, bind_at, end, bound, next})
        IO.pure(Reply(), position(first, socket, other, changed))
    case Fail{_} _: fatal(socket, other, "UDP session send failed")

def sent(reply: Discovery.RU(), other: Socket, first: Bool, driver: Driver, notice: Session.Notice) -> IO(Reply()):
  (socket, result) = reply
  sent_result(result, socket, other, first, driver, notice)

def send_on(first: Bool, a: Socket, b: Socket, driver: Driver, +reference: Pairs.Ref, bytes: List<&2, U32>, notice: Session.Notice) -> IO(Reply()):
  match first reference:
    case True{} Pairs.Ref{_, _, _, +remote}:
      IO.bind(Discovery.RU(), Reply(), W.wire_udp_send_to(a, C.host(remote), C.port(remote), bytes, 1000), m => sent(m, b, True{}, driver, notice))
    case False{} Pairs.Ref{_, _, _, +remote}:
      IO.bind(Discovery.RU(), Reply(), W.wire_udp_send_to(b, C.host(remote), C.port(remote), bytes, 1000), m => sent(m, a, False{}, driver, notice))

def send_registered(registered: Bool, first: Bool, a: Socket, b: Socket, driver: Driver, reference: Pairs.Ref, bytes: List<&2, U32>, notice: Session.Notice) -> IO(Reply()):
  match registered:
    case False{}: fatal(a, b, "unregistered send base")
    case True{}: send_on(first, a, b, driver, reference, bytes, notice)

def send(a: Socket, b: Socket, driver: Driver, reference: Pairs.Ref, bytes: List<&2, U32>, notice: Session.Notice) -> IO(Reply()):
  match driver reference:
    case Driver{+state, +first, +second, +bind_at, +end, +bound, +next} Pairs.Ref{+id, +component, +base, +remote}:
      send_registered(Bool.or(C.address_same(base, first), C.address_same(base, second)), C.address_same(base, first), a, b,
        Driver{state, first, second, bind_at, end, bound, next}, Pairs.Ref{id, component, base, remote}, bytes, notice)

def current_send(ok: Bool, a: Socket, b: Socket, driver: Driver, reference: Pairs.Ref, bytes: List<&2, U32>, notice: Session.Notice) -> IO(Reply()):
  match ok:
    case False{}: IO.pure(Reply(), (a, (b, driver)))
    case True{}: send(a, b, driver, reference, bytes, notice)

def repaired(value: Maybe<&2, Session.Step>, a: Socket, b: Socket, driver: Driver,
             again: Socket -> Socket -> Driver -> IO(Reply())) -> IO(Reply()):
  match value:
    case None{}: again(a, b, driver)
    case Some{s}:
      do IO<Reply()>:
        changed : Driver <- updated(s, driver)
        return (a, (b, changed))

def repair_random(value: Entropy(), a: Socket, b: Socket, driver: Driver, token: U32, gen: U32,
                  again: Socket -> Socket -> Driver -> IO(Reply())) -> IO(Reply()):
  match value driver:
    case Done{(high, (low, _))} Driver{+state, +first, +second, +bind_at, +end, +bound, +next}:
      repaired(Session.repair(state, token, gen, high, low), a, b, Driver{state, first, second, bind_at, end, bound, next}, again)
    case Fail{_} _: fatal(a, b, "host RNG failed")

def repair_go(fuel: Nat, a: Socket, b: Socket, driver: Driver, +token: U32, +gen: U32) -> IO(Reply()):
  match fuel:
    case 0n: fatal(a, b, "conflict repair failed")
    case 1n+p: IO.bind(Entropy(), Reply(), random(), entropy => repair_random(entropy, a, b, driver, token, gen,
      sa => sb => d => repair_go(p, sa, sb, d, token, gen)))

def event(+notice: Session.Notice, a: Socket, b: Socket, driver: Driver) -> IO(Reply()):
  match notice driver:
    case Session.Attempt{A.Transaction{Some{A.Record{S.Flight{_, +ref, _}, _, _, _}}, Tx.Send{_, _, _, bytes, _}}}
         Driver{+state, +first, +second, +bind_at, +end, +bound, +next}:
      current_send(Session.current_send(state, notice), a, b, Driver{state, first, second, bind_at, end, bound, next}, ref, bytes, notice)
    case Session.Reply{ref, bytes, _} d: send(a, b, d, ref, bytes, notice)
    case Session.Attempt{A.Transaction{Some{A.Record{S.Flight{_, _, _}, gen, _, _}}, Tx.Finished{token, Reliable.Received{Response.Error{487}, _}}}} d:
      repair_go(16n, a, b, d, token, gen)
    case _ d: IO.pure(Reply(), (a, (b, d)))

def continued(reply: Reply(), tail: List<&2, Session.Notice>, again: Socket -> Socket -> Driver -> List<&2, Session.Notice> -> IO(Reply())) -> IO(Reply()):
  (a, (b, driver)) = reply
  again(a, b, driver, tail)

def show_event(value: Session.Notice) -> IO(Unit):
  match value:
    case Session.Attempt{A.AtCapacity{}}: IO.pure(Unit, Unit{})
    case Session.Attempt{A.Waiting{_}}: IO.pure(Unit, Unit{})
    case Session.Attempt{A.Idle{}}: IO.pure(Unit, Unit{})
    case Session.Attempt{A.Invalid{}}: IO.pure(Unit, Unit{})
    case Session.WaitingCredentials{}: IO.pure(Unit, Unit{})
    case v: Output.event(v)

def execute(fuel: Nat, a: Socket, b: Socket, driver: Driver, values: List<&2, Session.Notice>) -> IO(Reply()):
  match fuel values:
    case _ Nil{}: IO.pure(Reply(), (a, (b, driver)))
    case 0n _: fatal(a, b, "session directive fuel exhausted")
    case 1n+p Con{+head, tail}:
      do IO<Reply()>:
        x : Unit <- show_event(head)
        IO.bind(Reply(), Reply(), event(head, a, b, driver), r => continued(r, tail, sa => sb => d => rest => execute(p, sa, sb, d, rest)))

def execute_step(step: Session.Step, a: Socket, b: Socket, driver: Driver) -> IO(Reply()):
  match step driver:
    case Session.Step{state, +values} Driver{_, first, second, bind_at, end, bound, next}:
      execute(Nat.add(List.length(&2, Session.Notice, values), 1n), a, b, Driver{state, first, second, bind_at, end, bound, next}, values)

def received_source(source: Maybe<&2, Stun.IPv4>, +base: Stun.IPv4, raw: List<&2, U32>, a: Socket, b: Socket, driver: Driver) -> IO(Reply()):
  match source driver:
    case Some{peer} Driver{+state, +first, +second, +bind_at, +end, +bound, +next}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        execute_step(Session.receive(state, Pairs.Ref{1, 1, base, peer}, raw, now), a, b, Driver{state, first, second, bind_at, end, bound, next})
    case None{} d: IO.pure(Reply(), (a, (b, d)))

def receive_failed(oversize: Bool, first: Bool, socket: Socket, other: Socket, driver: Driver) -> IO(Reply()):
  match oversize:
    case True{}: IO.pure(Reply(), position(first, socket, other, driver))
    case False{}: fatal(socket, other, "UDP session receive failed")

def received_result(result: Result<&1, &1, U32 & String, Maybe<&1, String & U32 & List<&2, U32>>>, socket: Socket, other: Socket,
                    first: Bool, base: Stun.IPv4, driver: Driver) -> IO(Reply()):
  match result first:
    case Done{Some{(+host, (+port, raw))}} True{}: received_source(C.address_read(host, port), base, raw, socket, other, driver)
    case Done{Some{(+host, (+port, raw))}} False{}: received_source(C.address_read(host, port), base, raw, other, socket, driver)
    case Done{None{}} f: IO.pure(Reply(), position(f, socket, other, driver))
    case Fail{(+code, _)} f: receive_failed(Bool.or(U32.is_eq(code, 40), U32.is_eq(code, 90)), f, socket, other, driver)

def received(reply: Discovery.RD(), other: Socket, first: Bool, base: Stun.IPv4, driver: Driver) -> IO(Reply()):
  (socket, result) = reply
  received_result(result, socket, other, first, base, driver)

def poll(a: Socket, b: Socket, driver: Driver) -> IO(Reply()):
  match driver:
    case Driver{state, +first, second, bind_at, end, bound, True{}}:
      IO.bind(Discovery.RD(), Reply(), W.wire_udp_recv_from_timeout(a, 65535, 5),
        r => received(r, b, True{}, first, Driver{state, first, second, bind_at, end, bound, False{}}))
    case Driver{state, first, +second, bind_at, end, bound, False{}}:
      IO.bind(Discovery.RD(), Reply(), W.wire_udp_recv_from_timeout(b, 65535, 5),
        r => received(r, a, False{}, second, Driver{state, first, second, bind_at, end, bound, True{}}))

def start_random(entropy: Entropy(), a: Socket, b: Socket, driver: Driver, now: Nat) -> IO(Reply()):
  match entropy driver:
    case Done{(x, (y, z))} Driver{+state, +first, +second, +bind_at, +end, +bound, +next}:
      execute_step(Session.start(state, Discovery.transaction(x, y, z), Retry.Policy{500, 3, 1}, now), a, b,
        Driver{state, first, second, bind_at, end, bound, next})
    case Fail{_} _: fatal(a, b, "host RNG failed")

def begin(reply: Reply()) -> IO(Reply()):
  (a, (b, driver)) = reply
  do IO<Reply()>:
    now : Nat <- IO.now()
    IO.bind(Entropy(), Reply(), random(), entropy => start_random(entropy, a, b, driver, now))

def bound(value: Maybe<&2, Session.Step>, a: Socket, b: Socket, driver: Driver) -> IO(Reply()):
  match value driver:
    case None{} _: fatal(a, b, "session credential binding failed")
    case Some{s} Driver{state, first, second, bind_at, end, _, next}:
      execute_step(s, a, b, Driver{state, first, second, bind_at, end, True{}, next})

def binding(due: Bool, a: Socket, b: Socket, driver: Driver) -> IO(Reply()):
  match due driver:
    case False{} d: IO.pure(Reply(), (a, (b, d)))
    case True{} Driver{+state, +first, +second, +bind_at, +end, +was_bound, +next}:
      bound(Session.bind(state, Ice.Credentials{"localFrag", "remoteFrag", "SyntheticPassword123456789"}), a, b,
        Driver{state, first, second, bind_at, end, was_bound, next})

def prepare(a: Socket, b: Socket, driver: Driver, +now: Nat) -> IO(Reply()):
  match driver:
    case Driver{state, first, second, +bind_at, end, +was_bound, next}:
      IO.bind(Reply(), Reply(), binding(Bool.and(Bool.not(was_bound), Nat.is_le(bind_at, now)), a, b,
        Driver{state, first, second, bind_at, end, was_bound, next}), ready => begin(ready))

def after_tick(reply: Reply()) -> IO(Reply()):
  (a, (b, driver)) = reply
  do IO<Reply()>:
    now : Nat <- IO.now()
    prepare(a, b, driver, now)

def after_start(reply: Reply()) -> IO(Reply()):
  (a, (b, driver)) = reply
  poll(a, b, driver)

def resumed(reply: Reply(), again: Socket -> Socket -> Driver -> IO(Unit)) -> IO(Unit):
  (a, (b, driver)) = reply
  again(a, b, driver)

def done(a: Socket, b: Socket, state: Session.State) -> IO(Unit):
  do IO<Unit>:
    x : Unit <- Socket.close(a)
    y : Unit <- Socket.close(b)
    final : Session.State <- Output.snapshot(state)
    z : Unit <- IO.print("done")
    IO.pure(Unit, Unit{})

def timed(expired: Bool, a: Socket, b: Socket, driver: Driver, now: Nat,
          again: Socket -> Socket -> Driver -> IO(Unit)) -> IO(Unit):
  match expired driver:
    case True{} Driver{state, _, _, _, _, _, _}: done(a, b, state)
    case False{} Driver{+state, +first, +second, +bind_at, +end, +was_bound, +next}:
      IO.bind(Reply(), Unit, IO.bind(Reply(), Reply(), IO.bind(Reply(), Reply(),
        execute_step(Session.tick(state, now), a, b, Driver{state, first, second, bind_at, end, was_bound, next}), r => after_tick(r)), r => after_start(r)),
        r => resumed(r, again))

def at_now(+now: Nat, a: Socket, b: Socket, driver: Driver, again: Socket -> Socket -> Driver -> IO(Unit)) -> IO(Unit):
  match driver:
    case Driver{+state, +first, +second, +bind_at, +end, +was_bound, +next}:
      timed(Nat.is_le(end, now), a, b, Driver{state, first, second, bind_at, end, was_bound, next}, now, again)

def loop(fuel: Nat, a: Socket, b: Socket, driver: Driver) -> IO(Unit):
  match fuel driver:
    case 0n Driver{state, _, _, _, _, _, _}: done(a, b, state)
    case 1n+p Driver{+state, +first, +second, +bind_at, +end, +was_bound, +next}:
      do IO<Unit>:
        now : Nat <- IO.now()
        at_now(now, a, b, Driver{state, first, second, bind_at, end, was_bound, next},
          sa => sb => d => loop(p, sa, sb, d))

def candidate(port: U32, priority: U32, foundation: String) -> C.Candidate:
  C.Candidate{1, priority, foundation, C.Host{}, Stun.IPv4{127, 0, 0, 1, port}}

def initialized_now(+now: Nat, a: Socket, b: Socket, state: Session.State, first: U32, second: U32, delay: U32, duration: U32) -> IO(Unit):
  loop(65536n, a, b, Driver{state, Stun.IPv4{127, 0, 0, 1, first}, Stun.IPv4{127, 0, 0, 1, second},
    Nat.add(now, U32.to_nat(delay)), Nat.add(now, U32.to_nat(duration)), False{}, True{}})

def initialized(value: Maybe<&2, Session.State>, a: Socket, b: Socket, first: U32, second: U32, delay: U32, duration: U32) -> IO(Unit):
  match value:
    case None{}:
      do IO<Unit>:
        x : Unit <- Socket.close(a)
        y : Unit <- Socket.close(b)
        IO.die(Unit, 3, "bad session input")
    case Some{state}:
      do IO<Unit>:
        now : Nat <- IO.now()
        x : Unit <- IO.print("ready")
        initialized_now(now, a, b, state, first, second, delay, duration)

def second_bound(result: Result<&1, &1, U32 & String, Socket>, a: Socket, +first: U32, +second: U32,
                 peer: U32, delay: U32, duration: U32, known: U32, capacity: U32) -> IO(Unit):
  match result:
    case Fail{_}:
      do IO<Unit>:
        x : Unit <- Socket.close(a)
        IO.die(Unit, 3, "second UDP bind failed")
    case Done{b}:
      initialized(Session.create([Check.Stream{1, [C.Local{candidate(first, 2130706431, "a"), candidate(first, 2130706431, "a")},
        C.Local{candidate(second, 2130706175, "b"), candidate(second, 2130706175, "b")}],
        Bool.pick(List<&2, C.Candidate>, U32.is_eq(known, 0), [], [candidate(peer, 2100000000, "remote")])}],
        Ice.Controlling{0, 1}, Incoming.Secret{"localFrag", "LocalFixturePassword123456"}, Auth.Dual{}, 100, capacity, 7), a, b, first, second, delay, duration)

def run(+first: U32, +second: U32, peer: U32, delay: U32, duration: U32, known: U32, capacity: U32) -> IO(Unit):
  do IO<Unit>:
    a : Socket <- IO.try(Socket, UDP.bind(first))
    IO.bind(Result<&1, &1, U32 & String, Socket>, Unit, UDP.bind(second),
      r => second_bound(r, a, first, second, peer, delay, duration, known, capacity))

def parsed(first: Maybe<&2, U32>, second: Maybe<&2, U32>, peer: Maybe<&2, U32>, delay: Maybe<&2, U32>, duration: Maybe<&2, U32>, known: Maybe<&2, U32>, capacity: Maybe<&2, U32>) -> IO(Unit):
  match first second peer delay duration known capacity:
    case Some{a} Some{b} Some{p} Some{d} Some{end} Some{k} Some{cap}: run(a, b, p, d, end, k, cap)
    case _ _ _ _ _ _ _: IO.die(Unit, 2, "bad UDP session arguments")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [first, second, peer, delay, duration, known, capacity]: parsed(U32.read(first), U32.read(second), U32.read(peer), U32.read(delay), U32.read(duration), U32.read(known), U32.read(capacity))
    case _: IO.die(Unit, 2, "usage: ice_session_udp <first-port> <second-port> <peer-port> <bind-delay-ms> <duration-ms> <known-remote> <capacity>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
