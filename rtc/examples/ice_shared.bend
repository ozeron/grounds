import Base
import ../ice_candidates.bend as C
import ../ice_checklist.bend as Check
import ../ice_transactions.bend as Tx
import ../ice_socket.bend as SocketIO
import ../ice_binding.bend as Ice
import ../ice_reliable.bend as Reliable
import ../ice_response.bend as Response
import ../stun_auth.bend as Auth
import ../stun_retry.bend as Retry
import ../stun.bend as Stun
import ../stun_client.bend as Discovery
import ../../crypto/bytes.bend as B
import ./ice_exchange.bend as Fixture

type Driver is Data:
  Driver{transactions: Tx.State, lists: List<&2, Check.Checklist>, next: Nat, done: Nat, deadline: Nat, cancel: U32}

def mapped(address: Stun.IPv4) -> String:
  match address:
    case Stun.IPv4{a, b, c, d, +p}: C.host(Stun.IPv4{a, b, c, d, p}) ++ "/" ++ U32.show(p)

def outcome(outcome: Reliable.Outcome) -> String:
  match outcome:
    case Reliable.Received{Response.Success{address}, _}: "success:" ++ mapped(address)
    case Reliable.Received{Response.Error{code}, _}: "error:" ++ U32.show(code)
    case Reliable.Received{Response.Invalid{}, _}: "invalid-response"
    case Reliable.TimedOut{}: "timeout"
    case Reliable.IntegrityViolation{}: "integrity-violation"
    case Reliable.TransportError{code}: "transport:" ++ U32.show(code)
    case Reliable.FloodLimit{}: "flood-limit"
    case Reliable.InvalidInput{}: "invalid-input"

def succeeded(outcome: Reliable.Outcome) -> Bool:
  match outcome:
    case Reliable.Received{Response.Success{_}, _}: True{}
    case _: False{}

def settled(result: Maybe<&2, List<&2, Check.Checklist>>, transactions: Tx.State,
            next: Nat, done: Nat, deadline: Nat, cancel: U32) -> IO(Driver):
  match result:
    case None{}: IO.die(Driver, 3, "invalid checklist transition")
    case Some{lists}: IO.pure(Driver, Driver{transactions, lists, next, Nat.add(done, 1n), deadline, cancel})

def late_settled(success: Bool, +token: U32, driver: Driver) -> IO(Driver):
  match success driver:
    case True{} Driver{tx, lists, next, done, deadline, cancel}:
      settled(Check.finish_check(lists, 1, U32.to_nat(token), True{}), tx, next, done, deadline, cancel)
    case False{} Driver{tx, lists, next, done, deadline, cancel}:
      IO.pure(Driver, Driver{tx, lists, next, Nat.add(done, 1n), deadline, cancel})

def notice(notice: Tx.Notice, driver: Driver) -> IO(Driver):
  match notice driver:
    case Tx.Sent{token} d:
      do IO<Driver>:
        x : Unit <- IO.print("sent:" ++ U32.show(token))
        return d
    case Tx.Finished{+token, +reply} Driver{tx, lists, next, done, deadline, cancel}:
      do IO<Driver>:
        x : Unit <- IO.print("finished:" ++ U32.show(token) ++ ":" ++ outcome(reply))
        settled(Check.finish_check(lists, 1, U32.to_nat(token), succeeded(reply)), tx, next, done, deadline, cancel)
    case Tx.Cancelled{+token} Driver{tx, lists, next, done, deadline, cancel}:
      do IO<Driver>:
        x : Unit <- IO.print("cancelled:" ++ U32.show(token))
        settled(Check.finish_check(lists, 1, U32.to_nat(token), False{}), tx, next, done, deadline, cancel)
    case Tx.Stopped{token} d:
      do IO<Driver>:
        x : Unit <- IO.print("stopped:" ++ U32.show(token))
        return d
    case Tx.LateResponse{+token, +response, mode} d:
      do IO<Driver>:
        x : Unit <- IO.print("late:" ++ U32.show(token) ++ ":" ++ outcome(Reliable.Received{response, mode}))
        late_settled(succeeded(Reliable.Received{response, Auth.Dual{}}), token, d)
    case Tx.Retired{token} Driver{tx, lists, next, done, deadline, cancel}:
      do IO<Driver>:
        x : Unit <- IO.print("retired:" ++ U32.show(token))
        return Driver{tx, lists, next, Nat.add(done, 1n), deadline, cancel}
    case Tx.Datagram{host, port, bytes} d:
      do IO<Driver>:
        x : Unit <- IO.print("datagram:" ++ host ++ ":" ++ U32.show(port) ++ ":" ++ B.hex(bytes))
        return d
    case Tx.SocketFailure{code} d:
      do IO<Driver>:
        x : Unit <- IO.print("socket-failure:" ++ U32.show(code))
        return d
    case Tx.Send{_, _, _, _, _} _: IO.die(Driver, 3, "unexecuted send")

def notices(fuel: Nat, values: List<&2, Tx.Notice>, driver: Driver) -> IO(Driver):
  match fuel values:
    case 0n _: IO.die(Driver, 3, "notice fuel exhausted")
    case 1n+_ Nil{}: IO.pure(Driver, driver)
    case 1n+p Con{head, tail}:
      do IO<Driver>:
        changed : Driver <- notice(head, driver)
        notices(p, tail, changed)

def handled(reply: SocketIO.Reply(), lists: List<&2, Check.Checklist>, next: Nat,
            done: Nat, deadline: Nat, cancel: U32,
            again: Socket -> Driver -> IO(Unit)) -> IO(Unit):
  (socket, Tx.Step{state, values}) = reply
  do IO<Unit>:
    changed : Driver <- notices(258n, values, Driver{state, lists, next, done, deadline, cancel})
    again(socket, changed)

def statuses(pairs: List<&2, Check.CandidatePair>, out: String) -> String:
  match pairs:
    case Nil{}: out
    case Con{Check.CandidatePair{_, _, _, state}, tail}: statuses(tail, out ++ ":" ++ U32.show(Check.state_code(state)))

def closed(socket: Socket, lists: List<&2, Check.Checklist>) -> IO(Unit):
  match lists:
    case [Check.Checklist{_, pairs}]:
      do IO<Unit>:
        x : Unit <- Socket.close(socket)
        IO.print(statuses(pairs, "checks"))
    case _:
      do IO<Unit>:
        x : Unit <- Socket.close(socket)
        IO.die(Unit, 3, "bad fixture checklist")

def cancelled_step(step: Tx.Step, saved: List<&2, Tx.Notice>) -> Tx.Step:
  match step:
    case Tx.Step{state, events}:
      Tx.Step{state, List.reverse.go(&2, Tx.Notice, List.reverse(&2, Tx.Notice, saved), events)}

def before_send(cancel: U32, step: Tx.Step) -> Tx.Step:
  match cancel step:
    case 2 Tx.Step{state, events}: cancelled_step(Tx.cancel(state, 0), events)
    case 4 Tx.Step{state, events}: cancelled_step(Tx.stop_retries(state, 0), events)
    case _ s: s

def applied_begin(result: Maybe<&2, List<&2, Check.Checklist>>, step: Tx.Step, socket: Socket,
                  +next: Nat, done: Nat, deadline: Nat, +cancel: U32,
                  again: Socket -> Driver -> IO(Unit)) -> IO(Unit):
  match result:
    case None{}: IO.die(Unit, 3, "cannot begin pair")
    case Some{lists}:
      IO.bind(SocketIO.Reply(), Unit, SocketIO.execute(socket, before_send(Bool.pick(U32, Nat.is_eq(next, 0n), cancel, 0), step)),
        reply => handled(reply, lists, Nat.add(next, 1n), done, deadline, cancel, again))

def started(result: Tx.Start, socket: Socket, driver: Driver,
            again: Socket -> Driver -> IO(Unit)) -> IO(Unit):
  match result driver:
    case Tx.Rejected{} _: IO.die(Unit, 3, "fixture transaction rejected")
    case Tx.Ready{step} Driver{_, +lists, +next, done, deadline, cancel}:
      applied_begin(Check.begin(lists, 1, next), step, socket, next, done, deadline, cancel, again)
    case Tx.Later{_} Driver{tx, lists, next, done, deadline, cancel}:
      IO.bind(SocketIO.Reply(), Unit, SocketIO.poll(socket, tx, 10),
        reply => handled(reply, lists, next, done, deadline, cancel, again))

def selected(pair: Maybe<&2, Check.CandidatePair>, socket: Socket, driver: Driver, now: Nat,
             again: Socket -> Driver -> IO(Unit)) -> IO(Unit):
  match pair driver:
    case None{} _: IO.die(Unit, 3, "missing fixture pair")
    case Some{Check.CandidatePair{_, C.Candidate{_, _, _, _, +address}, _, _}}
         Driver{+tx, +lists, +next, +done, +deadline, +cancel}:
      started(Tx.start(tx, U32.from_nat(next), C.host(address), C.port(address),
        Discovery.transaction(U32.from_nat(Nat.add(next, 1n)), 2, 3), Retry.Policy{500, 3, 1},
        Fixture.credentials(), Ice.Check{1845494271, Ice.Controlling{4275878552, 1985229328}}, Auth.Dual{}, now),
        socket, Driver{tx, lists, next, done, deadline, cancel}, again)

def continuing(finished: Bool, late: Bool, start_more: Bool, cancel_first: Bool,
               socket: Socket, driver: Driver, now: Nat, again: Socket -> Driver -> IO(Unit)) -> IO(Unit):
  match finished late start_more cancel_first driver:
    case True{} _ _ _ Driver{_, lists, _, _, _, _}: closed(socket, lists)
    case False{} True{} _ _ _:
      do IO<Unit>:
        x : Unit <- Socket.close(socket)
        IO.die(Unit, 3, "fixture deadline exceeded")
    case False{} False{} _ True{} Driver{+tx, lists, next, done, deadline, cancel}:
      IO.bind(SocketIO.Reply(), Unit, SocketIO.execute(socket, Bool.pick(Tx.Step, U32.is_eq(cancel, 3), Tx.stop_retries(tx, 0), Tx.cancel(tx, 0))),
        reply => handled(reply, lists, next, done, deadline, 0, again))
    case False{} False{} True{} False{} Driver{+tx, +lists, +next, +done, +deadline, +cancel}:
      selected(Check.get_stream(lists, 1, next), socket, Driver{tx, lists, next, done, deadline, cancel}, now, again)
    case False{} False{} False{} False{} Driver{tx, lists, next, done, deadline, cancel}:
      IO.bind(SocketIO.Reply(), Unit, SocketIO.poll(socket, tx, 50),
        reply => handled(reply, lists, next, done, deadline, cancel, again))

def tick_driver(socket: Socket, driver: Driver, +now: Nat, again: Socket -> Driver -> IO(Unit)) -> IO(Unit):
  match driver:
    case Driver{+tx, +lists, +next, +done, +deadline, +cancel}:
      continuing(Nat.is_eq(done, 2n), Nat.is_le(deadline, now), Nat.is_lt(next, 2n),
        Bool.and(Bool.or(U32.is_eq(cancel, 1), U32.is_eq(cancel, 3)), Nat.is_eq(next, 1n)), socket, Driver{tx, lists, next, done, deadline, cancel}, now, again)

def loop(fuel: Nat, socket: Socket, driver: Driver) -> IO(Unit):
  match fuel driver:
    case 0n _:
      do IO<Unit>:
        x : Unit <- Socket.close(socket)
        IO.die(Unit, 3, "fixture loop exhausted")
    case 1n+p Driver{+tx, +lists, +next, +done, +deadline, +cancel}:
      do IO<Unit>:
        now : Nat <- IO.now()
        tick_driver(socket, Driver{tx, lists, next, done, deadline, cancel}, now, s => d => loop(p, s, d))

def initialized(lists: Maybe<&2, List<&2, Check.Checklist>>, local_port: U32, cancel: U32) -> IO(Unit):
  match lists:
    case None{}: IO.die(Unit, 3, "bad fixture candidates")
    case Some{lists}:
      do IO<Unit>:
        socket : Socket <- IO.try(Socket, UDP.bind(local_port))
        now : Nat <- IO.now()
        loop(65536n, socket, Driver{Tx.default(), lists, 0n, 0n, Nat.add(now, 3000n), cancel})

def run(+local: U32, port_a: U32, port_b: U32, cancel: U32) -> IO(Unit):
  initialized(Check.build([Check.Stream{1,
    [C.Local{C.Candidate{1, 2130706431, "local", C.Host{}, Stun.IPv4{127, 0, 0, 1, local}},
             C.Candidate{1, 2130706431, "local", C.Host{}, Stun.IPv4{127, 0, 0, 1, local}}}],
    [C.Candidate{1, 2130706430, "remoteA", C.Host{}, Stun.IPv4{127, 0, 0, 1, port_a}},
     C.Candidate{1, 2130706429, "remoteB", C.Host{}, Stun.IPv4{127, 0, 0, 1, port_b}}]}], True{}, 100), local, cancel)

def parsed(local: Maybe<&2, U32>, a: Maybe<&2, U32>, b: Maybe<&2, U32>, scenario: String) -> IO(Unit):
  match local a b scenario:
    case Some{l} Some{a} Some{b} "normal": run(l, a, b, 0)
    case Some{l} Some{a} Some{b} "cancel": run(l, a, b, 1)
    case Some{l} Some{a} Some{b} "queued-cancel": run(l, a, b, 2)
    case Some{l} Some{a} Some{b} "stop": run(l, a, b, 3)
    case Some{l} Some{a} Some{b} "queued-stop": run(l, a, b, 4)
    case _ _ _ _: IO.die(Unit, 2, "invalid fixture arguments")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [local, a, b, scenario]: parsed(U32.read(local), U32.read(a), U32.read(b), scenario)
    case _: IO.die(Unit, 2, "usage: ice_shared <local-port> <peer-A-port> <peer-B-port> <normal|cancel|queued-cancel>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
