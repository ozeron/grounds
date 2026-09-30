import Base
import ../ice_incoming.bend as Incoming
import ../ice_transactions.bend as Tx
import ../ice_socket.bend as SocketIO
import ../ice_candidates.bend as C
import ../ice_binding.bend as Ice
import ../ice_reliable.bend as Reliable
import ../ice_response.bend as Response
import ../stun_auth.bend as Auth
import ../stun.bend as Stun
import ../stun_retry.bend as Retry
import ../stun_client.bend as Discovery
import ../../wire/wire.bend as W
import ./ice_exchange.bend as Fixture
import ./ice_accept.bend as Output

type Driver is Data:
  Driver{transactions: Tx.State, role: Ice.Role, finished: Bool, accepted: Nat, target: Nat, deadline: Nat}

def Reply() -> Type:
  Socket & Driver

def secret() -> Incoming.Secret:
  Incoming.Secret{"localFrag", "LocalFixturePassword123456"}

def sent(result: Discovery.RU(), driver: Driver) -> IO(Reply()):
  (socket, outcome) = result
  do IO<Reply()>:
    x : Unit <- IO.pass(Unit, outcome)
    return (socket, driver)

def incoming(decision: Incoming.Decision, socket: Socket, +host: String, +port: U32, driver: Driver) -> IO(Reply()):
  match decision driver:
    case Incoming.Accepted{+reply, +request, +role, +switched} Driver{tx, _, done, count, target, end}:
      do IO<Reply()>:
        x : Unit <- Output.show(Incoming.Accepted{reply, request, role, switched})
        IO.bind(Discovery.RU(), Reply(), W.wire_udp_send_to(socket, host, port, reply, 1000),
          result => sent(result, Driver{tx, role, done, Nat.add(count, 1n), target, end}))
    case Incoming.Rejected{+reply, +code, +auth} d:
      do IO<Reply()>:
        x : Unit <- Output.show(Incoming.Rejected{reply, code, auth})
        IO.bind(Discovery.RU(), Reply(), W.wire_udp_send_to(socket, host, port, reply, 1000), result => sent(result, d))
    case Incoming.Ignored{} d:
      do IO<Reply()>:
        x : Unit <- IO.print("ignored")
        return (socket, d)
    case Incoming.InvalidInput{} _:
      do IO<Reply()>:
        x : Unit <- Socket.close(socket)
        IO.die(Reply(), 3, "bad incoming configuration")

def datagram(address: Maybe<&2, Stun.IPv4>, socket: Socket, host: String, port: U32, raw: List<&2, U32>, driver: Driver) -> IO(Reply()):
  match address driver:
    case Some{source} Driver{+tx, +role, +done, +count, +target, +end}:
      incoming(Incoming.receive(raw, secret(), role, source), socket, host, port, Driver{tx, role, done, count, target, end})
    case None{} d: IO.pure(Reply(), (socket, d))

def notice(value: Tx.Notice, socket: Socket, driver: Driver) -> IO(Reply()):
  match value driver:
    case Tx.Datagram{+host, +port, bytes} d:
      datagram(C.address_read(host, port), socket, host, port, bytes, d)
    case Tx.Sent{_} d:
      do IO<Reply()>:
        x : Unit <- IO.print("sent")
        return (socket, d)
    case Tx.Finished{_, Reliable.Received{Response.Success{_}, _}} Driver{tx, role, _, count, target, end}:
      do IO<Reply()>:
        x : Unit <- IO.print("outgoing:success")
        return (socket, Driver{tx, role, True{}, count, target, end})
    case _ _:
      do IO<Reply()>:
        x : Unit <- Socket.close(socket)
        IO.die(Reply(), 3, "unexpected transaction outcome")

def next_notice(reply: Reply(), tail: List<&2, Tx.Notice>, again: Socket -> Driver -> List<&2, Tx.Notice> -> IO(Reply())) -> IO(Reply()):
  (socket, driver) = reply
  again(socket, driver, tail)

def notices(fuel: Nat, socket: Socket, driver: Driver, values: List<&2, Tx.Notice>) -> IO(Reply()):
  match fuel values:
    case 0n _:
      do IO<Reply()>:
        x : Unit <- Socket.close(socket)
        IO.die(Reply(), 3, "notice fuel exhausted")
    case 1n+_ Nil{}: IO.pure(Reply(), (socket, driver))
    case 1n+p Con{head, tail}:
      IO.bind(Reply(), Reply(), notice(head, socket, driver),
        changed => next_notice(changed, tail, s => d => rest => notices(p, s, d, rest)))

def resumed(reply: Reply(), again: Socket -> Driver -> IO(Unit)) -> IO(Unit):
  (socket, driver) = reply
  again(socket, driver)

def polled(reply: SocketIO.Reply(), role: Ice.Role, done: Bool, count: Nat, target: Nat, end: Nat,
           again: Socket -> Driver -> IO(Unit)) -> IO(Unit):
  (socket, Tx.Step{tx, values}) = reply
  IO.bind(Reply(), Unit, notices(258n, socket, Driver{tx, role, done, count, target, end}, values),
    changed => resumed(changed, again))

def tick(finished: Bool, expired: Bool, socket: Socket, driver: Driver,
         again: Socket -> Driver -> IO(Unit)) -> IO(Unit):
  match finished expired driver:
    case True{} _ Driver{_, role, _, count, _, _}:
      do IO<Unit>:
        x : Unit <- Socket.close(socket)
        IO.print("done:" ++ Nat.show(count) ++ ":" ++ Output.role(role))
    case False{} True{} _:
      do IO<Unit>:
        x : Unit <- Socket.close(socket)
        IO.die(Unit, 3, "duplex fixture deadline exceeded")
    case False{} False{} Driver{tx, role, done, count, target, end}:
      IO.bind(SocketIO.Reply(), Unit, SocketIO.poll(socket, tx, 50),
        reply => polled(reply, role, done, count, target, end, again))

def timed(socket: Socket, driver: Driver, now: Nat, again: Socket -> Driver -> IO(Unit)) -> IO(Unit):
  match driver:
    case Driver{+tx, +role, +done, +count, +target, +end}:
      tick(Bool.and(done, Nat.is_le(target, count)), Nat.is_le(end, now), socket, Driver{tx, role, done, count, target, end}, again)

def loop(fuel: Nat, socket: Socket, driver: Driver) -> IO(Unit):
  match fuel:
    case 0n:
      do IO<Unit>:
        x : Unit <- Socket.close(socket)
        IO.die(Unit, 3, "duplex loop exhausted")
    case 1n+p:
      do IO<Unit>:
        now : Nat <- IO.now()
        timed(socket, driver, now, s => d => loop(p, s, d))

def started(result: Tx.Start, socket: Socket, +now: Nat, target: Nat) -> IO(Unit):
  match result:
    case Tx.Ready{step}:
      IO.bind(SocketIO.Reply(), Unit, SocketIO.execute(socket, step),
        reply => polled(reply, Ice.Controlling{0, 1}, False{}, 0n, target, Nat.add(now, 3000n), s => d => loop(65536n, s, d)))
    case _:
      do IO<Unit>:
        x : Unit <- Socket.close(socket)
        IO.die(Unit, 3, "duplex start rejected")

def start(socket: Socket, peer_port: U32, +now: Nat, target: Nat) -> IO(Unit):
  started(Tx.start(Tx.default(), 0, "127.0.0.1", peer_port, Discovery.transaction(1, 2, 3), Retry.Policy{500, 3, 1},
    Fixture.credentials(), Ice.Check{1845494271, Ice.Controlling{0, 1}}, Auth.Dual{}, now), socket, now, target)

def run(local: U32, peer: U32, target: U32) -> IO(Unit):
  do IO<Unit>:
    socket : Socket <- IO.try(Socket, UDP.bind(local))
    now : Nat <- IO.now()
    start(socket, peer, now, U32.to_nat(target))

def parsed(local: Maybe<&2, U32>, peer: Maybe<&2, U32>, target: Maybe<&2, U32>) -> IO(Unit):
  match local peer target:
    case Some{l} Some{p} Some{t}: run(l, p, t)
    case _ _ _: IO.die(Unit, 2, "bad duplex arguments")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [local, peer, target]: parsed(U32.read(local), U32.read(peer), U32.read(target))
    case _: IO.die(Unit, 2, "usage: ice_duplex <local-port> <peer-port> <accepted-count>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)

