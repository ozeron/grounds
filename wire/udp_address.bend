import Base
import ./wire.bend as W
import ./udp.bend as Bytes

def Name() -> Type:
  Socket & Result<&1, &1, U32 & String, String & U32>

def closed_error(socket: Socket, message: String) -> IO(Unit):
  do IO<Unit>:
    x : Unit <- Socket.close(socket)
    IO.die(Unit, 3, message)

def rejected_code(valid: Bool, again: Unit -> IO(Unit)) -> IO(Unit):
  match valid:
    case False{}: IO.die(Unit, 3, "occupied bind returned wrong error")
    case True{}: again(Unit{})

def rejected_bind(result: Result<&1, &1, U32 & String, Socket>, again: Unit -> IO(Unit)) -> IO(Unit):
  match result:
    case Done{s}: closed_error(s, "occupied bind succeeded")
    case Fail{(+code, _)}: rejected_code(Bool.or(U32.is_eq(code, 48), U32.is_eq(code, 98)), again)

def reject_binds(fuel: Nat, +host: String, +port: U32) -> IO(Unit):
  match fuel:
    case 0n: IO.pure(Unit, Unit{})
    case 1n+p:
      IO.bind(Result<&1, &1, U32 & String, Socket>, Unit, W.wire_udp_bind(host, port),
        r => rejected_bind(r, x => reject_binds(p, host, port)))

def echoed(result: Result<&1, &1, U32 & String, Unit>, socket: Socket,
           again: Socket -> IO(Unit)) -> IO(Unit):
  match result:
    case Done{_}: again(socket)
    case Fail{_}: closed_error(socket, "UDP echo send failed")

def sent(reply: Bytes.RU(), again: Socket -> IO(Unit)) -> IO(Unit):
  (socket, result) = reply
  echoed(result, socket, again)

def datagram(result: Result<&1, &1, U32 & String, Maybe<&1, String & U32 & List<&2, U32>>>,
             socket: Socket, again: Socket -> IO(Unit)) -> IO(Unit):
  match result:
    case Done{Some{(host, (port, bytes))}}:
      IO.bind(Bytes.RU(), Unit, W.wire_udp_send_to(socket, host, port, bytes, 1000), r => sent(r, again))
    case _: closed_error(socket, "UDP echo receive failed")

def received(reply: Bytes.RD(), again: Socket -> IO(Unit)) -> IO(Unit):
  (socket, result) = reply
  datagram(result, socket, again)

def echo(fuel: Nat, socket: Socket) -> IO(Unit):
  match fuel:
    case 0n:
      do IO<Unit>:
        x : Unit <- Socket.close(socket)
        IO.print("closed")
    case 1n+p:
      IO.bind(Bytes.RD(), Unit, W.wire_udp_recv_from_timeout(socket, 65535, 2000), r => received(r, s => echo(p, s)))

def ready(socket: Socket, +host: String, +port: U32, +reps: U32, count: U32) -> IO(Unit):
  do IO<Unit>:
    x : Unit <- IO.print("bound:" ++ host ++ ":" ++ U32.show(port))
    y : Unit <- reject_binds(U32.to_nat(reps), host, port)
    z : Unit <- IO.print("rejections:" ++ U32.show(reps))
    echo(U32.to_nat(count), socket)

def named_result(result: Result<&1, &1, U32 & String, String & U32>, socket: Socket, reps: U32, count: U32) -> IO(Unit):
  match result:
    case Done{(host, port)}: ready(socket, host, port, reps, count)
    case Fail{_}: closed_error(socket, "local address query failed")

def named(reply: Name(), reps: U32, count: U32) -> IO(Unit):
  (socket, result) = reply
  named_result(result, socket, reps, count)

def bound(result: Result<&1, &1, U32 & String, Socket>, reps: U32, count: U32) -> IO(Unit):
  match result:
    case Fail{(code, _)}: IO.print("failed:" ++ U32.show(code))
    case Done{s}: IO.bind(Name(), Unit, W.wire_udp_local_address(s), r => named(r, reps, count))

def run(+host: String, port: U32, reps: U32, count: U32) -> IO(Unit):
  IO.bind(Result<&1, &1, U32 & String, Socket>, Unit,
    W.wire_udp_bind(Bool.pick(String, String.eq(host, "@nul"), "127.0.0.1\u{0}hidden", host), port), r => bound(r, reps, count))

def parsed(host: String, port: Maybe<&2, U32>, reps: Maybe<&2, U32>, count: Maybe<&2, U32>) -> IO(Unit):
  match port reps count:
    case Some{p} Some{r} Some{n}: run(host, p, r, n)
    case _ _ _: IO.die(Unit, 2, "bad UDP address arguments")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [host, port, reps, count]: parsed(host, U32.read(port), U32.read(reps), U32.read(count))
    case _: IO.die(Unit, 2, "usage: udp_address <IPv4> <port> <occupied-bind-count> <echo-count>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
