import Base
import ../ice_binding.bend as Ice
import ../ice_transactions.bend as Tx
import ../ice_socket.bend as SocketIO
import ../ice_reliable.bend as Reliable
import ../ice_response.bend as Response
import ../stun_auth.bend as Auth
import ../stun_retry.bend as Retry
import ../stun_client.bend as Discovery
import ../../wire/wire.bend as W
import ./ice_clock.bend as Clock

# This is a retained-transaction wire fixture, not a nominating ICE agent.
def finish(socket: Socket, state: Tx.State, text: String) -> IO(Unit):
  do IO<Unit>:
    x : Unit <- Socket.close(socket)
    y : Unit <- IO.print(text)
    z : Unit <- IO.print("state:" ++ Clock.snapshot(state, 0n))
    IO.print("done")

def terminal(values: List<&2, Tx.Notice>, found: Bool) -> Bool:
  match values:
    case Nil{}: found
    case Con{Tx.Finished{_, _}, tail}: terminal(tail, True{})
    case Con{Tx.LateResponse{_, _, _}, tail}: terminal(tail, True{})
    case Con{Tx.Retired{_}, tail}: terminal(tail, True{})
    case Con{Tx.SocketFailure{_}, tail}: terminal(tail, True{})
    case Con{_, tail}: terminal(tail, found)

def outcome(values: List<&2, Tx.Notice>, out: String) -> String:
  match values:
    case Nil{}: out
    case Con{Tx.Finished{_, Reliable.Received{Response.Error{code}, _}}, tail}:
      outcome(tail, out ++ ":error" ++ U32.show(code))
    case Con{head, tail}: outcome(tail, Clock.events([head], out))

def handled_done(done: Bool, socket: Socket, state: Tx.State, text: String, stopped: Bool,
                 again: Socket -> Tx.State -> Bool -> IO(Unit)) -> IO(Unit):
  match done:
    case True{}: finish(socket, state, text)
    case False{}:
      do IO<Unit>:
        x : Unit <- IO.print(text)
        again(socket, state, stopped)

def handled(reply: SocketIO.Reply(), stopped: Bool, again: Socket -> Tx.State -> Bool -> IO(Unit)) -> IO(Unit):
  (socket, Tx.Step{state, +events}) = reply
  handled_done(terminal(events, False{}), socket, state, outcome(events, "event"), stopped, again)

def turn(stop: Bool, socket: Socket, state: Tx.State, stopped: Bool,
         again: Socket -> Tx.State -> Bool -> IO(Unit)) -> IO(Unit):
  match stop:
    case True{}:
      IO.bind(SocketIO.Reply(), Unit, SocketIO.execute(socket, Tx.stop_retries(state, 0)), r => handled(r, True{}, again))
    case False{}:
      IO.bind(SocketIO.Reply(), Unit, SocketIO.poll(socket, state, 25), r => handled(r, stopped, again))

def timed(expired: Bool, +now: Nat, socket: Socket, state: Tx.State, +stopped: Bool, stop_at: Nat,
          again: Socket -> Tx.State -> Bool -> IO(Unit)) -> IO(Unit):
  match expired:
    case True{}: finish(socket, state, "fixture-expired")
    case False{}: turn(Bool.and(Bool.not(stopped), Nat.is_le(stop_at, now)), socket, state, stopped, again)

def at_now(+now: Nat, socket: Socket, state: Tx.State, stopped: Bool, stop_at: Nat, end: Nat,
           again: Socket -> Tx.State -> Bool -> IO(Unit)) -> IO(Unit):
  timed(Nat.is_le(end, now), now, socket, state, stopped, stop_at, again)

def loop(fuel: Nat, socket: Socket, state: Tx.State, stopped: Bool, +stop_at: Nat, +end: Nat) -> IO(Unit):
  match fuel:
    case 0n: finish(socket, state, "fixture-fuel")
    case 1n+p:
      do IO<Unit>:
        now : Nat <- IO.now()
        at_now(now, socket, state, stopped, stop_at, end,
          s => tx => done => loop(p, s, tx, done, stop_at, end))

def begun(result: Tx.Start, socket: Socket, +now: Nat, stop: Bool) -> IO(Unit):
  match result:
    case Tx.Ready{step}:
      IO.bind(SocketIO.Reply(), Unit, SocketIO.execute(socket, step), r =>
        handled(r, False{}, s => tx => done => loop(8192n, s, tx, done,
          Nat.add(now, Bool.pick(Nat, stop, 150n, 10000n)), Nat.add(now, 3000n))))
    case Tx.Rejected{}: finish(socket, Tx.default(), "rejected")
    case Tx.Later{_}: finish(socket, Tx.default(), "unexpected-pacing")

def starting(+now: Nat, socket: Socket, peer: U32, mode: Auth.Mode, stop: Bool, controlled: Bool) -> IO(Unit):
  begun(Tx.start_intent(Tx.default(), 0, "127.0.0.1", peer, Discovery.transaction(1, 2, 3), Retry.Policy{500, 2, 1},
      Ice.Credentials{"localFrag", "remoteFrag", "SyntheticPassword123456789"},
      Ice.Check{1845494271, Bool.pick(Ice.Role, controlled, Ice.Controlled{0, 1}, Ice.Controlling{0, 1})}, True{}, mode, now), socket, now, stop)

def ready(socket: Socket, host: String, bound: U32, peer: U32, mode: Auth.Mode, stop: Bool, controlled: Bool) -> IO(Unit):
  do IO<Unit>:
    x : Unit <- IO.print("base:" ++ host ++ "/" ++ U32.show(bound))
    y : Unit <- IO.print("ready")
    now : Nat <- IO.now()
    starting(now, socket, peer, mode, stop, controlled)

def named_result(result: Result<&1, &1, U32 & String, String & U32>, socket: Socket, peer: U32,
                 mode: Auth.Mode, stop: Bool, controlled: Bool) -> IO(Unit):
  match result:
    case Done{(host, port)}: ready(socket, host, port, peer, mode, stop, controlled)
    case Fail{_}:
      do IO<Unit>:
        x : Unit <- Socket.close(socket)
        IO.die(Unit, 3, "local address failed")

def named(reply: Socket & Result<&1, &1, U32 & String, String & U32>, peer: U32, mode: Auth.Mode, stop: Bool, controlled: Bool) -> IO(Unit):
  (socket, result) = reply
  named_result(result, socket, peer, mode, stop, controlled)

def bound(result: Result<&1, &1, U32 & String, Socket>, peer: U32, mode: Auth.Mode, stop: Bool, controlled: Bool) -> IO(Unit):
  match result:
    case Done{socket}:
      IO.bind(Socket & Result<&1, &1, U32 & String, String & U32>, Unit, W.wire_udp_local_address(socket),
        r => named(r, peer, mode, stop, controlled))
    case Fail{_}: IO.die(Unit, 3, "bind failed")

def configured(peer: U32, mode: Auth.Mode, scenario: String) -> IO(Unit):
  match scenario:
    case "active": IO.bind(Result<&1, &1, U32 & String, Socket>, Unit, W.wire_udp_bind("127.0.0.1", 0), r => bound(r, peer, mode, False{}, False{}))
    case "listen": IO.bind(Result<&1, &1, U32 & String, Socket>, Unit, W.wire_udp_bind("127.0.0.1", 0), r => bound(r, peer, mode, True{}, False{}))
    case "controlled": IO.bind(Result<&1, &1, U32 & String, Socket>, Unit, W.wire_udp_bind("127.0.0.1", 0), r => bound(r, peer, mode, False{}, True{}))
    case _: IO.die(Unit, 2, "unknown scenario")

def parsed(peer: Maybe<&2, U32>, mode: String, scenario: String) -> IO(Unit):
  match peer mode:
    case Some{p} "legacy": configured(p, Auth.Legacy{}, scenario)
    case Some{p} "sha256": configured(p, Auth.Sha256{}, scenario)
    case Some{p} "dual": configured(p, Auth.Dual{}, scenario)
    case _ _: IO.die(Unit, 2, "bad arguments")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [port, mode, scenario]: parsed(U32.read(port), mode, scenario)
    case _: IO.die(Unit, 2, "usage: ice_nomination_udp <peer-port> <mode> <active|listen|controlled>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
