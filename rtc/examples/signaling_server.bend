import Base
import ../signaling.bend as Signal
import ../signaling_auth.bend as Access
import ../ice_transport.bend as T
import ../ice_binding.bend as Ice
import ../ice_incoming.bend as Incoming
import ../ice_candidates.bend as C
import ../ice_pairs.bend as Pairs
import ../stun.bend as Stun
import ../stun_client.bend as Discovery
import ../stun_sign.bend as Sign
import ./signaling_answer.bend as Answer
import ./ice_transport_effects.bend as Udp
import ./ice_transport_output.bend as Output
import ../../http/server/server.bend as Server
import ../../http/server/websocket.bend as Ws
import ../../http/server/websocket_conn.bend as Conn
import ../../http/server/websocket_frame.bend as Frame
import ../../http/core/request.bend as Req
import ../../http/core/response.bend as Res
import ../../http/core/status.bend as Status
import ../../http/wire/bytes.bend as Bytes
import ../../crypto/bytes.bend as B
import ../../json/json.bend as J
import ../../wire/wire.bend as W
import ../../utf8/utf8.bend as U

# Local ICE evaluator: one authenticated WebSocket owns one actual UDP base.
# Its public synthetic cookie is a test selector. HTTP/WS is plaintext; DTLS,
# data and media are intentionally absent. A lifetime never extends on restart.
# This adapter accepts unfragmented text signaling messages only (<=32768 bytes).
type Driver is Data:
  Driver{signal: Signal.State, base: Stun.IPv4, buffer: Bytes.Bytes,
         end: Nat, frames: U32, closed: Bool}

def Reply() -> Type:
  Socket & Socket & Driver

def stop(driver: Driver) -> Driver:
  match driver:
    case Driver{state, base, buffer, end, frames, _}: Driver{state, base, buffer, end, frames, True{}}

def ws_sent(value: Discovery.RU(), udp: Socket, driver: Driver) -> IO(Reply()):
  match value:
    case (ws, Done{_}): IO.pure(Reply(), (ws, (udp, driver)))
    case (ws, Fail{_}): IO.pure(Reply(), (ws, (udp, stop(driver))))

def send_ws(op: U32, payload: Bytes.Bytes, ws: Socket, udp: Socket, driver: Driver) -> IO(Reply()):
  IO.bind(Discovery.RU(), Reply(), W.wire_send_timeout(ws, Bytes.to_list(Frame.write(op, payload)), 1000),
    value => ws_sent(value, udp, driver))

def send_text(text: String, ws: Socket, udp: Socket, driver: Driver) -> IO(Reply()):
  send_ws(1, Bytes.of_list(U.encode(text)), ws, udp, driver)

def udp_driver(state: T.State, +base: Stun.IPv4) -> Udp.Driver:
  Udp.Driver{state, base, [], 0n, 0, "browser", False{}}

def udp_done(value: Udp.Reply(), ws: Socket, driver: Driver) -> IO(Reply()):
  (udp, d) = value
  match d driver:
    case Udp.Driver{transport, _, _, _, _, _, _} Driver{state, base, buffer, end, frames, closed}:
      IO.pure(Reply(), (ws, (udp, Driver{Signal.replace(state, transport), base, buffer, end, frames, closed})))

def udp_event(notice: T.Notice, owner: Maybe<&2, T.State>, +now: Nat,
              ws: Socket, udp: Socket, +driver: Driver) -> IO(Reply()):
  match notice owner driver:
    case T.Transmit{packet} Some{s} Driver{_, base, _, _, _, _}:
      IO.bind(Udp.Reply(), Reply(), Udp.request_now(now, udp, udp_driver(s, base), packet), r => udp_done(r, ws, driver))
    case +n Some{s} Driver{_, base, _, _, _, _}:
      IO.bind(Udp.Reply(), Reply(), Udp.reply_now(now, udp, udp_driver(s, base), n), r => udp_done(r, ws, driver))
    case _ _ d: IO.pure(Reply(), (ws, (udp, d)))

def event(+notice: T.Notice, ws: Socket, udp: Socket, +driver: Driver) -> IO(Reply()):
  match driver:
    case Driver{state, _, _, _, _, _}:
      do IO<Reply()>:
        x : Unit <- Output.event(notice)
        now : Nat <- IO.now()
        udp_event(notice, Signal.owner(state), now, ws, udp, driver)

def continued(value: Reply(), again: Socket -> Socket -> Driver -> IO(Reply())) -> IO(Reply()):
  (ws, (udp, driver)) = value
  again(ws, udp, driver)

def execute(values: List<&2, T.Notice>, ws: Socket, udp: Socket, driver: Driver) -> IO(Reply()):
  match values:
    case Nil{}: IO.pure(Reply(), (ws, (udp, driver)))
    case Con{head, tail}:
      IO.bind(Reply(), Reply(), event(head, ws, udp, driver), r => continued(r, a => b => d => execute(tail, a, b, d)))

def stepped(step: T.Step, ws: Socket, udp: Socket, driver: Driver) -> IO(Reply()):
  match step driver:
    case T.Step{transport, events} Driver{state, base, buffer, end, frames, closed}:
      execute(events, ws, udp, Driver{Signal.replace(state, transport), base, buffer, end, frames, closed})

def tick_owner(owner: Maybe<&2, T.State>, now: Nat, ws: Socket, udp: Socket, driver: Driver) -> IO(Reply()):
  match owner:
    case Some{state}: stepped(T.tick(state, now), ws, udp, driver)
    case None{}: IO.pure(Reply(), (ws, (udp, driver)))

def tick(value: Reply()) -> IO(Reply()):
  (ws, (udp, +driver)) = value
  match driver:
    case Driver{state, _, _, _, _, _}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        tick_owner(Signal.owner(state), now, ws, udp, driver)

def begin_owner(owner: Maybe<&2, T.State>, now: Nat, ws: Socket, udp: Socket, +driver: Driver) -> IO(Reply()):
  match owner driver:
    case Some{s} Driver{_, base, _, _, _, False{}}:
      IO.bind(Udp.Reply(), Reply(), Udp.begin_due(now, udp, udp_driver(s, base)), r => udp_done(r, ws, driver))
    case _ d: IO.pure(Reply(), (ws, (udp, d)))

def begin(value: Reply()) -> IO(Reply()):
  (ws, (udp, +driver)) = value
  match driver:
    case Driver{state, _, _, _, _, _}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        begin_owner(Signal.owner(state), now, ws, udp, driver)

def received_owner(owner: Maybe<&2, T.State>, source: Maybe<&2, Stun.IPv4>, +raw: List<&2, U32>,
                   now: Nat, ws: Socket, udp: Socket, +driver: Driver) -> IO(Reply()):
  match owner source driver:
    case Some{state} Some{+peer} Driver{_, base, _, _, _, _}:
      do IO<Reply()>:
        x : Unit <- IO.print("browser-receive:" ++ C.host(peer) ++ ":" ++ U32.show(C.port(peer)) ++ ":" ++ B.hex(raw))
        stepped(T.receive(state, Pairs.Ref{1, 1, base, peer}, raw, now), ws, udp, driver)
    case _ _ d: IO.pure(Reply(), (ws, (udp, d)))

def received(value: Discovery.RD(), ws: Socket, +driver: Driver) -> IO(Reply()):
  (udp, result) = value
  match result driver:
    case Done{Some{(host, (port, raw))}} Driver{state, _, _, _, _, _}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        received_owner(Signal.owner(state), C.address_read(host, port), raw, now, ws, udp, driver)
    case Done{None{}} d: IO.pure(Reply(), (ws, (udp, d)))
    case Fail{_} d: IO.pure(Reply(), (ws, (udp, stop(d))))

def poll_udp(value: Reply()) -> IO(Reply()):
  (ws, (udp, driver)) = value
  IO.bind(Discovery.RD(), Reply(), W.wire_udp_recv_from_timeout(udp, 65535, 10), r => received(r, ws, driver))

def signaled_owner(owner: Maybe<&2, T.State>, now: Nat, ws: Socket, udp: Socket, driver: Driver) -> IO(Reply()):
  match owner:
    case Some{s}: stepped(T.local_signaled(s, now), ws, udp, driver)
    case None{}: IO.pure(Reply(), (ws, (udp, driver)))

def answer_sent(value: Reply()) -> IO(Reply()):
  (ws, (udp, +driver)) = value
  match driver:
    case Driver{state, _, _, _, _, False{}}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        signaled_owner(Signal.owner(state), now, ws, udp, driver)
    case d: IO.pure(Reply(), (ws, (udp, d)))

def changed(change: Signal.Change, ws: Socket, udp: Socket, driver: Driver) -> IO(Reply()):
  match change driver:
    case Signal.Accepted{+state, events} Driver{_, +base, buffer, end, frames, closed}:
      do IO<Reply()>:
        x : Unit <- Output.events(events)
        IO.bind(Reply(), Reply(), send_text(J.encode(J.JArr{[J.JStr{"answer"}, J.JStr{Answer.answer(state, base)}]}), ws, udp,
          Driver{state, base, buffer, end, frames, closed}), answer_sent)
    case Signal.Rejected{_, reason} d:
      do IO<Reply()>:
        x : Unit <- IO.print("signaling-rejected:" ++ reason)
        send_ws(8, Conn.code_bytes(1008), ws, udp, stop(d))

# One bounded OS request supplies the 64-bit local fragment, 128-bit password
# and 64-bit tie-breaker. Byte-to-word conversion stays in Bend.
def entropy(fuel: Nat, bytes: List<&2, U32>, acc: List<&2, U32>) -> Result<&1, &2, U32 & String, List<&2, U32>>:
  match fuel bytes:
    case 0n Nil{}: Done{List.reverse(&2, U32, acc)}
    case 1n+p Con{a, Con{b, Con{c, Con{d, tail}}}}:
      entropy(p, tail, Con{U32.or(U32.or(U32.shln(a, 24n), U32.shln(b, 16n)), U32.or(U32.shln(c, 8n), d)), acc})
    case _ _: Fail{(5, "host entropy returned wrong byte count")}

def random(value: Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Result<&1, &2, U32 & String, List<&2, U32>>):
  match value:
    case Done{bytes}: IO.pure(Result<&1, &2, U32 & String, List<&2, U32>>, entropy(8n, bytes, []))
    case Fail{e}: IO.pure(Result<&1, &2, U32 & String, List<&2, U32>>, Fail{e})

def random_offer(value: Result<&1, &2, U32 & String, List<&2, U32>>, command: Signal.Command,
                 ws: Socket, udp: Socket, +driver: Driver) -> IO(Reply()):
  match value driver:
    case Done{[a, b, c, d, e, f, g, h]} Driver{state, base, _, _, _, _}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        changed(Signal.apply(state, command, base,
          Incoming.Secret{B.hex(Sign.word_bytes(a, Sign.word_bytes(b, []))),
            B.hex(Sign.word_bytes(c, Sign.word_bytes(d, Sign.word_bytes(e, Sign.word_bytes(f, [])))))},
          Ice.Controlled{g, h}, now), ws, udp, driver)
    case _ d: send_ws(8, Conn.code_bytes(1011), ws, udp, stop(d))

def command(value: Signal.Command, ws: Socket, udp: Socket, driver: Driver) -> IO(Reply()):
  match value:
    case Signal.Bad{reason}: changed(Signal.Rejected{Signal.Ended{}, reason}, ws, udp, driver)
    case cmd:
      IO.bind(Result<&1, &2, U32 & String, List<&2, U32>>, Reply(),
        IO.bind(Result<&1, &1, U32 & String, List<&2, U32>>, Result<&1, &2, U32 & String, List<&2, U32>>,
          W.wire_random_bytes(32), random), r => random_offer(r, cmd, ws, udp, driver))

def data.valid(ok: Bool, payload: Bytes.Bytes, ws: Socket, udp: Socket, driver: Driver) -> IO(Reply()):
  match ok:
    case True{}: command(Signal.command(Bytes.to_list(payload)), ws, udp, driver)
    case False{}: send_ws(8, Conn.code_bytes(1007), ws, udp, stop(driver))

def data(fin: Bool, +payload: Bytes.Bytes, ws: Socket, udp: Socket, driver: Driver) -> IO(Reply()):
  match fin:
    case True{}:
      data.valid(Conn.payload_ok(1, payload), payload, ws, udp, driver)
    case False{}: send_ws(8, Conn.code_bytes(1003), ws, udp, stop(driver))

def close_frame(ok: Bool, payload: Bytes.Bytes, ws: Socket, udp: Socket, driver: Driver) -> IO(Reply()):
  match ok:
    case True{}: send_ws(8, payload, ws, udp, stop(driver))
    case False{}: send_ws(8, Conn.code_bytes(1002), ws, udp, stop(driver))

def frame(fin: Bool, op: U32, +payload: Bytes.Bytes, ws: Socket, udp: Socket, driver: Driver) -> IO(Reply()):
  match op:
    case 1: data(fin, payload, ws, udp, driver)
    case 8: close_frame(Conn.close_payload(payload), payload, ws, udp, driver)
    case 9: send_ws(10, payload, ws, udp, driver)
    case 10: IO.pure(Reply(), (ws, (udp, driver)))
    case _: send_ws(8, Conn.code_bytes(1003), ws, udp, stop(driver))

def ws_received(value: Conn.RP(), udp: Socket, driver: Driver) -> IO(Reply()):
  (ws, result) = value
  match result driver:
    case Done{Some{Con{head, tail}}} Driver{state, base, buffer, end, frames, closed}:
      IO.pure(Reply(), (ws, (udp, Driver{state, base, Bytes.app(buffer, Bytes.of_list(Con{head, tail})), end, frames, closed})))
    case Done{None{}} d: IO.pure(Reply(), (ws, (udp, d)))
    case _ d: IO.pure(Reply(), (ws, (udp, stop(d))))

def parsed(value: Frame.Parsed, ws: Socket, udp: Socket, driver: Driver) -> IO(Reply()):
  match value driver:
    case Frame.More{} d:
      IO.bind(Conn.RP(), Reply(), W.wire_recv_timeout(ws, 32768, 10), r => ws_received(r, udp, d))
    case Frame.Bad{code} d: send_ws(8, Conn.code_bytes(code), ws, udp, stop(d))
    case Frame.Frame{fin, op, payload, rest} Driver{state, base, _, end, frames, closed}:
      frame(fin, op, payload, ws, udp, Driver{state, base, rest, end, (frames + 1 : U32), closed})

def bounded(ok: Bool, ws: Socket, udp: Socket, +driver: Driver) -> IO(Reply()):
  match ok driver:
    case True{} Driver{_, _, buffer, _, _, _}: parsed(Frame.parse(buffer), ws, udp, driver)
    case False{} d: send_ws(8, Conn.code_bytes(1009), ws, udp, stop(d))

def poll_ws(value: Reply()) -> IO(Reply()):
  (ws, (udp, +driver)) = value
  match driver:
    case Driver{_, _, +buffer, _, frames, _}:
      bounded(Bool.and(Nat.is_le(Frame.size(buffer, 0n), 32768n), U32.is_lt(frames, 64)), ws, udp, driver)

def closed_step(step: T.Step) -> IO(Unit):
  match step:
    case T.Step{_, events}: Output.events(events)

def close_owner(owner: Maybe<&2, T.State>) -> IO(Unit):
  match owner:
    case None{}: IO.pure(Unit, Unit{})
    case Some{s}: closed_step(T.close(s))

def finish(ws: Socket, udp: Socket, driver: Driver) -> IO(Unit):
  match driver:
    case Driver{state, base, _, _, _, _}:
      do IO<Unit>:
        c : Unit <- close_owner(Signal.owner(state))
        x : Unit <- W.wire_close(ws)
        y : Unit <- W.wire_close(udp)
        z : Unit <- IO.print("signaling-closed:" ++ U32.show(C.port(base)))
        IO.pure(Unit, Unit{})

def loop_next(value: Reply(), again: Socket -> Socket -> Driver -> IO(Unit)) -> IO(Unit):
  (ws, (udp, driver)) = value
  again(ws, udp, driver)

def turn(done: Bool, ws: Socket, udp: Socket, driver: Driver, again: Socket -> Socket -> Driver -> IO(Unit)) -> IO(Unit):
  match done:
    case True{}: finish(ws, udp, driver)
    case False{}:
      IO.bind(Reply(), Unit, IO.bind(Reply(), Reply(), IO.bind(Reply(), Reply(), IO.bind(Reply(), Reply(),
        tick((ws, (udp, driver))), begin), poll_udp), poll_ws), r => loop_next(r, again))

def timed(+now: Nat, stop_flag: U32, ws: Socket, udp: Socket, +driver: Driver, again: Socket -> Socket -> Driver -> IO(Unit)) -> IO(Unit):
  match driver:
    case Driver{_, _, _, end, _, closed}:
      turn(Bool.or(closed, Bool.or(Nat.is_le(end, now), Bool.not(U32.is_eq(stop_flag, 0)))), ws, udp, driver, again)

def loop(fuel: Nat, ws: Socket, udp: Socket, driver: Driver) -> IO(Unit):
  match fuel:
    case 0n: finish(ws, udp, driver)
    case 1n+p:
      do IO<Unit>:
        now : Nat <- IO.now()
        stopping : U32 <- W.wire_stopping()
        timed(now, stopping, ws, udp, driver, a => b => d => loop(p, a, b, d))

def named_result(result: Result<&1, &1, U32 & String, String & U32>, ws: Socket, udp: Socket, buffer: Bytes.Bytes) -> IO(Unit):
  match result:
    case Done{(host, +port)}:
      do IO<Unit>:
        +now : Nat <- IO.now()
        x : Unit <- IO.print("signaling-base:" ++ host ++ ":" ++ U32.show(port))
        loop(8192n, ws, udp, Driver{Signal.Fresh{}, Stun.IPv4{127, 0, 0, 1, port}, buffer, Nat.add(now, 45000n), 0, False{}})
    case Fail{_}:
      do IO<Unit>:
        x : Unit <- W.wire_close(ws)
        W.wire_close(udp)

def named(value: Socket & Result<&1, &1, U32 & String, String & U32>, ws: Socket, buffer: Bytes.Bytes) -> IO(Unit):
  (udp, result) = value
  named_result(result, ws, udp, buffer)

def bound(value: Result<&1, &1, U32 & String, Socket>, ws: Socket, buffer: Bytes.Bytes) -> IO(Unit):
  match value:
    case Done{udp}:
      IO.bind(Socket & Result<&1, &1, U32 & String, String & U32>, Unit, W.wire_udp_local_address(udp), r => named(r, ws, buffer))
    case Fail{_}: W.wire_close(ws)

def session(ws: Socket, buffer: Bytes.Bytes) -> IO(Unit):
  IO.bind(Result<&1, &1, U32 & String, Socket>, Unit, W.wire_udp_bind("127.0.0.1", 0), r => bound(r, ws, buffer))

def upgraded(value: Maybe<&2, String>) -> IO(Server.Out):
  match value:
    case Some{key}: IO.pure(Server.Out, Server.Upgrade{key, ws => buffer => session(ws, buffer)})
    case None{}: IO.pure(Server.Out, Server.Whole{Res.bad_request()})

def capacity(ok: Bool, request: Req.Request) -> IO(Server.Out):
  match ok:
    case True{}: upgraded(Ws.accept(request))
    case False{}: IO.pure(Server.Out, Server.Whole{Res.text(Status.Status{503}, "fixture connection limit")})

def authorized(decision: Access.Decision, request: Req.Request) -> IO(Server.Out):
  match decision:
    case Access.Allowed{}:
      do IO<Server.Out>:
        n : U32 <- W.wire_live(0)
        capacity(U32.is_le(n, 8), request)
    case Access.DeniedOrigin{}: IO.pure(Server.Out, Server.Whole{Res.text(Status.Status{403}, "denied Origin")})
    case Access.DeniedAuth{}: IO.pure(Server.Out, Server.Whole{Res.text(Status.Status{401}, "failed fixture authentication")})
    case Access.BadRequest{}: IO.pure(Server.Out, Server.Whole{Res.bad_request()})

def dispatch(+request: Req.Request) -> IO(Server.Out):
  match request:
    case Req.Request{_, "/", _, _}: IO.pure(Server.Out, Server.Whole{Res.html(Status.ok(), "<!doctype html><title>Grounds ICE evaluator</title><p>Local synthetic ICE test peer.</p>")})
    case _:
      authorized(Access.authorize(request, "127.0.0.1:8089", "http://127.0.0.1:8089", "grounds-fixture=local-synthetic-session"), request)

def app(request: Req.Request) -> IO(Server.Out):
  dispatch(request)

def main() -> IO(Unit):
  Server.serve_out(~app, Server.Config{8089, 8192, 32768, 8, 5000, 5000, 5000, None{}, False{}})
