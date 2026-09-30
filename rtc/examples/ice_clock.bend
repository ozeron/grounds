import Base
import ../ice_transactions.bend as Tx
import ../ice_socket.bend as SocketIO
import ../ice_binding.bend as Ice
import ../ice_reliable.bend as Reliable
import ../ice_response.bend as Response
import ../stun_auth.bend as Auth
import ../stun_retry.bend as Retry
import ../stun_client.bend as Discovery
import ./ice_exchange.bend as Fixture
import ../../io/io.bend as Io

def verdict(outcome: Reliable.Outcome) -> String:
  match outcome:
    case Reliable.TimedOut{}: "timeout"
    case Reliable.IntegrityViolation{}: "integrity"
    case Reliable.TransportError{code}: "transport" ++ U32.show(code)
    case Reliable.Received{Response.Success{_}, _}: "success"
    case _: "other"

def late(response: Response.Response, mode: Auth.Mode) -> String:
  match response mode:
    case Response.Success{_} Auth.Legacy{}: "success-legacy"
    case Response.Success{_} _: "success-sha256"
    case Response.Error{code} Auth.Legacy{}: "error" ++ U32.show(code) ++ "-legacy"
    case Response.Error{code} _: "error" ++ U32.show(code) ++ "-sha256"
    case Response.Invalid{} _: "invalid"

def events(values: List<&2, Tx.Notice>, out: String) -> String:
  match values:
    case Nil{}: out
    case Con{Tx.Send{token, _, _, _, _}, tail}: events(tail, out ++ ":send" ++ U32.show(token))
    case Con{Tx.Finished{token, reply}, tail}: events(tail, out ++ ":done" ++ U32.show(token) ++ "-" ++ verdict(reply))
    case Con{Tx.Cancelled{token}, tail}: events(tail, out ++ ":cancel" ++ U32.show(token))
    case Con{Tx.Stopped{token}, tail}: events(tail, out ++ ":stop" ++ U32.show(token))
    case Con{Tx.Retired{token}, tail}: events(tail, out ++ ":retire" ++ U32.show(token))
    case Con{Tx.LateResponse{token, response, mode}, tail}: events(tail, out ++ ":late" ++ U32.show(token) ++ "-" ++ late(response, mode))
    case Con{Tx.SocketFailure{code}, tail}: events(tail, out ++ ":socket" ++ U32.show(code))
    case Con{Tx.Datagram{_, _, _}, tail}: events(tail, out ++ ":raw")
    case Con{_, tail}: events(tail, out ++ ":other")

def entries(values: List<&2, Tx.Entry>, +base: Nat, out: String) -> String:
  match values:
    case Nil{}: out
    case Con{Tx.Entry{token, _, deadline, waits, _}, tail}:
      entries(tail, base, out ++ ":" ++ U32.show(token) ++ "/" ++ Nat.show(Nat.sub(deadline, base)) ++ "/" ++ Nat.show(List.length(&2, U32, waits)))
    case Con{Tx.Listening{token, _, deadline}, tail}:
      entries(tail, base, out ++ ":" ++ U32.show(token) ++ "/" ++ Nat.show(Nat.sub(deadline, base)) ++ "/listening")

def snapshot(state: Tx.State, +base: Nat) -> String:
  match state:
    case Tx.State{values, _, _, start, send}:
      entries(values, base, Nat.show(Nat.sub(start, base)) ++ "," ++ Nat.show(Nat.sub(send, base)))

def emit(step: Tx.Step, base: Nat) -> IO(Tx.State):
  match step:
    case Tx.Step{+state, values}:
      do IO<Tx.State>:
        x : Unit <- IO.print(events(values, snapshot(state, base)))
        return state

def begun(result: Tx.Start, state: Tx.State, +base: Nat) -> IO(Tx.State):
  match result:
    case Tx.Ready{step}: emit(step, base)
    case Tx.Later{at}:
      do IO<Tx.State>:
        x : Unit <- IO.print("later:" ++ Nat.show(Nat.sub(at, base)))
        return state
    case Tx.Rejected{}:
      do IO<Tx.State>:
        x : Unit <- IO.print("rejected")
        return state

def start(+state: Tx.State, +token: U32, tx: U32, requests: U32, now: Nat, base: Nat) -> IO(Tx.State):
  begun(Tx.start(state, token, "127.0.0.1", (9000 + token : U32),
    Discovery.transaction(tx, 2, 3), Retry.Policy{500, requests, 1}, Fixture.credentials(),
    Ice.Check{1845494271, Ice.Controlling{4275878552, 1985229328}}, Auth.Dual{}, now), state, base)

def pacing(+base: Nat) -> IO(Unit):
  do IO<Unit>:
    s0 : Tx.State <- start(Tx.default(), 0, 1, 3, base, base)
    s1 : Tx.State <- start(s0, 1, 2, 3, Nat.add(base, 49n), base)
    s2 : Tx.State <- start(s1, 1, 2, 3, Nat.add(base, 50n), base)
    s3 : Tx.State <- emit(Tx.tick(s2, Nat.add(base, 500n)), base)
    s4 : Tx.State <- emit(Tx.tick(s3, Nat.add(base, 500n)), base)
    s5 : Tx.State <- emit(Tx.tick(s4, Nat.add(base, 550n)), base)
    s6 : Tx.State <- emit(Tx.tick(s5, Nat.add(base, 1500n)), base)
    s7 : Tx.State <- emit(Tx.tick(s6, Nat.add(base, 1550n)), base)
    s8 : Tx.State <- emit(Tx.tick(s7, Nat.add(base, 2000n)), base)
    s9 : Tx.State <- emit(Tx.tick(s8, Nat.add(base, 2050n)), base)
    IO.print("wake:" ++ U32.show(Tx.timeout(s9, Nat.add(base, 2050n), 37)))

def ack(+base: Nat) -> IO(Unit):
  do IO<Unit>:
    s0 : Tx.State <- start(Tx.default(), 0, 1, 1, base, base)
    s1 : Tx.State <- emit(Tx.Step{Tx.sent(s0, Nat.add(base, 498n), True{}), []}, base)
    s2 : Tx.State <- emit(Tx.tick(s1, Nat.add(base, 500n)), base)
    s3 : Tx.State <- start(s2, 1, 2, 1, Nat.add(base, 503n), base)
    s4 : Tx.State <- start(s3, 1, 2, 1, Nat.add(base, 548n), base)
    s5 : Tx.State <- emit(Tx.failed(s4, 1, 22), base)
    IO.print("wake:" ++ U32.show(Tx.timeout(s5, Nat.add(base, 548n), 37)))

def stale(step: Tx.Step) -> IO(Unit):
  match step:
    case Tx.Step{+state, [ +command ]}:
      do IO<Unit>:
        x : Unit <- IO.print(Bool.pick(String, Tx.current_send(state, command), "current", "missing"))
        retired : Tx.State <- emit(Tx.cancel(state, 0), 0n)
        IO.print(Bool.pick(String, Tx.current_send(retired, command), "stale-sent", "stale-suppressed"))
    case _: IO.die(Unit, 3, "bad fixture start")

def cancel_result(result: Tx.Start) -> IO(Unit):
  match result:
    case Tx.Ready{step}: stale(step)
    case _: IO.die(Unit, 3, "bad fixture start")

def cancel_test() -> IO(Unit):
  cancel_result(Tx.start(Tx.default(), 0, "127.0.0.1", 9000, Discovery.transaction(1, 2, 3),
    Retry.Policy{500, 1, 1}, Fixture.credentials(),
    Ice.Check{1845494271, Ice.Controlling{4275878552, 1985229328}}, Auth.Dual{}, 0n))

def duplicate_test(+base: Nat) -> IO(Unit):
  do IO<Unit>:
    s0 : Tx.State <- start(Tx.default(), 0, 1, 1, base, base)
    s1 : Tx.State <- start(s0, 0, 2, 1, Nat.add(base, 50n), base)
    s2 : Tx.State <- start(s1, 1, 1, 1, Nat.add(base, 50n), base)
    s3 : Tx.State <- start(s2, 1, 2, 1, Nat.add(base, 50n), base)
    s4 : Tx.State <- emit(Tx.cancel(s3, 0), base)
    s5 : Tx.State <- emit(Tx.cancel(s4, 0), base)
    s6 : Tx.State <- emit(Tx.tick(s5, Nat.add(base, 550n)), base)
    IO.print("wake:" ++ U32.show(Tx.timeout(s6, Nat.add(base, 550n), 37)))

def boundary(+state: Tx.State, +raw: List<&2, U32>, +base: Nat) -> IO(Unit):
  do IO<Unit>:
    early : Tx.State <- emit(Tx.receive(state, "127.0.0.1", 9000, raw, Nat.add(base, 499n)), base)
    late : Tx.State <- emit(Tx.receive(state, "127.0.0.1", 9000, raw, Nat.add(base, 500n)), base)
    drained : Tx.State <- emit(Tx.tick(early, Nat.add(base, 500n)), base)
    IO.print("wake:" ++ U32.show(Tx.timeout(late, Nat.add(base, 500n), 37)))

def response_test(+base: Nat, path: String) -> IO(Unit):
  do IO<Unit>:
    raw : List<&2, U32> <- Io.read_bytes(path)
    state : Tx.State <- start(Tx.default(), 0, 1, 1, base, base)
    boundary(state, raw, base)

def response_base(base: Maybe<&2, U32>, path: String) -> IO(Unit):
  match base:
    case Some{b}: response_test(U32.to_nat(b), path)
    case None{}: IO.die(Unit, 2, "bad fixture clock")

def wake(+state: Tx.State, now: Nat, cap: U32) -> IO(Tx.State):
  do IO<Tx.State>:
    x : Unit <- IO.print("wake:" ++ U32.show(Tx.timeout(state, now, cap)))
    return state

def stopped_schedule(+base: Nat) -> IO(Unit):
  do IO<Unit>:
    s0 : Tx.State <- start(Tx.default(), 0, 1, 3, base, base)
    s1 : Tx.State <- emit(Tx.tick(s0, Nat.add(base, 600n)), base)
    s2 : Tx.State <- emit(Tx.stop_retries(s1, 0), base)
    s3 : Tx.State <- emit(Tx.tick(s2, Nat.add(base, 1600n)), base)
    s4 : Tx.State <- emit(Tx.stop_retries(s3, 0), base)
    awake : Tx.State <- wake(s4, Nat.add(base, 2050n), 1000)
    s5 : Tx.State <- emit(Tx.tick(awake, Nat.add(base, 2099n)), base)
    s6 : Tx.State <- emit(Tx.tick(s5, Nat.add(base, 2100n)), base)
    s7 : Tx.State <- emit(Tx.stop_retries(s6, 0), base)
    IO.print("wake:" ++ U32.show(Tx.timeout(s7, Nat.add(base, 2100n), 37)))

def stopped_capacity(+base: Nat) -> IO(Unit):
  do IO<Unit>:
    s0 : Tx.State <- start(Tx.State{[], 50, 2, base, base}, 0, 1, 3, base, base)
    s1 : Tx.State <- emit(Tx.stop_retries(s0, 0), base)
    s2 : Tx.State <- start(s1, 0, 2, 3, Nat.add(base, 50n), base)
    s3 : Tx.State <- start(s2, 1, 1, 3, Nat.add(base, 50n), base)
    s4 : Tx.State <- start(s3, 1, 2, 3, Nat.add(base, 50n), base)
    s5 : Tx.State <- emit(Tx.stop_retries(s4, 1), base)
    s6 : Tx.State <- start(s5, 2, 3, 3, Nat.add(base, 100n), base)
    s7 : Tx.State <- emit(Tx.cancel(s6, 0), base)
    s8 : Tx.State <- start(s7, 0, 1, 1, Nat.add(base, 100n), base)
    s9 : Tx.State <- emit(Tx.failed(s8, 1, 22), base)
    s10 : Tx.State <- emit(Tx.tick(s9, Nat.add(base, 600n)), base)
    IO.print("wake:" ++ U32.show(Tx.timeout(s10, Nat.add(base, 600n), 37)))

def suppressed(+state: Tx.State, command: Tx.Notice) -> IO(Tx.State):
  do IO<Tx.State>:
    x : Unit <- IO.print(Bool.pick(String, Tx.current_send(state, command), "stale-sent", "stale-suppressed"))
    return state

def stop_queued(step: Tx.Step) -> IO(Unit):
  match step:
    case Tx.Step{+state, [+command]}:
      do IO<Unit>:
        stopped : Tx.State <- emit(Tx.stop_retries(state, 0), 0n)
        suppressed : Tx.State <- suppressed(stopped, command)
        done : Tx.State <- emit(Tx.tick(suppressed, 2000n), 0n)
        IO.print("wake:" ++ U32.show(Tx.timeout(done, 2000n, 37)))
    case _: IO.die(Unit, 3, "bad queued fixture")

def stopped_queued(result: Tx.Start) -> IO(Unit):
  match result:
    case Tx.Ready{step}: stop_queued(step)
    case _: IO.die(Unit, 3, "bad queued fixture")

def queued_test() -> IO(Unit):
  stopped_queued(Tx.start(Tx.default(), 0, "127.0.0.1", 9000, Discovery.transaction(1, 2, 3),
    Retry.Policy{500, 3, 1}, Fixture.credentials(),
    Ice.Check{1845494271, Ice.Controlling{4275878552, 1985229328}}, Auth.Dual{}, 0n))

def queued_retry(result: Tx.Start) -> IO(Unit):
  match result:
    case Tx.Ready{Tx.Step{state, _}}: stop_queued(Tx.tick(state, 500n))
    case _: IO.die(Unit, 3, "bad queued retry fixture")

def retry_queued_test() -> IO(Unit):
  queued_retry(Tx.start(Tx.default(), 0, "127.0.0.1", 9000, Discovery.transaction(1, 2, 3),
    Retry.Policy{500, 3, 1}, Fixture.credentials(),
    Ice.Check{1845494271, Ice.Controlling{4275878552, 1985229328}}, Auth.Dual{}, 0n))

def default_stopped(result: Tx.Start, +base: Nat) -> IO(Unit):
  match result:
    case Tx.Ready{step}:
      do IO<Unit>:
        s0 : Tx.State <- emit(step, base)
        s1 : Tx.State <- emit(Tx.stop_retries(s0, 0), base)
        s2 : Tx.State <- emit(Tx.tick(s1, Nat.add(base, 31500n)), base)
        s3 : Tx.State <- wake(s2, Nat.add(base, 39499n), 1000)
        s4 : Tx.State <- emit(Tx.tick(s3, Nat.add(base, 39500n)), base)
        IO.print("wake:" ++ U32.show(Tx.timeout(s4, Nat.add(base, 39500n), 37)))
    case _: IO.die(Unit, 3, "bad default fixture")

def default_test(+base: Nat) -> IO(Unit):
  default_stopped(Tx.start(Tx.default(), 0, "127.0.0.1", 9000, Discovery.transaction(1, 2, 3),
    Retry.default(), Fixture.credentials(), Ice.Check{1845494271, Ice.Controlling{0, 1}}, Auth.Dual{}, base), base)

def stopped_socket(+base: Nat) -> IO(Unit):
  do IO<Unit>:
    s0 : Tx.State <- start(Tx.default(), 0, 1, 3, base, base)
    s1 : Tx.State <- emit(Tx.stop_retries(s0, 0), base)
    s2 : Tx.State <- start(s1, 1, 2, 3, Nat.add(base, 50n), base)
    s3 : Tx.State <- emit(SocketIO.fail_all(s2, 77), base)
    IO.print("wake:" ++ U32.show(Tx.timeout(s3, Nat.add(base, 50n), 37)))

def listening_state(+s0: Tx.State, +raw: List<&2, U32>, +base: Nat, when: U32) -> IO(Unit):
  do IO<Unit>:
    s1 : Tx.State <- emit(Tx.receive(s0, "127.0.0.1", 9000, raw, Nat.add(base, 100n)), base)
    s2 : Tx.State <- emit(Tx.stop_retries(s0, 0), base)
    s3 : Tx.State <- emit(Tx.receive(s2, "127.0.0.1", 9001, raw, Nat.add(base, 200n)), base)
    s4 : Tx.State <- emit(Tx.receive(s3, "127.0.0.2", 9000, raw, Nat.add(base, 300n)), base)
    s5 : Tx.State <- emit(Tx.receive(s4, "127.0.0.1", 9000, raw, Nat.add(base, U32.to_nat(when))), base)
    s6 : Tx.State <- emit(Tx.tick(s5, Nat.add(base, 2000n)), base)
    # A prior integrity violation must not turn interrupted expiry into failure.
    s7 : Tx.State <- emit(Tx.stop_retries(s1, 0), base)
    s8 : Tx.State <- emit(Tx.tick(s7, Nat.add(base, 2000n)), base)
    IO.print("wake:" ++ U32.show(Tx.timeout(s8, Nat.add(base, 2000n), 37)))

def listening_bytes(+raw: List<&2, U32>, +base: Nat, when: U32) -> IO(Unit):
  do IO<Unit>:
    s0 : Tx.State <- start(Tx.default(), 0, 1, 3, base, base)
    listening_state(s0, raw, base, when)

def listening_response(base: Nat, when: U32, path: String) -> IO(Unit):
  do IO<Unit>:
    raw : List<&2, U32> <- Io.read_bytes(path)
    listening_bytes(raw, base, when)

def listening_numbers(base: Maybe<&2, U32>, when: Maybe<&2, U32>, path: String) -> IO(Unit):
  match base when:
    case Some{b} Some{w}: listening_response(U32.to_nat(b), w, path)
    case _ _: IO.die(Unit, 2, "bad fixture clocks")

def parsed(base: Maybe<&2, U32>, scenario: String) -> IO(Unit):
  match base scenario:
    case Some{b} "pacing": pacing(U32.to_nat(b))
    case Some{b} "ack": ack(U32.to_nat(b))
    case Some{b} "duplicate": duplicate_test(U32.to_nat(b))
    case Some{_} "cancel": cancel_test()
    case Some{b} "stop-schedule": stopped_schedule(U32.to_nat(b))
    case Some{b} "stop-capacity": stopped_capacity(U32.to_nat(b))
    case Some{_} "stop-queued": queued_test()
    case Some{_} "stop-queued-retry": retry_queued_test()
    case Some{b} "stop-default": default_test(U32.to_nat(b))
    case Some{b} "stop-socket": stopped_socket(U32.to_nat(b))
    case _ _: IO.die(Unit, 2, "bad fixture arguments")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case ["response", base, path]: response_base(U32.read(base), path)
    case ["listening", base, when, path]: listening_numbers(U32.read(base), U32.read(when), path)
    case [scenario, base]: parsed(U32.read(base), scenario)
    case _: IO.die(Unit, 2, "usage: ice_clock <pacing|ack|duplicate|cancel> <base>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
