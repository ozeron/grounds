import Base
import ../ice_transactions.bend as Tx
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

def events(values: List<&2, Tx.Notice>, out: String) -> String:
  match values:
    case Nil{}: out
    case Con{Tx.Send{token, _, _, _, _}, tail}: events(tail, out ++ ":send" ++ U32.show(token))
    case Con{Tx.Finished{token, reply}, tail}: events(tail, out ++ ":done" ++ U32.show(token) ++ "-" ++ verdict(reply))
    case Con{Tx.Cancelled{token}, tail}: events(tail, out ++ ":cancel" ++ U32.show(token))
    case Con{Tx.Datagram{_, _, _}, tail}: events(tail, out ++ ":raw")
    case Con{_, tail}: events(tail, out ++ ":other")

def entries(values: List<&2, Tx.Entry>, +base: Nat, out: String) -> String:
  match values:
    case Nil{}: out
    case Con{Tx.Entry{token, _, deadline, waits, _}, tail}:
      entries(tail, base, out ++ ":" ++ U32.show(token) ++ "/" ++ Nat.show(Nat.sub(deadline, base)) ++ "/" ++ Nat.show(List.length(&2, U32, waits)))

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

def parsed(base: Maybe<&2, U32>, scenario: String) -> IO(Unit):
  match base scenario:
    case Some{b} "pacing": pacing(U32.to_nat(b))
    case Some{b} "ack": ack(U32.to_nat(b))
    case Some{b} "duplicate": duplicate_test(U32.to_nat(b))
    case Some{_} "cancel": cancel_test()
    case _ _: IO.die(Unit, 2, "bad fixture arguments")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case ["response", base, path]: response_base(U32.read(base), path)
    case [scenario, base]: parsed(U32.read(base), scenario)
    case _: IO.die(Unit, 2, "usage: ice_clock <pacing|ack|duplicate|cancel> <base>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
