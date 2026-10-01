import Base
import ../ice_transport.bend as T
import ../ice_agent.bend as Agent
import ../ice_consent.bend as Consent
import ../ice_session.bend as Session
import ../ice_attempts.bend as A
import ../ice_scheduler.bend as S
import ../ice_transactions.bend as Tx
import ./ice_scheduler_output.bend as Scheduler
import ./ice_session_output.bend as Output
import ./ice_agent_output.bend as Life
import ./ice_consent_output.bend as Probe
import ../../crypto/bytes.bend as B

def source(value: T.Source) -> String:
  match value:
    case T.Check{_}: "check"
    case T.Probe{_}: "probe"

def packet(value: T.Packet) -> String:
  match value:
    case T.Packet{ticket, gen, ref, bytes, src}:
      Nat.show(ticket) ++ ":" ++ U32.show(gen) ++ ":" ++ source(src) ++ ":" ++ Scheduler.ref_text(ref) ++ ":" ++ B.hex(bytes)

def event(+value: T.Notice) -> IO(Unit):
  match value:
    case T.Transmit{p}: IO.print("transmit:" ++ packet(p))
    case T.Reply{ref, gen, bytes, code}: IO.print("reply:" ++ U32.show(gen) ++ ":" ++ U32.show(code) ++ ":" ++ Scheduler.ref_text(ref) ++ ":" ++ B.hex(bytes))
    case T.AgentEvent{e}: Output.events([e])
    case T.Lifecycle{e}: Life.lifecycle([e])
    case T.ConsentEvent{ref, gen, e}:
      do IO<Unit>:
        a : Unit <- IO.print("consent-event:" ++ U32.show(gen) ++ ":" ++ Scheduler.ref_text(ref))
        Probe.event(e)
    case T.Selected{ref, gen}: IO.print("consent-selected:" ++ U32.show(gen) ++ ":" ++ Scheduler.ref_text(ref))
    case T.Restarted{gen}: IO.print("restarted:" ++ U32.show(gen))
    case T.Waiting{at}: IO.print("waiting:" ++ Nat.show(at))
    case T.Rejected{}: IO.print("rejected")
    case T.Exhausted{}: IO.print("exhausted")
    case T.Closed{}: IO.print("closed")

def events(values: List<&2, T.Notice>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{head, tail}:
      do IO<Unit>:
        a : Unit <- event(head)
        events(tail)

def aliases(values: List<&2, T.Slot>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{T.Slot{Consent.State{Consent.Route{ref, gen, _, _, mode}, Consent.Clock{status, expires, next, rto, _, _}, probes, recent, _}, _, refs}, tail}:
      do IO<Unit>:
        a : Unit <- IO.print("slot:" ++ U32.show(gen) ++ ":" ++ Scheduler.ref_text(ref) ++ ":" ++ Probe.status(status) ++ ":" ++ Nat.show(expires) ++ ":" ++ Nat.show(next) ++ ":" ++ U32.show(rto) ++ ":" ++ Probe.mode(mode) ++ ":" ++ Nat.show(List.length(&2, Consent.Probe, probes)) ++ ":" ++ Nat.show(List.length(&2, List<&2, U32>, recent)))
        b : Unit <- Scheduler.show_refs(refs)
        aliases(tail)

def pending(value: Maybe<&2, T.Packet>) -> String:
  match value:
    case None{}: "none"
    case Some{p}: packet(p)

def engine(session: Session.State) -> IO(Unit):
  match session:
    case Session.State{A.State{S.State{lists, queues, flights, role, _, _, gen, _}, Tx.State{entries, _, _, start, send}, records, policies}, _, _, peer, waiting, _}:
      IO.print("ice:" ++ U32.show(gen) ++ ":" ++ Nat.show(List.length(&2, A.Record, records)) ++ ":" ++ Nat.show(List.length(&2, S.Flight, flights)) ++ ":" ++ Nat.show(List.length(&2, Tx.Entry, entries)) ++ ":" ++ Nat.show(List.length(&2, Session.Pending, waiting)) ++ ":" ++ Nat.show(start) ++ ":" ++ Nat.show(send))

def snapshot(+state: T.State, +now: Nat) -> IO(Unit):
  match state:
    case T.State{+agent, +slots, +previous, gate, p, ticket, history, _, closed}:
      do IO<Unit>:
        a : Unit <- IO.print("owner:" ++ U32.show(Agent.generation(agent)) ++ ":" ++ Life.status_text(Agent.status(agent)) ++ ":" ++ Probe.flag(closed) ++ ":" ++ Nat.show(gate) ++ ":" ++ Nat.show(ticket) ++ ":" ++ Nat.show(List.length(&2, T.Stamp, history)))
        b : Unit <- IO.print("pending:" ++ pending(p))
        c : Unit <- IO.print("slot-count:" ++ Nat.show(List.length(&2, T.Slot, slots)) ++ ":" ++ Nat.show(List.length(&2, T.Slot, previous)))
        d : Unit <- engine(Agent.session(agent))
        e : Unit <- aliases(slots)
        f : Unit <- aliases(previous)
        g : Unit <- IO.print("role:" ++ Scheduler.role_text(Agent.role(agent)))
        IO.print("timeout:" ++ U32.show(T.timeout(state, now, 60000)))
