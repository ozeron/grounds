import Base
import ../ice_binding.bend as Ice
import ../ice_session.bend as Session
import ../ice_attempts.bend as A
import ../ice_registry.bend as R
import ../ice_scheduler.bend as S
import ../ice_pairs.bend as Pairs
import ../ice_incoming.bend as Incoming
import ../ice_checklist.bend as Check
import ../ice_candidates.bend as C
import ../ice_transactions.bend as Tx
import ../ice_reliable.bend as Reliable
import ../ice_response.bend as Response
import ./ice_scheduler.bend as Scheduler
import ./ice_model.bend as Model
import ./ice_accept.bend as Format
import ./ice_clock.bend as Clock
import ../../crypto/bytes.bend as B

def record(value: A.Record) -> String:
  match value:
    case A.Record{S.Flight{token, reference, role}, gen, tx, conflict}:
      U32.show(token) ++ ":" ++ U32.show(gen) ++ ":" ++ Scheduler.ref_text(reference) ++ ":" ++ Format.role(role) ++ ":" ++
      Format.flag(conflict) ++ ":" ++ B.hex(tx)

def maybe_record(value: Maybe<&2, A.Record>) -> String:
  match value:
    case None{}: "none"
    case Some{r}: record(r)

def verdict(outcome: Reliable.Outcome) -> String:
  match outcome:
    case Reliable.Received{Response.Error{code}, mode}: "error" ++ U32.show(code) ++ "-" ++ Format.mode(mode)
    case Reliable.Received{Response.Success{_}, mode}: "success-" ++ Format.mode(mode)
    case _: Clock.verdict(outcome)

def event(value: Session.Notice) -> IO(Unit):
  match value:
    case Session.Attempt{A.NonSymmetric{r, observed, failed}}:
      IO.print("non-symmetric:" ++ Format.flag(failed) ++ ":" ++ record(r) ++ ":observed:" ++ Scheduler.ref_text(observed))
    case Session.Attempt{A.Transaction{r, Tx.Send{token, _, _, bytes, fresh}}}:
      IO.print("send:" ++ U32.show(token) ++ ":" ++ Format.flag(fresh) ++ ":" ++ maybe_record(r) ++ ":" ++ B.hex(bytes))
    case Session.Attempt{A.Transaction{r, Tx.Finished{token, outcome}}}:
      IO.print("finished:" ++ U32.show(token) ++ ":" ++ verdict(outcome) ++ ":" ++ maybe_record(r))
    case Session.Attempt{A.Transaction{r, Tx.LateResponse{token, response, mode}}}:
      IO.print("late:" ++ U32.show(token) ++ ":" ++ Clock.late(response, mode) ++ ":" ++ maybe_record(r))
    case Session.Attempt{A.Transaction{r, Tx.Retired{token}}}: IO.print("retired:" ++ U32.show(token) ++ ":" ++ maybe_record(r))
    case Session.Attempt{A.Transaction{r, Tx.Stopped{token}}}: IO.print("stopped:" ++ U32.show(token) ++ ":" ++ maybe_record(r))
    case Session.Attempt{A.Transaction{_, Tx.Sent{token}}}: IO.print("sent:" ++ U32.show(token))
    case Session.Attempt{A.Transaction{_, Tx.Datagram{_, _, raw}}}: IO.print("raw:" ++ B.hex(raw))
    case Session.Attempt{A.AtCapacity{}}: IO.print("capacity")
    case Session.Attempt{A.Waiting{at}}: IO.print("waiting:" ++ Nat.show(at))
    case Session.Attempt{A.Idle{}}: IO.print("idle")
    case Session.Datagram{reference, raw}:
      do IO<Unit>:
        x : Unit <- IO.print("datagram:" ++ Scheduler.ref_text(reference))
        IO.print("raw:" ++ B.hex(raw))
    case Session.Reply{reference, bytes, code}: IO.print("reply:" ++ Scheduler.ref_text(reference) ++ ":" ++ U32.show(code) ++ ":" ++ B.hex(bytes))
    case Session.Accepted{r, Incoming.Request{_, remote, priority, role, nominate, mode}, switched}:
      IO.print("accepted:" ++ Scheduler.ref_text(r) ++ ":" ++ remote ++ ":" ++ U32.show(priority) ++ ":" ++ Format.role(role) ++ ":" ++ Format.flag(nominate) ++ ":" ++ Format.mode(mode) ++ ":" ++ Format.flag(switched))
    case Session.Applied{r}: IO.print("applied:" ++ Scheduler.ref_text(r))
    case Session.Deferred{r, overloaded}: IO.print("deferred:" ++ Scheduler.ref_text(r) ++ ":" ++ Format.flag(overloaded))
    case Session.Unbound{r}: IO.print("unbound:" ++ Scheduler.ref_text(r))
    case Session.WaitingCredentials{}: IO.print("credentials")
    case _: IO.print("invalid")

def events(values: List<&2, Session.Notice>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{head, tail}:
      do IO<Unit>:
        x : Unit <- event(head)
        events(tail)

def records(values: List<&2, A.Record>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{r, tail}:
      do IO<Unit>:
        x : Unit <- IO.print("record:" ++ record(r))
        records(tail)

def pending(values: List<&2, Session.Pending>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{Session.Pending{r, Incoming.Request{_, remote, priority, _, nominate, _}}, tail}:
      do IO<Unit>:
        x : Unit <- IO.print("pending:" ++ Scheduler.ref_text(r) ++ ":" ++ remote ++ ":" ++ U32.show(priority) ++ ":" ++ Format.flag(nominate))
        pending(tail)

def remotes(values: List<&2, C.Candidate>, +id: U32) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{C.Candidate{component, priority, foundation, _, +address}, tail}:
      do IO<Unit>:
        x : Unit <- IO.print("remote:" ++ U32.show(id) ++ ":" ++ U32.show(component) ++ ":" ++ U32.show(priority) ++ ":" ++ foundation ++ ":" ++ C.host(address) ++ "/" ++ U32.show(C.port(address)))
        remotes(tail, id)

def registry(values: List<&2, Check.Stream>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{Check.Stream{id, _, rs}, tail}:
      do IO<Unit>:
        x : Unit <- remotes(rs, id)
        registry(tail)

def policies(values: List<&2, A.PeerMode>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{A.PeerMode{+address, mode}, tail}:
      do IO<Unit>:
        x : Unit <- IO.print("policy:" ++ C.host(address) ++ "/" ++ U32.show(C.port(address)) ++ ":" ++ Format.mode(mode))
        policies(tail)

def snapshot(+state: Session.State) -> IO(Session.State):
  match state:
    case Session.State{A.State{S.State{+lists, +qs, +fs, +role, +cursor, +next_token, +generation, +limit}, +engine, +rs, +ps},
                       R.State{+streams, +next, +learned, +capacity}, +secret, +peer, +waiting, +mode}:
      do IO<Session.State>:
        a : Unit <- IO.print("session:" ++ Format.flag(Maybe.is_some(&2, Ice.Credentials, peer)) ++ ":" ++ Nat.show(learned) ++ ":" ++ Format.mode(mode))
        b : Unit <- IO.print("schedule:" ++ Format.role(role) ++ ":" ++ Nat.show(cursor) ++ ":" ++ Nat.show(next_token) ++ ":" ++ U32.show(generation))
        c : Unit <- Model.show_lists(lists)
        d : Unit <- Scheduler.show_queues(qs)
        e : Unit <- Scheduler.show_flights(fs)
        f : Unit <- IO.print("engine:" ++ Clock.snapshot(engine, 0n))
        g : Unit <- records(rs)
        h : Unit <- pending(waiting)
        i : Unit <- registry(streams)
        j : Unit <- policies(ps)
        IO.pure(Session.State, Session.State{A.State{S.State{lists, qs, fs, role, cursor, next_token, generation, limit}, engine, rs, ps},
          R.State{streams, next, learned, capacity}, secret, peer, waiting, mode})
