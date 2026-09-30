import Base
import ./ice_binding.bend as Ice
import ./ice_response.bend as Response
import ./stun_auth.bend as Auth
import ./stun_retry.bend as Retry
import ./stun_client.bend as Discovery
import ../wire/wire.bend as W

type Outcome is Data:
  Received{response: Response.Response, algorithm: Auth.Mode}
  TimedOut{}
  IntegrityViolation{}
  TransportError{code: U32}
  FloodLimit{}
  InvalidInput{}

def Reply() -> Type:
  Socket & Outcome

type Context is Data:
  Context{host: String, port: U32, transaction: List<&2, U32>, key: List<&2, U32>, mode: Auth.Mode, bytes: List<&2, U32>}

type Attempt is Data:
  Attempt{context: Context, deadline: Nat, next: List<&2, U32>, violated: Bool}

def source_checked(ok: Bool, raw: List<&2, U32>, transaction: List<&2, U32>,
                   key: List<&2, U32>, mode: Auth.Mode) -> Maybe<&2, Response.Reply>:
  match ok:
    case False{}: None{}
    case True{}: Response.parse(raw, transaction, key, mode)

def source(context: Context, from: String, from_port: U32, raw: List<&2, U32>) -> Maybe<&2, Response.Reply>:
  match context:
    case Context{host, port, transaction, key, mode, _}:
      source_checked(Bool.and(String.eq(host, from), U32.is_eq(port, from_port)), raw, transaction, key, mode)

def source_failed(ok: Bool, raw: List<&2, U32>, transaction: List<&2, U32>, key: List<&2, U32>, mode: Auth.Mode) -> Bool:
  match ok:
    case False{}: False{}
    case True{}: Response.integrity_failed(raw, transaction, key, mode)

def suspect(context: Context, from: String, from_port: U32, raw: List<&2, U32>) -> Bool:
  match context:
    case Context{host, port, transaction, key, mode, _}:
      source_failed(Bool.and(String.eq(host, from), U32.is_eq(port, from_port)), raw, transaction, key, mode)

def got(response: Maybe<&2, Response.Reply>, socket: Socket, failed: Bool, again: Socket -> Bool -> IO(Reply())) -> IO(Reply()):
  match response:
    case Some{Response.Reply{r, mode}}: IO.pure(Reply(), (socket, Received{r, mode}))
    case None{}: again(socket, failed)

def recv_failed(oversize: Bool, code: U32, socket: Socket, again: Socket -> Bool -> IO(Reply())) -> IO(Reply()):
  match oversize:
    case True{}: again(socket, False{})
    case False{}: IO.pure(Reply(), (socket, TransportError{code}))

def datagram(socket: Socket, +context: Context, +from: String, +port: U32, +bytes: List<&2, U32>,
             again: Socket -> Bool -> IO(Reply())) -> IO(Reply()):
  got(source(context, from, port, bytes), socket, suspect(context, from, port, bytes), again)

def recv_result(result: Result<&1, &1, U32 & String, Maybe<&1, String & U32 & List<&2, U32>>>,
                socket: Socket, +context: Context, again: Socket -> Bool -> IO(Reply())) -> IO(Reply()):
  match result:
    case Done{Some{(from, (port, bytes))}}:
      datagram(socket, context, from, port, bytes, again)
    case Done{None{}}:
      # Re-read the monotonic clock, including if the OS woke slightly early.
      again(socket, False{})
    case Fail{(+code, _)}:
      recv_failed(Bool.or(U32.is_eq(code, 40), U32.is_eq(code, 90)), code, socket, again)

def received(m: Discovery.RD(), context: Context, again: Socket -> Bool -> IO(Reply())) -> IO(Reply()):
  (socket, result) = m
  recv_result(result, socket, context, again)

def sent_result(result: Result<&1, &1, U32 & String, Unit>, socket: Socket, attempt: Attempt,
                resume: Socket -> Attempt -> IO(Reply())) -> IO(Reply()):
  match result:
    case Done{_}: resume(socket, attempt)
    case Fail{(code, _)}: IO.pure(Reply(), (socket, TransportError{code}))

def sent(m: Discovery.RU(), attempt: Attempt, resume: Socket -> Attempt -> IO(Reply())) -> IO(Reply()):
  (socket, result) = m
  sent_result(result, socket, attempt, resume)

def transmit(socket: Socket, attempt: Attempt, ms: U32, resume: Socket -> Attempt -> IO(Reply())) -> IO(Reply()):
  match attempt:
    case Attempt{Context{+host, +port, +transaction, +key, +mode, +bytes}, +deadline, +next, +violated}:
      IO.bind(Discovery.RU(), Reply(), W.wire_udp_send_to(socket, host, port, bytes, ms),
        m => sent(m, Attempt{Context{host, port, transaction, key, mode, bytes}, deadline, next, violated}, resume))

def expired(socket: Socket, attempt: Attempt, +now: Nat, resume: Socket -> Attempt -> IO(Reply())) -> IO(Reply()):
  match attempt:
    case Attempt{_, _, Nil{}, violated}:
      IO.pure(Reply(), (socket, Bool.pick(Outcome, violated, IntegrityViolation{}, TimedOut{})))
    case Attempt{context, _, Con{+interval, tail}, violated}:
      transmit(socket, Attempt{context, Nat.add(now, U32.to_nat(interval)), tail, violated}, interval, resume)

def tick(due: Bool, socket: Socket, +attempt: Attempt, now: Nat, left: U32,
         again: Socket -> Bool -> IO(Reply()), resume: Socket -> Attempt -> IO(Reply())) -> IO(Reply()):
  match due:
    case True{}:
      expired(socket, attempt, now, resume)
    case False{}:
      match attempt:
        case Attempt{context, _, _, _}:
          IO.bind(Discovery.RD(), Reply(), W.wire_udp_recv_from_timeout(socket, 65535, left),
            m => received(m, context, again))

def timed(socket: Socket, +attempt: Attempt, +now: Nat, +deadline: Nat,
          again: Socket -> Bool -> IO(Reply()), resume: Socket -> Attempt -> IO(Reply())) -> IO(Reply()):
  tick(Nat.is_le(deadline, now), socket, attempt, now, U32.from_nat(Nat.sub(deadline, now)), again, resume)

# Fuel covers the entire transaction, not a fresh quota per retransmission.
# Invalid traffic never moves the absolute deadline of the current attempt.
def wait(fuel: Nat, socket: Socket, +attempt: Attempt) -> IO(Reply()):
  match fuel attempt:
    case 0n _:
      IO.pure(Reply(), (socket, FloodLimit{}))
    case 1n+ +p Attempt{+context, +deadline, +next, +violated}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        timed(socket, Attempt{context, deadline, next, violated}, now, deadline,
          s => bad => wait(p, s, Attempt{context, deadline, next, Bool.or(violated, bad)}),
          s => a => wait(p, s, a))

def start(socket: Socket, context: Context, intervals: List<&2, U32>) -> IO(Reply()):
  match intervals:
    case Nil{}:
      IO.pure(Reply(), (socket, InvalidInput{}))
    case Con{+interval, tail}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        transmit(socket, Attempt{context, Nat.add(now, U32.to_nat(interval)), tail, False{}}, interval,
          s => a => wait(65536n, s, a))

def prepared(raw: Maybe<&2, List<&2, U32>>, intervals: Maybe<&2, List<&2, U32>>,
             socket: Socket, host: String, port: U32, transaction: List<&2, U32>, key: List<&2, U32>, mode: Auth.Mode) -> IO(Reply()):
  match raw intervals:
    case Some{bytes} Some{waits}:
      start(socket, Context{host, port, transaction, key, mode, bytes}, waits)
    case _ _:
      IO.pure(Reply(), (socket, InvalidInput{}))

# IPv4 literal; caller retains ownership on every outcome. Request is signed
# exactly once and identical bytes, transaction and source socket are reused.
def exchange(socket: Socket, +transaction: List<&2, U32>, host: String, port: U32,
             policy: Retry.Policy, +credentials: Ice.Credentials, check: Ice.Check, +mode: Auth.Mode) -> IO(Reply()):
  prepared(Ice.request(transaction, credentials, check, mode), Retry.intervals(policy),
    socket, host, port, transaction, Ice.key(credentials), mode)

def closed(reply: Reply()) -> IO(Outcome):
  (socket, outcome) = reply
  do IO<Outcome>:
    x : Unit <- Socket.close(socket)
    return outcome

def request(host: String, port: U32, policy: Retry.Policy, credentials: Ice.Credentials,
            check: Ice.Check, mode: Auth.Mode) -> IO(Outcome):
  do IO<Outcome>:
    a : U32 <- IO.try(U32, IO.random_u32())
    b : U32 <- IO.try(U32, IO.random_u32())
    c : U32 <- IO.try(U32, IO.random_u32())
    socket : Socket <- IO.try(Socket, UDP.bind(0))
    reply : Reply() <- exchange(socket, Discovery.transaction(a, b, c), host, port, policy, credentials, check, mode)
    closed(reply)
