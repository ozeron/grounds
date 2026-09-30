import Base
import ./ice_binding.bend as Ice
import ./stun.bend as Stun
import ./stun_auth.bend as Auth
import ./stun_client.bend as Discovery
import ../wire/wire.bend as W

def Reply() -> Type:
  Socket & Maybe<&2, Stun.IPv4>

type Exchange is Data:
  Exchange{host: String, port: U32, transaction: List<&2, U32>, key: List<&2, U32>, mode: Auth.Mode, deadline: Nat}

def packet(ok: Bool, raw: List<&2, U32>, transaction: List<&2, U32>,
           key: List<&2, U32>, mode: Auth.Mode) -> Maybe<&2, Stun.IPv4>:
  match ok:
    case False{}:
      None{}
    case True{}:
      Ice.response(raw, transaction, key, mode)

def source(exchange: Exchange, from: String, from_port: U32, raw: List<&2, U32>) -> Maybe<&2, Stun.IPv4>:
  match exchange:
    case Exchange{host, port, transaction, key, mode, _}:
      packet(Bool.and(String.eq(host, from), U32.is_eq(port, from_port)), raw, transaction, key, mode)

def checked(reply: Maybe<&2, Stun.IPv4>, socket: Socket, again: Socket -> IO(Reply())) -> IO(Reply()):
  match reply:
    case Some{address}:
      IO.pure(Reply(), (socket, Some{address}))
    case None{}:
      again(socket)

def failed(oversize: Bool, socket: Socket, again: Socket -> IO(Reply())) -> IO(Reply()):
  match oversize:
    case True{}:
      again(socket)
    case False{}:
      IO.pure(Reply(), (socket, None{}))

def received_result(r: Result<&1, &1, U32 & String, Maybe<&1, String & U32 & List<&2, U32>>>,
                    socket: Socket, exchange: Exchange, again: Socket -> IO(Reply())) -> IO(Reply()):
  match r:
    case Done{Some{(from, (port, raw))}}:
      checked(source(exchange, from, port, raw), socket, again)
    case Done{None{}}:
      IO.pure(Reply(), (socket, None{}))
    case Fail{(+code, _)}:
      failed(Bool.or(U32.is_eq(code, 40), U32.is_eq(code, 90)), socket, again)

def received(m: Discovery.RD(), exchange: Exchange, again: Socket -> IO(Reply())) -> IO(Reply()):
  (socket, result) = m
  received_result(result, socket, exchange, again)

def wait_checked(over: Bool, socket: Socket, +exchange: Exchange, left: U32,
                 again: Socket -> IO(Reply())) -> IO(Reply()):
  match over:
    case True{}:
      IO.pure(Reply(), (socket, None{}))
    case False{}:
      IO.bind(Discovery.RD(), Reply(), W.wire_udp_recv_from_timeout(socket, 65535, left),
        m => received(m, exchange, again))

def wait_now(socket: Socket, +exchange: Exchange, +deadline: Nat, +now: Nat,
             again: Socket -> IO(Reply())) -> IO(Reply()):
  wait_checked(Nat.is_le(deadline, now), socket, exchange,
    U32.from_nat(Nat.sub(deadline, now)), again)

# The deadline is never reset by invalid traffic; fuel bounds receive turns
# at 65,536 as an additional flood limit. There are no retransmissions yet.
def wait(fuel: Nat, socket: Socket, +exchange: Exchange) -> IO(Reply()):
  match fuel exchange:
    case 0n _:
      IO.pure(Reply(), (socket, None{}))
    case 1n+p Exchange{+host, +port, +transaction, +key, +mode, +deadline}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        wait_now(socket, Exchange{host, port, transaction, key, mode, deadline}, deadline, now,
          s => wait(p, s, Exchange{host, port, transaction, key, mode, deadline}))

def sent_result(r: Result<&1, &1, U32 & String, Unit>, socket: Socket, exchange: Exchange) -> IO(Reply()):
  match r:
    case Done{_}:
      wait(65536n, socket, exchange)
    case Fail{_}:
      IO.pure(Reply(), (socket, None{}))

def sent(m: Discovery.RU(), exchange: Exchange) -> IO(Reply()):
  (socket, result) = m
  sent_result(result, socket, exchange)

def send(raw: Maybe<&2, List<&2, U32>>, socket: Socket, +host: String, +port: U32,
         +ms: U32, transaction: List<&2, U32>, key: List<&2, U32>, mode: Auth.Mode) -> IO(Reply()):
  match raw:
    case None{}:
      IO.pure(Reply(), (socket, None{}))
    case Some{bytes}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        result : Discovery.RU() <- W.wire_udp_send_to(socket, host, port, bytes, ms)
        sent(result, Exchange{host, port, transaction, key, mode, Nat.add(now, U32.to_nat(ms))})

# Caller owns the socket before and after the exchange. An IPv4 literal is
# required because source checks compare it directly with recvfrom's address.
def exchange(socket: Socket, +transaction: List<&2, U32>, host: String, port: U32, ms: U32,
             +credentials: Ice.Credentials, check: Ice.Check, +mode: Auth.Mode) -> IO(Reply()):
  send(Ice.request(transaction, credentials, check, mode), socket, host, port, ms,
    transaction, Ice.key(credentials), mode)

def closed(reply: Reply()) -> IO(Maybe<&2, Stun.IPv4>):
  (socket, address) = reply
  do IO<Maybe<&2, Stun.IPv4>>:
    x : Unit <- Socket.close(socket)
    return address

# Convenience one-shot transaction; use exchange to retain a bound socket.
def request(host: String, port: U32, ms: U32, credentials: Ice.Credentials,
            check: Ice.Check, mode: Auth.Mode) -> IO(Maybe<&2, Stun.IPv4>):
  do IO<Maybe<&2, Stun.IPv4>>:
    a : U32 <- IO.try(U32, IO.random_u32())
    b : U32 <- IO.try(U32, IO.random_u32())
    c : U32 <- IO.try(U32, IO.random_u32())
    socket : Socket <- IO.try(Socket, UDP.bind(0))
    reply : Reply() <- exchange(socket, Discovery.transaction(a, b, c), host, port, ms, credentials, check, mode)
    closed(reply)
