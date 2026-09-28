import Base
import ../wire/wire.bend as W
import ./stun.bend as Stun

# One unauthenticated Binding transaction to discover an IPv4 server-reflexive
# address. ICE checks will add authentication, retries, and pair management.
def RU() -> Type:
  Socket & Result<&1, &1, U32 & String, Unit>

def RD() -> Type:
  Socket & Result<&1, &1, U32 & String, Maybe<&1, String & U32 & List<&2, U32>>>

def word_bytes(+x: U32, tail: List<&2, U32>) -> List<&2, U32>:
  Con{U32.and(U32.shrn(x, 24n), 255),
    Con{U32.and(U32.shrn(x, 16n), 255),
      Con{U32.and(U32.shrn(x, 8n), 255), Con{U32.and(x, 255), tail}}}}

def transaction(+a: U32, +b: U32, +c: U32) -> List<&2, U32>:
  word_bytes(a, word_bytes(b, word_bytes(c, [])))

def required(packet: Maybe<&2, List<&2, U32>>) -> IO(List<&2, U32>):
  match packet:
    case Some{bytes}:
      IO.pure(List<&2, U32>, bytes)
    case None{}:
      IO.die(List<&2, U32>, 1, "STUN transaction ID is invalid")

def sent(m: RU()) -> IO(Socket):
  (s, r) = m
  do IO<Socket>:
    x : Unit <- IO.pass(Unit, r)
    return s

def mapped(ok: Bool, packet: Stun.Packet) -> Maybe<&2, Stun.IPv4>:
  match ok:
    case True{}:
      Stun.mapped_ipv4(packet)
    case False{}:
      None{}

def checked.packet(+packet: Stun.Packet, transaction: List<&2, U32>) -> Maybe<&2, Stun.IPv4>:
  mapped(Stun.binding_success(packet, transaction), packet)

def checked(parsed: Maybe<&2, Stun.Packet>, transaction: List<&2, U32>) -> Maybe<&2, Stun.IPv4>:
  match parsed:
    case Some{packet}:
      checked.packet(packet, transaction)
    case None{}:
      None{}

def source(ok: Bool, bytes: List<&2, U32>, transaction: List<&2, U32>) -> Maybe<&2, Stun.IPv4>:
  match ok:
    case True{}:
      checked(Stun.parse(bytes), transaction)
    case False{}:
      None{}

def response(r: Result<&1, &1, U32 & String, Maybe<&1, String & U32 & List<&2, U32>>>,
             +host: String, +port: U32, transaction: List<&2, U32>) -> Maybe<&2, Stun.IPv4>:
  match r:
    case Done{Some{(from, (from_port, bytes))}}:
      source(Bool.and(String.eq(host, from), U32.is_eq(port, from_port)), bytes, transaction)
    case _:
      None{}

def received(m: RD(), +host: String, +port: U32,
             transaction: List<&2, U32>) -> IO(Maybe<&2, Stun.IPv4>):
  (s, r) = m
  do IO<Maybe<&2, Stun.IPv4>>:
    result : Maybe<&2, Stun.IPv4> <- IO.pure(Maybe<&2, Stun.IPv4>, response(r, host, port, transaction))
    x : Unit <- Socket.close(s)
    return result

def request.with_transaction(+transaction: List<&2, U32>, +host: String,
                             +port: U32, +ms: U32) -> IO(Maybe<&2, Stun.IPv4>):
  do IO<Maybe<&2, Stun.IPv4>>:
    bytes : List<&2, U32> <- required(Stun.binding_request(transaction))
    socket : Socket <- IO.try(Socket, UDP.bind(0))
    sent_packet : RU() <- W.wire_udp_send_to(socket, host, port, bytes, ms)
    socket2 : Socket <- sent(sent_packet)
    reply : RD() <- W.wire_udp_recv_from_timeout(socket2, 65535, ms)
    received(reply, host, port, transaction)

def request(+host: String, +port: U32, +ms: U32) -> IO(Maybe<&2, Stun.IPv4>):
  do IO<Maybe<&2, Stun.IPv4>>:
    a : U32 <- IO.try(U32, IO.random_u32())
    b : U32 <- IO.try(U32, IO.random_u32())
    c : U32 <- IO.try(U32, IO.random_u32())
    request.with_transaction(transaction(a, b, c), host, port, ms)
