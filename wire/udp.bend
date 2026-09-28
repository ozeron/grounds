import Base
import ./wire.bend as W

def RU() -> Type:
  Socket & Result<&1, &1, U32 & String, Unit>

def RD() -> Type:
  Socket & Result<&1, &1, U32 & String, Maybe<&1, String & U32 & List<&2, U32>>>

def upto(n: Nat, +i: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      List.reverse(&2, U32, acc)
    case 1n+p:
      upto(p, (i + 1 : U32), Con{i, acc})

def same(a: List<&2, U32>, b: List<&2, U32>, ok: Bool) -> Bool:
  match a b:
    case Nil{} Nil{}:
      ok
    case Con{+x, at} Con{+y, bt}:
      same(at, bt, Bool.and(ok, U32.is_eq(x, y)))
    case _ _:
      False{}

def assert(ok: Bool, message: String) -> IO(Unit):
  match ok:
    case True{}:
      IO.pure(Unit, Unit{})
    case False{}:
      IO.die(Unit, 1, message)

law sent:
  for m: RU()
  IO(Socket)

def sent(m):
  (s, r) = m
  do IO<Socket>:
    x : Unit <- IO.pass(Unit, r)
    return s

law got:
  for m: RD()
  IO(Socket & Maybe<&1, String & U32 & List<&2, U32>>)

def got(m):
  (s, r) = m
  do IO<Socket & Maybe<&1, String & U32 & List<&2, U32>>>:
    v : Maybe<&1, String & U32 & List<&2, U32>> <- IO.pass(Maybe<&1, String & U32 & List<&2, U32>>, r)
    return (s, v)

def check_none(v: Maybe<&1, String & U32 & List<&2, U32>>) -> IO(Unit):
  match v:
    case None{}:
      IO.pure(Unit, Unit{})
    case Some{_}:
      IO.die(Unit, 1, "udp: timeout returned a datagram")

def check_packet(v: Maybe<&1, String & U32 & List<&2, U32>>, want_port: U32, want: List<&2, U32>) -> IO(Unit):
  match v:
    case None{}:
      IO.die(Unit, 1, "udp: datagram timed out")
    case Some{(host, (port, bytes))}:
      do IO<Unit>:
        a : Unit <- assert(U32.is_eq(port, want_port), "udp: wrong source port")
        b : Unit <- assert(same(bytes, want, True{}), "udp: bytes changed")
        assert(String.eq(host, "127.0.0.1"), "udp: wrong source host")

def failed_send(m: RU(), code: U32) -> IO(Socket):
  (s, r) = m
  match r:
    case Done{_}:
      IO.die(Socket, 1, "udp: invalid byte was sent")
    case Fail{(got_code, _)}:
      do IO<Socket>:
        x : Unit <- assert(U32.is_eq(got_code, code), "udp: wrong send error")
        return s

def failed_recv(m: RD()) -> IO(Socket):
  (s, r) = m
  match r:
    case Done{_}:
      IO.die(Socket, 1, "udp: oversized datagram was truncated")
    case Fail{(+code, _)}:
      do IO<Socket>:
        x : Unit <- assert(Bool.or(U32.is_eq(code, 40), U32.is_eq(code, 90)), "udp: wrong size error")
        return s

def check_got_none(m: Socket & Maybe<&1, String & U32 & List<&2, U32>>) -> IO(Socket):
  (s, v) = m
  do IO<Socket>:
    x : Unit <- check_none(v)
    return s

def check_got_packet(m: Socket & Maybe<&1, String & U32 & List<&2, U32>>, port: U32, bytes: List<&2, U32>) -> IO(Socket):
  (s, v) = m
  do IO<Socket>:
    x : Unit <- check_packet(v, port, bytes)
    return s

def main() -> IO(Unit):
  do IO<Unit>:
    a : Socket <- IO.try(Socket, UDP.bind(47833))
    b : Socket <- IO.try(Socket, UDP.bind(47834))
    empty_poll : RD() <- W.wire_udp_recv_from_timeout(b, 256, 20)
    empty_result : Socket & Maybe<&1, String & U32 & List<&2, U32>> <- got(empty_poll)
    b1 : Socket <- check_got_none(empty_result)
    all_sent : RU() <- W.wire_udp_send_to(a, "127.0.0.1", 47834, upto(256n, 0, []), 1000)
    a1 : Socket <- sent(all_sent)
    all_recv : RD() <- W.wire_udp_recv_from_timeout(b1, 256, 1000)
    all_result : Socket & Maybe<&1, String & U32 & List<&2, U32>> <- got(all_recv)
    b2 : Socket <- check_got_packet(all_result, 47833, upto(256n, 0, []))
    zero_sent : RU() <- W.wire_udp_send_to(b2, "127.0.0.1", 47833, [], 1000)
    b3 : Socket <- sent(zero_sent)
    zero_recv : RD() <- W.wire_udp_recv_from_timeout(a1, 0, 1000)
    zero_result : Socket & Maybe<&1, String & U32 & List<&2, U32>> <- got(zero_recv)
    a2 : Socket <- check_got_packet(zero_result, 47834, [])
    too_long : RU() <- W.wire_udp_send_to(a2, "127.0.0.1", 47834, [1, 2, 3], 1000)
    a3 : Socket <- sent(too_long)
    truncated : RD() <- W.wire_udp_recv_from_timeout(b3, 2, 1000)
    b4 : Socket <- failed_recv(truncated)
    bad : RU() <- W.wire_udp_send_to(a3, "127.0.0.1", 47834, [256], 1000)
    a4 : Socket <- failed_send(bad, 22)
    no_bad : RD() <- W.wire_udp_recv_from_timeout(b4, 8, 20)
    no_bad_result : Socket & Maybe<&1, String & U32 & List<&2, U32>> <- got(no_bad)
    b5 : Socket <- check_got_none(no_bad_result)
    x : Unit <- Socket.close(a4)
    y : Unit <- Socket.close(b5)
    IO.print("udp: 256 bytes, zero datagram, timeout, oversize and invalid byte")
