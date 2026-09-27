import Base
import ./resp.bend as R
import ../wire/wire.bend as W

# grounds-redis: a Redis client. command(sock, args) sends one command and
# reads its reply:
#
#   s : Socket <- IO.try(Socket, Redis.connect("127.0.0.1", 6379))
#   m : Redis.Reply() <- Redis.command(s, ["SET", "k", "v"])

def RB() -> Type:
  Socket & Result<&1, &1, U32 & String, List<&2, U32>>

def RU() -> Type:
  Socket & Result<&1, &1, U32 & String, Unit>

# the socket back, and the reply or why there is none
def Reply() -> Type:
  Socket & Result<&1, &1, String, R.Reply>

def connect(host: String, port: U32) -> IO(Result<&1, &1, U32 & String, Socket>):
  W.connect(host, port)

def close(s: Socket) -> IO(Unit):
  W.close(s)

def fail(s: Socket, why: String) -> IO(Reply()):
  IO.pure(Reply(), (s, Fail{why}))

# one parse of what has come: the reply, or read on
def got.parsed(p: R.Parsed, acc: R.Buf, s: Socket, k: R.Buf -> Socket -> IO(Reply())) -> IO(Reply()):
  match p:
    case R.Parsed{reply, _}:
      IO.pure(Reply(), (s, Done{reply}))
    case R.More{}:
      k(acc, s)
    case R.Bad{why}:
      fail(s, why)

# the copy is parsed, the original kept for a read that needs more
def got.more(+all: R.Buf, s: Socket, k: R.Buf -> Socket -> IO(Reply())) -> IO(Reply()):
  got.parsed(R.parse.buf(R.buf.copy(all, R.BNil{})), all, s, k)

def got.bytes(closed: Bool, acc: R.Buf, +bs: R.Buf, s: Socket, k: R.Buf -> Socket -> IO(Reply())) -> IO(Reply()):
  match closed:
    case True{}:
      fail(s, "connection closed")
    case False{}:
      got.more(R.buf.app(acc, bs), s, k)

def got.new(acc: R.Buf, +bs: R.Buf, s: Socket, k: R.Buf -> Socket -> IO(Reply())) -> IO(Reply()):
  got.bytes(R.buf.empty(bs), acc, bs, s, k)

def got.fold(r: Result<&1, &1, U32 & String, List<&2, U32>>, acc: R.Buf, s: Socket, k: R.Buf -> Socket -> IO(Reply())) -> IO(Reply()):
  match r:
    case Done{bs}:
      got.new(acc, R.buf.of(bs), s, k)
    case Fail{_}:
      fail(s, "read failed")

# reads until one reply has come; fuel bounds the reads
law got:
  for fuel: Nat
  for acc: R.Buf
  for m: RB()
  IO(Reply())

def got(fuel, acc, m):
  match fuel:
    case 0n:
      (s, _) = m
      fail(s, "no reply")
    case 1n+f:
      (s, r) = m
      got.fold(r, acc, s, a => sk => IO.bind(RB(), Reply(), W.wire_recv(sk, 65536), m2 => got(f, a, m2)))

def sent.fold(r: Result<&1, &1, U32 & String, Unit>, s: Socket) -> IO(Reply()):
  match r:
    case Done{_}:
      IO.bind(RB(), Reply(), W.wire_recv(s, 65536), m => got(100000n, R.BNil{}, m))
    case Fail{_}:
      fail(s, "send failed")

law sent:
  for m: RU()
  IO(Reply())

def sent(m):
  (s, r) = m
  sent.fold(r, s)

# send one command, read its reply
def command(s: Socket, args: List<&2, String>) -> IO(Reply()):
  IO.bind(RU(), Reply(), W.wire_send(s, R.encode(args)), sent)

def ping(s: Socket) -> IO(Reply()):
  command(s, ["PING"])

def get(s: Socket, key: String) -> IO(Reply()):
  command(s, ["GET", key])

def set(s: Socket, key: String, value: String) -> IO(Reply()):
  command(s, ["SET", key, value])

def del(s: Socket, key: String) -> IO(Reply()):
  command(s, ["DEL", key])

def incr(s: Socket, key: String) -> IO(Reply()):
  command(s, ["INCR", key])
