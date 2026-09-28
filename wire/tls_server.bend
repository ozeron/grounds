import Base
import ./wire.bend as W

# wire_tls_listen_ctx and wire_tls_accept: a TLS server on 7203 with
# $TLS_CERT and $TLS_KEY. It serves 2 connections: after the handshake, the
# plain wire_recv_timeout and wire_send_timeout move the bytes through TLS,
# and wire_close ends the session. Prints what each client sent

def RU() -> Type:
  Socket & Result<&1, &1, U32 & String, Unit>

def RP() -> Type:
  Socket & Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>

def text(bs: List<&2, U32>, acc: String) -> String:
  match bs:
    case Nil{}:
      String.reverse(acc)
    case Con{b, t}:
      text(t, SCon{Chr{b}, acc})

def says(r: Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>) -> String:
  match r:
    case Done{Some{bs}}:
      "got " ++ text(bs, "")
    case Done{None{}}:
      "timed out"
    case Fail{(_, why)}:
      "failed: " ++ why

law replied:
  for m: RU()
  IO(Unit)

def replied(m):
  (s, _) = m
  W.wire_close(s)

law read:
  for m: RP()
  IO(Unit)

def read(m):
  (s, r) = m
  do IO<Unit>:
    x : Unit <- IO.print(says(r))
    u : RU() <- W.wire_send_timeout(s, [104, 101, 108, 108, 111, 32, 111, 118, 101, 114, 32, 116, 108, 115], 2000)
    replied(u)

def shook.go(r: Result<&1, &1, U32 & String, Unit>, s: Socket) -> IO(Unit):
  match r:
    case Done{_}:
      IO.bind(RP(), Unit, W.wire_recv_timeout(s, 4096, 2000), m => read(m))
    case Fail{(_, why)}:
      IO.bind(Unit, Unit, IO.print("handshake failed: " ++ why), u => W.wire_close(s))

law shook:
  for m: RU()
  IO(Unit)

def shook(m):
  (s, r) = m
  shook.go(r, s)

law accepted:
  for m: Listener & Result<&1, &1, U32 & String, Socket>
  for k: Listener -> IO(Unit)
  IO(Unit)

def accepted(m, k):
  (l, r) = m
  do IO<Unit>:
    s : Socket <- IO.pass(Socket, r)
    t : RU() <- W.wire_tls_accept(s, 2000)
    x : Unit <- shook(t)
    k(l)

def serve(n: Nat, l: Listener) -> IO(Unit):
  match n:
    case 0n:
      W.close_listener(l)
    case 1n+p:
      IO.bind(Listener & Result<&1, &1, U32 & String, Socket>, Unit, W.accept(l), m => accepted(m, l2 => serve(p, l2)))

def env.or(r: Result<&1, &1, U32 & String, String>) -> String:
  match r:
    case Done{v}:
      v
    case Fail{_}:
      ""

def env(name: String) -> IO(String):
  IO.bind(Result<&1, &1, U32 & String, String>, String, IO.get_env(name), r => IO.pure(String, env.or(r)))

def main() -> IO(Unit):
  do IO<Unit>:
    c : String <- env("TLS_CERT")
    k : String <- env("TLS_KEY")
    x : Unit <- IO.try(Unit, W.wire_tls_listen_ctx(c, k))
    l : Listener <- IO.try(Listener, W.listen(7203))
    y : Unit <- IO.print("ready")
    serve(2n, l)
