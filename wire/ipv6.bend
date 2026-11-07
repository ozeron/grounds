import Base
import ./wire.bend as W
import ./dial.bend as D

# IPv6 transport, native: a listener on ::1, bytes both ways over it, the
# IPv4 port of the same number refused, A and AAAA lookups, dialing a
# dual-stack name to an IPv6-only and an IPv4-only listener (the second
# falls back past the refused ::1), and a lookup cut off at its deadline.
# ipv6_check.py runs it and reads the lines.

def RU() -> Type:
  Socket & Result<&1, &1, U32 & String, Unit>

def RB() -> Type:
  Socket & Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>

def RA() -> Type:
  Listener & Result<&1, &1, U32 & String, Maybe<&1, Socket>>

def errno(+c: U32) -> String:
  Bool.pick(String, Bool.or(U32.is_eq(c, 61), U32.is_eq(c, 111)), "refused",
    Bool.pick(String, Bool.or(U32.is_eq(c, 60), U32.is_eq(c, 110)), "timeout",
      Bool.pick(String, U32.is_eq(c, 22), "invalid", "errno " ++ U32.show(c))))

def bytes.show(bs: List<&2, U32>) -> String:
  match bs:
    case Nil{}:
      ""
    case Con{+b, Nil{}}:
      U32.show(b)
    case Con{+b, t}:
      U32.show(b) ++ "," ++ bytes.show(t)

def names.show(xs: List<&2, String>) -> String:
  match xs:
    case Nil{}:
      ""
    case Con{x, Nil{}}:
      x
    case Con{x, t}:
      x ++ "," ++ names.show(t)

def got(r: RB()) -> IO(Unit):
  (s, x) = r
  match x:
    case Done{Some{bs}}:
      do IO<Unit>:
        W.close(s)
        IO.print("v6 bytes: " ++ bytes.show(bs))
    case Done{None{}}:
      do IO<Unit>:
        W.close(s)
        IO.print("v6 bytes: none")
    case Fail{(c, _)}:
      do IO<Unit>:
        W.close(s)
        IO.print("v6 bytes: " ++ errno(c))

def sent(r: RU(), a: Socket) -> IO(Unit):
  (c, x) = r
  match x:
    case Done{_}:
      do IO<Unit>:
        W.close(c)
        b : RB() <- W.wire_recv_timeout(a, 16, 2000)
        got(b)
    case Fail{(e, _)}:
      do IO<Unit>:
        W.close(c)
        W.close(a)
        IO.print("v6 send: " ++ errno(e))

def accepted(r: RA(), c: Socket) -> IO(Listener):
  (l, x) = r
  match x:
    case Done{Some{a}}:
      do IO<Listener>:
        s : RU() <- W.wire_send(c, [1, 2, 255])
        sent(s, a)
        return l
    case Done{None{}}:
      do IO<Listener>:
        W.close(c)
        IO.print("v6 accept: none")
        return l
    case Fail{(e, _)}:
      do IO<Listener>:
        W.close(c)
        IO.print("v6 accept: " ++ errno(e))
        return l

def connected(r: Result<&1, &1, U32 & String, Socket>, l: Listener) -> IO(Listener):
  match r:
    case Done{c}:
      IO.bind(RA(), Listener, W.wire_accept_timeout(l, 2000), a => accepted(a, c))
    case Fail{(e, _)}:
      do IO<Listener>:
        IO.print("v6 connect: " ++ errno(e))
        return l

def refused(r: Result<&1, &1, U32 & String, Socket>) -> IO(Unit):
  match r:
    case Done{c}:
      do IO<Unit>:
        W.close(c)
        IO.print("v4 same port: connected")
    case Fail{(e, _)}:
      IO.print("v4 same port: " ++ errno(e))

def looked(name: String, r: Result<&1, &1, U32 & String, List<&2, String>>) -> IO(Unit):
  match r:
    case Done{xs}:
      IO.print(name ++ ": " ++ names.show(xs))
    case Fail{(e, _)}:
      IO.print(name ++ ": " ++ errno(e))

# which listener took a dialed connection
def took(r: RA(), name: String) -> IO(Listener):
  (l, x) = r
  match x:
    case Done{Some{a}}:
      do IO<Listener>:
        W.close(a)
        IO.print(name ++ ": accepted")
        return l
    case Done{None{}}:
      do IO<Listener>:
        IO.print(name ++ ": not accepted")
        return l
    case Fail{(e, _)}:
      do IO<Listener>:
        IO.print(name ++ ": " ++ errno(e))
        return l

def dialed(d: D.Dialed, l: Listener, name: String) -> IO(Listener):
  match d:
    case D.Dialed{c}:
      do IO<Listener>:
        W.close(c)
        IO.bind(RA(), Listener, W.wire_accept_timeout(l, 2000), a => took(a, name))
    case D.Unresolved{+e}:
      do IO<Listener>:
        IO.print(name ++ ": unresolved " ++ errno(e))
        return l
    case D.Unreached{+e}:
      do IO<Listener>:
        IO.print(name ++ ": unreached " ++ errno(e))
        return l
    case D.Late{}:
      do IO<Listener>:
        IO.print(name ++ ": late")
        return l

def dial.to(host: String, port: U32, l: Listener, name: String) -> IO(Listener):
  do IO<Listener>:
    now : Nat <- IO.now()
    d : D.Dialed <- D.dial(host, port, Nat.add(now, 2000n))
    dialed(d, l, name)

def dial.none(d: D.Dialed) -> IO(Unit):
  match d:
    case D.Dialed{c}:
      do IO<Unit>:
        W.close(c)
        IO.print("dial closed port: connected")
    case D.Unresolved{+e}:
      IO.print("dial closed port: unresolved " ++ errno(e))
    case D.Unreached{+e}:
      IO.print("dial closed port: unreached " ++ errno(e))
    case D.Late{}:
      IO.print("dial closed port: late")

def bad(name: String, r: Result<&1, &1, U32 & String, Listener>) -> IO(Unit):
  match r:
    case Done{l}:
      do IO<Unit>:
        W.close_listener(l)
        IO.print(name ++ ": listening")
    case Fail{(e, _)}:
      IO.print(name ++ ": " ++ errno(e))

def bad.connect(r: Result<&1, &1, U32 & String, Socket>) -> IO(Unit):
  match r:
    case Done{c}:
      do IO<Unit>:
        W.close(c)
        IO.print("connect zone: connected")
    case Fail{(e, _)}:
      IO.print("connect zone: " ++ errno(e))

def slow(r: Result<&1, &1, U32 & String, List<&2, String>>, +ms: Nat) -> IO(Unit):
  match r:
    case Done{xs}:
      IO.print("slow lookup: " ++ names.show(xs) ++ " " ++ U32.show(U32.from_nat(ms)))
    case Fail{(e, _)}:
      IO.print("slow lookup: " ++ errno(e) ++ " " ++ U32.show(U32.from_nat(ms)))

def main() -> IO(Unit):
  do IO<Unit>:
    l6 : Listener <- IO.try(Listener, W.wire_listen_on("::1", 47841))
    c : Result<&1, &1, U32 & String, Socket> <- W.wire_connect_timeout("::1", 47841, 2000)
    l6b : Listener <- connected(c, l6)
    v4 : Result<&1, &1, U32 & String, Socket> <- W.wire_connect_timeout("127.0.0.1", 47841, 2000)
    refused(v4)
    a : Result<&1, &1, U32 & String, List<&2, String>> <- W.wire_resolve_timeout("localhost", 5000)
    looked("lookup localhost", a)
    b : Result<&1, &1, U32 & String, List<&2, String>> <- W.wire_resolve_timeout("no-such-host.invalid", 5000)
    looked("lookup invalid", b)
    l6c : Listener <- dial.to("localhost", 47841, l6b, "dial localhost to ::1 only")
    l6d : Listener <- dial.to("0:0::1", 47841, l6c, "dial literal 0:0::1")
    W.close_listener(l6d)
    l4 : Listener <- IO.try(Listener, W.wire_listen_on("127.0.0.1", 47842))
    l4b : Listener <- dial.to("localhost", 47842, l4, "dial localhost to 127.0.0.1 only")
    W.close_listener(l4b)
    now : Nat <- IO.now()
    n : D.Dialed <- D.dial("localhost", 47843, Nat.add(now, 2000n))
    dial.none(n)
    z : Result<&1, &1, U32 & String, Listener> <- W.wire_listen_on("fe80::1%lo0", 0)
    bad("listen zone", z)
    y : Result<&1, &1, U32 & String, Listener> <- W.wire_listen_on("localhost", 0)
    bad("listen name", y)
    x : Result<&1, &1, U32 & String, Socket> <- W.wire_connect_timeout("::1%lo0", 47841, 500)
    bad.connect(x)
    +t0 : Nat <- IO.now()
    s : Result<&1, &1, U32 & String, List<&2, String>> <- W.wire_resolve_timeout("grounds-nonexistent-q7.local", 300)
    +t1 : Nat <- IO.now()
    slow(s, Nat.sub(t1, t0))
