import Base
import ./wire.bend as W
import ./ip.bend as I

# A TCP connection to a host by name or literal, within one deadline: the
# connection policy over wire's OS effects (RFC 8305 address ordering,
# sequential attempts).
#
#   d <- D.dial("localhost", 8443, deadline)   # deadline: IO.now() ms
#
# - An IPv4 or IPv6 literal is connected to at once; no lookup.
# - A name is looked up with wire_resolve_timeout (A and AAAA) bounded by the
#   deadline. A lookup still running at the deadline is Unresolved{ETIMEDOUT}.
# - The addresses keep the resolver's order (RFC 6724), then alternate
#   families from the first one's (RFC 8305 section 4), at most I.max_tries.
#   Scoped (link-local "%zone") addresses are dropped.
# - Attempts run one after another, not raced: Bend's IO has one
#   continuation per connect, and a staggered race would need a multi-socket
#   effect that closes the losers. Each attempt but the last gets
#   I.budget(left, n): the time left shared by the n addresses still to try,
#   but at least I.attempt_floor_ms (or what is left). A refused or unreachable
#   address moves on at once; a silent one costs its share, not the deadline.
#   The last address gets all that is left.
# - Only TCP failures move on to the next address. What happens on the
#   connection (TLS, HTTP) is the caller's.

type Dialed is Type:
  Dialed{socket: Socket}
  # the lookup failed (its errno; ETIMEDOUT past the deadline), or gave no
  # usable address (0)
  Unresolved{code: U32}
  # every address failed; the last one's errno
  Unreached{code: U32}
  # the deadline passed before the lookup or an attempt could start
  Late{}

# Connecting
# ----------

def left(+dl: Nat, +now: Nat) -> U32:
  U32.from_nat(Nat.sub(dl, now))


type Cn is Data:
  Cn{n: U32, xs: List<&2, String>}

def counted.con(s: String, c: Cn) -> Cn:
  match c:
    case Cn{+n, xs}:
      Cn{U32.inc(n), Con{s, xs}}

def counted(xs: List<&2, String>) -> Cn:
  match xs:
    case Nil{}:
      Cn{0, Nil{}}
    case Con{s, t}:
      counted.con(s, counted(t))

def attempt.r(r: Result<&1, &1, U32 & String, Socket>, next: U32 -> IO(Dialed)) -> IO(Dialed):
  match r:
    case Done{socket}:
      IO.pure(Dialed, Dialed{socket})
    case Fail{(code, _)}:
      next(code)

def attempt(late: Bool, a: String, +n: U32, port: U32, +dl: Nat, +now: Nat, next: U32 -> IO(Dialed)) -> IO(Dialed):
  match late:
    case True{}:
      IO.pure(Dialed, Late{})
    case False{}:
      IO.bind(Result<&1, &1, U32 & String, Socket>, Dialed, W.wire_connect_timeout(a, port, I.budget(left(dl, now), n)), r => attempt.r(r, next))

# each address in turn, n of them; last: the errno of the one before
def attempts(xs: List<&2, String>, +n: U32, +port: U32, +dl: Nat, last: U32) -> IO(Dialed):
  match xs:
    case Nil{}:
      IO.pure(Dialed, Unreached{last})
    case Con{a, t}:
      do IO<Dialed>:
        +now : Nat <- IO.now()
        attempt(Nat.is_le(dl, now), a, n, port, dl, now, code => attempts(t, U32.sub(n, 1), port, dl, code))

def resolved.n(none: Bool, xs: List<&2, String>, +n: U32, +port: U32, +dl: Nat) -> IO(Dialed):
  match none:
    case True{}:
      IO.pure(Dialed, Unresolved{0})
    case False{}:
      attempts(xs, n, port, dl, 0)

def resolved.cn(c: Cn, +port: U32, +dl: Nat) -> IO(Dialed):
  match c:
    case Cn{+n, xs}:
      resolved.n(U32.is_eq(n, 0), xs, n, port, dl)

def resolved(r: Result<&1, &1, U32 & String, List<&2, String>>, +port: U32, +dl: Nat) -> IO(Dialed):
  match r:
    case Done{xs}:
      resolved.cn(counted(I.order(xs)), port, dl)
    case Fail{(code, _)}:
      IO.pure(Dialed, Unresolved{code})

def lookup(late: Bool, host: String, +port: U32, +dl: Nat, +now: Nat) -> IO(Dialed):
  match late:
    case True{}:
      IO.pure(Dialed, Late{})
    case False{}:
      IO.bind(Result<&1, &1, U32 & String, List<&2, String>>, Dialed, W.wire_resolve_timeout(host, left(dl, now)), r => resolved(r, port, dl))

def by_name(host: String, +port: U32, +dl: Nat) -> IO(Dialed):
  do IO<Dialed>:
    +now : Nat <- IO.now()
    lookup(Nat.is_le(dl, now), host, port, dl, now)

def dial.lit(lit: Bool, +host: String, +port: U32, +dl: Nat) -> IO(Dialed):
  match lit:
    case True{}:
      attempts([host], 1, port, dl, 0)
    case False{}:
      by_name(host, port, dl)

# a TCP connection to host (a name, or an IPv4/IPv6 literal without
# brackets) and port, by the deadline dl (an IO.now() time)
def dial(+host: String, +port: U32, +dl: Nat) -> IO(Dialed):
  dial.lit(I.literal(host), host, port, dl)
