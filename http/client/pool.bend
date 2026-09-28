import Base
import ./client.bend as C
import ../../wire/wire.bend as W
import ../wire/http1.bend as H1
import ../wire/bytes.bend as B
import ../core/headers.bend as H
import ../core/text.bend as T
import ../../json/json.bend as J
import ../core/event.bend as Ev

# grounds-http-client's pool: kept connections, for any origin, and the
# same verbs as the client's
#
#   x <- Pool.with(C.R(C.Reply), cfg, 8, p => Pool.send_ok(p, C.get(u)))
#
# A pool passes its connections through a channel, and a channel counts
# what it carries, so a program that uses a pool is partly counted; a
# program that does not use one never loads this module.

# an idle connection: its origin, and when it was last used
type Idle is Type:
  Idle{sock: Socket, tls: Bool, last: Nat, origin: String}

# the pool's state, behind a one-slot channel that serves as its lock: the
# idle connections, newest first; how many more may be opened; how many
# tasks wait for one; and whether it is closing
type St is Type:
  St{idle: List<&1, Idle>, free: Nat, waiting: Nat, closing: Bool}

type Pool is Data:
  Pool{cfg: C.Config, state: Chan(St), wake: Chan(Unit), size: U32}

def put(+ch: Chan(St), s: St) -> IO(Unit):
  IO.bind(Bool, Unit, Chan.send(St, ch, s), x => IO.pure(Unit, Unit{}))

def wake(n: Bool, +w: Chan(Unit)) -> IO(Unit):
  match n:
    case True{}:
      IO.bind(Bool, Unit, Chan.send(Unit, w, Unit{}), x => IO.pure(Unit, Unit{}))
    case False{}:
      IO.pure(Unit, Unit{})

def shut.all(xs: List<&1, Idle>) -> IO(Unit):
  match xs:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{Idle{s, tls, _, _}, t}:
      IO.bind(Unit, Unit, C.shut(tls, s), u => shut.all(t))

def count(xs: List<&1, Idle>, +n: Nat) -> Nat:
  match xs:
    case Nil{}:
      n
    case Con{_, t}:
      count(t, Nat.add(n, 1n))

# Taking a connection
# -------------------

# what a scan of the idle list found: one for the origin, the others in
# order, and those idle too long, to close
type Pick is Type:
  Pick{got: Maybe<&1, Idle>, rest: List<&1, Idle>, dead: List<&1, Idle>, n: Nat}

def old(+now: Nat, +last: Nat, +ms: U32) -> Bool:
  Bool.not(Nat.is_le(now, Nat.add(last, U32.to_nat(ms))))

def pick.one(stale: Bool, hit: Bool, i: Idle, p: Pick) -> Pick:
  match stale hit p:
    case True{} _ Pick{g, r, d, +n}:
      Pick{g, r, Con{i, d}, Nat.add(n, 1n)}
    case False{} True{} Pick{None{}, r, d, n}:
      Pick{Some{i}, r, d, n}
    case False{} _ Pick{g, r, d, n}:
      Pick{g, Con{i, r}, d, n}

def pick.end(p: Pick) -> Pick:
  match p:
    case Pick{g, r, d, n}:
      Pick{g, List.reverse(&1, Idle, r), d, n}

def pick(xs: List<&1, Idle>, +key: String, +now: Nat, +ms: U32, p: Pick) -> Pick:
  match xs:
    case Nil{}:
      pick.end(p)
    case Con{Idle{s, tls, +last, +org}, t}:
      pick(t, key, now, ms, pick.one(old(now, last, ms), T.same(org, key, True{}), Idle{s, tls, last, org}, p))

# the last of a list, and the rest
type Last is Type:
  Last{init: List<&1, Idle>, last: Maybe<&1, Idle>}

def last.go(xs: List<&1, Idle>, acc: List<&1, Idle>) -> Last:
  match xs:
    case Nil{}:
      Last{List.reverse(&1, Idle, acc), None{}}
    case Con{x, Nil{}}:
      Last{List.reverse(&1, Idle, acc), Some{x}}
    case Con{x, t}:
      last.go(t, Con{x, acc})

# what a request does: use a kept connection, open one (evicting another
# origin's oldest when the pool is full), wait, or give up on a closing pool
type Plan is Type:
  Use{conn: Idle}
  New{evict: Maybe<&1, Idle>}
  Wait{}
  Gone{}

type Dec is Type:
  Dec{plan: Plan, st: St, dead: List<&1, Idle>}

def decide.full(l: Last, +waiting: Nat, dead: List<&1, Idle>) -> Dec:
  match l:
    case Last{init, Some{x}}:
      Dec{New{Some{x}}, St{init, 0n, waiting, False{}}, dead}
    case Last{init, None{}}:
      Dec{Wait{}, St{init, 0n, Nat.add(waiting, 1n), False{}}, dead}

def decide.free(room: Bool, rest: List<&1, Idle>, +free: Nat, +waiting: Nat, dead: List<&1, Idle>) -> Dec:
  match room:
    case True{}:
      Dec{New{None{}}, St{rest, Nat.sub(free, 1n), waiting, False{}}, dead}
    case False{}:
      decide.full(last.go(rest, []), waiting, dead)

def maybe.cons(m: Maybe<&1, Idle>, xs: List<&1, Idle>) -> List<&1, Idle>:
  match m:
    case Some{x}:
      Con{x, xs}
    case None{}:
      xs

def decide(p: Pick, +free: Nat, +waiting: Nat, closing: Bool) -> Dec:
  match p closing:
    case Pick{g, r, d, +n} True{}:
      Dec{Gone{}, St{r, Nat.add(free, n), waiting, True{}}, maybe.cons(g, d)}
    case Pick{Some{c}, r, d, +n} False{}:
      Dec{Use{c}, St{r, Nat.add(free, n), waiting, False{}}, d}
    case Pick{None{}, r, d, +n} False{}:
      decide.free(Bool.not(Nat.is_eq(Nat.add(free, n), 0n)), r, Nat.add(free, n), waiting, d)

# what a request got: a kept connection, room to open one, or nothing
type Taken is Type:
  Kept{sock: Socket, tls: Bool}
  Room{}
  Shut{}

def evicted(m: Maybe<&1, Idle>) -> IO(Unit):
  match m:
    case Some{Idle{s, tls, _, _}}:
      C.shut(tls, s)
    case None{}:
      IO.pure(Unit, Unit{})

def acted(plan: Plan, +p: Pool, +key: String, +fuel: Nat, again: Unit -> IO(Taken)) -> IO(Taken):
  match plan p:
    case Use{Idle{s, tls, _, _}} _:
      IO.pure(Taken, Kept{s, tls})
    case New{ev} _:
      IO.bind(Unit, Taken, evicted(ev), u => IO.pure(Taken, Room{}))
    case Wait{} Pool{_, _, +w, _}:
      IO.bind(Maybe<&1, Unit>, Taken, Chan.recv(Unit, w), u => again(Unit{}))
    case Gone{} _:
      IO.pure(Taken, Shut{})

def act(d: Dec, +p: Pool, +key: String, +fuel: Nat, again: Unit -> IO(Taken)) -> IO(Taken):
  match d p:
    case Dec{plan, st, dead} Pool{_, +ch, _, _}:
      do IO<Taken>:
        x : Unit <- put(ch, st)
        y : Unit <- shut.all(dead)
        acted(plan, p, key, fuel, again)

def taken.st(m: Maybe<&1, St>, +p: Pool, +key: String, +fuel: Nat, +now: Nat, again: Unit -> IO(Taken)) -> IO(Taken):
  match m p:
    case Some{St{idle, +free, +waiting, closing}} Pool{C.Config{_, _, _, _, _, _, +ms}, _, _, _}:
      act(decide(pick(idle, key, now, ms, Pick{None{}, [], [], 0n}), free, waiting, closing), p, key, fuel, again)
    case None{} _:
      IO.pure(Taken, Shut{})

# a connection for key's origin: kept, or room to open one; waiting while
# every connection is in use
def take(+fuel: Nat, +p: Pool, +key: String) -> IO(Taken):
  match fuel p:
    case 0n _:
      IO.pure(Taken, Shut{})
    case 1n+n Pool{_, +ch, _, _}:
      do IO<Taken>:
        m : Maybe<&1, St> <- Chan.recv(St, ch)
        +now : Nat <- IO.now()
        taken.st(m, p, key, n, now, u => take(n, p, key))

# Giving it back
# --------------

def gave(m: Maybe<&1, St>, keep: Bool, s: Socket, +tls: Bool, +key: String, +p: Pool, +now: Nat) -> IO(Unit):
  match m keep p:
    case Some{St{idle, free, +waiting, False{}}} True{} Pool{_, +ch, +w, _}:
      do IO<Unit>:
        x : Unit <- put(ch, St{Con{Idle{s, tls, now, key}, idle}, free, Nat.sub(waiting, 1n), False{}})
        wake(Bool.not(Nat.is_eq(waiting, 0n)), w)
    case Some{St{idle, free, +waiting, closing}} _ Pool{_, +ch, +w, _}:
      do IO<Unit>:
        x : Unit <- put(ch, St{idle, Nat.add(free, 1n), Nat.sub(waiting, 1n), closing})
        y : Unit <- C.shut(tls, s)
        wake(Bool.not(Nat.is_eq(waiting, 0n)), w)
    case None{} _ _:
      C.shut(tls, s)

# a connection back: kept if it may carry another request, else closed and
# its room given back
def give(keep: Bool, s: Socket, +tls: Bool, +key: String, +p: Pool) -> IO(Unit):
  match p:
    case Pool{_, +ch, _, _}:
      do IO<Unit>:
        m : Maybe<&1, St> <- Chan.recv(St, ch)
        +now : Nat <- IO.now()
        gave(m, keep, s, tls, key, p, now)

def freed(m: Maybe<&1, St>, +p: Pool) -> IO(Unit):
  match m p:
    case Some{St{idle, free, +waiting, closing}} Pool{_, +ch, +w, _}:
      do IO<Unit>:
        x : Unit <- put(ch, St{idle, Nat.add(free, 1n), Nat.sub(waiting, 1n), closing})
        wake(Bool.not(Nat.is_eq(waiting, 0n)), w)
    case None{} _:
      IO.pure(Unit, Unit{})

# room back, for a connection that was never opened or is already closed
def release(+p: Pool) -> IO(Unit):
  match p:
    case Pool{_, +ch, _, _}:
      IO.bind(Maybe<&1, St>, Unit, Chan.recv(St, ch), m => freed(m, p))

# One try
# -------

def after(e: C.Ex, +key: String, +p: Pool) -> IO(C.Hop):
  match e:
    case C.Got{s, +tls, C.Meta{c, hs, +reuse}, o}:
      IO.bind(Unit, C.Hop, give(reuse, s, tls, key, p), u => IO.pure(C.Hop, C.HopGot{C.Meta{c, hs, reuse}, o}))
    case C.Lost{err, _, _}:
      IO.bind(Unit, C.Hop, release(p), u => IO.pure(C.Hop, C.HopLost{err}))

def fresh.opened(o: C.Opened, req: B.Bytes, +key: String, +p: Pool, +lim: C.Lim) -> IO(C.Hop):
  match o:
    case C.Opened{s, +tls}:
      IO.bind(C.Ex, C.Hop, C.exchange(s, tls, req, lim, C.Keep{[]}), e => after(e, key, p))
    case C.NotOpened{e}:
      IO.bind(Unit, C.Hop, release(p), u => IO.pure(C.Hop, C.HopLost{e}))

# on a new connection, the pool's room for it already taken
def fresh(sp: C.Spec, +key: String, +p: Pool, +lim: C.Lim) -> IO(C.Hop):
  match sp:
    case C.Spec{C.Verb{name, +head, sized, _}, C.Url{+tls, host, +port, target, auth}, hs, b, _}:
      IO.bind(C.Opened, C.Hop, C.open(tls, host, port, C.lim.dl(lim)), o => fresh.opened(o, H1.write_request(name, target, auth, C.hs.clean(hs, []), b, sized, False{}), key, p, C.lim.with_head(lim, head)))
    case C.Spec{_, C.UBad{e}, _, _, _}:
      IO.bind(Unit, C.Hop, release(p), u => IO.pure(C.Hop, C.HopLost{e}))

# after a try on a kept connection: one the server had closed is tried
# once more on a new one, if the request is safe to repeat
def kept.after(e: C.Ex, spare: C.Spec, +again: Bool, +key: String, +p: Pool, +lim: C.Lim) -> IO(C.Hop):
  match e again:
    case C.Lost{_, True{}, _} True{}:
      fresh(spare, key, p, lim)
    case other _:
      after(other, key, p)

def kept.run(ha: C.HSpec, gb: C.HSpec, s: Socket, +tls: Bool, +key: String, +p: Pool, +lim: C.Lim) -> IO(C.Hop):
  match ha gb:
    case C.HSpec{+h, a} C.HSpec{+g, b}:
      IO.bind(C.Ex, C.Hop, C.exchange(s, tls, C.req.of(a, True{}), C.lim.with_head(lim, h), C.Keep{[]}), e => kept.after(e, b, g, key, p, lim))

def kept.go(sp2: C.Spec2, s: Socket, +tls: Bool, +key: String, +p: Pool, +lim: C.Lim) -> IO(C.Hop):
  match sp2:
    case C.Spec2{a, b}:
      kept.run(C.head.of.keep(a), C.verb.again(b), s, tls, key, p, lim)

def used(t: Taken, sp: C.Spec, +key: String, +p: Pool, +lim: C.Lim) -> IO(C.Hop):
  match t:
    case Kept{s, +tls}:
      kept.go(C.spec.dup(sp), s, tls, key, p, lim)
    case Room{}:
      fresh(sp, key, p, lim)
    case Shut{}:
      IO.pure(C.Hop, C.HopLost{C.Closed{}})

def hop.of(o: C.Orig, +p: Pool, +lim: C.Lim) -> IO(C.Hop):
  match o:
    case C.Orig{+key, sp}:
      IO.bind(Taken, C.Hop, take(4294967295n, p, key), t => used(t, sp, key, p, lim))

# one try through the pool
def hop(sp: C.Spec, +p: Pool, +lim: C.Lim) -> IO(C.Hop):
  hop.of(C.spec.origin(sp), p, lim)

# Driving
# -------

def drive.go(sp2: C.Spec2, l: C.Left, +p: Pool, +lim: C.Lim, k: C.DK()) -> IO(C.RR()):
  match sp2:
    case C.Spec2{a, b}:
      IO.bind(C.Hop, C.RR(), hop(a, p, lim), h => C.hopped(h, C.verb.again(b), l, k))

# a request, then its redirects and retries, through the pool
def drive(fuel: Nat, sp: C.Spec, l: C.Left, +p: Pool, +lim: C.Lim) -> IO(C.RR()):
  match fuel:
    case 0n:
      IO.pure(C.RR(), Fail{C.Redirects{}})
    case 1n+n:
      drive.go(C.spec.dup(sp), l, p, lim, s => l2 => drive(n, s, l2, p, lim))

def start(sp: C.Spec, +p: Pool) -> IO(C.RR()):
  match p:
    case Pool{C.Config{+ms, mh, mb, +rt, bo, +rd, _}, _, _, _}:
      do IO<C.RR()>:
        +now : Nat <- IO.now()
        drive(C.fuel.of(rt, rd), sp, C.left.of(rt, rd, bo), p, C.lim.of(now, ms, mh, mb))

def send.go(+p: Pool, s: Result<&2, &2, C.Err, C.Spec>) -> IO(C.RR()):
  match s:
    case Done{sp}:
      start(sp, p)
    case Fail{e}:
      IO.pure(C.RR(), Fail{e})

# The verbs
# ---------

# as C.send, through the pool
def send(+p: Pool, r: C.Req) -> IO(C.RR()):
  send.go(p, C.spec.of(r))

def send_ok(+p: Pool, r: C.Req) -> IO(C.RR()):
  IO.bind(C.RR(), C.RR(), send(p, r), x => IO.pure(C.RR(), C.ok.of(x)))

def send_json(-A: Data, +p: Pool, r: C.Req, dec: J.Json -> Result<&2, &2, J.Access, A>) -> IO(C.R(A)):
  IO.bind(C.RR(), C.R(A), send_ok(p, r), x => IO.pure(C.R(A), C.json.of(A, x, dec)))

# Streams
# -------

def stream.back(c: C.Conn, +key: String, +p: Pool) -> IO(Unit):
  match c:
    case C.Conn{s, +tls, reuse}:
      give(reuse, s, tls, key, p)
    case C.NoConn{}:
      release(p)

def stream.end(pt: C.Part, +key: String, +p: Pool) -> IO(C.R(C.Head)):
  match pt:
    case C.Part{res, c}:
      IO.bind(Unit, C.R(C.Head), stream.back(c, key, p), u => IO.pure(C.R(C.Head), res))

def stream.opened(~f: List<&2, U32> -> IO(Bool), o: C.Opened, req: B.Bytes, +key: String, +p: Pool, +lim: C.Lim) -> IO(C.R(C.Head)):
  match o:
    case C.Opened{s, +tls}:
      IO.bind(C.Ex, C.R(C.Head), C.stream.x(~f, s, tls, req, lim), e => stream.end(C.stream.part(e), key, p))
    case C.NotOpened{e}:
      IO.bind(Unit, C.R(C.Head), release(p), u => IO.pure(C.R(C.Head), Fail{e}))

def stream.taken(~f: List<&2, U32> -> IO(Bool), t: Taken, req: B.Bytes, tls0: Bool, host: String, +port: U32, +key: String, +p: Pool, +lim: C.Lim) -> IO(C.R(C.Head)):
  match t:
    case Kept{s, +tls}:
      IO.bind(C.Ex, C.R(C.Head), C.stream.x(~f, s, tls, req, lim), e => stream.end(C.stream.part(e), key, p))
    case Room{}:
      IO.bind(C.Opened, C.R(C.Head), C.open(tls0, host, port, C.lim.dl(lim)), o => stream.opened(~f, o, req, key, p, lim))
    case Shut{}:
      IO.pure(C.R(C.Head), Fail{C.Closed{}})

def stream.spec(~f: List<&2, U32> -> IO(Bool), o: C.Orig, +p: Pool, +dl: Nat) -> IO(C.R(C.Head)):
  match o p:
    case C.Orig{+key, C.Spec{C.Verb{name, +head, sized, _}, C.Url{+tls, host, +port, target, auth}, hs, b, _}} Pool{C.Config{+ms, mh, _, _, _, _, _}, _, _, _}:
      IO.bind(Taken, C.R(C.Head), take(4294967295n, p, key), t => stream.taken(~f, t, H1.write_request(name, target, auth, C.hs.clean(hs, []), b, sized, False{}), tls, host, port, key, p, C.lim.stream(dl, ms, mh, head)))
    case C.Orig{_, C.Spec{_, C.UBad{e}, _, _, _}} _:
      IO.pure(C.R(C.Head), Fail{e})

def stream.go(~f: List<&2, U32> -> IO(Bool), s: Result<&2, &2, C.Err, C.Spec>, +p: Pool, +dl: Nat) -> IO(C.R(C.Head)):
  match s:
    case Done{sp}:
      stream.spec(~f, C.spec.origin(sp), p, dl)
    case Fail{e}:
      IO.pure(C.R(C.Head), Fail{e})

# as C.stream, through the pool: the connection is held until the body
# ends, then kept if it may be
def stream(~f: List<&2, U32> -> IO(Bool), +p: Pool, r: C.Req) -> IO(C.R(C.Head)):
  match p:
    case Pool{C.Config{+ms, _, _, _, _, _, _}, _, _, _}:
      do IO<C.R(C.Head)>:
        +now : Nat <- IO.now()
        stream.go(~f, C.spec.of(r), p, Nat.add(now, U32.to_nat(ms)))

# Opening and closing
# -------------------

# a pool of up to n connections, for any origin, opened as they are needed
def open(cfg: C.Config, +n: U32) -> IO(Pool):
  do IO<Pool>:
    +ch : Chan(St) <- Chan.new(St, 1)
    +w : Chan(Unit) <- Chan.new(Unit, 1024)
    x : Unit <- put(ch, St{[], U32.to_nat(n), 0n, False{}})
    return Pool{cfg, ch, w, n}

def shut.count(xs: List<&1, Idle>, +n: Nat) -> IO(Nat):
  match xs:
    case Nil{}:
      IO.pure(Nat, n)
    case Con{Idle{s, tls, _, _}, t}:
      IO.bind(Unit, Nat, C.shut(tls, s), u => shut.count(t, Nat.add(n, 1n)))

def closed.check(all: Bool, +free: Nat, +waiting: Nat, +p: Pool, again: Unit -> IO(Unit)) -> IO(Unit):
  match all p:
    case True{} Pool{_, +ch, +w, _}:
      do IO<Unit>:
        y : Unit <- Chan.close(Unit, w)
        Chan.close(St, ch)
    case False{} Pool{_, +ch, +w, _}:
      do IO<Unit>:
        x : Unit <- put(ch, St{[], free, Nat.add(waiting, 1n), True{}})
        y : Maybe<&1, Unit> <- Chan.recv(Unit, w)
        again(Unit{})

def closed.k(+free: Nat, +n: U32, +waiting: Nat, +p: Pool, again: Unit -> IO(Unit)) -> IO(Unit):
  closed.check(Nat.is_le(U32.to_nat(n), free), free, waiting, p, again)

def closed.st(m: Maybe<&1, St>, +p: Pool, again: Unit -> IO(Unit)) -> IO(Unit):
  match m p:
    case Some{St{idle, +free, +waiting, _}} Pool{_, _, _, +n}:
      IO.bind(Nat, Unit, shut.count(idle, 0n), k => closed.k(Nat.add(free, k), n, waiting, p, again))
    case None{} _:
      IO.pure(Unit, Unit{})

def closing(+fuel: Nat, +p: Pool) -> IO(Unit):
  match fuel p:
    case 0n _:
      IO.pure(Unit, Unit{})
    case 1n+k Pool{_, +ch, _, _}:
      IO.bind(Maybe<&1, St>, Unit, Chan.recv(St, ch), m => closed.st(m, p, u => closing(k, p)))

# close the pool and its connections, once each one in use comes back
def close(+p: Pool) -> IO(Unit):
  closing(4294967295n, p)

# open a pool, run f with it, and close it on every path
def with(-A: Type, cfg: C.Config, +n: U32, f: Pool -> IO(A)) -> IO(A):
  do IO<A>:
    +p : Pool <- open(cfg, n)
    a : A <- f(p)
    x : Unit <- close(p)
    return a

# Event streams
# -------------

def ev.back(p2: C.EvPart, +key: String, +p: Pool) -> IO(C.Try):
  match p2:
    case C.EvPart{t, c}:
      IO.bind(Unit, C.Try, stream.back(c, key, p), u => IO.pure(C.Try, t))

def ev.opened(~on: Ev.Message -> IO(Bool), o: C.Opened, req: B.Bytes, +key: String, +p: Pool, +lim: C.Lim) -> IO(C.Try):
  match o:
    case C.Opened{s, +tls}:
      IO.bind(C.Ex, C.Try, C.ev.x(~on, s, tls, req, lim), e => ev.back(C.ev.part(e), key, p))
    case C.NotOpened{e}:
      IO.bind(Unit, C.Try, release(p), u => IO.pure(C.Try, C.Try{Some{e}, None{}, None{}, False{}}))

def ev.taken(~on: Ev.Message -> IO(Bool), t: Taken, req: B.Bytes, tls0: Bool, host: String, +port: U32, +key: String, +p: Pool, +lim: C.Lim) -> IO(C.Try):
  match t:
    case Kept{s, +tls}:
      IO.bind(C.Ex, C.Try, C.ev.x(~on, s, tls, req, lim), e => ev.back(C.ev.part(e), key, p))
    case Room{}:
      IO.bind(C.Opened, C.Try, C.open(tls0, host, port, C.lim.dl(lim)), o => ev.opened(~on, o, req, key, p, lim))
    case Shut{}:
      IO.pure(C.Try, C.Try{Some{C.Closed{}}, None{}, None{}, False{}})

# one try at an event stream through the pool
def ev.try(~on: Ev.Message -> IO(Bool), o: C.Orig, last: Maybe<&2, String>, +p: Pool, +dl: Nat) -> IO(C.Try):
  match o p:
    case C.Orig{+key, C.Spec{C.Verb{name, +head, sized, _}, C.Url{+tls, host, +port, target, auth}, hs, b, _}} Pool{C.Config{+ms, mh, _, _, _, _, _}, _, _, _}:
      IO.bind(Taken, C.Try, take(4294967295n, p, key), t => ev.taken(~on, t, H1.write_request(name, target, auth, List.append(&2, H.Header, C.hs.clean(hs, []), C.ev.hs(last)), b, sized, False{}), tls, host, port, key, p, C.lim.stream(dl, ms, mh, head)))
    case C.Orig{_, C.Spec{_, C.UBad{e}, _, _, _}} _:
      IO.pure(C.Try, C.Try{Some{e}, None{}, None{}, False{}})

def ev.now(~on: Ev.Message -> IO(Bool), sp: C.Spec, last: Maybe<&2, String>, +p: Pool) -> IO(C.Try):
  match p:
    case Pool{C.Config{+ms, _, _, _, _, _, _}, _, _, _}:
      do IO<C.Try>:
        +now : Nat <- IO.now()
        ev.try(~on, C.spec.origin(sp), last, p, Nat.add(now, U32.to_nat(ms)))

def ev.once(~on: Ev.Message -> IO(Bool), s: Result<&2, &2, C.Err, C.Spec>, +p: Pool) -> IO(C.R(C.Ended)):
  match s:
    case Done{sp}:
      IO.bind(C.Try, C.R(C.Ended), ev.now(~on, sp, None{}, p), t => IO.pure(C.R(C.Ended), C.ev.end(t, 0)))
    case Fail{e}:
      IO.pure(C.R(C.Ended), Fail{e})

# as C.events, through the pool
def events(~on: Ev.Message -> IO(Bool), +p: Pool, r: C.Req) -> IO(C.R(C.Ended)):
  ev.once(~on, C.spec.of(r), p)

def ev.retry.try(~on: Ev.Message -> IO(Bool), sp2: C.Spec2, k: C.RtK, +left: U32, +p: Pool, again: C.Spec -> C.Rt -> IO(C.R(C.Ended))) -> IO(C.R(C.Ended)):
  match sp2 k:
    case C.Spec2{a, b} C.RtK{rt, last}:
      IO.bind(C.Try, C.R(C.Ended), ev.now(~on, a, last, p), t => C.rt.tried(C.try.go(t), left, rt, r => again(b, r)))

def ev.retry.go(~on: Ev.Message -> IO(Bool), fuel: Nat, sp: C.Spec, rt: C.Rt, +left: U32, +p: Pool) -> IO(C.R(C.Ended)):
  match fuel:
    case 0n:
      IO.pure(C.R(C.Ended), Done{C.Ended{C.rt.last(rt), 0}})
    case 1n+f:
      ev.retry.try(~on, C.spec.dup(sp), C.rt.split(rt), left, p, s => r => ev.retry.go(~on, f, s, r, (left - 1 : U32), p))

def ev.retry(~on: Ev.Message -> IO(Bool), s: Result<&2, &2, C.Err, C.Spec>, +n: U32, +p: Pool) -> IO(C.R(C.Ended)):
  match s p:
    case Done{sp} Pool{C.Config{_, _, _, _, +bo, _, _}, _, _, _}:
      ev.retry.go(~on, Nat.add(U32.to_nat(n), 1n), sp, C.Rt{None{}, 0, bo}, n, p)
    case Fail{e} _:
      IO.pure(C.R(C.Ended), Fail{e})

# as C.events_retry, through the pool
def events_retry(~on: Ev.Message -> IO(Bool), +p: Pool, r: C.Req, +n: U32) -> IO(C.R(C.Ended)):
  ev.retry(~on, C.spec.of(r), n, p)
