import Base
import ./client.bend as Legacy
import ./bend_transport.bend as Tr
import ./bend_client.bend as C
import ./url.bend as Ur
import ../../wire/wire.bend as W
import ../wire/http1.bend as H1
import ../wire/bytes.bend as B
import ../core/headers.bend as H
import ../core/text.bend as T
import ../../json/json.bend as J
import ../core/event.bend as Ev

# Opt-in Bend TLS pool: affine transport owners, for any origin, and the
# same verbs as the client's
#
#   x <- Pool.with(C.R(C.Reply), cfg, 8, p => Pool.send_ok(p, C.get(u)))
#
# A pool passes its connections through a channel, and a channel counts
# what it carries, so a program that uses a pool is partly counted; a
# program that does not use one never loads this module.

# an idle connection: its origin, and when it was last used
type Idle is Type:
  Idle{sock: Tr.Connection, tls: Bool, last: Nat, origin: String}

# what a waiter is handed: a kept connection for its origin; another
# origin's connection, to close before it opens its own in that room; room
# to open one; or nothing, the pool is closing
type Grant is Type:
  GKept{sock: Tr.Connection, tls: Bool}
  GEvict{sock: Tr.Connection, tls: Bool}
  GRoom{}
  GShut{}

# a waiting task: its number, its origin, and its own one-slot box
type Ticket is Data:
  Ticket{id: Nat, key: String, box: Chan(Grant)}

# the pool's state, behind a one-slot channel that serves as its lock: the
# idle connections, newest first; how many more may be opened; the tasks
# waiting for one, oldest first; the next ticket's number; and whether it
# is closing
#
# Waiters are addressed one by one. While any task waits there is no idle
# connection and no room (it would have taken one), so whatever comes back
# goes straight to the oldest waiter: its ticket leaves the queue and its
# grant is put in its box under the lock. A ticket is therefore either in
# the queue or its grant is in its box, and a waiter that gives up finds
# out which under the lock: it removes its ticket, or takes its grant and
# gives it back like any other return. No count of wakes is shared.
type St is Type:
  St{idle: List<&1, Idle>, free: Nat, queue: List<&2, Ticket>, next: Nat, closing: Bool}

type Pool is Data:
  Pool{cfg: C.Config, state: Chan(St), size: U32}

def put(+ch: Chan(St), s: St) -> IO(Unit):
  IO.bind(Result<&1, &1, St, Unit>, Unit, Chan.send(St, ch, s), x => IO.pure(Unit, Unit{}))

# a box takes exactly one grant: its ticket leaves the queue as it is sent
def grant(+box: Chan(Grant), g: Grant) -> IO(Unit):
  IO.bind(Result<&1, &1, Grant, Unit>, Unit, Chan.send(Grant, box, g), x => IO.pure(Unit, Unit{}))

# tell every waiter the pool is closing
def shut.queue(q: List<&2, Ticket>) -> IO(Unit):
  match q:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{Ticket{_, _, +box}, t}:
      IO.bind(Unit, Unit, grant(box, GShut{}), u => shut.queue(t))

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
  Await{}
  Gone{}

type Dec is Type:
  Dec{plan: Plan, st: St, dead: List<&1, Idle>}

# the waiters and the next ticket's number, carried through a decision
type Wq is Type:
  Wq{queue: List<&2, Ticket>, next: Nat}

def st.of(idle: List<&1, Idle>, +free: Nat, wq: Wq, closing: Bool) -> St:
  match wq:
    case Wq{q, next}:
      St{idle, free, q, next, closing}

def decide.full(l: Last, wq: Wq, dead: List<&1, Idle>) -> Dec:
  match l:
    case Last{init, Some{x}}:
      Dec{New{Some{x}}, st.of(init, 0n, wq, False{}), dead}
    case Last{init, None{}}:
      Dec{Await{}, st.of(init, 0n, wq, False{}), dead}

def decide.free(room: Bool, rest: List<&1, Idle>, +free: Nat, wq: Wq, dead: List<&1, Idle>) -> Dec:
  match room:
    case True{}:
      Dec{New{None{}}, st.of(rest, Nat.sub(free, 1n), wq, False{}), dead}
    case False{}:
      decide.full(last.go(rest, []), wq, dead)

def maybe.cons(m: Maybe<&1, Idle>, xs: List<&1, Idle>) -> List<&1, Idle>:
  match m:
    case Some{x}:
      Con{x, xs}
    case None{}:
      xs

def decide(p: Pick, +free: Nat, wq: Wq, closing: Bool) -> Dec:
  match p closing:
    case Pick{g, r, d, +n} True{}:
      Dec{Gone{}, st.of(r, Nat.add(free, n), wq, True{}), maybe.cons(g, d)}
    case Pick{Some{c}, r, d, +n} False{}:
      Dec{Use{c}, st.of(r, Nat.add(free, n), wq, False{}), d}
    case Pick{None{}, r, d, +n} False{}:
      decide.free(Bool.not(Nat.is_eq(Nat.add(free, n), 0n)), r, Nat.add(free, n), wq, d)

# what a request got: a kept connection, room to open one, nothing (the
# pool is closing), or none before the request's deadline
type Taken is Type:
  Kept{sock: Tr.Connection, tls: Bool}
  Room{}
  Shut{}
  Late{}

# what a request found under the lock: an answer now, or a place in the
# queue (its ticket's number and box)
type Entry is Type:
  Now{taken: Taken}
  Queued{id: Nat, box: Chan(Grant)}

def evicted(m: Maybe<&1, Idle>) -> IO(Unit):
  match m:
    case Some{Idle{s, tls, _, _}}:
      C.shut(tls, s)
    case None{}:
      IO.pure(Unit, Unit{})

def acted(plan: Plan) -> IO(Entry):
  match plan:
    case Use{Idle{s, tls, _, _}}:
      IO.pure(Entry, Now{Kept{s, tls}})
    case New{ev}:
      IO.bind(Unit, Entry, evicted(ev), u => IO.pure(Entry, Now{Room{}}))
    case Await{}:
      IO.pure(Entry, Now{Late{}})
    case Gone{}:
      IO.pure(Entry, Now{Shut{}})

# join the queue's end, under the lock; the ticket's number
def enqueue(st: St, +key: String, +box: Chan(Grant), +ch: Chan(St)) -> IO(Nat):
  match st:
    case St{idle, free, q, +next, closing}:
      IO.bind(Unit, Nat, put(ch, St{idle, free, List.append(&2, Ticket, q, [Ticket{next, key, box}]), Nat.add(next, 1n), closing}), u => IO.pure(Nat, next))

# a request that must wait joins the queue, unless its deadline has passed
def planned(plan: Plan, late: Bool, st: St, dead: List<&1, Idle>, +ch: Chan(St), +key: String) -> IO(Entry):
  match plan late:
    case Await{} False{}:
      do IO<Entry>:
        +box : Chan(Grant) <- Chan.new(Grant, 1)
        +id : Nat <- enqueue(st, key, box, ch)
        y : Unit <- shut.all(dead)
        return Queued{id, box}
    case other _:
      do IO<Entry>:
        x : Unit <- put(ch, st)
        y : Unit <- shut.all(dead)
        acted(other)

def act(d: Dec, +p: Pool, +key: String, late: Bool) -> IO(Entry):
  match d p:
    case Dec{plan, st, dead} Pool{_, +ch, _}:
      planned(plan, late, st, dead, ch, key)

def taken.st(m: Maybe<&1, St>, +p: Pool, +key: String, +now: Nat, +dl: Nat) -> IO(Entry):
  match m p:
    case Some{St{idle, +free, q, next, closing}} Pool{C.Config{_, _, _, _, _, _, +ms, policy, _, _, _}, _, _}:
      act(decide(pick(idle, key, now, ms, Pick{None{}, [], [], 0n}), free, Wq{q, next}, closing), p, key, Nat.is_le(dl, now))
    case None{} _:
      IO.pure(Entry, Now{Shut{}})

# under the lock: a connection for key's origin, room to open one, or a
# place in the queue
def enter(+p: Pool, +key: String, +dl: Nat) -> IO(Entry):
  match p:
    case Pool{_, +ch, _}:
      do IO<Entry>:
        m : Maybe<&1, St> <- Chan.recv(St, ch)
        +now : Nat <- IO.now()
        taken.st(m, p, key, now, dl)

# a grant, as what the request got
def granted(g: Grant) -> IO(Taken):
  match g:
    case GKept{s, tls}:
      IO.pure(Taken, Kept{s, tls})
    case GEvict{s, tls}:
      IO.bind(Unit, Taken, C.shut(tls, s), u => IO.pure(Taken, Room{}))
    case GRoom{}:
      IO.pure(Taken, Room{})
    case GShut{}:
      IO.pure(Taken, Shut{})

# Giving it back
# --------------

# room back: to the oldest waiter if there is one (the closer, while the
# pool closes: the room then goes back to the pool and the closer looks
# again), else to the pool
def room.back(st: St, +ch: Chan(St)) -> IO(Unit):
  match st:
    case St{idle, +free, Con{Ticket{_, _, +box}, t}, next, False{}}:
      IO.bind(Unit, Unit, grant(box, GRoom{}), u => put(ch, St{idle, free, t, next, False{}}))
    case St{idle, +free, Con{Ticket{_, _, +box}, t}, next, True{}}:
      IO.bind(Unit, Unit, grant(box, GShut{}), u => put(ch, St{idle, Nat.add(free, 1n), t, next, True{}}))
    case St{idle, +free, Nil{}, next, closing}:
      put(ch, St{idle, Nat.add(free, 1n), [], next, closing})

def handed(same: Bool, s: Tr.Connection, +tls: Bool) -> Grant:
  match same:
    case True{}:
      GKept{s, tls}
    case False{}:
      GEvict{s, tls}

# a kept connection back: to the oldest waiter (to use, or to close for its
# own origin's), else idle
def kept.back(st: St, s: Tr.Connection, +tls: Bool, +key: String, +now: Nat, +ch: Chan(St)) -> IO(Unit):
  match st:
    case St{idle, free, Con{Ticket{_, +k, +box}, t}, next, closing}:
      IO.bind(Unit, Unit, grant(box, handed(T.same(k, key, True{}), s, tls)), u => put(ch, St{idle, free, t, next, closing}))
    case St{idle, free, Nil{}, next, closing}:
      put(ch, St{Con{Idle{s, tls, now, key}, idle}, free, [], next, closing})

def gave(m: Maybe<&1, St>, keep: Bool, s: Tr.Connection, +tls: Bool, +key: String, +p: Pool, +now: Nat) -> IO(Unit):
  match m keep p:
    case Some{St{idle, free, q, next, False{}}} True{} Pool{_, +ch, _}:
      kept.back(St{idle, free, q, next, False{}}, s, tls, key, now, ch)
    case Some{st} _ Pool{_, +ch, _}:
      IO.bind(Unit, Unit, room.back(st, ch), u => C.shut(tls, s))
    case None{} _ _:
      C.shut(tls, s)

# a connection back: kept if it may carry another request, else closed and
# its room given back
def give(keep: Bool, s: Tr.Connection, +tls: Bool, +key: String, +p: Pool) -> IO(Unit):
  match p:
    case Pool{_, +ch, _}:
      do IO<Unit>:
        m : Maybe<&1, St> <- Chan.recv(St, ch)
        +now : Nat <- IO.now()
        gave(m, keep, s, tls, key, p, now)

def freed(m: Maybe<&1, St>, +p: Pool) -> IO(Unit):
  match m p:
    case Some{st} Pool{_, +ch, _}:
      room.back(st, ch)
    case None{} _:
      IO.pure(Unit, Unit{})

# room back, for a connection that was never opened or is already closed
def release(+p: Pool) -> IO(Unit):
  match p:
    case Pool{_, +ch, _}:
      IO.bind(Maybe<&1, St>, Unit, Chan.recv(St, ch), m => freed(m, p))

# how many tasks wait, how much room is free and how many connections are
# idle (for tests and diagnostics)
type Counts is Data:
  Counts{waiting: Nat, free: Nat, idle: Nat}

type Seen is Type:
  Seen{idle: List<&1, Idle>, n: Nat}

def seen(xs: List<&1, Idle>, +n: Nat, acc: List<&1, Idle>) -> Seen:
  match xs:
    case Nil{}:
      Seen{List.reverse(&1, Idle, acc), n}
    case Con{x, t}:
      seen(t, Nat.add(n, 1n), Con{x, acc})

def tickets(q: List<&2, Ticket>, +n: Nat) -> Nat:
  match q:
    case Nil{}:
      n
    case Con{_, t}:
      tickets(t, Nat.add(n, 1n))

def counts.seen(v: Seen, +free: Nat, +q: List<&2, Ticket>, next: Nat, closing: Bool, +ch: Chan(St)) -> IO(Counts):
  match v:
    case Seen{idle, +n}:
      IO.bind(Unit, Counts, put(ch, St{idle, free, q, next, closing}), u => IO.pure(Counts, Counts{tickets(q, 0n), free, n}))

def counts.st(m: Maybe<&1, St>, +p: Pool) -> IO(Counts):
  match m p:
    case Some{St{idle, +free, +q, next, closing}} Pool{_, +ch, _}:
      counts.seen(seen(idle, 0n, []), free, q, next, closing, ch)
    case None{} _:
      IO.pure(Counts, Counts{0n, 0n, 0n})

def counts(+p: Pool) -> IO(Counts):
  match p:
    case Pool{_, +ch, _}:
      IO.bind(Maybe<&1, St>, Counts, Chan.recv(St, ch), m => counts.st(m, p))

# Waiting
# -------

# a grant a waiter that gave up no longer wants, given back like any return
# (so it goes to the next waiter, if there is one)
def passed(m: Maybe<&1, Grant>, +key: String, +p: Pool) -> IO(Taken):
  match m:
    case Some{GKept{s, +tls}}:
      IO.bind(Unit, Taken, give(True{}, s, tls, key, p), u => IO.pure(Taken, Late{}))
    case Some{GEvict{s, +tls}}:
      do IO<Taken>:
        u : Unit <- C.shut(tls, s)
        v : Unit <- release(p)
        return Late{}
    case Some{GRoom{}}:
      IO.bind(Unit, Taken, release(p), u => IO.pure(Taken, Late{}))
    case _:
      IO.pure(Taken, Late{})

# a queue without one ticket, and whether it was there
type Out is Type:
  Out{found: Bool, rest: List<&2, Ticket>}

def drop.kept(x: Ticket, o: Out) -> Out:
  match o:
    case Out{found, rest}:
      Out{found, Con{x, rest}}

def drop.one(hit: Bool, x: Ticket, t: List<&2, Ticket>, more: Unit -> Out) -> Out:
  match hit:
    case True{}:
      Out{True{}, t}
    case False{}:
      drop.kept(x, more(Unit{}))

def drop(q: List<&2, Ticket>, +id: Nat) -> Out:
  match q:
    case Nil{}:
      Out{False{}, []}
    case Con{Ticket{+i, k, b}, +t}:
      drop.one(Nat.is_eq(i, id), Ticket{i, k, b}, t, u => drop(t, id))

# Still queued: the ticket is removed and nothing was handed over. Gone from
# the queue: a return took it out and put its grant in the box before
# putting the state back, so the grant is there now; it is passed on.
def left.out(o: Out, idle: List<&1, Idle>, +free: Nat, +next: Nat, closing: Bool, +ch: Chan(St), +key: String, +box: Chan(Grant), +p: Pool) -> IO(Taken):
  match o:
    case Out{True{}, q}:
      do IO<Taken>:
        x : Unit <- put(ch, St{idle, free, q, next, closing})
        y : Unit <- Chan.close(Grant, box)
        return Late{}
    case Out{False{}, q}:
      do IO<Taken>:
        x : Unit <- put(ch, St{idle, free, q, next, closing})
        m : Maybe<&1, Grant> <- Chan.recv(Grant, box)
        y : Unit <- Chan.close(Grant, box)
        passed(m, key, p)

def left.st(m: Maybe<&1, St>, +p: Pool, +key: String, +id: Nat, +box: Chan(Grant)) -> IO(Taken):
  match m p:
    case Some{St{idle, +free, q, +next, closing}} Pool{_, +ch, _}:
      left.out(drop(q, id), idle, free, next, closing, ch, key, box, p)
    case None{} _:
      IO.pure(Taken, Late{})

# a waiter past its deadline leaves the queue
def leave(+p: Pool, +key: String, +id: Nat, +box: Chan(Grant)) -> IO(Taken):
  match p:
    case Pool{_, +ch, _}:
      IO.bind(Maybe<&1, St>, Taken, Chan.recv(St, ch), m => left.st(m, p, key, id, box))

def woke(r: Poll<&1, &1, Maybe<&1, Grant>, Unit>, +p: Pool, +key: String, +id: Nat, +box: Chan(Grant)) -> IO(Taken):
  match r:
    case Ready{Some{g}}:
      IO.bind(Unit, Taken, Chan.close(Grant, box), u => granted(g))
    case Ready{None{}}:
      IO.pure(Taken, Shut{})
    case Wait{_}:
      leave(p, key, id, box)

# wait in the queue for a grant, but not past the deadline
def wait(+p: Pool, +key: String, +id: Nat, +box: Chan(Grant), +dl: Nat) -> IO(Taken):
  do IO<Taken>:
    +now : Nat <- IO.now()
    r : Poll<&1, &1, Maybe<&1, Grant>, Unit> <- Chan.try_recv(Grant, box, C.left(dl, now))
    woke(r, p, key, id, box)

def entered(e: Entry, +p: Pool, +key: String, +dl: Nat) -> IO(Taken):
  match e:
    case Now{t}:
      IO.pure(Taken, t)
    case Queued{+id, +box}:
      wait(p, key, id, box, dl)

# a connection for key's origin: kept, or room to open one; waiting while
# every connection is in use, until dl (fuel 0: none)
def take(+fuel: Nat, +p: Pool, +key: String, +dl: Nat) -> IO(Taken):
  match fuel:
    case 0n:
      IO.pure(Taken, Shut{})
    case 1n+n:
      IO.bind(Entry, Taken, enter(p, key, dl), e => entered(e, p, key, dl))

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
    case C.Spec{Ur.Verb{name, +head, sized, _}, Ur.Url{+tls, host, +port, target, auth}, hs, b, _}:
      IO.bind(C.Opened, C.Hop, C.open.lim(tls, host, port, lim), o => fresh.opened(o, H1.write_request(name, target, auth, C.hs.clean(hs, []), b, sized, False{}), key, p, C.lim.with_head(lim, head)))
    case C.Spec{_, Ur.UBad{}, _, _, _}:
      IO.bind(Unit, C.Hop, release(p), u => IO.pure(C.Hop, C.HopLost{Legacy.BadUrl{}}))

# after a try on a kept connection: one the server had closed is tried
# once more on a new one, if the request is safe to repeat
def kept.after(e: C.Ex, spare: C.Spec, +again: Bool, +key: String, +p: Pool, +lim: C.Lim) -> IO(C.Hop):
  match e again:
    case C.Lost{_, True{}, _} True{}:
      fresh(spare, key, p, lim)
    case other _:
      after(other, key, p)

def kept.run(ha: C.HSpec, gb: C.HSpec, s: Tr.Connection, +tls: Bool, +key: String, +p: Pool, +lim: C.Lim) -> IO(C.Hop):
  match ha gb:
    case C.HSpec{+h, a} C.HSpec{+g, b}:
      IO.bind(C.Ex, C.Hop, C.exchange(s, tls, C.req.of(a, True{}), C.lim.with_head(lim, h), C.Keep{[]}), e => kept.after(e, b, g, key, p, lim))

def kept.go(sp2: C.Spec2, s: Tr.Connection, +tls: Bool, +key: String, +p: Pool, +lim: C.Lim) -> IO(C.Hop):
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
      IO.pure(C.Hop, C.HopLost{Legacy.Closed{}})
    case Late{}:
      IO.pure(C.Hop, C.HopLost{Legacy.Timeout{}})

def hop.of(o: C.Orig, +p: Pool, +lim: C.Lim) -> IO(C.Hop):
  match o:
    case C.Orig{+key, sp}:
      IO.bind(Taken, C.Hop, take(4294967295n, p, key, C.lim.dl(lim)), t => used(t, sp, key, p, lim))

# one try through the pool
def hop(sp: C.Spec, +p: Pool, +lim: C.Lim) -> IO(C.Hop):
  hop.of(C.spec.origin(sp), p, lim)

# Driving
# -------

def drive.go(sp2: C.Spec2, l: C.Left, +p: Pool, +lim: C.Lim, k: C.DK()) -> IO(C.RR()):
  match sp2:
    case C.Spec2{a, b}:
      IO.bind(C.Hop, C.RR(), hop(a, p, lim), h => C.hopped(h, C.verb.again(b), l, k))

# no try, retry or redirect starts past the total deadline
def drive.at(late: Bool, sp: C.Spec, l: C.Left, +p: Pool, +lim: C.Lim, k: C.DK()) -> IO(C.RR()):
  match late:
    case True{}:
      IO.pure(C.RR(), Fail{Legacy.Timeout{}})
    case False{}:
      drive.go(C.spec.dup(sp), l, p, lim, k)

# a request, then its redirects and retries, through the pool
def drive(fuel: Nat, sp: C.Spec, l: C.Left, +p: Pool, +lim: C.Lim) -> IO(C.RR()):
  match fuel:
    case 0n:
      IO.pure(C.RR(), Fail{Legacy.Redirects{}})
    case 1n+n:
      do IO<C.RR()>:
        +now : Nat <- IO.now()
        drive.at(Nat.is_le(C.lim.dl(lim), now), sp, l, p, lim, s => l2 => drive(n, s, l2, p, lim))

def start(sp: C.Spec, +p: Pool) -> IO(C.RR()):
  match p:
    case Pool{C.Config{+ms, mh, mb, +rt, bo, +rd, _, policy, cm, rm, ua}, _, _}:
      do IO<C.RR()>:
        +now : Nat <- IO.now()
        drive(C.fuel.of(rt, rd), C.spec.agent(ua, sp), C.left.of(rt, rd, bo, Nat.add(now, U32.to_nat(ms))), p, C.lim.of(now, ms, mh, mb, policy, C.Ph{cm, rm}))

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
      IO.bind(C.Opened, C.R(C.Head), C.open.lim(tls0, host, port, lim), o => stream.opened(~f, o, req, key, p, lim))
    case Shut{}:
      IO.pure(C.R(C.Head), Fail{Legacy.Closed{}})
    case Late{}:
      IO.pure(C.R(C.Head), Fail{Legacy.Timeout{}})

def stream.spec(~f: List<&2, U32> -> IO(Bool), o: C.Orig, +p: Pool, +dl: Nat) -> IO(C.R(C.Head)):
  match o p:
    case C.Orig{+key, C.Spec{Ur.Verb{name, +head, sized, _}, Ur.Url{+tls, host, +port, target, auth}, hs, b, _}} Pool{C.Config{+ms, mh, _, _, _, _, _, policy, cm, rm, _}, _, _}:
      IO.bind(Taken, C.R(C.Head), take(4294967295n, p, key, dl), t => stream.taken(~f, t, H1.write_request(name, target, auth, C.hs.clean(hs, []), b, sized, False{}), tls, host, port, key, p, C.lim.stream(dl, ms, mh, head, policy, C.Ph{cm, rm})))
    case C.Orig{_, C.Spec{_, Ur.UBad{}, _, _, _}} _:
      IO.pure(C.R(C.Head), Fail{Legacy.BadUrl{}})

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
    case Pool{C.Config{+ms, _, _, _, _, _, _, policy, _, _, ua}, _, _}:
      do IO<C.R(C.Head)>:
        +now : Nat <- IO.now()
        stream.go(~f, C.spec.agent.r(ua, C.spec.of(r)), p, Nat.add(now, U32.to_nat(ms)))

# Opening and closing
# -------------------

# a pool of up to n connections, for any origin, opened as they are needed
def open(cfg: C.Config, +n: U32) -> IO(Pool):
  do IO<Pool>:
    +ch : Chan(St) <- Chan.new(St, 1)
    x : Unit <- put(ch, St{[], U32.to_nat(n), [], 0n, False{}})
    return Pool{cfg, ch, n}

def shut.count(xs: List<&1, Idle>, +n: Nat) -> IO(Nat):
  match xs:
    case Nil{}:
      IO.pure(Nat, n)
    case Con{Idle{s, tls, _, _}, t}:
      IO.bind(Unit, Nat, C.shut(tls, s), u => shut.count(t, Nat.add(n, 1n)))

# the closer waits in the queue like a request, with no deadline; whatever
# comes back while the pool closes is closed and its room returned
def closer.got(m: Maybe<&1, Grant>) -> IO(Unit):
  match m:
    case Some{GKept{s, tls}}:
      C.shut(tls, s)
    case Some{GEvict{s, tls}}:
      C.shut(tls, s)
    case _:
      IO.pure(Unit, Unit{})

def closed.check(all: Bool, +free: Nat, +next: Nat, +p: Pool, again: Unit -> IO(Unit)) -> IO(Unit):
  match all p:
    case True{} Pool{_, +ch, _}:
      Chan.close(St, ch)
    case False{} Pool{_, +ch, _}:
      do IO<Unit>:
        +box : Chan(Grant) <- Chan.new(Grant, 1)
        x : Unit <- put(ch, St{[], free, [Ticket{next, "", box}], Nat.add(next, 1n), True{}})
        m : Maybe<&1, Grant> <- Chan.recv(Grant, box)
        y : Unit <- Chan.close(Grant, box)
        z : Unit <- closer.got(m)
        again(Unit{})

def closed.k(+free: Nat, +n: U32, +next: Nat, +p: Pool, again: Unit -> IO(Unit)) -> IO(Unit):
  closed.check(Nat.is_le(U32.to_nat(n), free), free, next, p, again)

# waiters still queued when the pool starts closing get nothing
def closed.st(m: Maybe<&1, St>, +p: Pool, again: Unit -> IO(Unit)) -> IO(Unit):
  match m p:
    case Some{St{idle, +free, q, +next, _}} Pool{_, _, +n}:
      do IO<Unit>:
        u : Unit <- shut.queue(q)
        +k : Nat <- shut.count(idle, 0n)
        closed.k(Nat.add(free, k), n, next, p, again)
    case None{} _:
      IO.pure(Unit, Unit{})

def closing(+fuel: Nat, +p: Pool) -> IO(Unit):
  match fuel p:
    case 0n _:
      IO.pure(Unit, Unit{})
    case 1n+k Pool{_, +ch, _}:
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
      IO.bind(C.Opened, C.Try, C.open.lim(tls0, host, port, lim), o => ev.opened(~on, o, req, key, p, lim))
    case Shut{}:
      IO.pure(C.Try, C.Try{Some{Legacy.Closed{}}, None{}, None{}, False{}})
    case Late{}:
      IO.pure(C.Try, C.Try{Some{Legacy.Timeout{}}, None{}, None{}, False{}})

# one try at an event stream through the pool
def ev.try(~on: Ev.Message -> IO(Bool), o: C.Orig, last: Maybe<&2, String>, +p: Pool, +dl: Nat) -> IO(C.Try):
  match o p:
    case C.Orig{+key, C.Spec{Ur.Verb{name, +head, sized, _}, Ur.Url{+tls, host, +port, target, auth}, hs, b, _}} Pool{C.Config{+ms, mh, _, _, _, _, _, policy, cm, rm, _}, _, _}:
      IO.bind(Taken, C.Try, take(4294967295n, p, key, dl), t => ev.taken(~on, t, H1.write_request(name, target, auth, List.append(&2, H.Header, C.hs.clean(hs, []), C.ev.hs(last)), b, sized, False{}), tls, host, port, key, p, C.lim.stream(dl, ms, mh, head, policy, C.Ph{cm, rm})))
    case C.Orig{_, C.Spec{_, Ur.UBad{}, _, _, _}} _:
      IO.pure(C.Try, C.Try{Some{Legacy.BadUrl{}}, None{}, None{}, False{}})

def ev.now(~on: Ev.Message -> IO(Bool), sp: C.Spec, last: Maybe<&2, String>, +p: Pool) -> IO(C.Try):
  match p:
    case Pool{C.Config{+ms, _, _, _, _, _, _, policy, _, _, _}, _, _}:
      do IO<C.Try>:
        +now : Nat <- IO.now()
        ev.try(~on, C.spec.origin(sp), last, p, Nat.add(now, U32.to_nat(ms)))

def ev.once(~on: Ev.Message -> IO(Bool), s: Result<&2, &2, C.Err, C.Spec>, +p: Pool) -> IO(C.R(C.Ended)):
  match s:
    case Done{sp}:
      IO.bind(C.Try, C.R(C.Ended), ev.now(~on, sp, None{}, p), t => IO.pure(C.R(C.Ended), C.ev.end(t, 0)))
    case Fail{e}:
      IO.pure(C.R(C.Ended), Fail{e})

# a request's spec, with the pool's User-Agent unless the caller set one
def spec.of(+p: Pool, r: C.Req) -> Result<&2, &2, C.Err, C.Spec>:
  match p:
    case Pool{C.Config{_, _, _, _, _, _, _, _, _, _, ua}, _, _}:
      C.spec.agent.r(ua, C.spec.of(r))

# as C.events, through the pool
def events(~on: Ev.Message -> IO(Bool), +p: Pool, r: C.Req) -> IO(C.R(C.Ended)):
  ev.once(~on, spec.of(p, r), p)

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
    case Done{sp} Pool{C.Config{_, _, _, _, +bo, _, _, policy, _, _, _}, _, _}:
      ev.retry.go(~on, Nat.add(U32.to_nat(n), 1n), sp, C.Rt{None{}, 0, bo}, n, p)
    case Fail{e} _:
      IO.pure(C.R(C.Ended), Fail{e})

# as C.events_retry, through the pool
def events_retry(~on: Ev.Message -> IO(Bool), +p: Pool, r: C.Req, +n: U32) -> IO(C.R(C.Ended)):
  ev.retry(~on, spec.of(p, r), n, p)
