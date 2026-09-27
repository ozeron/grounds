import Base
import ./resp.bend as R
import ../wire/wire.bend as W

# grounds-redis: a Redis client.
#
#   c : Result<&1, &1, Redis.Down, Redis.Client()> <- Redis.open(Redis.config("127.0.0.1", 6379))
#   g : Redis.Got(Redis.Res(Maybe<&2, String>)) <- Redis.get(c, "k")
#
# Every call hands the client back with its answer, or fails with Down.
# A client that fails is closed and not handed back: a connection left
# half-read can never be used again. Open a new one, or use a Pool.

# Config
# ------

type Config is Data:
  Config{host: String, port: U32, user: Maybe<&2, String>, password: Maybe<&2, String>, db: U32, resp3: Bool, timeout_ms: U32, max_reply: U32}

# why a client is gone; each closes it
type Down is Data:
  Timeout{}
  Closed{}
  TooLarge{}
  Protocol{why: String}
  Io{why: String}
  Rejected{why: String}

# a client's state: bytes read past the last reply, and its limits
type St is Data:
  St{buf: R.Buf, ms: U32, max: Nat}

def Client() -> Type:
  Socket & St

# the client back with an answer, or why it is gone
def Got(-A: Data) -> Type:
  Result<&1, &1, Down, Client() & A>

def gone(-A: Data, s: Socket, d: Down) -> IO(Got(A)):
  do IO<Got(A)>:
    x : Unit <- W.close(s)
    return Fail{d}

# Reading a reply
# ---------------

def RU() -> Type:
  Socket & Result<&1, &1, U32 & String, Unit>

law sent.m:
  for -A: Data
  for st: St
  for k: Client() -> IO(Got(A))
  for m: RU()
  IO(Got(A))

def timed_out(+code: U32) -> Bool:
  Bool.or(U32.is_eq(code, 60), U32.is_eq(code, 110))

def sent.fail(-A: Data, t: Bool, why: String, s: Socket) -> IO(Got(A)):
  match t:
    case True{}:
      gone(A, s, Timeout{})
    case False{}:
      gone(A, s, Io{why})

def sent(-A: Data, r: Result<&1, &1, U32 & String, Unit>, s: Socket, st: St, k: Client() -> IO(Got(A))) -> IO(Got(A)):
  match r:
    case Done{_}:
      k((s, st))
    case Fail{(code, why)}:
      sent.fail(A, timed_out(code), why, s)

def sent.m(A, st, k, m):
  (s, r) = m
  sent(A, r, s, st, k)

def send.st(-A: Data, s: Socket, st: St, bytes: R.Buf, k: Client() -> IO(Got(A))) -> IO(Got(A)):
  match st:
    case St{buf, +ms, max}:
      IO.bind(RU(), Got(A), W.wire_send_timeout(s, R.buf.list(bytes), ms), m => sent.m(A, St{buf, ms, max}, k, m))

# a free client, or a place for one to be opened
def Slot() -> Type:
  Maybe<&1, Client()>

def back(-A: Data, +ch: Chan(Slot()), g: Got(A)) -> IO(Result<&1, &1, Down, A>):
  match g:
    case Done{(c, a)}:
      do IO<Result<&1, &1, Down, A>>:
        x : Bool <- Chan.send(Slot(), ch, Some{c})
        return Done{a}
    case Fail{d}:
      do IO<Result<&1, &1, Down, A>>:
        x : Bool <- Chan.send(Slot(), ch, None{})
        return Fail{d}

def use(-A: Data, +ch: Chan(Slot()), r: Result<&1, &1, Down, Client()>, f: Client() -> IO(Got(A))) -> IO(Result<&1, &1, Down, A>):
  match r:
    case Done{c}:
      IO.bind(Got(A), Result<&1, &1, Down, A>, f(c), g => back(A, ch, g))
    case Fail{d}:
      do IO<Result<&1, &1, Down, A>>:
        x : Bool <- Chan.send(Slot(), ch, None{})
        return Fail{d}

def auth(user: Maybe<&2, String>, pw: Maybe<&2, String>) -> List<&2, List<&2, String>>:
  match user pw:
    case _ None{}:
      []
    case None{} Some{p}:
      [["AUTH", p]]
    case Some{u} Some{p}:
      [["AUTH", u, p]]

def hello(user: Maybe<&2, String>, pw: Maybe<&2, String>) -> List<&2, String>:
  match user pw:
    case _ None{}:
      ["HELLO", "3"]
    case None{} Some{p}:
      ["HELLO", "3", "AUTH", "default", p]
    case Some{u} Some{p}:
      ["HELLO", "3", "AUTH", u, p]

def select.go(zero: Bool, +db: U32) -> List<&2, List<&2, String>>:
  match zero:
    case True{}:
      []
    case False{}:
      [["SELECT", U32.show(db)]]

def select(+db: U32) -> List<&2, List<&2, String>>:
  select.go(U32.is_eq(db, 0), db)

# the commands a connection starts with: HELLO 3 or AUTH, then SELECT
def greet(r3: Bool, user: Maybe<&2, String>, pw: Maybe<&2, String>, +db: U32) -> List<&2, List<&2, String>>:
  match r3:
    case True{}:
      Con{hello(user, pw), select(db)}
    case False{}:
      List.append(&2, List<&2, String>, auth(user, pw), select(db))

def refused(r: R.Reply) -> Maybe<&2, String>:
  match r:
    case R.Error{e}:
      Some{e}
    case R.BulkError{e}:
      Some{R.text(R.buf.of(e))}
    case _:
      None{}

# send bytes within the timeout, then go on with k
def send(-A: Data, c: Client(), bytes: R.Buf, k: Client() -> IO(Got(A))) -> IO(Got(A)):
  (s, st) = c
  send.st(A, s, st, bytes, k)

# Commands
# --------

# a reply being read: its deadline, the bytes read for it so far, and
# the limits
type Rd is Data:
  Rd{dl: Nat, total: Nat, ms: U32, max: Nat}

# bytes that came while a bulk string was still short, newest first
type Chunks is Data:
  CNil{}
  CCon{bs: R.Buf, t: Chunks}

def Next() -> Type:
  Socket -> R.Parsed -> Rd -> IO(Got(R.Reply))

# clients shared by tasks: each call takes one and gives it back. A client
# that fails is replaced by a new one, opened on its next use
type Pool is Data:
  Pool{cfg: Config, slots: Chan(Slot()), size: U32}

def close(c: Client()) -> IO(Unit):
  (s, _) = c
  W.close(s)

# wait on for more bytes, then go on with the Next given
def Again() -> Type:
  Socket -> R.Mode -> Nat -> Chunks -> Rd -> Next() -> IO(Got(R.Reply))

def RB() -> Type:
  Socket & Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>

law polled.m:
  for m: RB()
  for at: R.Mode
  for +missing: Nat
  for cs: Chunks
  for rd: Rd
  for again: Again()
  for k: Next()
  IO(Got(R.Reply))

def chunks.join(cs: Chunks, acc: R.Buf) -> R.Buf:
  match cs:
    case CNil{}:
      acc
    case CCon{bs, t}:
      chunks.join(t, R.cat(bs, acc))

def arrived.parse(s: Socket, m: R.Mode, rd: Rd, k: Next()) -> IO(Got(R.Reply)):
  match rd:
    case Rd{dl, total, ms, +max}:
      k(s, R.parse.at(m, Nat.sub(max, 16n)), Rd{dl, total, ms, max})

def arrived.fits(ok: Bool, +missing: Nat, s: Socket, at: R.Mode, cs: Chunks, rd: Rd, again: Again(), k: Next()) -> IO(Got(R.Reply)):
  match ok missing:
    case False{} _:
      gone(R.Reply, s, TooLarge{})
    case True{} 0n:
      arrived.parse(s, R.feed(at, chunks.join(cs, R.BNil{})), rd, k)
    case True{} 1n+m:
      again(s, at, 1n+m, cs, rd, k)

# bytes came: count them, and parse again once a bulk string has all come
def arrived(c: R.Counted, s: Socket, at: R.Mode, +missing: Nat, cs: Chunks, rd: Rd, again: Again(), k: Next()) -> IO(Got(R.Reply)):
  match c rd:
    case R.Counted{+n, bs} Rd{dl, +total, ms, +max}:
      arrived.fits(Nat.is_le(Nat.add(total, n), max), Nat.sub(missing, n), s, at, CCon{bs, cs}, Rd{dl, Nat.add(total, n), ms, max}, again, k)

def polled(r: Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>, s: Socket, at: R.Mode, +missing: Nat, cs: Chunks, rd: Rd, again: Again(), k: Next()) -> IO(Got(R.Reply)):
  match r:
    case Done{Some{Nil{}}}:
      gone(R.Reply, s, Closed{})
    case Done{Some{bs}}:
      arrived(R.counted(bs), s, at, missing, cs, rd, again, k)
    case Done{None{}}:
      gone(R.Reply, s, Timeout{})
    case Fail{(_, why)}:
      gone(R.Reply, s, Io{why})

def polled.m(m, at, missing, cs, rd, again, k):
  (s, r) = m
  polled(r, s, at, missing, cs, rd, again, k)

def wait.left(over: Bool, +left: Nat, s: Socket, at: R.Mode, +missing: Nat, cs: Chunks, rd: Rd, again: Again(), k: Next()) -> IO(Got(R.Reply)):
  match over:
    case True{}:
      gone(R.Reply, s, Timeout{})
    case False{}:
      IO.bind(RB(), Got(R.Reply), W.wire_recv_timeout(s, 65536, U32.from_nat(left)), m => polled.m(m, at, missing, cs, rd, again, k))

def wait.at(+now: Nat, s: Socket, at: R.Mode, +missing: Nat, cs: Chunks, rd: Rd, again: Again(), k: Next()) -> IO(Got(R.Reply)):
  match rd:
    case Rd{+dl, total, ms, max}:
      wait.left(Nat.is_le(dl, now), Nat.sub(dl, now), s, at, missing, cs, Rd{dl, total, ms, max}, again, k)

# wait for more bytes, until the reply's deadline; fuel bounds the reads
def wait(fuel: Nat, s: Socket, at: R.Mode, +missing: Nat, cs: Chunks, rd: Rd, k: Next()) -> IO(Got(R.Reply)):
  match fuel:
    case 0n:
      gone(R.Reply, s, Timeout{})
    case 1n+f:
      do IO<Got(R.Reply)>:
        +now : Nat <- IO.now()
        wait.at(now, s, at, missing, cs, rd, s2 => a => n => c => r => kk => wait(f, s2, a, n, c, r, kk), k)

def is_push(r: R.Reply) -> Bool:
  match r:
    case R.RPush{_}:
      True{}
    case _:
      False{}

def done.st(rest: R.Buf, rd: Rd) -> St:
  match rd:
    case Rd{_, _, ms, max}:
      St{rest, ms, max}

def reply.kept(push: Bool, r: R.Reply, rest: R.Buf, s: Socket, rd: Rd, k: Next()) -> IO(Got(R.Reply)):
  match push rd:
    case True{} Rd{dl, total, ms, +max}:
      k(s, R.parse.buf(rest, Nat.sub(max, 16n)), Rd{dl, total, ms, max})
    case False{} _:
      IO.pure(Got(R.Reply), Done{((s, done.st(rest, rd)), r)})

def handle.p(p: R.Parsed, s: Socket, rd: Rd, k: Next()) -> IO(Got(R.Reply)):
  match p:
    case R.Parsed{+r, rest}:
      reply.kept(is_push(r), r, rest, s, rd, k)
    case R.More{at, +missing}:
      wait(4294967295n, s, at, missing, CNil{}, rd, k)
    case R.Bad{why}:
      gone(R.Reply, s, Protocol{why})
    case R.TooLarge{}:
      gone(R.Reply, s, TooLarge{})

# one parse: the reply, or wait for more. A push (RESP3 client tracking,
# pub/sub) is not a reply to a command and is skipped
def handle(fuel: Nat, s: Socket, p: R.Parsed, rd: Rd) -> IO(Got(R.Reply)):
  match fuel:
    case 0n:
      gone(R.Reply, s, Protocol{"too many pushes"})
    case 1n+f:
      handle.p(p, s, rd, s2 => q => r => handle(f, s2, q, r))

def read.left(+left: Nat, s: Socket, buf: R.Buf, +now: Nat, +ms: U32, +max: Nat) -> IO(Got(R.Reply)):
  handle(4294967295n, s, R.parse.buf(buf, Nat.sub(max, 16n)), Rd{Nat.add(now, U32.to_nat(ms)), left, ms, max})

# a length or count is refused when it cannot fit with its header (16 bytes
# at most) in the cap; bytes left from the last read count toward it
def read.st(s: Socket, st: St, +now: Nat) -> IO(Got(R.Reply)):
  match st:
    case St{+buf, +ms, +max}:
      read.left(R.buf.len(buf, 0n), s, buf, now, ms, max)

# the next reply, within the timeout
def read(c: Client()) -> IO(Got(R.Reply)):
  (s, st) = c
  do IO<Got(R.Reply)>:
    +now : Nat <- IO.now()
    read.st(s, st, now)

# Sending
# -------

# send a command, read its reply. An error reply is a reply: the client
# stays open
def command(c: Client(), args: List<&2, String>) -> IO(Got(R.Reply)):
  send(R.Reply, c, R.encode.buf(R.args.text(args), R.BNil{}), read)

def greeted(m: Maybe<&2, String>, c: Client(), k: Client() -> IO(Result<&1, &1, Down, Client()>)) -> IO(Result<&1, &1, Down, Client()>):
  match m:
    case None{}:
      k(c)
    case Some{why}:
      do IO<Result<&1, &1, Down, Client()>>:
        x : Unit <- close(c)
        return Fail{Rejected{why}}

def greet.got(g: Got(R.Reply), k: Client() -> IO(Result<&1, &1, Down, Client()>)) -> IO(Result<&1, &1, Down, Client()>):
  match g:
    case Done{(c, r)}:
      greeted(refused(r), c, k)
    case Fail{d}:
      IO.pure(Result<&1, &1, Down, Client()>, Fail{d})

def handshake(cmds: List<&2, List<&2, String>>, c: Client()) -> IO(Result<&1, &1, Down, Client()>):
  match cmds:
    case Nil{}:
      IO.pure(Result<&1, &1, Down, Client()>, Done{c})
    case Con{cmd, t}:
      IO.bind(Got(R.Reply), Result<&1, &1, Down, Client()>, command(c, cmd), g => greet.got(g, c2 => handshake(t, c2)))

def open.fail(t: Bool, why: String) -> Down:
  match t:
    case True{}:
      Timeout{}
    case False{}:
      Io{why}

def opened(r: Result<&1, &1, U32 & String, Socket>, st: St, cmds: List<&2, List<&2, String>>) -> IO(Result<&1, &1, Down, Client()>):
  match r:
    case Done{s}:
      handshake(cmds, (s, st))
    case Fail{(+code, why)}:
      IO.pure(Result<&1, &1, Down, Client()>, Fail{open.fail(timed_out(code), why)})

# connect within the timeout, then HELLO 3 or AUTH, and SELECT, as the
# config says. A refused AUTH or SELECT is Rejected, and the connection closed
def open(cfg: Config) -> IO(Result<&1, &1, Down, Client()>):
  match cfg:
    case Config{h, p, u, pw, +db, r3, +ms, max}:
      IO.bind(Result<&1, &1, U32 & String, Socket>, Result<&1, &1, Down, Client()>, W.wire_connect_timeout(h, p, ms), r => opened(r, St{R.BNil{}, ms, U32.to_nat(max)}, greet(r3, u, pw, db)))

# Sessions
# --------

def session.done(-A: Data, g: Got(A)) -> IO(Result<&1, &1, Down, A>):
  match g:
    case Done{(c, a)}:
      IO.bind(Unit, Result<&1, &1, Down, A>, close(c), x => IO.pure(Result<&1, &1, Down, A>, Done{a}))
    case Fail{d}:
      IO.pure(Result<&1, &1, Down, A>, Fail{d})

def session.opened(-A: Data, r: Result<&1, &1, Down, Client()>, f: Client() -> IO(Got(A))) -> IO(Result<&1, &1, Down, A>):
  match r:
    case Done{c}:
      IO.bind(Got(A), Result<&1, &1, Down, A>, f(c), g => session.done(A, g))
    case Fail{d}:
      IO.pure(Result<&1, &1, Down, A>, Fail{d})

# open a client, run f with it, and close it, whatever happens: f hands the
# client back with its answer, and a client that failed was closed already.
# The type system cannot make a client be closed (a value may always be
# dropped), so this, or a Pool, is how to never leave one open
def session(-A: Data, cfg: Config, f: Client() -> IO(Got(A))) -> IO(Result<&1, &1, Down, A>):
  IO.bind(Result<&1, &1, Down, Client()>, Result<&1, &1, Down, A>, open(cfg), r => session.opened(A, r, f))

# Pools
# -----

def fresh.slot(-A: Data, cfg: Config, +ch: Chan(Slot()), s: Maybe<&1, Slot()>, f: Client() -> IO(Got(A))) -> IO(Result<&1, &1, Down, A>):
  match s:
    case Some{Some{c}}:
      IO.bind(Unit, Result<&1, &1, Down, A>, close(c), x => IO.bind(Result<&1, &1, Down, Client()>, Result<&1, &1, Down, A>, open(cfg), r => use(A, ch, r, f)))
    case Some{None{}}:
      IO.bind(Result<&1, &1, Down, Client()>, Result<&1, &1, Down, A>, open(cfg), r => use(A, ch, r, f))
    case None{}:
      IO.pure(Result<&1, &1, Down, A>, Fail{Closed{}})

# as with, on a new connection: a retry after a failure must not take a
# client that went stale the same way
def with.fresh(-A: Data, p: Pool, f: Client() -> IO(Got(A))) -> IO(Result<&1, &1, Down, A>):
  match p:
    case Pool{cfg, +ch, _}:
      IO.bind(Maybe<&1, Slot()>, Result<&1, &1, Down, A>, Chan.recv(Slot(), ch), s => fresh.slot(A, cfg, ch, s, f))

def retry.got(r: Result<&1, &1, Down, R.Reply>, again: Down -> IO(Result<&1, &1, Down, R.Reply>)) -> IO(Result<&1, &1, Down, R.Reply>):
  match r:
    case Fail{Rejected{w}}:
      IO.pure(Result<&1, &1, Down, R.Reply>, Fail{Rejected{w}})
    case Fail{TooLarge{}}:
      IO.pure(Result<&1, &1, Down, R.Reply>, Fail{TooLarge{}})
    case Fail{d}:
      again(d)
    case other:
      IO.pure(Result<&1, &1, Down, R.Reply>, other)

# closed or failed i/o: the server may have restarted, and the pool's other
# clients with it. A timeout says only that this reply was slow
def stale(d: Down) -> Bool:
  match d:
    case Closed{}:
      True{}
    case Io{_}:
      True{}
    case _:
      False{}

def slot(-A: Data, cfg: Config, +ch: Chan(Slot()), s: Maybe<&1, Slot()>, f: Client() -> IO(Got(A))) -> IO(Result<&1, &1, Down, A>):
  match s:
    case Some{Some{c}}:
      use(A, ch, Done{c}, f)
    case Some{None{}}:
      IO.bind(Result<&1, &1, Down, Client()>, Result<&1, &1, Down, A>, open(cfg), r => use(A, ch, r, f))
    case None{}:
      IO.pure(Result<&1, &1, Down, A>, Fail{Closed{}})

# run f with a client from the pool, waiting for one when all are in use
def with(-A: Data, p: Pool, f: Client() -> IO(Got(A))) -> IO(Result<&1, &1, Down, A>):
  match p:
    case Pool{cfg, +ch, _}:
      IO.bind(Maybe<&1, Slot()>, Result<&1, &1, Down, A>, Chan.recv(Slot(), ch), s => slot(A, cfg, ch, s, f))

def attempt(fresh: Bool, +p: Pool, +args: List<&2, String>) -> IO(Result<&1, &1, Down, R.Reply>):
  match fresh:
    case True{}:
      with.fresh(R.Reply, p, c => command(c, args))
    case False{}:
      with(R.Reply, p, c => command(c, args))

def run.again(+retries: Nat, +p: Pool, +args: List<&2, String>, +d: Down) -> IO(Result<&1, &1, Down, R.Reply>):
  match retries:
    case 0n:
      IO.pure(Result<&1, &1, Down, R.Reply>, Fail{d})
    case 1n+m:
      IO.bind(Result<&1, &1, Down, R.Reply>, Result<&1, &1, Down, R.Reply>, attempt(stale(d), p, args), r => retry.got(r, d2 => run.again(m, p, args, d2)))

# a value, or the error Redis answered with; the client stays open either way
def Res(-A: Data) -> Data:
  Result<&2, &2, String, A>

def typed.got(-A: Data, g: Got(R.Reply), f: R.Reply -> Res(A)) -> Got(Res(A)):
  match g:
    case Done{(c, r)}:
      Done{(c, f(r))}
    case Fail{d}:
      Fail{d}

# a command, its reply read by f
def call(-A: Data, c: Client(), args: List<&2, String>, f: R.Reply -> Res(A)) -> IO(Got(Res(A))):
  IO.bind(Got(R.Reply), Got(Res(A)), command(c, args), g => IO.pure(Got(Res(A)), typed.got(A, g, f)))

def pool.fill(+n: Nat, +ch: Chan(Slot())) -> IO(Unit):
  match n:
    case 0n:
      IO.pure(Unit, Unit{})
    case 1n+m:
      IO.bind(Bool, Unit, Chan.send(Slot(), ch, None{}), x => pool.fill(m, ch))

# a pool of up to n clients, opened as they are first used
def pool(cfg: Config, +n: U32) -> IO(Pool):
  do IO<Pool>:
    +ch : Chan(Slot()) <- Chan.new(Slot(), n)
    x : Unit <- pool.fill(U32.to_nat(n), ch)
    return Pool{cfg, ch, n}

def run(+retries: Nat, +p: Pool, +args: List<&2, String>) -> IO(Result<&1, &1, Down, R.Reply>):
  IO.bind(Result<&1, &1, Down, R.Reply>, Result<&1, &1, Down, R.Reply>, with(R.Reply, p, c => command(c, args)), r => retry.got(r, d => run.again(retries, p, args, d)))

def replies.got(r: Got(R.Reply), acc: List<&2, R.Reply>, k: Client() -> List<&2, R.Reply> -> IO(Got(List<&2, R.Reply>))) -> IO(Got(List<&2, R.Reply>)):
  match r:
    case Done{(c, x)}:
      k(c, Con{x, acc})
    case Fail{d}:
      IO.pure(Got(List<&2, R.Reply>), Fail{d})

# read n replies, in order
def replies(+n: Nat, c: Client(), acc: List<&2, R.Reply>) -> IO(Got(List<&2, R.Reply>)):
  match n:
    case 0n:
      IO.pure(Got(List<&2, R.Reply>), Done{(c, List.reverse(&2, R.Reply, acc))})
    case 1n+m:
      IO.bind(Got(R.Reply), Got(List<&2, R.Reply>), read(c), r => replies.got(r, acc, c2 => a2 => replies(m, c2, a2)))

# no AUTH, db 0, RESP2, 5 s to connect, per send and per reply, replies up
# to 8 MiB. A reply takes about 20 bytes of memory per byte while it is read
def config(host: String, port: U32) -> Config:
  Config{host, port, None{}, None{}, 0, False{}, 5000, 8388608}

def with_password(c: Config, pw: String) -> Config:
  match c:
    case Config{h, p, u, _, db, r3, ms, max}:
      Config{h, p, u, Some{pw}, db, r3, ms, max}

# an ACL user (Redis 6+)
def with_user(c: Config, user: String, pw: String) -> Config:
  match c:
    case Config{h, p, _, _, db, r3, ms, max}:
      Config{h, p, Some{user}, Some{pw}, db, r3, ms, max}

def with_db(c: Config, db: U32) -> Config:
  match c:
    case Config{h, p, u, pw, _, r3, ms, max}:
      Config{h, p, u, pw, db, r3, ms, max}

# RESP3 through HELLO 3: maps, sets, doubles and pushes come as such
def with_resp3(c: Config) -> Config:
  match c:
    case Config{h, p, u, pw, db, _, ms, max}:
      Config{h, p, u, pw, db, True{}, ms, max}

# how long a send, or a whole reply, may take
def with_timeout(c: Config, ms: U32) -> Config:
  match c:
    case Config{h, p, u, pw, db, r3, _, max}:
      Config{h, p, u, pw, db, r3, ms, max}

# the most bytes one reply may take
def with_max_reply(c: Config, bytes: U32) -> Config:
  match c:
    case Config{h, p, u, pw, db, r3, ms, _}:
      Config{h, p, u, pw, db, r3, ms, bytes}

# Clients
# -------

def down.show(d: Down) -> String:
  match d:
    case Timeout{}:
      "timed out"
    case Closed{}:
      "connection closed"
    case TooLarge{}:
      "reply too large"
    case Protocol{w}:
      "protocol error: " ++ w
    case Io{w}:
      "i/o error: " ++ w
    case Rejected{w}:
      "rejected: " ++ w

def octets(xs: List<&2, U32>, ok: Bool) -> Bool:
  match xs:
    case Nil{}:
      ok
    case Con{+x, t}:
      octets(t, Bool.and(ok, U32.is_le(x, 255)))

def octets.all(xs: List<&2, List<&2, U32>>, ok: Bool) -> Bool:
  match xs:
    case Nil{}:
      ok
    case Con{x, t}:
      octets.all(t, octets(x, ok))

def command_bytes.go(ok: Bool, c: Client(), args: List<&2, List<&2, U32>>) -> IO(Got(R.Reply)):
  match ok:
    case True{}:
      send(R.Reply, c, R.encode.buf(R.args.bytes(args), R.BNil{}), read)
    case False{}:
      IO.pure(Got(R.Reply), Done{(c, R.Error{"ERR grounds: an argument byte is past 255"})})

# the same, with each argument as bytes: values need not be UTF-8. A value
# past 255 is not a byte: the command is not sent, and the answer is an
# error reply, with the client still open
def command_bytes(c: Client(), +args: List<&2, List<&2, U32>>) -> IO(Got(R.Reply)):
  command_bytes.go(octets.all(args, True{}), c, args)

def cmds.enc(xs: List<&2, List<&2, String>>, tail: R.Buf) -> R.Buf:
  match xs:
    case Nil{}:
      tail
    case Con{x, t}:
      R.encode.buf(R.args.text(x), cmds.enc(t, tail))

# send many commands in one write, then read their replies in order: one
# round trip. Each reply has the timeout to itself
def pipeline(c: Client(), +cmds: List<&2, List<&2, String>>) -> IO(Got(List<&2, R.Reply>)):
  send(List<&2, R.Reply>, c, cmds.enc(cmds, R.BNil{}), c2 => replies(List.length(&2, List<&2, String>, cmds), c2, []))

# Typed answers
# -------------

# a signed integer, as INCR answers
type Z is Data:
  Z{neg: Bool, n: Nat}

def unexpected(-A: Data, r: R.Reply) -> Res(A):
  Fail{"unexpected reply: " ++ R.show(r)}

def as_ok(r: R.Reply) -> Res(Unit):
  match r:
    case R.Simple{_}:
      Done{Unit{}}
    case R.Error{e}:
      Fail{e}
    case R.BulkError{e}:
      Fail{R.text(R.buf.of(e))}
    case other:
      unexpected(Unit, other)

def as_text(r: R.Reply) -> Res(Maybe<&2, String>):
  match r:
    case R.Bulk{bs}:
      Done{Some{R.text(R.buf.of(bs))}}
    case R.Simple{t}:
      Done{Some{t}}
    case R.Verbatim{_, bs}:
      Done{Some{R.text(R.buf.of(bs))}}
    case R.RNil{}:
      Done{None{}}
    case R.Error{e}:
      Fail{e}
    case R.BulkError{e}:
      Fail{R.text(R.buf.of(e))}
    case other:
      unexpected(Maybe<&2, String>, other)

def as_bytes(r: R.Reply) -> Res(Maybe<&2, List<&2, U32>>):
  match r:
    case R.Bulk{bs}:
      Done{Some{bs}}
    case R.RNil{}:
      Done{None{}}
    case R.Error{e}:
      Fail{e}
    case R.BulkError{e}:
      Fail{R.text(R.buf.of(e))}
    case other:
      unexpected(Maybe<&2, List<&2, U32>>, other)

def z.end(ok: Bool, +n: Nat) -> Maybe<&2, Nat>:
  match ok:
    case True{}:
      Some{n}
    case False{}:
      None{}

def z.go(s: String, +acc: Nat, +cnt: Nat) -> Maybe<&2, Nat>:
  match s:
    case SNil{}:
      z.end(Bool.and(Nat.is_gt(cnt, 0n), Nat.is_le(cnt, 14n)), acc)
    case SCon{Chr{x}, t}:
      z.go(t, Nat.add(Nat.mul(10n, acc), Nat.sub(U32.to_nat(x), 48n)), 1n+cnt)

def z.of(neg: Bool, m: Maybe<&2, Nat>) -> Res(Z):
  match m:
    case Some{n}:
      Done{Z{neg, n}}
    case None{}:
      Fail{"integer out of range"}

# an integer's digits (the parser checked them) as a Z, when it has at most
# 14: a Nat past 2^48 - 1 aborts the runtime
def z(s: String) -> Res(Z):
  match s:
    case SCon{'-', t}:
      z.of(True{}, z.go(t, 0n, 0n))
    case other:
      z.of(False{}, z.go(other, 0n, 0n))

def nat.of(r: Res(Z)) -> Res(Nat):
  match r:
    case Done{Z{False{}, n}}:
      Done{n}
    case Done{Z{True{}, _}}:
      Fail{"negative integer"}
    case Fail{e}:
      Fail{e}

def bool.of(r: Res(Z)) -> Res(Bool):
  match r:
    case Done{Z{False{}, 0n}}:
      Done{False{}}
    case Done{Z{False{}, 1n}}:
      Done{True{}}
    case Done{_}:
      Fail{"not 0 or 1"}
    case Fail{e}:
      Fail{e}

def as_int(r: R.Reply) -> Res(Z):
  match r:
    case R.Int{t}:
      z(t)
    case R.Error{e}:
      Fail{e}
    case R.BulkError{e}:
      Fail{R.text(R.buf.of(e))}
    case other:
      unexpected(Z, other)

def as_nat(r: R.Reply) -> Res(Nat):
  match r:
    case R.Int{t}:
      nat.of(z(t))
    case R.Error{e}:
      Fail{e}
    case R.BulkError{e}:
      Fail{R.text(R.buf.of(e))}
    case other:
      unexpected(Nat, other)

def as_bool(r: R.Reply) -> Res(Bool):
  match r:
    case R.Int{t}:
      bool.of(z(t))
    case R.RBool{b}:
      Done{b}
    case R.Error{e}:
      Fail{e}
    case R.BulkError{e}:
      Fail{R.text(R.buf.of(e))}
    case other:
      unexpected(Bool, other)

# an array or set; None for the null array, which is not the empty one
def as_list(r: R.Reply) -> Res(Maybe<&2, List<&2, R.Reply>>):
  match r:
    case R.Arr{xs}:
      Done{Some{xs}}
    case R.RSet{xs}:
      Done{Some{xs}}
    case R.RNil{}:
      Done{None{}}
    case R.Error{e}:
      Fail{e}
    case R.BulkError{e}:
      Fail{R.text(R.buf.of(e))}
    case other:
      unexpected(Maybe<&2, List<&2, R.Reply>>, other)

def call_bytes(-A: Data, c: Client(), args: List<&2, List<&2, U32>>, f: R.Reply -> Res(A)) -> IO(Got(Res(A))):
  IO.bind(Got(R.Reply), Got(Res(A)), command_bytes(c, args), g => IO.pure(Got(Res(A)), typed.got(A, g, f)))

def ping(c: Client()) -> IO(Got(Res(Unit))):
  call(Unit, c, ["PING"], as_ok)

def get(c: Client(), key: String) -> IO(Got(Res(Maybe<&2, String>))):
  call(Maybe<&2, String>, c, ["GET", key], as_text)

def get_bytes(c: Client(), key: List<&2, U32>) -> IO(Got(Res(Maybe<&2, List<&2, U32>>))):
  call_bytes(Maybe<&2, List<&2, U32>>, c, [[71, 69, 84], key], as_bytes)

def set(c: Client(), key: String, value: String) -> IO(Got(Res(Unit))):
  call(Unit, c, ["SET", key, value], as_ok)

def set_bytes(c: Client(), key: List<&2, U32>, value: List<&2, U32>) -> IO(Got(Res(Unit))):
  call_bytes(Unit, c, [[83, 69, 84], key, value], as_ok)

# SET with an expiry in seconds
def set_ex(c: Client(), key: String, value: String, secs: U32) -> IO(Got(Res(Unit))):
  call(Unit, c, ["SET", key, value, "EX", U32.show(secs)], as_ok)

# how many of the keys were there
def del(c: Client(), keys: List<&2, String>) -> IO(Got(Res(Nat))):
  call(Nat, c, Con{"DEL", keys}, as_nat)

def exists(c: Client(), key: String) -> IO(Got(Res(Bool))):
  call(Bool, c, ["EXISTS", key], as_bool)

def incr(c: Client(), key: String) -> IO(Got(Res(Z))):
  call(Z, c, ["INCR", key], as_int)

def incr_by(c: Client(), key: String, by: String) -> IO(Got(Res(Z))):
  call(Z, c, ["INCRBY", key, by], as_int)

def expire(c: Client(), key: String, secs: U32) -> IO(Got(Res(Bool))):
  call(Bool, c, ["EXPIRE", key, U32.show(secs)], as_bool)

# seconds left; -1 without expiry, -2 without the key
def ttl(c: Client(), key: String) -> IO(Got(Res(Z))):
  call(Z, c, ["TTL", key], as_int)

# Opening
# -------

def drain.slot(s: Maybe<&1, Slot()>, k: Unit -> IO(Unit)) -> IO(Unit):
  match s:
    case Some{Some{c}}:
      IO.bind(Unit, Unit, close(c), k)
    case _:
      k(Unit{})

def drain(+n: Nat, +ch: Chan(Slot())) -> IO(Unit):
  match n:
    case 0n:
      Chan.close(Slot(), ch)
    case 1n+m:
      IO.bind(Maybe<&1, Slot()>, Unit, Chan.recv(Slot(), ch), s => drain.slot(s, x => drain(m, ch)))

# close a pool and its clients. It waits for each client in use to come back
# first, so none is left open
def pool.close(p: Pool) -> IO(Unit):
  match p:
    case Pool{_, ch, n}:
      drain(U32.to_nat(n), ch)
