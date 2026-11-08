import Base
import ../bend_client.bend as C
import ../bend_pool.bend as Pool
import ../bend_transport.bend as Tr
import ../client.bend as Legacy
import ../../../io/io.bend as Io
import ../../../crypto/bytes.bend as Bytes
import ../../../wire/bend_tls_client_cli.bend as Number
import ../../../json/json.bend as J
import ../../core/event.bend as Ev

def count(bytes: List<&2,U32>, +n: U32) -> U32:
  match bytes:
    case Nil{}: n
    case Con{_,rest}: count(rest,U32.inc(n))

def error(e: Legacy.Err) -> String:
  match e:
    case Legacy.Tls{why}: "error:tls:" ++ why
    case Legacy.Timeout{}: "error:timeout"
    case Legacy.Closed{}: "error:closed"
    case other: "error:" ++ C.show(other)

def reply(r: C.R(C.Reply)) -> IO(Unit):
  match r:
    case Done{C.Reply{status,_,body}}: IO.print("ok:" ++ U32.show(status) ++ ":" ++ U32.show(count(body,0)))
    case Fail{why}: IO.print(error(why))

def pooled(+cfg: C.Config, +url: String, +p: Pool.Pool) -> IO(Unit):
  do IO<Unit>:
    a : C.R(C.Reply) <- Pool.send(p,C.get(url))
    reply(a)
    b : C.R(C.Reply) <- Pool.send(p,C.get(url))
    reply(b)
    c : C.R(C.Reply) <- Pool.send(p,C.get(url))
    reply(c)

def tally(bytes: List<&2,U32>) -> IO(Bool):
  IO.bind(Unit,Bool,IO.print("part:" ++ Bytes.hex(bytes)),u => IO.pure(Bool,True{}))

def streamed(r: C.R(C.Head)) -> IO(Unit):
  match r:
    case Done{C.Head{status,_}}: IO.print("ok:" ++ U32.show(status))
    case Fail{why}: IO.print(error(why))

def event(e: Ev.Message) -> IO(Bool):
  match e:
    case Ev.Message{name,+data,id}:
      do IO<Bool>:
        IO.print("event:" ++ name ++ ":" ++ data ++ ":" ++ Maybe.default(&2,String,id,""))
        IO.pure(Bool,Bool.not(String.eq(data,"stop")))

def ended(r: C.R(C.Ended)) -> IO(Unit):
  match r:
    case Done{C.Ended{last,n}}: IO.print("ended:" ++ Maybe.default(&2,String,last,"") ++ ":" ++ U32.show(n))
    case Fail{why}: IO.print(error(why))

def decode(j: J.Json) -> Result<&2,&2,J.Access,String>:
  J.string_at(j,[J.Name{"name"}])

def json_result(r: C.R(String)) -> IO(Unit):
  match r:
    case Done{value}: IO.print("json:" ++ value)
    case Fail{why}: IO.print(error(why))

# M6 modes. Dispatched with String.eq, never long literal patterns with a
# large default (see BUILD_MEMORY.md).
type Sum is Data:
  Sum{n: U32, a: U32, b: U32}

# a count and Adler-32's two halves, so a checker can compare pieces
def sum.step(s: Sum, +x: U32) -> Sum:
  match s:
    case Sum{+n,+a,+b}: Sum{U32.inc(n),U32.mod(U32.add(a,x),65521),U32.mod(U32.add(b,U32.mod(U32.add(a,x),65521)),65521)}

def sum.go(bytes: List<&2,U32>, s: Sum) -> Sum:
  match bytes:
    case Nil{}: s
    case Con{+x,rest}: sum.go(rest,sum.step(s,x))

def sum.show(s: Sum) -> String:
  match s:
    case Sum{n,a,b}: U32.show(n) ++ ":" ++ U32.show(a) ++ ":" ++ U32.show(b)

def summed(r: C.R(C.Reply)) -> IO(Unit):
  match r:
    case Done{C.Reply{status,_,body}}: IO.print("ok:" ++ U32.show(status) ++ ":" ++ sum.show(sum.go(body,Sum{0,1,0})))
    case Fail{why}: IO.print(error(why))

def piece(bytes: List<&2,U32>) -> IO(Bool):
  IO.bind(Unit,Bool,IO.print("sum:" ++ sum.show(sum.go(bytes,Sum{0,1,0}))),u => IO.pure(Bool,True{}))

def timed(act: IO(C.R(C.Reply))) -> IO(Unit):
  do IO<Unit>:
    t0 : Nat <- IO.now()
    r : C.R(C.Reply) <- act
    reply(r)
    t1 : Nat <- IO.now()
    IO.print("elapsed:" ++ Nat.show(Nat.sub(t1,t0)))

def again(n: Nat, +p: Pool.Pool, +url: String) -> IO(Unit):
  match n:
    case 0n: IO.pure(Unit,Unit{})
    case 1n+k: IO.bind(C.R(C.Reply),Unit,Pool.send(p,C.get(url)),r => IO.bind(Unit,Unit,reply(r),u => again(k,p,url)))

def pair(+p: Pool.Pool, a: C.Req, b: C.Req) -> IO(Unit):
  do IO<Unit>:
    x : C.R(C.Reply) <- Pool.send(p,a)
    reply(x)
    y : C.R(C.Reply) <- Pool.send(p,b)
    reply(y)

def idle(+p: Pool.Pool, +url: String) -> IO(Unit):
  do IO<Unit>:
    x : C.R(C.Reply) <- Pool.send(p,C.get(url))
    reply(x)
    u : Unit <- IO.sleep(400)
    y : C.R(C.Reply) <- Pool.send(p,C.get(url))
    reply(y)

def timed.head(act: IO(C.R(C.Head))) -> IO(Unit):
  do IO<Unit>:
    t0 : Nat <- IO.now()
    r : C.R(C.Head) <- act
    streamed(r)
    t1 : Nat <- IO.now()
    IO.print("elapsed:" ++ Nat.show(Nat.sub(t1,t0)))

def quiet(bytes: List<&2,U32>) -> IO(Bool):
  IO.pure(Bool,True{})

# n bytes, the i-th being i mod 251, for an upload the peer can check
def fill(n: Nat, +i: U32, acc: List<&2,U32>) -> List<&2,U32>:
  match n:
    case 0n: List.reverse(&2,U32,acc)
    case 1n+k: fill(k,U32.inc(i),Con{U32.mod(i,251),acc})

def upload(url: String) -> C.Req:
  C.post(url,C.bytes("application/octet-stream",fill(2097152n,0,[])))

# a pool of one held by a 2 s stream while a GET with a short total
# deadline waits for it
def saturated(+p: Pool.Pool, +url: String) -> IO(Unit):
  do IO<Unit>:
    ch : Chan(C.R(C.Head)) <- IO.fork(C.R(C.Head),Pool.stream(~quiet,p,C.get(url)))
    u : Unit <- IO.sleep(150)
    timed(Pool.send(p,C.get(url ++ "?fast")))
    h : C.R(C.Head) <- IO.join(C.R(C.Head),ch)
    streamed(h)

# Takes that give up on a pool of one held by another task: a deadline
# already past (wait 0) or 1 ms away. Each counts as a Late.
def late(t: Pool.Taken) -> IO(Nat):
  match t:
    case Pool.Late{}: IO.pure(Nat,1n)
    case Pool.Kept{s,_}: IO.bind(Unit,Nat,Tr.close(s),u => IO.pure(Nat,0n))
    case _: IO.pure(Nat,0n)

def give_up(n: Nat, +p: Pool.Pool, +wait: Nat, +k: Nat) -> IO(Nat):
  match n:
    case 0n: IO.pure(Nat,k)
    case 1n+m:
      do IO<Nat>:
        now : Nat <- IO.now()
        t : Pool.Taken <- Pool.take(8n,p,"waiter",Nat.add(now,wait))
        x : Nat <- late(t)
        give_up(m,p,wait,Nat.add(k,x))

def room(t: Pool.Taken) -> IO(Nat):
  match t:
    case Pool.Room{}: IO.pure(Nat,1n)
    case Pool.Kept{s,_}: IO.bind(Unit,Nat,Tr.close(s),u => IO.pure(Nat,0n))
    case _: IO.pure(Nat,0n)

# give the held room back and take it again, n times
def cycle(n: Nat, +p: Pool.Pool, +k: Nat) -> IO(Nat):
  match n:
    case 0n: IO.pure(Nat,k)
    case 1n+m:
      do IO<Nat>:
        u : Unit <- Pool.give(False{},Tr.Closed{},True{},"waiter",p)
        now : Nat <- IO.now()
        t : Pool.Taken <- Pool.take(8n,p,"waiter",Nat.add(now,2000n))
        x : Nat <- room(t)
        cycle(m,p,Nat.add(k,x))

# 1,200 waiters give up while the only connection is held (600 at once,
# 600 after 1 ms), then it goes back and is taken 1,100 times, then two
# ordinary GETs: none of this may wait on wakes owed to waiters that left.
def waiters(+p: Pool.Pool, +url: String) -> IO(Unit):
  do IO<Unit>:
    now : Nat <- IO.now()
    held : Pool.Taken <- Pool.take(8n,p,"waiter",Nat.add(now,2000n))
    r : Nat <- room(held)
    a : Nat <- give_up(600n,p,0n,0n)
    b : Nat <- give_up(600n,p,1n,0n)
    c : Nat <- cycle(1100n,p,0n)
    IO.print("waiters:" ++ Nat.show(r) ++ ":" ++ Nat.show(Nat.add(a,b)) ++ ":" ++ Nat.show(c))
    u : Unit <- Pool.give(False{},Tr.Closed{},True{},"waiter",p)
    x : C.R(C.Reply) <- Pool.send(p,C.get(url))
    reply(x)
    y : C.R(C.Reply) <- Pool.send(p,C.get(url))
    reply(y)

def auth3(url: String) -> C.Req:
  C.with(C.get(url),[("Authorization","secret"),("Cookie","secret"),("Proxy-Authorization","secret")])

# Waiters are addressed one by one (review fix 3). The steps of a take
# (`enter`, then `wait` or `leave`) are driven by hand here, so each
# interleaving of a return, a waiter giving up and a newcomer happens in a
# known order; the counts are read under the pool's lock.
def counts(c: Pool.Counts) -> String:
  match c:
    case Pool.Counts{w,f,i}: Nat.show(w) ++ "/" ++ Nat.show(f) ++ "/" ++ Nat.show(i)

def shown(t: Pool.Taken) -> IO(String):
  match t:
    case Pool.Kept{s,_}: IO.bind(Unit,String,Tr.close(s),u => IO.pure(String,"kept"))
    case Pool.Room{}: IO.pure(String,"room")
    case Pool.Shut{}: IO.pure(String,"shut")
    case Pool.Late{}: IO.pure(String,"late")

# a fake kept connection (no socket), for the pool's bookkeeping only
def kept(+p: Pool.Pool, +key: String) -> IO(Unit):
  Pool.give(True{},Tr.Closed{},True{},key,p)

def queued(e: Pool.Entry, +p: Pool.Pool, +key: String, +dl: Nat, +quit: Bool) -> IO(String):
  match e quit:
    case Pool.Now{t} _: IO.bind(String,String,shown(t),x => IO.pure(String,"now-" ++ x))
    case Pool.Queued{+id,+box} True{}: IO.bind(Pool.Taken,String,Pool.leave(p,key,id,box),x => shown(x))
    case Pool.Queued{+id,+box} False{}: IO.bind(Pool.Taken,String,Pool.wait(p,key,id,box,dl),x => shown(x))

# A queued, the room handed to A, newcomer B queued, A gives up holding the
# grant: A passes it to B, which gets it at once
def handoff.passed(+p: Pool.Pool) -> IO(String):
  do IO<String>:
    +now : Nat <- IO.now()
    h : Pool.Taken <- Pool.take(8n,p,"w",Nat.add(now,2000n))
    rh : String <- shown(h)
    a : Pool.Entry <- Pool.enter(p,"w",Nat.add(now,100n))
    u : Unit <- Pool.release(p)
    b : Pool.Entry <- Pool.enter(p,"w",Nat.add(now,2000n))
    c1 : Pool.Counts <- Pool.counts(p)
    ra : String <- queued(a,p,"w",0n,True{})
    rb : String <- queued(b,p,"w",Nat.add(now,2000n),False{})
    c2 : Pool.Counts <- Pool.counts(p)
    v : Unit <- Pool.release(p)
    c3 : Pool.Counts <- Pool.counts(p)
    +end : Nat <- IO.now()
    return rh ++ ":" ++ ra ++ ":" ++ rb ++ ":" ++ counts(c1) ++ ":" ++ counts(c2) ++ ":" ++ counts(c3) ++ ":" ++ Nat.show(Nat.sub(end,now))

# A gives up while still queued: nothing was handed to it
def handoff.queued(+p: Pool.Pool) -> IO(String):
  do IO<String>:
    +now : Nat <- IO.now()
    h : Pool.Taken <- Pool.take(8n,p,"w",Nat.add(now,2000n))
    rh : String <- shown(h)
    a : Pool.Entry <- Pool.enter(p,"w",Nat.add(now,100n))
    c1 : Pool.Counts <- Pool.counts(p)
    ra : String <- queued(a,p,"w",0n,True{})
    c2 : Pool.Counts <- Pool.counts(p)
    v : Unit <- Pool.release(p)
    c3 : Pool.Counts <- Pool.counts(p)
    return rh ++ ":" ++ ra ++ ":" ++ counts(c1) ++ ":" ++ counts(c2) ++ ":" ++ counts(c3)

# a kept connection goes to A, which gave up: A passes it on to B as kept;
# then one goes to a waiter for another origin, which closes it for room
def handoff.kept(+p: Pool.Pool) -> IO(String):
  do IO<String>:
    +now : Nat <- IO.now()
    h : Pool.Taken <- Pool.take(8n,p,"w",Nat.add(now,2000n))
    rh : String <- shown(h)
    a : Pool.Entry <- Pool.enter(p,"w",Nat.add(now,100n))
    b : Pool.Entry <- Pool.enter(p,"w",Nat.add(now,2000n))
    u : Unit <- kept(p,"w")
    ra : String <- queued(a,p,"w",0n,True{})
    rb : String <- queued(b,p,"w",Nat.add(now,2000n),False{})
    c : Pool.Entry <- Pool.enter(p,"other",Nat.add(now,2000n))
    v : Unit <- kept(p,"w")
    rc : String <- queued(c,p,"other",Nat.add(now,2000n),False{})
    w : Unit <- kept(p,"other")
    c1 : Pool.Counts <- Pool.counts(p)
    return rh ++ ":" ++ ra ++ ":" ++ rb ++ ":" ++ rc ++ ":" ++ counts(c1)

# a waiter queued when the pool starts closing gets nothing at once; the
# close ends when the held room comes back
def handoff.close(+p: Pool.Pool) -> IO(String):
  do IO<String>:
    +now : Nat <- IO.now()
    h : Pool.Taken <- Pool.take(8n,p,"w",Nat.add(now,5000n))
    rh : String <- shown(h)
    a : Pool.Entry <- Pool.enter(p,"w",Nat.add(now,5000n))
    ch : Chan(Unit) <- IO.fork(Unit,Pool.close(p))
    ra : String <- queued(a,p,"w",Nat.add(now,5000n),False{})
    +mid : Nat <- IO.now()
    b : Pool.Taken <- Pool.take(8n,p,"w",Nat.add(now,5000n))
    rb : String <- shown(b)
    u : Unit <- Pool.release(p)
    x : Unit <- IO.join(Unit,ch)
    return rh ++ ":" ++ ra ++ ":" ++ rb ++ ":" ++ Bool.pick(String,Nat.is_le(Nat.sub(mid,now),1000n),"prompt","slow")

def handoff(+cfg: C.Config) -> IO(Unit):
  do IO<Unit>:
    a : String <- Pool.with(String,cfg,1,p => handoff.passed(p))
    IO.print("handoff-passed:" ++ a)
    b : String <- Pool.with(String,cfg,1,p => handoff.queued(p))
    IO.print("handoff-queued:" ++ b)
    c : String <- Pool.with(String,cfg,1,p => handoff.kept(p))
    IO.print("handoff-kept:" ++ c)
    d : String <- Pool.with(String,cfg,1,p => handoff.close(p))
    IO.print("handoff-close:" ++ d)

# Randomized: rounds of 8 tasks on a pool of 2 for two origins, each with a
# deadline 0-7 ms away and a hold of 0-3 ms, giving back kept or closed.
# Returns, give-ups and newcomers interleave freely; no task may end
# materially past its deadline, and at the end nobody waits and all room
# is back.
type Race is Data:
  Race{late: Nat, got: Nat, over: Nat}

def race.add(a: Race, b: Race) -> Race:
  match a b:
    case Race{l1,g1,+o1} Race{l2,g2,+o2}: Race{Nat.add(l1,l2),Nat.add(g1,g2),Nat.max(o1,o2)}

def race.back(t: Pool.Taken, +keep: Bool, +key: String, +hold: U32, +p: Pool.Pool, +over: Nat) -> IO(Race):
  match t:
    case Pool.Kept{s,+tls}:
      do IO<Race>:
        u : Unit <- IO.sleep(hold)
        v : Unit <- Pool.give(keep,s,tls,key,p)
        return Race{0n,1n,over}
    case Pool.Room{}:
      do IO<Race>:
        u : Unit <- IO.sleep(hold)
        v : Unit <- Pool.give(keep,Tr.Closed{},True{},key,p)
        return Race{0n,1n,over}
    case Pool.Late{}: IO.pure(Race,Race{1n,0n,over})
    case Pool.Shut{}: IO.pure(Race,Race{0n,0n,1000000n})

def race.key(+r: U32) -> String:
  Bool.pick(String,U32.is_eq(U32.mod(U32.div(r,8),2),0),"a","b")

def racer.at(+p: Pool.Pool, +r: U32, +dl: Nat) -> IO(Race):
  do IO<Race>:
    t : Pool.Taken <- Pool.take(8n,p,race.key(r),dl)
    +after : Nat <- IO.now()
    race.back(t,U32.is_eq(U32.mod(U32.div(r,16),3),0),race.key(r),U32.mod(U32.div(r,64),4),p,Nat.sub(after,dl))

def racer(+p: Pool.Pool, +r: U32) -> IO(Race):
  IO.bind(Nat,Race,IO.now(),now => racer.at(p,r,Nat.add(now,U32.to_nat(U32.mod(r,8)))))

def lcg(+x: U32) -> U32:
  U32.add(U32.mul(x,1664525),1013904223)

def race.join(chs: List<&2,Chan(Race)>, acc: Race) -> IO(Race):
  match chs:
    case Nil{}: IO.pure(Race,acc)
    case Con{+c,t}: IO.bind(Race,Race,IO.join(Race,c),r => race.join(t,race.add(acc,r)))

def race.fork(n: Nat, +p: Pool.Pool, +x: U32, chs: List<&2,Chan(Race)>) -> IO(Race):
  match n:
    case 0n: race.join(chs,Race{0n,0n,0n})
    case 1n+k: IO.bind(Chan(Race),Race,IO.fork(Race,racer(p,U32.div(lcg(x),256))),c => race.fork(k,p,lcg(x),Con{c,chs}))

def race.rounds(n: Nat, +p: Pool.Pool, +x: U32, acc: Race) -> IO(Race):
  match n:
    case 0n: IO.pure(Race,acc)
    case 1n+k: IO.bind(Race,Race,race.fork(8n,p,x,[]),r => race.rounds(k,p,lcg(lcg(lcg(x))),race.add(acc,r)))

def race.show(r: Race, c: Pool.Counts) -> String:
  match r c:
    case Race{+l,+g,o} Pool.Counts{w,f,i}:
      "race:" ++ Nat.show(Nat.add(l,g)) ++ ":" ++ Nat.show(l) ++ ":" ++ Nat.show(g) ++ ":" ++ Nat.show(o) ++ ":" ++ Nat.show(w) ++ ":" ++ Nat.show(Nat.add(f,i))

def race(+p: Pool.Pool) -> IO(Unit):
  do IO<Unit>:
    r : Race <- race.rounds(250n,p,7,Race{0n,0n,0n})
    c : Pool.Counts <- Pool.counts(p)
    IO.print(race.show(r,c))

type Mode is Data:
  MPool{}
  MJson{}
  MForm{}
  MStream{}
  MPoolStream{}
  MEvents{}
  MEventsRetry{}
  MPoolEvents{}
  MTimeout{}
  MHead{}
  MSmall{}
  MSmallHead{}
  MSum{}
  MStreamSum{}
  MHeaders{}
  MPost{}
  MDelete{}
  MNoRedirect{}
  MPool10{}
  MPool2{}
  MPool3w{}
  MPoolIdle{}
  MPoolHead{}
  MPoolPost{}
  MConnectTimeout{}
  MReadTimeout{}
  MTotalTimeout{}
  MTimed{}
  MAuth{}
  MStreamRead{}
  MPoolStreamRead{}
  MEventsRead{}
  MPoolEventsRead{}
  MUpload{}
  MPoolUpload{}
  MPoolSaturated{}
  MRetryBudget{}
  MRetryFits{}
  MPoolRetryBudget{}
  MProxyAuth{}
  MUaCustom{}
  MUaNone{}
  MUaSet{}
  MPoolWaiters{}
  MPoolHandoff{}
  MPoolRace{}

def mode.pick(hit: Bool, m: Mode, rest: Mode) -> Mode:
  match hit:
    case True{}: m
    case False{}: rest

def mode.more(+mode: String) -> Mode:
  mode.pick(String.eq(mode,"stream-read"),MStreamRead{},mode.pick(String.eq(mode,"pool-stream-read"),MPoolStreamRead{},mode.pick(String.eq(mode,"events-read"),MEventsRead{},mode.pick(String.eq(mode,"pool-events-read"),MPoolEventsRead{},mode.pick(String.eq(mode,"upload"),MUpload{},mode.pick(String.eq(mode,"pool-upload"),MPoolUpload{},mode.pick(String.eq(mode,"pool-saturated"),MPoolSaturated{},mode.pick(String.eq(mode,"retry-budget"),MRetryBudget{},mode.pick(String.eq(mode,"retry-fits"),MRetryFits{},mode.pick(String.eq(mode,"pool-retry-budget"),MPoolRetryBudget{},mode.pick(String.eq(mode,"proxy-auth"),MProxyAuth{},mode.pick(String.eq(mode,"ua-custom"),MUaCustom{},mode.pick(String.eq(mode,"ua-none"),MUaNone{},mode.pick(String.eq(mode,"ua-set"),MUaSet{},mode.pick(String.eq(mode,"pool-waiters"),MPoolWaiters{},mode.pick(String.eq(mode,"pool-handoff"),MPoolHandoff{},mode.pick(String.eq(mode,"pool-race"),MPoolRace{},MAuth{})))))))))))))))))

def mode.of(+mode: String) -> Mode:
  mode.pick(String.eq(mode,"pool"),MPool{},mode.pick(String.eq(mode,"json"),MJson{},mode.pick(String.eq(mode,"form"),MForm{},mode.pick(String.eq(mode,"stream"),MStream{},mode.pick(String.eq(mode,"pool-stream"),MPoolStream{},mode.pick(String.eq(mode,"events"),MEvents{},mode.pick(String.eq(mode,"events-retry"),MEventsRetry{},mode.pick(String.eq(mode,"pool-events"),MPoolEvents{},mode.pick(String.eq(mode,"timeout"),MTimeout{},mode.pick(String.eq(mode,"head"),MHead{},mode.pick(String.eq(mode,"small"),MSmall{},mode.pick(String.eq(mode,"small-head"),MSmallHead{},mode.pick(String.eq(mode,"sum"),MSum{},mode.pick(String.eq(mode,"stream-sum"),MStreamSum{},mode.pick(String.eq(mode,"headers"),MHeaders{},mode.pick(String.eq(mode,"post"),MPost{},mode.pick(String.eq(mode,"delete"),MDelete{},mode.pick(String.eq(mode,"noredirect"),MNoRedirect{},mode.pick(String.eq(mode,"pool10"),MPool10{},mode.pick(String.eq(mode,"pool2"),MPool2{},mode.pick(String.eq(mode,"pool3w"),MPool3w{},mode.pick(String.eq(mode,"pool-idle"),MPoolIdle{},mode.pick(String.eq(mode,"pool-head"),MPoolHead{},mode.pick(String.eq(mode,"pool-post"),MPoolPost{},mode.pick(String.eq(mode,"connect-timeout"),MConnectTimeout{},mode.pick(String.eq(mode,"read-timeout"),MReadTimeout{},mode.pick(String.eq(mode,"total-timeout"),MTotalTimeout{},mode.pick(String.eq(mode,"timed"),MTimed{},mode.more(mode)))))))))))))))))))))))))))))

def cup() -> J.Json:
  J.JObj{[J.Field{"name",J.JStr{"cup"}}]}

def run(m: Mode, +cfg: C.Config, +url: String) -> IO(Unit):
  match m:
    case MPool{}: Pool.with(Unit,cfg,1,p => pooled(cfg,url,p))
    case MJson{}: IO.bind(C.R(String),Unit,C.send_json(String,cfg,C.post(url,C.json(J.JObj{[J.Field{"name",J.JStr{"cup"}}]})),decode),json_result)
    case MForm{}: IO.bind(C.R(C.Reply),Unit,C.send(cfg,C.post(url,C.form([("q","a b"),("n","2")]))),reply)
    case MStream{}: IO.bind(C.R(C.Head),Unit,C.stream(~tally,cfg,C.get(url)),streamed)
    case MPoolStream{}: Pool.with(Unit,cfg,1,p => IO.bind(C.R(C.Head),Unit,Pool.stream(~tally,p,C.get(url)),streamed))
    case MEvents{}: IO.bind(C.R(C.Ended),Unit,C.events(~event,cfg,C.get(url)),ended)
    case MEventsRetry{}: IO.bind(C.R(C.Ended),Unit,C.events_retry(~event,cfg,C.get(url),1),ended)
    case MPoolEvents{}: Pool.with(Unit,cfg,1,p => IO.bind(C.R(C.Ended),Unit,Pool.events_retry(~event,p,C.get(url),1),ended))
    case MTimeout{}: IO.bind(C.R(C.Reply),Unit,C.send(C.with_timeout(cfg,200),C.get(url)),reply)
    case MHead{}: IO.bind(C.R(C.Reply),Unit,C.send(cfg,C.head(url)),reply)
    case MSmall{}: IO.bind(C.R(C.Reply),Unit,C.send(C.with_max_body(cfg,1024),C.get(url)),reply)
    case MSmallHead{}: IO.bind(C.R(C.Reply),Unit,C.send(C.with_max_head(cfg,256),C.get(url)),reply)
    # a 4 MiB buffered body takes about 2.9 s natively, too close to the
    # 3 s default here; 10 s as for the 2 MiB upload
    case MSum{}: IO.bind(C.R(C.Reply),Unit,C.send(C.with_timeout(cfg,10000),C.get(url)),summed)
    case MStreamSum{}: IO.bind(C.R(C.Head),Unit,C.stream(~piece,cfg,C.get(url)),streamed)
    case MHeaders{}: IO.bind(C.R(C.Reply),Unit,C.send(cfg,C.with(C.post(url,C.text("hi")),[("X-Ok","1"),("Bad Name","x"),("X-Ctl","a\u{1}b"),("Transfer-Encoding ","chunked"),("X:Y","z"),("X-Del","\u{7f}"),("Host","evil"),("X-Tab","a\tb")])),reply)
    case MPost{}: IO.bind(C.R(C.Reply),Unit,C.send(cfg,C.with(C.post(url,C.json(cup())),[("Authorization","secret"),("Cookie","secret"),("Content-Language","en")])),reply)
    case MDelete{}: IO.bind(C.R(C.Reply),Unit,C.send(cfg,C.with(C.method("DELETE",url,C.text("gone")),[("Authorization","secret")])),reply)
    case MNoRedirect{}: IO.bind(C.R(C.Reply),Unit,C.send(C.with_redirects(cfg,0),C.get(url)),reply)
    case MPool10{}: Pool.with(Unit,cfg,1,p => again(10n,p,url))
    case MPool2{}: Pool.with(Unit,cfg,1,p => again(2n,p,url))
    case MPool3w{}: Pool.with(Unit,cfg,2,p => again(3n,p,url))
    case MPoolIdle{}: Pool.with(Unit,C.with_idle(cfg,100),1,p => idle(p,url))
    case MPoolHead{}: Pool.with(Unit,cfg,1,p => pair(p,C.head(url),C.get(url)))
    case MPoolPost{}: Pool.with(Unit,cfg,1,p => pair(p,C.get(url),C.post(url,C.text("x"))))
    case MConnectTimeout{}: timed(C.send(C.with_connect_timeout(cfg,500),C.get(url)))
    case MReadTimeout{}: timed(C.send(C.with_read_timeout(cfg,300),C.get(url)))
    case MTotalTimeout{}: timed(C.send(C.with_read_timeout(C.with_timeout(cfg,800),500),C.get(url)))
    case MTimed{}: timed(C.send(cfg,C.get(url)))
    case MAuth{}: IO.bind(C.R(C.Reply),Unit,C.send(cfg,C.with(C.get(url),[("Authorization","secret"),("Cookie","secret")])),reply)
    case MStreamRead{}: timed.head(C.stream(~quiet,C.with_read_timeout(cfg,300),C.get(url)))
    case MPoolStreamRead{}: Pool.with(Unit,C.with_read_timeout(cfg,300),1,p => timed.head(Pool.stream(~quiet,p,C.get(url))))
    case MEventsRead{}: IO.bind(C.R(C.Ended),Unit,C.events(~event,C.with_read_timeout(cfg,300),C.get(url)),ended)
    case MPoolEventsRead{}: Pool.with(Unit,C.with_read_timeout(cfg,300),1,p => IO.bind(C.R(C.Ended),Unit,Pool.events(~event,p,C.get(url)),ended))
    case MUpload{}: timed(C.send(C.with_read_timeout(C.with_timeout(cfg,10000),300),upload(url)))
    case MPoolUpload{}: Pool.with(Unit,C.with_read_timeout(C.with_timeout(cfg,10000),300),1,p => timed(Pool.send(p,upload(url))))
    case MPoolSaturated{}: Pool.with(Unit,C.with_timeout(cfg,400),1,p => saturated(p,url))
    case MRetryBudget{}: timed(C.send(C.with_retries(C.with_timeout(cfg,800),3,5000),C.get(url)))
    case MRetryFits{}: timed(C.send(C.with_retries(cfg,2,100),C.get(url)))
    case MPoolRetryBudget{}: Pool.with(Unit,C.with_retries(C.with_timeout(cfg,800),3,5000),1,p => timed(Pool.send(p,C.get(url))))
    case MProxyAuth{}: IO.bind(C.R(C.Reply),Unit,C.send(cfg,auth3(url)),reply)
    case MUaCustom{}: IO.bind(C.R(C.Reply),Unit,C.send(cfg,C.with(C.get(url),[("User-Agent","mine/1")])),reply)
    case MUaNone{}: IO.bind(C.R(C.Reply),Unit,C.send(C.without_user_agent(cfg),C.get(url)),reply)
    case MUaSet{}: IO.bind(C.R(C.Reply),Unit,C.send(C.with_user_agent(cfg,"probe/2"),C.get(url)),reply)
    case MPoolWaiters{}: Pool.with(Unit,cfg,1,p => waiters(p,url))
    case MPoolHandoff{}: handoff(cfg)
    case MPoolRace{}: Pool.with(Unit,cfg,2,p => race(p))

def execute(+cfg: C.Config, +url: String, +mode: String) -> IO(Unit):
  run(mode.of(mode),cfg,url)

def prepared(value: Legacy.R(Tr.Policy), url: String, mode: String) -> IO(Unit):
  match value:
    case Fail{why}: IO.print(error(why))
    case Done{policy}: execute(C.with_timeout(C.default(policy),3000),url,mode)

def command(args: List<String>) -> IO(Unit):
  match args:
    case [nfkc,profile,ca,now,url,mode]:
      do IO<Unit>:
        at : Nat <- IO.now()
        normalization : List<&2,U32> <- Io.read_bytes(nfkc)
        tables : List<&2,U32> <- Io.read_bytes(profile)
        pem : List<&2,U32> <- Io.read_bytes(ca)
        prepared(Tr.from_pem(normalization,tables,[pem],Tr.Clock{Number.number(now),at}),url,mode)
    case _: IO.die(Unit,2,"nfkc profile anchor.pem civil-seconds url mode")

def main() -> IO(Unit):
  IO.bind(List<String>,Unit,Io.args(),command)
