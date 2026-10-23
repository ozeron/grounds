import Base
import ../../wire/wire.bend as W
import ../../wire/bend_tls_client.bend as TLS
import ../../crypto/unicode32_prepare.bend as U
import ../../crypto/x509_chain.bend as X
import ../../crypto/pem.bend as PEM
import ../../utf8/utf8.bend as Utf
import ./client.bend as Legacy

# Explicit immutable admission inputs. Clock binds caller-supplied trusted
# civil UTC seconds since 0001-01-01 to an IO.now monotonic millisecond sample.
# Authenticated Unicode assets are decoded into fresh affine arrays per open.
type Clock is Data:
  Clock{civil_seconds: Nat, monotonic_ms: Nat}

type Policy is Data:
  Policy{normalization: List<&2,U32>, profile: List<&2,U32>, anchors: List<&2,List<&2,U32>>, clock: Clock}

type Connection is Type:
  Raw{socket: Socket}
  Bend{connection: TLS.Connection}
  Closed{}

type Ip is Data:
  Ip{bytes: List<&2,U32>}
  NotIp{}

def anchors.done(reversed: List<&2,List<&2,U32>>) -> Legacy.R(List<&2,List<&2,U32>>):
  match reversed:
    case Nil{}: Fail{Legacy.Tls{"empty-anchors"}}
    case values: Done{List.reverse(&2,List<&2,U32>,values)}

def anchor(value: Result<&2,&1,PEM.Error,PEM.Block>, next: List<&2,U32> -> Legacy.R(List<&2,List<&2,U32>>)) -> Legacy.R(List<&2,List<&2,U32>>):
  match value:
    case Done{PEM.Block{PEM.Certificate{},der}}: next(der)
    case _: Fail{Legacy.Tls{"invalid-anchor-pem"}}

def anchors(left: Nat, pems: List<&2,List<&2,U32>>, reversed: List<&2,List<&2,U32>>) -> Legacy.R(List<&2,List<&2,U32>>):
  match left pems:
    case _ Nil{}: anchors.done(reversed)
    case 0n _: Fail{Legacy.Tls{"anchor-limit"}}
    case 1n+p Con{pem,rest}: anchor(PEM.decode(pem),der => anchors(p,rest,Con{der,reversed}))

def prepared(normalization: List<&2,U32>, profile: List<&2,U32>, clock: Clock, value: Legacy.R(List<&2,List<&2,U32>>)) -> Legacy.R(Policy):
  match value:
    case Done{roots}: Done{Policy{normalization,profile,roots,clock}}
    case Fail{error}: Fail{error}

# One certificate per PEM value, 1..16 anchors. No ambient host CA store.
def from_pem(normalization: List<&2,U32>, profile: List<&2,U32>, pems: List<&2,List<&2,U32>>, clock: Clock) -> Legacy.R(Policy):
  prepared(normalization,profile,clock,anchors(16n,pems,[]))

def ipv4_next(valid: Bool, next: Unit -> Ip) -> Ip:
  match valid:
    case True{}: next(Unit{})
    case False{}: NotIp{}

def ipv4(s: String, +part: U32, digit: Bool, reversed: List<&2,U32>, +count: U32) -> Ip:
  match s:
    case SNil{}: Bool.pick(Ip,Bool.and(digit,U32.is_eq(count,3)),Ip{List.reverse(&2,U32,Con{part,reversed})},NotIp{})
    case SCon{Chr{46},rest}: ipv4_next(Bool.and(digit,U32.is_lt(count,3)),u => ipv4(rest,0,False{},Con{part,reversed},U32.inc(count)))
    case SCon{Chr{+c},rest}: ipv4_next(Bool.and(Bool.and(U32.is_ge(c,48),U32.is_le(c,57)),U32.is_le(U32.add(U32.mul(part,10),U32.sub(c,48)),255)),u => ipv4(rest,U32.add(U32.mul(part,10),U32.sub(c,48)),True{},reversed,count))

def identity(ip: Ip, host: String) -> X.Identity:
  match ip:
    case Ip{bytes}: X.Ip{bytes}
    case NotIp{}: X.Dns{Utf.encode(host)}

def tls_error(+reason: String) -> Legacy.Err:
  Bool.pick(Legacy.Err,String.eq(reason,"deadline"),Legacy.Timeout{},Legacy.Tls{reason})

def opened(value: Result<&2,&1,TLS.Error,TLS.Connection>) -> Legacy.R(Connection):
  match value:
    case Done{connection}: Done{Bend{connection}}
    case Fail{TLS.Error{_,reason,_}}: Fail{tls_error(reason)}

def clock_at(clock: Clock, now: Nat) -> Nat:
  match clock:
    case Clock{civil,monotonic}: Nat.add(civil,Nat.div(Nat.sub(now,monotonic),1000n))

def clock_now(clock: Clock) -> IO(Nat):
  IO.bind(Nat,Nat,IO.now(),now => IO.pure(Nat,clock_at(clock,now)))

def connect_tables(value: Maybe<&1,U.Tables>, roots: List<&2,List<&2,U32>>, clock: Clock, expected: X.Identity, deadline: Nat, socket: Socket) -> IO(Legacy.R(Connection)):
  match value:
    case None{}:
      do IO<Legacy.R(Connection)>:
        W.close(socket)
        IO.pure(Legacy.R(Connection),Fail{Legacy.Tls{"invalid-unicode-assets"}})
    case Some{tables}:
      do IO<Legacy.R(Connection)>:
        value : Result<&2,&1,TLS.Error,TLS.Connection> <- TLS.connect(socket,TLS.Config{tables,roots,expected,True{},clock_now(clock),deadline})
        IO.pure(Legacy.R(Connection),opened(value))

def connect(policy: Policy, +host: String, deadline: Nat, socket: Socket) -> IO(Legacy.R(Connection)):
  match policy:
    case Policy{normalization,profile,roots,clock}: connect_tables(U.tables(normalization,profile),roots,clock,identity(ipv4(host,0,False{},[],0),host),deadline,socket)

def RU() -> Type:
  Connection & Result<&1,&1,U32 & String,Unit>

def RP() -> Type:
  Connection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>>

def failed(reason: String) -> U32 & String:
  match reason:
    case "deadline": (60,"deadline")
    case other: (65535,other)

# Only EOF/transport loss before a response can be a stale pooled socket.
# Authentication/protocol failures must remain visible to the caller.
def starts(s: String, prefix: String) -> Bool:
  match s prefix:
    case _ SNil{}: True{}
    case SCon{Chr{x},xs} SCon{Chr{y},ys}: Bool.and(U32.is_eq(x,y),starts(xs,ys))
    case _ _: False{}

def stale(+code: U32, +reason: String) -> Bool:
  match code:
    case 65535: Bool.or(String.eq(reason,"truncated"),starts(reason,"transport:"))
    case _: Bool.not(Bool.or(U32.is_eq(code,60),U32.is_eq(code,110)))

def error(+code: U32, reason: String) -> Legacy.Err:
  match code:
    case 65535: Legacy.Tls{reason}
    case _: Bool.pick(Legacy.Err,Bool.or(U32.is_eq(code,60),U32.is_eq(code,110)),Legacy.Timeout{},Legacy.Closed{})

def raw_sent(pair: Socket & Result<&1,&1,U32 & String,Unit>) -> IO(RU()):
  (socket,result) = pair
  IO.pure(RU(),(Raw{socket},result))

def sent(value: Result<&2,&1,TLS.Error,TLS.Connection>) -> IO(RU()):
  match value:
    case Done{connection}: IO.pure(RU(),(Bend{connection},Done{Unit{}}))
    case Fail{TLS.Error{_,reason,_}}: IO.pure(RU(),(Closed{},Fail{failed(reason)}))

def send(connection: Connection, bytes: List<&2,U32>, +at: Nat) -> IO(RU()):
  match connection:
    case Raw{socket}:
      do IO<RU()>:
        now : Nat <- IO.now()
        pair : Socket & Result<&1,&1,U32 & String,Unit> <- W.wire_send_timeout(socket,bytes,TLS.remaining(at,now))
        raw_sent(pair)
    case Bend{connection}:
      do IO<RU()>:
        value : Result<&2,&1,TLS.Error,TLS.Connection> <- TLS.send(TLS.deadline(connection,at),bytes)
        sent(value)
    case Closed{}: IO.pure(RU(),(Closed{},Fail{(9,"closed")}))

def raw_read(pair: Socket & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>>) -> IO(RP()):
  (socket,result) = pair
  IO.pure(RP(),(Raw{socket},result))

def received(value: Result<&2,&1,TLS.Error,TLS.Received>) -> IO(RP()):
  match value:
    case Done{TLS.Received{connection,bytes}}: IO.pure(RP(),(Bend{connection},Done{Some{bytes}}))
    case Fail{TLS.Error{_,reason,_}}: IO.pure(RP(),(Closed{},Fail{failed(reason)}))

def recv(connection: Connection, +at: Nat) -> IO(RP()):
  match connection:
    case Raw{socket}:
      do IO<RP()>:
        now : Nat <- IO.now()
        pair : Socket & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>> <- W.wire_recv_timeout(socket,65536,TLS.remaining(at,now))
        raw_read(pair)
    case Bend{connection}:
      do IO<RP()>:
        value : Result<&2,&1,TLS.Error,TLS.Received> <- TLS.recv(TLS.deadline(connection,at))
        received(value)
    case Closed{}: IO.pure(RP(),(Closed{},Fail{(9,"closed")}))

def close(connection: Connection) -> IO(Unit):
  match connection:
    case Raw{socket}: W.close(socket)
    case Bend{connection}: TLS.close(connection)
    case Closed{}: IO.pure(Unit,Unit{})
