import Base
import ./bend_tls_client.bend as C
import ./wire.bend as W
import ../crypto/unicode32_prepare.bend as U
import ../crypto/unicode32_prepare_cli.bend as Tables
import ../crypto/x509_chain.bend as A
import ../crypto/bytes.bend as B
import ../crypto/traffic.bend as T
import ../io/io.bend as Io

# Synthetic interop evaluator. The driver consumes caller-supplied authenticated
# Unicode assets/DER anchors. Clock input is civil UTC from the peer harness's
# OS wall clock via argv, not a conversion of the monotonic deadline effect.
def decimal.go(bytes: String, +acc: Nat, valid: Bool) -> Maybe<&2,Nat>:
  match bytes:
    case SNil{}: Bool.pick(Maybe<&2,Nat>,valid,Some{acc},None{})
    case SCon{Chr{+c},rest}: decimal.go(rest,Nat.add(Nat.mul(acc,10n),U32.to_nat(U32.sub(c,48))),Bool.and(valid,Bool.and(U32.is_ge(c,48),U32.is_le(c,57))))

def number(s: String) -> Nat:
  Maybe.default(&2,Nat,decimal.go(s,0n,True{}),0n)

def bytes(s: String, reversed: List<&2,U32>) -> List<&2,U32>:
  match s:
    case SNil{}: List.reverse(&2,U32,reversed)
    case SCon{Chr{c},rest}: bytes(rest,Con{c,reversed})

def error(value: C.Error) -> IO(Unit):
  match value:
    case C.Error{code,reason,_}: IO.print("error:" ++ U32.show(code) ++ ":" ++ reason)

def emit_closed(data: List<&2,U32>, value: Result<&2,&1,C.Error,C.Received>) -> IO(Unit):
  match value:
    case Fail{why}: error(why)
    case Done{C.Received{C.Connection{pipe,+suite,+group,+alpn,closed},Nil{}}}:
      do IO<Unit>:
        C.close(C.Connection{pipe,suite,group,alpn,closed})
        IO.print("ok:" ++ U32.show(suite) ++ ":" ++ U32.show(group) ++ ":" ++ Bool.pick(String,alpn,"true","false") ++ ":" ++ B.hex(data))
    case Done{C.Received{connection,_}}:
      do IO<Unit>:
        C.close(connection)
        IO.print("error:10:expected-close-notify")

def received_data(wait_close: Bool, connection: C.Connection, data: List<&2,U32>) -> IO(Unit):
  match wait_close:
    case True{}: IO.bind(Result<&2,&1,C.Error,C.Received>,Unit,C.recv(connection),value => emit_closed(data,value))
    case False{}:
      match connection:
        case C.Connection{pipe,+suite,+group,+alpn,closed}:
          do IO<Unit>:
            C.close(C.Connection{pipe,suite,group,alpn,closed})
            IO.print("ok:" ++ U32.show(suite) ++ ":" ++ U32.show(group) ++ ":" ++ Bool.pick(String,alpn,"true","false") ++ ":" ++ B.hex(data))

def received(mode: String, value: Result<&2,&1,C.Error,C.Received>) -> IO(Unit):
  match value:
    case Fail{why}: error(why)
    case Done{C.Received{connection,data}}: received_data(String.eq(mode,"close"),connection,data)

def sent(mode: String, value: Result<&2,&1,C.Error,C.Connection>) -> IO(Unit):
  match value:
    case Fail{why}: error(why)
    case Done{connection}: IO.bind(Result<&2,&1,C.Error,C.Received>,Unit,C.recv(connection),value => received(mode,value))

def bulk(left: Nat, out: List<&2,U32>) -> List<&2,U32>:
  match left:
    case 0n: out
    case 1n+p: bulk(p,Con{112,out})

def ping_bytes(mode: String) -> List<&2,U32>:
  match mode:
    case "bulk": bulk(40000n,[])
    case _: [112,105,110,103]

def send_ping(+mode: String, value: Result<&2,&1,C.Error,C.Connection>) -> IO(Unit):
  match value:
    case Fail{why}: error(why)
    case Done{connection}: IO.bind(Result<&2,&1,C.Error,C.Connection>,Unit,C.send(connection,ping_bytes(mode)),value => sent(mode,value))

def connect_success(update: Bool, mode: String, connection: C.Connection) -> IO(Unit):
  match update:
    case True{}: IO.bind(Result<&2,&1,C.Error,C.Connection>,Unit,C.key_update(connection,True{}),value => send_ping(mode,value))
    case False{}: send_ping(mode,Done{connection})

def connected(value: Result<&2,&1,C.Error,C.Connection>, +mode: String) -> IO(Unit):
  match value:
    case Fail{why}: error(why)
    case Done{connection}: connect_success(String.eq(mode,"update"),mode,connection)

def socket_connected(tables: U.Tables, anchor: List<&2,U32>, identity: String, now: Nat, +mode: String, at: Nat, result: Result<&1,&1,U32 & String,Socket>) -> IO(Unit):
  match result:
    case Fail{(_,why)}: IO.print("connect-error:" ++ why)
    case Done{socket}:
      expected = Bool.pick(A.Identity,String.eq(mode,"ip"),A.Ip{[127,0,0,1]},A.Dns{bytes(identity,[])})
      span = Bool.pick(Nat,String.eq(mode,"timeout"),200n,15000n)
      do IO<Unit>:
        result : Result<&2,&1,C.Error,C.Connection> <- C.connect(socket,C.Config{tables,[anchor],expected,True{},IO.pure(Nat,now),Nat.add(at,span)})
        connected(result,mode)

def run(tables: U.Tables, anchor: List<&2,U32>, identity: String, port: U32, now: Nat, mode: String) -> IO(Unit):
  do IO<Unit>:
    at : Nat <- IO.now()
    result : Result<&1,&1,U32 & String,Socket> <- W.wire_connect_timeout("127.0.0.1",port,2000)
    socket_connected(tables,anchor,identity,now,mode,at,result)

def loaded(value: Maybe<&1,U.Tables>, anchor: List<&2,U32>, identity: String, port: U32, now: Nat, mode: String) -> IO(Unit):
  match value:
    case None{}: IO.die(Unit,2,"invalid unicode assets")
    case Some{tables}: run(tables,anchor,identity,port,now,mode)

def command(args: List<String>) -> IO(Unit):
  match args:
    case [nfkc,profile,anchor,identity,port,now,mode]:
      do IO<Unit>:
        tables : Maybe<&1,U.Tables> <- Tables.read_tables(nfkc,profile)
        anchor : List<&2,U32> <- Io.read_bytes(anchor)
        loaded(tables,anchor,identity,U32.from_nat(number(port)),number(now),mode)
    case _: IO.die(Unit,2,"run nfkc prepare anchor identity port civil-seconds mode")

def reserved(pair: T.WriteKey & Bool) -> IO(Unit):
  (_,required) = pair
  IO.print(Bool.pick(String,required,"true","false"))

def diagnostics() -> IO(Unit):
  do IO<Unit>:
    reserved(C.reserve_write(T.WriteKey{T.AesReady{[],[],[],T.Counter{0,16777214}},T.Generation{0,0}}))
    reserved(C.reserve_write(T.WriteKey{T.AesReady{[],[],[],T.Counter{0,16777215}},T.Generation{0,0}}))
    reserved(C.reserve_write(T.WriteKey{T.ChachaReady{[],[],[],T.Counter{4294967295,4294967293}},T.Generation{0,0}}))
    reserved(C.reserve_write(T.WriteKey{T.ChachaReady{[],[],[],T.Counter{4294967295,4294967294}},T.Generation{0,0}}))
    IO.print(Bool.pick(String,C.identity_valid(A.Dns{bytes("localhost",[])}),"true","false"))
    IO.print(Bool.pick(String,C.identity_valid(A.Dns{bytes("127.0.0.1",[])}),"true","false"))
    IO.print(Bool.pick(String,C.identity_valid(A.Dns{[]}),"true","false"))
    IO.print(Bool.pick(String,C.identity_valid(A.Dns{[97,0,98]}),"true","false"))
    IO.print(Bool.pick(String,C.identity_valid(A.Ip{[127,0,0,1]}),"true","false"))
    IO.print(Bool.pick(String,C.identity_valid(A.Ip{[127,0,0]}),"true","false"))

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case ["diagnostics"]: diagnostics()
    case Con{"run",rest}: command(rest)
    case _: IO.die(Unit,2,"expected run")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- Io.args()
    dispatch(args)
