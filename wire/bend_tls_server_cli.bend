import Base
import ./bend_tls_server.bend as S
import ./bend_tls_client.bend as Transport
import ./bend_tls_client_cli.bend as ClientCLI
import ./tls_server_handshake.bend as N
import ../crypto/pem.bend as PEM
import ../crypto/bytes.bend as B
import ../io/io.bend as Io
import ./wire.bend as W

# Bounded synthetic evaluator: fresh credential import for every connection.
# The listener remains alive across failure batches for descriptor checks.
def error(value: Transport.Error) -> IO(Unit):
  match value:
    case Transport.Error{code,reason,_}: IO.print("error:" ++ U32.show(code) ++ ":" ++ reason)

def echoed(value: Result<&2,&1,Transport.Error,S.Connection>, next: S.Connection -> IO(Unit)) -> IO(Unit):
  match value:
    case Fail{why}: error(why)
    case Done{connection}: next(connection)

def echo_received(+left: Nat, +mode: String, value: Result<&2,&1,Transport.Error,S.Received>, next: Nat -> S.Connection -> IO(Unit)) -> IO(Unit):
  match value:
    case Fail{why}: error(why)
    case Done{S.Received{connection,Nil{}}}: S.close(connection)
    case Done{S.Received{connection,+bytes}}:
      IO.bind(Result<&2,&1,Transport.Error,S.Connection>,Unit,S.send(connection,bytes),value => echoed(value,c => next(Nat.sub(left,B.length(bytes)),c)))

def echo_loop(+fuel: Nat, +left: Nat, +mode: String, connection: S.Connection) -> IO(Unit):
  match fuel left:
    case _ 0n: S.close(connection)
    case 0n _: S.close(connection)
    case 1n+p left:
      IO.bind(Result<&2,&1,Transport.Error,S.Received>,Unit,S.recv(connection),value => echo_received(left,mode,value,n => c => echo_loop(p,n,mode,c)))

def application(+mode: String, value: Result<&2,&1,Transport.Error,S.Connection>) -> IO(Unit):
  match value:
    case Fail{why}: error(why)
    case Done{connection}: echo_loop(1048576n,Bool.pick(Nat,String.eq(mode,"bulk"),40000n,4n),mode,connection)

def accepted_mode(+mode: String, connection: S.Connection) -> IO(Unit):
  match mode:
    case "update": IO.bind(Result<&2,&1,Transport.Error,S.Connection>,Unit,S.key_update(connection,True{}),value => application(mode,value))
    case _: application(mode,Done{connection})

def accepted(+mode: String, value: Result<&2,&1,Transport.Error,S.Connection>) -> IO(Unit):
  match value:
    case Fail{why}: error(why)
    case Done{S.Connection{Transport.Connection{pipe,+suite,+group,+alpn,closed},+sni}}:
      do IO<Unit>:
        IO.print("accepted:" ++ U32.show(suite) ++ ":" ++ U32.show(group) ++ ":" ++ Bool.pick(String,alpn,"true","false") ++ ":" ++ B.hex(sni))
        accepted_mode(mode,S.Connection{Transport.Connection{pipe,suite,group,alpn,closed},sni})

def imported(socket: Socket, +mode: String, value: Result<&2,&1,PEM.Error,S.Config>) -> IO(Unit):
  match value:
    case Fail{_}:
      do IO<Unit>:
        Socket.close(socket)
        IO.print("import-error")
    case Done{config}:
      IO.bind(Result<&2,&1,Transport.Error,S.Connection>,Unit,S.accept(socket,config),value => accepted(mode,value))

def socket_accepted(+leaf: List<&2,U32>, +key: List<&2,U32>, +group: U32, +suite: U32, +mode: String, value: Result<&1,&1,U32 & String,Socket>) -> IO(Unit):
  match value:
    case Fail{(_,why)}: IO.print("accept-error:" ++ why)
    case Done{socket}:
      do IO<Unit>:
        at : Nat <- IO.now()
        imported(socket,mode,S.from_pem([leaf],key,N.Policy{[suite],[group],True{}},Nat.add(at,Bool.pick(Nat,String.eq(mode,"timeout"),200n,15000n))))

def serve_pair(+leaf: List<&2,U32>, +key: List<&2,U32>, +group: U32, +suite: U32, +mode: String, pair: Listener & Result<&1,&1,U32 & String,Socket>, next: Listener -> IO(Unit)) -> IO(Unit):
  (listener,result) = pair
  do IO<Unit>:
    socket_accepted(leaf,key,group,suite,mode,result)
    IO.print("handled")
    next(listener)

def serve(+count: Nat, listener: Listener, +leaf: List<&2,U32>, +key: List<&2,U32>, +group: U32, +suite: U32, +mode: String) -> IO(Unit):
  match count:
    case 0n: Listener.close(listener)
    case 1n+p:
      IO.bind(Listener & Result<&1,&1,U32 & String,Socket>,Unit,W.accept(listener),pair => serve_pair(leaf,key,group,suite,mode,pair,l => serve(p,l,leaf,key,group,suite,mode)))

def listen(+leaf: List<&2,U32>, +key: List<&2,U32>, +port: U32, +group: U32, +suite: U32, +mode: String, +count: Nat) -> IO(Unit):
  do IO<Unit>:
    listener : Listener <- IO.try(Listener,TCP.listen("127.0.0.1",port))
    IO.print("ready")
    serve(count,listener,leaf,key,group,suite,mode)

def command(args: List<String>) -> IO(Unit):
  match args:
    case [cert,key,port,group,suite,mode,count]:
      do IO<Unit>:
        cert_bytes : List<&2,U32> <- Io.read_bytes(cert)
        key_bytes : List<&2,U32> <- Io.read_bytes(key)
        listen(cert_bytes,key_bytes,U32.from_nat(ClientCLI.number(port)),U32.from_nat(ClientCLI.number(group)),U32.from_nat(ClientCLI.number(suite)),mode,ClientCLI.number(count))
    case _: IO.die(Unit,2,"cert.pem key.pem port group suite mode connections")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- Io.args()
    command(args)
