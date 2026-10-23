import Base
import ../../wire/wire.bend as W
import ../../wire/bend_tls_server.bend as TLS
import ../../wire/bend_tls_client.bend as T
import ../../crypto/traffic.bend as Traffic
import ../../wire/tls_handshake_stream.bend as HS

# One owner throughout HTTP parsing, keep-alive and streamed writes. Closed is
# the successor of a fatal TLS operation (TLS has already closed its socket).
type Connection is Type:
  Raw{socket: Socket}
  Bend{connection: TLS.Connection}
  Closed{}

def Sent() -> Type:
  Connection & Result<&1, &1, U32 & String, Unit>

def Read() -> Type:
  Connection & Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>

def sent(value: Result<&2,&1,T.Error,TLS.Connection>) -> IO(Sent()):
  match value:
    case Done{connection}: IO.pure(Sent(), (Bend{connection}, Done{Unit{}}))
    case Fail{T.Error{code,reason,_}}: IO.pure(Sent(), (Closed{}, Fail{(code,reason)}))

def raw_sent(pair: Socket & Result<&1,&1,U32 & String,Unit>) -> IO(Sent()):
  (socket,result) = pair
  IO.pure(Sent(), (Raw{socket},result))

def send(connection: Connection, bytes: List<&2,U32>, +ms: U32) -> IO(Sent()):
  match connection:
    case Raw{socket}: IO.bind(Socket & Result<&1,&1,U32 & String,Unit>,Sent(),W.wire_send_timeout(socket,bytes,ms),raw_sent)
    case Bend{connection}:
      do IO<Sent()>:
        now : Nat <- IO.now()
        value : Result<&2,&1,T.Error,TLS.Connection> <- TLS.send(TLS.deadline(connection,Nat.add(now,U32.to_nat(ms))),bytes)
        sent(value)
    case Closed{}: IO.pure(Sent(), (Closed{},Fail{(9,"closed transport")}))

def raw_read(pair: Socket & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>>) -> IO(Read()):
  (socket,result) = pair
  IO.pure(Read(), (Raw{socket},result))

# OS readiness only, without consuming any ciphertext. An idle poll must not
# expire the affine TLS receive owner or split/discard an incomplete record.
def http_readable(socket: Socket, ms: U32) -> IO(Socket & Result<&1,&1,U32 & String,Bool>):
  import "./effs/readable.c"
  import "./effs/readable.js"

def received(value: Result<&2,&1,T.Error,TLS.Received>) -> IO(Read()):
  match value:
    case Done{TLS.Received{connection,bytes}}: IO.pure(Read(), (Bend{connection},Done{Some{bytes}}))
    case Fail{T.Error{code,reason,_}}: IO.pure(Read(), (Closed{},Fail{(code,reason)}))

def readable.result(result: Result<&1,&1,U32 & String,Bool>, connection: TLS.Connection) -> IO(Read()):
  match result:
    case Done{False{}}: IO.pure(Read(), (Bend{connection},Done{None{}}))
    case Done{True{}}: IO.bind(Result<&2,&1,T.Error,TLS.Received>,Read(),TLS.recv(connection),received)
    case Fail{error}:
      do IO<Read()>:
        TLS.close(connection)
        IO.pure(Read(), (Closed{},Fail{error}))

def readable(pair: Socket & Result<&1,&1,U32 & String,Bool>, read: Maybe<&1,Traffic.ReadKey>, write: Maybe<&1,Traffic.WriteKey>, decoder: HS.Decoder, +at: Nat, suite: U32, group: U32, alpn: Bool, closed: Bool, sni: List<&2,U32>) -> IO(Read()):
  (socket,result) = pair
  readable.result(result,TLS.Connection{T.Connection{T.Pipe{socket,read,write,decoder,at},suite,group,alpn,closed},sni})

def recv(connection: Connection, max: U32, +ms: U32, +record_ms: U32) -> IO(Read()):
  match connection:
    case Raw{socket}: IO.bind(Socket & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>>,Read(),W.wire_recv_timeout(socket,max,ms),raw_read)
    case Bend{TLS.Connection{T.Connection{T.Pipe{socket,read,write,decoder,_},suite,group,alpn,closed},sni}}:
      do IO<Read()>:
        now : Nat <- IO.now()
        pair : Socket & Result<&1,&1,U32 & String,Bool> <- http_readable(socket,ms)
        readable(pair,read,write,decoder,Nat.add(now,U32.to_nat(record_ms)),suite,group,alpn,closed,sni)
    case Closed{}: IO.pure(Read(), (Closed{},Fail{(9,"closed transport")}))

def close(connection: Connection) -> IO(Unit):
  match connection:
    case Raw{socket}: W.wire_close(socket)
    case Bend{connection}: TLS.close(connection)
    case Closed{}: IO.pure(Unit,Unit{})
