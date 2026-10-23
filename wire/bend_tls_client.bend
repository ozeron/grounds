import Base
import ./wire.bend as W
import ./tls_client.bend as M
import ./tls_transcript.bend as X
import ./tls_handshake_codec.bend as C
import ./tls_handshake_stream.bend as HS
import ./tls_key_share.bend as K
import ./tls_record.bend as R
import ../crypto/traffic.bend as T
import ../crypto/bytes.bend as B
import ../crypto/x509_chain.bend as A
import ../crypto/unicode32_prepare.bend as U

# OS byte TCP/RNG only; all TLS protocol/cryptography is Bend. Synthetic keys.
# now is caller-provided wall-clock IO in civil UTC seconds since 0001-01-01;
# deadline is absolute IO.now milliseconds. A connected socket is consumed on
# EVERY result. Failed operations close it and return no connection successor.
type Config is Type:
  Config{tables: U.Tables, anchors: List<&2,List<&2,U32>>, identity: A.Identity, alpn: Bool, now: IO(Nat), deadline: Nat}

type Error is Data:
  Error{alert: U32, reason: String, notify: Bool}

type Pipe is Type:
  Pipe{socket: Socket, read: Maybe<&1,T.ReadKey>, write: Maybe<&1,T.WriteKey>, decoder: HS.Decoder, deadline: Nat}

type Connection is Type:
  Connection{pipe: Pipe, suite: U32, group: U32, alpn: Bool, closed: Bool}

type HandshakeWork is Type:
  Expect{pipe: Pipe, state: M.State}
  Process{pipe: Pipe, state: M.State, messages: List<&2,List<&2,U32>>}
  Act{pipe: Pipe, action: M.Action, rest: List<&2,List<&2,U32>>}
  Shook{result: Result<&2,&1,Error,Connection>}

type Boundary is Type:
  Boundary{pipe: Pipe, valid: Bool}

type Received is Type:
  Received{connection: Connection, bytes: List<&2,U32>}

def remaining(+deadline: Nat, now: Nat) -> U32:
  U32.from_nat(Nat.min(Nat.sub(deadline,now),4294967295n))

def transport_error(code: U32, reason: String) -> Error:
  match code:
    case 60: Error{80,"deadline",True{}}
    case 110: Error{80,"deadline",True{}}
    case _: Error{80,"transport:" ++ reason,False{}}

def read_got(socket: Socket, result: Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>>, left: Nat, reversed: List<&2,U32>, deadline: Nat, next: Socket -> Nat -> List<&2,U32> -> IO(Socket & Result<&2,&2,Error,List<&2,U32>>)) -> IO(Socket & Result<&2,&2,Error,List<&2,U32>>):
  match result:
    case Fail{(code,reason)}: IO.pure(Socket & Result<&2,&2,Error,List<&2,U32>>,(socket,Fail{transport_error(code,reason)}))
    case Done{None{}}: IO.pure(Socket & Result<&2,&2,Error,List<&2,U32>>,(socket,Fail{Error{80,"deadline",True{}}}))
    case Done{Some{Nil{}}}: IO.pure(Socket & Result<&2,&2,Error,List<&2,U32>>,(socket,Fail{Error{50,"truncated",True{}}}))
    case Done{Some{+bytes}}: next(socket,Nat.sub(left,B.length(bytes)),List.reverse.go(&2,U32,bytes,reversed))

def read_pair(pair: Socket & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>>, left: Nat, reversed: List<&2,U32>, deadline: Nat, next: Socket -> Nat -> List<&2,U32> -> IO(Socket & Result<&2,&2,Error,List<&2,U32>>)) -> IO(Socket & Result<&2,&2,Error,List<&2,U32>>):
  (socket,result) = pair
  read_got(socket,result,left,reversed,deadline,next)

def read_ms(socket: Socket, +left: Nat, reversed: List<&2,U32>, deadline: Nat, ms: U32, next: Socket -> Nat -> List<&2,U32> -> IO(Socket & Result<&2,&2,Error,List<&2,U32>>)) -> IO(Socket & Result<&2,&2,Error,List<&2,U32>>):
  match ms:
    case 0: IO.pure(Socket & Result<&2,&2,Error,List<&2,U32>>,(socket,Fail{Error{80,"deadline",True{}}}))
    case ms:
      do IO<Socket & Result<&2,&2,Error,List<&2,U32>>>:
        pair : Socket & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>> <- W.wire_recv_timeout(socket,U32.from_nat(left),ms)
        read_pair(pair,left,reversed,deadline,next)

def read_wait(socket: Socket, left: Nat, reversed: List<&2,U32>, +deadline: Nat, now: Nat, next: Socket -> Nat -> List<&2,U32> -> IO(Socket & Result<&2,&2,Error,List<&2,U32>>)) -> IO(Socket & Result<&2,&2,Error,List<&2,U32>>):
  read_ms(socket,left,reversed,deadline,remaining(deadline,now),next)

def read_loop(fuel: Nat, socket: Socket, left: Nat, reversed: List<&2,U32>, +deadline: Nat) -> IO(Socket & Result<&2,&2,Error,List<&2,U32>>):
  match fuel left:
    case _ 0n: IO.pure(Socket & Result<&2,&2,Error,List<&2,U32>>,(socket,Done{List.reverse(&2,U32,reversed)}))
    case 0n _: IO.pure(Socket & Result<&2,&2,Error,List<&2,U32>>,(socket,Fail{Error{80,"read-budget",True{}}}))
    case 1n+p count:
      do IO<Socket & Result<&2,&2,Error,List<&2,U32>>>:
        now : Nat <- IO.now()
        read_wait(socket,count,reversed,deadline,now,sk => count => rev => read_loop(p,sk,count,rev,deadline))

def read_exact(socket: Socket, +left: Nat, reversed: List<&2,U32>, deadline: Nat) -> IO(Socket & Result<&2,&2,Error,List<&2,U32>>):
  read_loop(Nat.add(left,1n),socket,left,reversed,deadline)

def plain(+kind: U32, +bytes: List<&2,U32>) -> List<&2,U32>:
  B.append([kind,3,3],C.vector16(bytes))

def protected(error: R.Error) -> Error:
  match error:
    case R.Overflow{}: Error{22,"record-overflow",True{}}
    case R.Crypto{T.Authentication{}}: Error{20,"bad-record-mac",True{}}
    case R.Crypto{_}: Error{80,"record-key",True{}}
    case R.Unexpected{}: Error{10,"record-type",True{}}
    case _: Error{50,"record-encoding",True{}}

def sealed(pipe: Pipe, result: Result<&2,&2,R.Error,List<&2,U32>>) -> Pipe & Result<&2,&2,Error,List<&2,U32>>:
  match result:
    case Fail{why}: (pipe,Fail{protected(why)})
    case Done{bytes}: (pipe,Done{bytes})

def seal_pair(socket: Socket, read: Maybe<&1,T.ReadKey>, decoder: HS.Decoder, deadline: Nat, pair: T.WriteKey & Result<&2,&2,R.Error,List<&2,U32>>) -> Pipe & Result<&2,&2,Error,List<&2,U32>>:
  (write,result) = pair
  sealed(Pipe{socket,read,Some{write},decoder,deadline},result)

def encode(pipe: Pipe, kind: U32, bytes: List<&2,U32>) -> Pipe & Result<&2,&2,Error,List<&2,U32>>:
  match pipe:
    case Pipe{socket,read,None{},decoder,deadline}: (Pipe{socket,read,None{},decoder,deadline},Done{plain(kind,bytes)})
    case Pipe{socket,read,Some{write},decoder,deadline}:
      seal_pair(socket,read,decoder,deadline,R.seal(write,kind,0n,bytes))

def sent(pipe: Pipe, result: Result<&1,&1,U32 & String,Unit>) -> Pipe & Result<&2,&2,Error,Unit>:
  match result:
    case Done{Unit{}}: (pipe,Done{Unit{}})
    case Fail{(code,reason)}: (pipe,Fail{transport_error(code,reason)})

def send_pair(pair: Socket & Result<&1,&1,U32 & String,Unit>, read: Maybe<&1,T.ReadKey>, write: Maybe<&1,T.WriteKey>, decoder: HS.Decoder, deadline: Nat) -> IO(Pipe & Result<&2,&2,Error,Unit>):
  (socket,result) = pair
  IO.pure(Pipe & Result<&2,&2,Error,Unit>,sent(Pipe{socket,read,write,decoder,deadline},result))

def transmit_ms(socket: Socket, read: Maybe<&1,T.ReadKey>, write: Maybe<&1,T.WriteKey>, decoder: HS.Decoder, deadline: Nat, bytes: List<&2,U32>, ms: U32) -> IO(Pipe & Result<&2,&2,Error,Unit>):
  match ms:
    case 0: IO.pure(Pipe & Result<&2,&2,Error,Unit>,(Pipe{socket,read,write,decoder,deadline},Fail{Error{80,"deadline",True{}}}))
    case ms:
      do IO<Pipe & Result<&2,&2,Error,Unit>>:
        pair : Socket & Result<&1,&1,U32 & String,Unit> <- W.wire_send_timeout(socket,bytes,ms)
        send_pair(pair,read,write,decoder,deadline)

def transmit_wait(pipe: Pipe, bytes: List<&2,U32>, now: Nat) -> IO(Pipe & Result<&2,&2,Error,Unit>):
  match pipe:
    case Pipe{socket,read,write,decoder,+deadline}: transmit_ms(socket,read,write,decoder,deadline,bytes,remaining(deadline,now))

def transmit_encoded(pair: Pipe & Result<&2,&2,Error,List<&2,U32>>) -> IO(Pipe & Result<&2,&2,Error,Unit>):
  (pipe,result) = pair
  match result:
    case Fail{error}: IO.pure(Pipe & Result<&2,&2,Error,Unit>,(pipe,Fail{error}))
    case Done{bytes}:
      do IO<Pipe & Result<&2,&2,Error,Unit>>:
        now : Nat <- IO.now()
        transmit_wait(pipe,bytes,now)

def transmit(pipe: Pipe, kind: U32, bytes: List<&2,U32>) -> IO(Pipe & Result<&2,&2,Error,Unit>):
  transmit_encoded(encode(pipe,kind,bytes))

# wire_send_timeout itself loops over partial OS writes. Splitting here bounds
# each TLS record; exact-sized reads leave coalesced records in the socket.
# Reserve an old-key record for KeyUpdate before a sending cap/nonce limit.
def reserve_epoch(epoch: T.Epoch, generation: T.Generation) -> T.WriteKey & Bool:
  match epoch:
    case T.AesReady{secret,key,iv,T.Counter{+high,+low}}:
      (T.WriteKey{T.AesReady{secret,key,iv,T.Counter{high,low}},generation},Bool.or(U32.is_gt(high,0),U32.is_ge(low,16777215)))
    case T.ChachaReady{secret,key,iv,T.Counter{+high,+low}}:
      (T.WriteKey{T.ChachaReady{secret,key,iv,T.Counter{high,low}},generation},Bool.and(U32.is_eq(high,4294967295),U32.is_ge(low,4294967294)))
    case epoch: (T.WriteKey{epoch,generation},False{})

def reserve_write(write: T.WriteKey) -> T.WriteKey & Bool:
  match write:
    case T.WriteKey{epoch,generation}: reserve_epoch(epoch,generation)

def reserve_pipe_pair(socket: Socket, read: Maybe<&1,T.ReadKey>, decoder: HS.Decoder, deadline: Nat, pair: T.WriteKey & Bool) -> Pipe & Bool:
  (write,required) = pair
  (Pipe{socket,read,Some{write},decoder,deadline},required)

def reserve_pipe(pipe: Pipe) -> Pipe & Bool:
  match pipe:
    case Pipe{socket,read,Some{write},decoder,deadline}: reserve_pipe_pair(socket,read,decoder,deadline,reserve_write(write))
    case pipe: (pipe,False{})

def rekey_pipe_keys(socket: Socket, read: Maybe<&1,T.ReadKey>, decoder: HS.Decoder, deadline: Nat, pair: T.WriteKey & Result<&2,&2,T.Error,Unit>) -> Pipe & Result<&2,&2,Error,Unit>:
  (write,result) = pair
  match result:
    case Done{Unit{}}: (Pipe{socket,read,Some{write},decoder,deadline},Done{Unit{}})
    case Fail{_}: (Pipe{socket,read,Some{T.close_write(write)},decoder,deadline},Fail{Error{80,"key-update-limit",True{}}})

def rekey_pipe_sent(pair: Pipe & Result<&2,&2,Error,Unit>) -> IO(Pipe & Result<&2,&2,Error,Unit>):
  (pipe,result) = pair
  match pipe result:
    case Pipe{socket,read,Some{write},decoder,deadline} Done{Unit{}}:
      IO.pure(Pipe & Result<&2,&2,Error,Unit>,rekey_pipe_keys(socket,read,decoder,deadline,T.rekey_write(write)))
    case pipe result: IO.pure(Pipe & Result<&2,&2,Error,Unit>,(pipe,result))

def prepare_reserved(pair: Pipe & Bool) -> IO(Pipe & Result<&2,&2,Error,Unit>):
  (pipe,required) = pair
  match required:
    case False{}: IO.pure(Pipe & Result<&2,&2,Error,Unit>,(pipe,Done{Unit{}}))
    case True{}: IO.bind(Pipe & Result<&2,&2,Error,Unit>,Pipe & Result<&2,&2,Error,Unit>,transmit(pipe,22,[24,0,0,1,0]),rekey_pipe_sent)

def prepare_record(pipe: Pipe, kind: U32) -> IO(Pipe & Result<&2,&2,Error,Unit>):
  match kind:
    case 23: prepare_reserved(reserve_pipe(pipe))
    case _: IO.pure(Pipe & Result<&2,&2,Error,Unit>,(pipe,Done{Unit{}}))

def write_next(pipe: Pipe, result: Result<&2,&2,Error,Unit>, kind: U32, rest: List<&2,U32>, next: Pipe -> List<&2,U32> -> IO(Pipe & Result<&2,&2,Error,Unit>)) -> IO(Pipe & Result<&2,&2,Error,Unit>):
  match result:
    case Fail{error}: IO.pure(Pipe & Result<&2,&2,Error,Unit>,(pipe,Fail{error}))
    case Done{Unit{}}: next(pipe,rest)

def write_pair(pair: Pipe & Result<&2,&2,Error,Unit>, kind: U32, rest: List<&2,U32>, next: Pipe -> List<&2,U32> -> IO(Pipe & Result<&2,&2,Error,Unit>)) -> IO(Pipe & Result<&2,&2,Error,Unit>):
  (pipe,result) = pair
  write_next(pipe,result,kind,rest,next)

def write_prepared(pair: Pipe & Result<&2,&2,Error,Unit>, +kind: U32, first: List<&2,U32>, rest: List<&2,U32>, next: Pipe -> List<&2,U32> -> IO(Pipe & Result<&2,&2,Error,Unit>)) -> IO(Pipe & Result<&2,&2,Error,Unit>):
  (pipe,result) = pair
  match result:
    case Fail{error}: IO.pure(Pipe & Result<&2,&2,Error,Unit>,(pipe,Fail{error}))
    case Done{Unit{}}:
      do IO<Pipe & Result<&2,&2,Error,Unit>>:
        pair : Pipe & Result<&2,&2,Error,Unit> <- transmit(pipe,kind,first)
        write_pair(pair,kind,rest,next)

def write_split(pipe: Pipe, +kind: U32, parts: R.Split, next: Pipe -> List<&2,U32> -> IO(Pipe & Result<&2,&2,Error,Unit>)) -> IO(Pipe & Result<&2,&2,Error,Unit>):
  match parts:
    case R.Split{first,rest}:
      do IO<Pipe & Result<&2,&2,Error,Unit>>:
        pair : Pipe & Result<&2,&2,Error,Unit> <- prepare_record(pipe,kind)
        write_prepared(pair,kind,first,rest,next)

def write_loop(fuel: Nat, pipe: Pipe, +kind: U32, bytes: List<&2,U32>) -> IO(Pipe & Result<&2,&2,Error,Unit>):
  match fuel bytes:
    case _ Nil{}: IO.pure(Pipe & Result<&2,&2,Error,Unit>,(pipe,Done{Unit{}}))
    case 0n _: IO.pure(Pipe & Result<&2,&2,Error,Unit>,(pipe,Fail{Error{80,"write-budget",True{}}}))
    case 1n+p bytes: write_split(pipe,kind,R.split(16384n,bytes,[]),pipe => tail => write_loop(p,pipe,kind,tail))

def write_records(pipe: Pipe, kind: U32, +bytes: List<&2,U32>) -> IO(Pipe & Result<&2,&2,Error,Unit>):
  write_loop(Nat.add(Nat.div(B.length(bytes),16384n),1n),pipe,kind,bytes)

def shutdown(pipe: Pipe) -> IO(Unit):
  match pipe:
    case Pipe{socket,_,_,_,_}: Socket.close(socket)

def abort_sent(pair: Pipe & Result<&2,&2,Error,Unit>) -> IO(Unit):
  (pipe,_) = pair
  shutdown(pipe)

def abort(pipe: Pipe, error: Error) -> IO(Unit):
  match error:
    case Error{code,_,True{}}:
      # A fatal alert is best effort, bounded by the caller's same deadline.
      IO.bind(Pipe & Result<&2,&2,Error,Unit>,Unit,transmit(pipe,21,[2,code]),abort_sent)
    case _: shutdown(pipe)

def failed(pipe: Pipe, +error: Error) -> IO(Result<&2,&1,Error,Connection>):
  do IO<Result<&2,&1,Error,Connection>>:
    abort(pipe,error)
    IO.pure(Result<&2,&1,Error,Connection>,Fail{error})

def opened(pipe: Pipe, result: Result<&2,&2,R.Error,R.Record>) -> Pipe & Result<&2,&2,Error,R.Record>:
  match result:
    case Fail{why}: (pipe,Fail{protected(why)})
    case Done{record}: (pipe,Done{record})

def open_pair(socket: Socket, write: Maybe<&1,T.WriteKey>, decoder: HS.Decoder, deadline: Nat, pair: T.ReadKey & Result<&2,&2,R.Error,R.Record>) -> Pipe & Result<&2,&2,Error,R.Record>:
  (read,result) = pair
  opened(Pipe{socket,Some{read},write,decoder,deadline},result)

def body(pipe: Pipe, kind: U32, header: List<&2,U32>, bytes: List<&2,U32>) -> Pipe & Result<&2,&2,Error,R.Record>:
  match pipe kind:
    case Pipe{socket,read,write,decoder,deadline} 20:
      (Pipe{socket,read,write,decoder,deadline},Done{R.Record{20,bytes,0n}})
    case Pipe{socket,None{},write,decoder,deadline} 23:
      (Pipe{socket,None{},write,decoder,deadline},Fail{Error{10,"early-application-record",True{}}})
    case Pipe{socket,Some{read},write,decoder,deadline} 23:
      open_pair(socket,write,decoder,deadline,R.open(read,B.append(header,bytes)))
    case Pipe{socket,None{},write,decoder,deadline} _:
      (Pipe{socket,None{},write,decoder,deadline},Done{R.Record{kind,bytes,0n}})
    case pipe _: (pipe,Fail{Error{10,"plaintext-after-server-hello",True{}}})

def body_got(pipe: Pipe, kind: U32, header: List<&2,U32>, result: Result<&2,&2,Error,List<&2,U32>>) -> Pipe & Result<&2,&2,Error,R.Record>:
  match result:
    case Fail{why}: (pipe,Fail{why})
    case Done{bytes}: body(pipe,kind,header,bytes)

def body_pair(pair: Socket & Result<&2,&2,Error,List<&2,U32>>, read: Maybe<&1,T.ReadKey>, write: Maybe<&1,T.WriteKey>, decoder: HS.Decoder, deadline: Nat, kind: U32, header: List<&2,U32>) -> IO(Pipe & Result<&2,&2,Error,R.Record>):
  (socket,result) = pair
  IO.pure(Pipe & Result<&2,&2,Error,R.Record>,body_got(Pipe{socket,read,write,decoder,deadline},kind,header,result))

def record_length(valid: Bool, bounded: Bool, pipe: Pipe, kind: U32, header: List<&2,U32>, size: Nat) -> IO(Pipe & Result<&2,&2,Error,R.Record>):
  match valid bounded pipe:
    case False{} _ pipe: IO.pure(Pipe & Result<&2,&2,Error,R.Record>,(pipe,Fail{Error{10,"record-header",True{}}}))
    case True{} False{} pipe: IO.pure(Pipe & Result<&2,&2,Error,R.Record>,(pipe,Fail{Error{22,"record-overflow",True{}}}))
    case True{} True{} Pipe{socket,read,write,decoder,+deadline}:
      do IO<Pipe & Result<&2,&2,Error,R.Record>>:
        pair : Socket & Result<&2,&2,Error,List<&2,U32>> <- read_exact(socket,size,[],deadline)
        body_pair(pair,read,write,decoder,deadline,kind,header)

def record_header(pipe: Pipe, result: Result<&2,&2,Error,List<&2,U32>>) -> IO(Pipe & Result<&2,&2,Error,R.Record>):
  match result:
    case Fail{error}: IO.pure(Pipe & Result<&2,&2,Error,R.Record>,(pipe,Fail{error}))
    case Done{[+kind,+major,+minor,+high,+low]}:
      +size = U32.to_nat(U32.add(U32.mul(high,256),low))
      valid = Bool.or(U32.is_eq(kind,20),Bool.or(U32.is_eq(kind,21),Bool.or(U32.is_eq(kind,22),U32.is_eq(kind,23))))
      bound = Bool.pick(Nat,U32.is_eq(kind,23),16401n,16384n)
      record_length(valid,Nat.is_le(size,bound),pipe,kind,[kind,major,minor,high,low],size)
    case _: IO.pure(Pipe & Result<&2,&2,Error,R.Record>,(pipe,Fail{Error{50,"record-header",True{}}}))

def header_pair(pair: Socket & Result<&2,&2,Error,List<&2,U32>>, read: Maybe<&1,T.ReadKey>, write: Maybe<&1,T.WriteKey>, decoder: HS.Decoder, deadline: Nat) -> IO(Pipe & Result<&2,&2,Error,R.Record>):
  (socket,result) = pair
  record_header(Pipe{socket,read,write,decoder,deadline},result)

def receive(pipe: Pipe) -> IO(Pipe & Result<&2,&2,Error,R.Record>):
  match pipe:
    case Pipe{socket,read,write,decoder,+deadline}:
      do IO<Pipe & Result<&2,&2,Error,R.Record>>:
        pair : Socket & Result<&2,&2,Error,List<&2,U32>> <- read_exact(socket,5n,[],deadline)
        header_pair(pair,read,write,decoder,deadline)

def boundary_result(socket: Socket, read: Maybe<&1,T.ReadKey>, write: Maybe<&1,T.WriteKey>, deadline: Nat, value: Maybe<&1,HS.Decoder>) -> Boundary:
  match value:
    case None{}: Boundary{Pipe{socket,read,write,HS.start(),deadline},False{}}
    case Some{decoder}: Boundary{Pipe{socket,read,write,decoder,deadline},True{}}

def aligned(pipe: Pipe) -> Boundary:
  match pipe:
    case Pipe{socket,read,write,decoder,deadline}: boundary_result(socket,read,write,deadline,HS.boundary(decoder))

def peer_alert_result(value: Result<&2,&2,U32,U32>) -> Error:
  match value:
    case Fail{code}: Error{code,"malformed-alert",True{}}
    case Done{code}: Error{code,"peer-alert",False{}}

def peer_alert(bytes: List<&2,U32>) -> Error:
  peer_alert_result(C.parse_alert(bytes))

def handshake_fail(pipe: Pipe, error: Error) -> IO(HandshakeWork):
  IO.bind(Result<&2,&1,Error,Connection>,HandshakeWork,failed(pipe,error),result => IO.pure(HandshakeWork,Shook{result}))

def handshake_sent(state: M.State, pair: Pipe & Result<&2,&2,Error,Unit>) -> IO(HandshakeWork):
  (pipe,result) = pair
  match result:
    case Fail{error}: handshake_fail(pipe,error)
    case Done{Unit{}}: IO.pure(HandshakeWork,Expect{pipe,state})

def ready_sent(read: T.ReadKey, write: T.WriteKey, suite: U32, group: U32, alpn: Bool, pair: Pipe & Result<&2,&2,Error,Unit>) -> IO(HandshakeWork):
  (pipe,result) = pair
  match pipe result:
    case pipe Fail{error}: handshake_fail(pipe,error)
    case Pipe{socket,_,_,_,deadline} Done{Unit{}}:
      IO.pure(HandshakeWork,Shook{Done{Connection{Pipe{socket,Some{read},Some{write},HS.start(),deadline},suite,group,alpn,False{}}}})

def retry_action(value: Boundary, rest: List<&2,List<&2,U32>>, auth: M.Auth, transcript: X.Transcript, private: Maybe<&1,K.Ephemeral>, public: List<&2,U32>, random: List<&2,U32>, group: U32, suite: U32, cookie: List<&2,U32>) -> IO(HandshakeWork):
  match value rest:
    case Boundary{pipe,True{}} Nil{}:
      match private:
        case Some{private}: IO.pure(HandshakeWork,Act{pipe,M.hello(auth,transcript,private,public,random,group,suite,cookie),[]})
        case None{}:
          do IO<HandshakeWork>:
            offer : Maybe<&1,K.Offer> <- K.generate(K.P256{})
            IO.pure(HandshakeWork,Act{pipe,M.retry_offer(auth,transcript,random,group,suite,cookie,offer),[]})
    case Boundary{pipe,_} _: handshake_fail(pipe,Error{10,"retry-record-boundary",True{}})

def install_action(value: Boundary, rest: List<&2,List<&2,U32>>, state: M.State, read: T.ReadKey, write: T.WriteKey) -> IO(HandshakeWork):
  match value rest:
    case Boundary{Pipe{socket,_,_,decoder,deadline},True{}} Nil{}: IO.pure(HandshakeWork,Expect{Pipe{socket,Some{read},Some{write},decoder,deadline},state})
    case Boundary{pipe,_} _: handshake_fail(pipe,Error{10,"epoch-boundary",True{}})

def complete_action(value: Boundary, rest: List<&2,List<&2,U32>>, read: T.ReadKey, write: T.WriteKey, last_flight: List<&2,U32>, suite: U32, group: U32, alpn: Bool) -> IO(HandshakeWork):
  match value rest:
    case Boundary{pipe,True{}} Nil{}: IO.bind(Pipe & Result<&2,&2,Error,Unit>,HandshakeWork,write_records(pipe,22,last_flight),pair => ready_sent(read,write,suite,group,alpn,pair))
    case Boundary{pipe,_} _: handshake_fail(pipe,Error{10,"finished-record-boundary",True{}})

def action(pipe: Pipe, value: M.Action, rest: List<&2,List<&2,U32>>) -> IO(HandshakeWork):
  match value:
    case M.Failed{code,reason}: handshake_fail(pipe,Error{code,reason,True{}})
    case M.Continue{state}: IO.pure(HandshakeWork,Process{pipe,state,rest})
    case M.SendHello{state,bytes}:
      match rest:
        case Nil{}: IO.bind(Pipe & Result<&2,&2,Error,Unit>,HandshakeWork,write_records(pipe,22,bytes),pair => handshake_sent(state,pair))
        case _: handshake_fail(pipe,Error{10,"hello-record-boundary",True{}})
    case M.Retry{auth,transcript,private,public,random,group,suite,cookie}: retry_action(aligned(pipe),rest,auth,transcript,private,public,random,group,suite,cookie)
    case M.Install{state,read,write}: install_action(aligned(pipe),rest,state,read,write)
    case M.Complete{read,write,last_flight,suite,group,alpn}: complete_action(aligned(pipe),rest,read,write,last_flight,suite,group,alpn)

def messages(pipe: Pipe, state: M.State, values: List<&2,List<&2,U32>>) -> IO(HandshakeWork):
  match values:
    case Nil{}: IO.pure(HandshakeWork,Expect{pipe,state})
    case Con{message,rest}: IO.pure(HandshakeWork,Act{pipe,M.step(state,message),rest})

def framing_error(error: HS.Error) -> Error:
  match error:
    case HS.Alignment{}: Error{10,"handshake-record-alignment",True{}}
    case _: Error{50,"handshake-framing",True{}}

def handshake_batch(socket: Socket, read: Maybe<&1,T.ReadKey>, write: Maybe<&1,T.WriteKey>, deadline: Nat, state: M.State, value: Result<&2,&1,HS.Error,HS.Batch>) -> IO(HandshakeWork):
  match value:
    case Fail{error}: handshake_fail(Pipe{socket,read,write,HS.start(),deadline},framing_error(error))
    case Done{HS.Batch{decoder,values}}: IO.pure(HandshakeWork,Process{Pipe{socket,read,write,decoder,deadline},state,values})

def handshake_alert(boundary: Boundary, bytes: List<&2,U32>) -> IO(HandshakeWork):
  match boundary:
    case Boundary{pipe,True{}}: handshake_fail(pipe,peer_alert(bytes))
    case Boundary{pipe,False{}}: handshake_fail(pipe,Error{10,"interleaved-alert",True{}})

def feed_handshake(pipe: Pipe, state: M.State, bytes: List<&2,U32>) -> IO(HandshakeWork):
  match pipe:
    case Pipe{socket,read,write,decoder,deadline}: handshake_batch(socket,read,write,deadline,state,HS.feed(decoder,bytes))

def handshake_record(pipe: Pipe, state: M.State, result: Result<&2,&2,Error,R.Record>) -> IO(HandshakeWork):
  match result:
    case Fail{error}: handshake_fail(pipe,error)
    case Done{R.Record{22,Nil{},_}}: handshake_fail(pipe,Error{10,"empty-handshake-record",True{}})
    case Done{R.Record{22,bytes,_}}: feed_handshake(pipe,state,bytes)
    case Done{R.Record{20,[1],_}}: IO.pure(HandshakeWork,Expect{pipe,state})
    case Done{R.Record{21,bytes,_}}:
      handshake_alert(aligned(pipe),bytes)
    case Done{_}: handshake_fail(pipe,Error{10,"unexpected-handshake-record",True{}})

def handshake_pair(pair: Pipe & Result<&2,&2,Error,R.Record>, state: M.State) -> IO(HandshakeWork):
  (pipe,result) = pair
  handshake_record(pipe,state,result)

def handshake_read(pipe: Pipe, state: M.State) -> IO(HandshakeWork):
  do IO<HandshakeWork>:
    pair : Pipe & Result<&2,&2,Error,R.Record> <- receive(pipe)
    handshake_pair(pair,state)

def handshake_budget(work: HandshakeWork) -> IO(Result<&2,&1,Error,Connection>):
  match work:
    case Shook{result}: IO.pure(Result<&2,&1,Error,Connection>,result)
    case Expect{pipe,_}: failed(pipe,Error{80,"handshake-budget",True{}})
    case Process{pipe,_,_}: failed(pipe,Error{80,"handshake-budget",True{}})
    case Act{pipe,_,_}: failed(pipe,Error{80,"handshake-budget",True{}})

def handshake_loop(fuel: Nat, work: HandshakeWork) -> IO(Result<&2,&1,Error,Connection>):
  match fuel work:
    case _ Shook{result}: IO.pure(Result<&2,&1,Error,Connection>,result)
    case 0n work: handshake_budget(work)
    case 1n+p Expect{pipe,state}: IO.bind(HandshakeWork,Result<&2,&1,Error,Connection>,handshake_read(pipe,state),next => handshake_loop(p,next))
    case 1n+p Process{pipe,state,values}: IO.bind(HandshakeWork,Result<&2,&1,Error,Connection>,messages(pipe,state,values),next => handshake_loop(p,next))
    case 1n+p Act{pipe,value,rest}: IO.bind(HandshakeWork,Result<&2,&1,Error,Connection>,action(pipe,value,rest),next => handshake_loop(p,next))

def started(pipe: Pipe, auth: M.Auth, random: Result<&1,&1,U32 & String,List<&2,U32>>, offer: Maybe<&1,K.Offer>) -> IO(Result<&2,&1,Error,Connection>):
  match random offer:
    case Done{random} Some{offer}: handshake_loop(1048576n,Act{pipe,M.start(auth,random,offer),[]})
    case _ _: failed(pipe,Error{80,"random",True{}})

def ipv4_literal(bytes: List<&2,U32>, +value: U32, +digits: U32, +parts: U32, valid: Bool) -> Bool:
  match bytes:
    case Nil{}: Bool.and(valid,Bool.and(U32.is_eq(parts,3),Bool.and(U32.is_gt(digits,0),U32.is_le(value,255))))
    case Con{46,rest}: ipv4_literal(rest,0,0,U32.inc(parts),Bool.and(valid,Bool.and(U32.is_lt(parts,3),Bool.and(U32.is_gt(digits,0),U32.is_le(value,255)))))
    case Con{+c,rest}: ipv4_literal(rest,U32.add(U32.mul(value,10),U32.sub(c,48)),U32.inc(digits),parts,Bool.and(valid,Bool.and(U32.is_lt(digits,3),Bool.and(U32.is_ge(c,48),U32.is_le(c,57)))))

def identity_valid(identity: A.Identity) -> Bool:
  match identity:
    case A.Dns{+bytes}: Bool.and(A.reference(A.Dns{bytes}),Bool.not(ipv4_literal(bytes,0,0,0,True{})))
    case +identity: A.reference(identity)

def connect_config(socket: Socket, config: Config) -> IO(Result<&2,&1,Error,Connection>):
  match config:
    case Config{tables,anchors,identity,alpn,clock,deadline}:
      do IO<Result<&2,&1,Error,Connection>>:
        now : Nat <- clock
        random : Result<&1,&1,U32 & String,List<&2,U32>> <- W.wire_random_bytes(32)
        offer : Maybe<&1,K.Offer> <- K.generate(K.X25519{})
        started(Pipe{socket,None{},None{},HS.start(),deadline},M.Auth{tables,anchors,identity,now,alpn},random,offer)

def connect_valid(valid: Bool, socket: Socket, config: Config) -> IO(Result<&2,&1,Error,Connection>):
  match valid:
    case False{}: failed(Pipe{socket,None{},None{},HS.start(),0n},Error{47,"invalid-identity",False{}})
    case True{}: connect_config(socket,config)

def connect(socket: Socket, config: Config) -> IO(Result<&2,&1,Error,Connection>):
  match config:
    case Config{tables,anchors,+identity,alpn,clock,at}: connect_valid(identity_valid(identity),socket,Config{tables,anchors,identity,alpn,clock,at})

# Update a deadline between application operations; never renew it implicitly.
def deadline(connection: Connection, at: Nat) -> Connection:
  match connection:
    case Connection{Pipe{socket,read,write,decoder,_},suite,group,alpn,closed}: Connection{Pipe{socket,read,write,decoder,at},suite,group,alpn,closed}

def send_result(suite: U32, group: U32, alpn: Bool, pair: Pipe & Result<&2,&2,Error,Unit>) -> IO(Result<&2,&1,Error,Connection>):
  (pipe,result) = pair
  match result:
    case Fail{error}: failed(pipe,error)
    case Done{Unit{}}: IO.pure(Result<&2,&1,Error,Connection>,Done{Connection{pipe,suite,group,alpn,False{}}})

def send_checked(valid: Bool, pipe: Pipe, suite: U32, group: U32, alpn: Bool, bytes: List<&2,U32>) -> IO(Result<&2,&1,Error,Connection>):
  match valid:
    case False{}: failed(pipe,Error{80,"send-on-closed-or-invalid",False{}})
    case True{}: IO.bind(Pipe & Result<&2,&2,Error,Unit>,Result<&2,&1,Error,Connection>,write_records(pipe,23,bytes),pair => send_result(suite,group,alpn,pair))

def send(connection: Connection, +bytes: List<&2,U32>) -> IO(Result<&2,&1,Error,Connection>):
  match connection:
    case Connection{pipe,suite,group,alpn,closed}: send_checked(Bool.and(Bool.not(closed),B.valid(bytes)),pipe,suite,group,alpn,bytes)

def rekey_write_pair(socket: Socket, read: Maybe<&1,T.ReadKey>, decoder: HS.Decoder, deadline: Nat, suite: U32, group: U32, alpn: Bool, pair: T.WriteKey & Result<&2,&2,T.Error,Unit>) -> IO(Result<&2,&1,Error,Connection>):
  (write,result) = pair
  match result:
    case Fail{_}: failed(Pipe{socket,read,Some{write},decoder,deadline},Error{80,"key-update-limit",True{}})
    case Done{Unit{}}: IO.pure(Result<&2,&1,Error,Connection>,Done{Connection{Pipe{socket,read,Some{write},decoder,deadline},suite,group,alpn,False{}}})

def update_sent(suite: U32, group: U32, alpn: Bool, pair: Pipe & Result<&2,&2,Error,Unit>) -> IO(Result<&2,&1,Error,Connection>):
  (pipe,result) = pair
  match pipe result:
    case pipe Fail{error}: failed(pipe,error)
    case Pipe{socket,read,Some{write},decoder,deadline} Done{Unit{}}:
      rekey_write_pair(socket,read,decoder,deadline,suite,group,alpn,T.rekey_write(write))
    case pipe _: failed(pipe,Error{80,"missing-application-write-key",True{}})

def key_update(connection: Connection, request: Bool) -> IO(Result<&2,&1,Error,Connection>):
  match connection:
    case Connection{pipe,suite,group,alpn,False{}}:
      IO.bind(Pipe & Result<&2,&2,Error,Unit>,Result<&2,&1,Error,Connection>,transmit(pipe,22,[24,0,0,1,Bool.pick(U32,request,1,0)]),pair => update_sent(suite,group,alpn,pair))
    case Connection{pipe,_,_,_,True{}}: failed(pipe,Error{80,"update-on-closed",False{}})

type ReceiveWork is Type:
  ReadMore{connection: Connection}
  Post{pipe: Pipe, suite: U32, group: U32, alpn: Bool, messages: List<&2,List<&2,U32>>}
  ReceivedResult{result: Result<&2,&1,Error,Received>}

def recv_failed(pipe: Pipe, +error: Error) -> IO(ReceiveWork):
  do IO<ReceiveWork>:
    abort(pipe,error)
    IO.pure(ReceiveWork,ReceivedResult{Fail{error}})

def recv_updated(rest: List<&2,List<&2,U32>>, value: Result<&2,&1,Error,Connection>) -> IO(ReceiveWork):
  match value:
    case Fail{error}: IO.pure(ReceiveWork,ReceivedResult{Fail{error}})
    case Done{Connection{pipe,suite,group,alpn,_}}: IO.pure(ReceiveWork,Post{pipe,suite,group,alpn,rest})

def respond_update(pipe: Pipe, suite: U32, group: U32, alpn: Bool, request: U32, rest: List<&2,List<&2,U32>>) -> IO(ReceiveWork):
  match request:
    case 0: IO.pure(ReceiveWork,Post{pipe,suite,group,alpn,rest})
    case _: IO.bind(Result<&2,&1,Error,Connection>,ReceiveWork,key_update(Connection{pipe,suite,group,alpn,False{}},False{}),value => recv_updated(rest,value))

def rekey_read_pair(socket: Socket, write: Maybe<&1,T.WriteKey>, deadline: Nat, suite: U32, group: U32, alpn: Bool, request: U32, rest: List<&2,List<&2,U32>>, pair: T.ReadKey & Result<&2,&2,T.Error,Unit>) -> IO(ReceiveWork):
  (read,result) = pair
  match result:
    case Fail{_}: recv_failed(Pipe{socket,Some{read},write,HS.start(),deadline},Error{80,"read-key-update",True{}})
    case Done{Unit{}}: respond_update(Pipe{socket,Some{read},write,HS.start(),deadline},suite,group,alpn,request,rest)

def peer_update_aligned(boundary: Boundary, suite: U32, group: U32, alpn: Bool, request: U32, rest: List<&2,List<&2,U32>>) -> IO(ReceiveWork):
  match boundary rest:
    case Boundary{Pipe{socket,Some{read},write,_,deadline},True{}} Nil{}:
      rekey_read_pair(socket,write,deadline,suite,group,alpn,request,[],T.rekey_read(read))
    case Boundary{pipe,_} _: recv_failed(pipe,Error{10,"update-record-boundary",True{}})

def post_ticket(server: Bool, pipe: Pipe, suite: U32, group: U32, alpn: Bool, rest: List<&2,List<&2,U32>>) -> IO(ReceiveWork):
  match server:
    case False{}: IO.pure(ReceiveWork,Post{pipe,suite,group,alpn,rest})
    case True{}: recv_failed(pipe,Error{10,"client-sent-session-ticket",True{}})

def post_message(server: Bool, pipe: Pipe, suite: U32, group: U32, alpn: Bool, value: Result<&2,&2,U32,C.Message>, rest: List<&2,List<&2,U32>>) -> IO(ReceiveWork):
  match value:
    case Fail{code}: recv_failed(pipe,Error{code,"post-handshake-codec",True{}})
    case Done{C.NewSessionTicket{}}: post_ticket(server,pipe,suite,group,alpn,rest)
    case Done{C.KeyUpdate{request}}: peer_update_aligned(aligned(pipe),suite,group,alpn,request,rest)
    case _: recv_failed(pipe,Error{10,"post-handshake-message",True{}})

def receive_post_decoder(socket: Socket, read: Maybe<&1,T.ReadKey>, write: Maybe<&1,T.WriteKey>, deadline: Nat, suite: U32, group: U32, alpn: Bool, decoder: HS.Decoder) -> IO(ReceiveWork):
  match decoder:
    case HS.Decoder{HS.Header{Nil{},0n},_}: IO.pure(ReceiveWork,ReadMore{Connection{Pipe{socket,read,write,HS.start(),deadline},suite,group,alpn,False{}}})
    case decoder: IO.pure(ReceiveWork,ReadMore{Connection{Pipe{socket,read,write,decoder,deadline},suite,group,alpn,False{}}})

def receive_post(pipe: Pipe, suite: U32, group: U32, alpn: Bool) -> IO(ReceiveWork):
  match pipe:
    case Pipe{socket,read,write,decoder,deadline}: receive_post_decoder(socket,read,write,deadline,suite,group,alpn,decoder)

def post_messages(server: Bool, pipe: Pipe, suite: U32, group: U32, alpn: Bool, values: List<&2,List<&2,U32>>) -> IO(ReceiveWork):
  match values:
    case Nil{}: receive_post(pipe,suite,group,alpn)
    case Con{message,rest}: post_message(server,pipe,suite,group,alpn,C.parse(message),rest)

def post_batch(socket: Socket, read: Maybe<&1,T.ReadKey>, write: Maybe<&1,T.WriteKey>, deadline: Nat, suite: U32, group: U32, alpn: Bool, value: Result<&2,&1,HS.Error,HS.Batch>) -> IO(ReceiveWork):
  match value:
    case Fail{error}: recv_failed(Pipe{socket,read,write,HS.start(),deadline},framing_error(error))
    case Done{HS.Batch{decoder,values}}: IO.pure(ReceiveWork,Post{Pipe{socket,read,write,decoder,deadline},suite,group,alpn,values})

def application_data(boundary: Boundary, suite: U32, group: U32, alpn: Bool, bytes: List<&2,U32>) -> IO(ReceiveWork):
  match boundary bytes:
    case Boundary{pipe,True{}} Nil{}: IO.pure(ReceiveWork,ReadMore{Connection{pipe,suite,group,alpn,False{}}})
    case Boundary{pipe,True{}} bytes: IO.pure(ReceiveWork,ReceivedResult{Done{Received{Connection{pipe,suite,group,alpn,False{}},bytes}}})
    case Boundary{pipe,False{}} _: recv_failed(pipe,Error{10,"interleaved-application-data",True{}})

def application_alert_parsed(pipe: Pipe, suite: U32, group: U32, alpn: Bool, value: Result<&2,&2,U32,U32>) -> IO(ReceiveWork):
  match value:
    case Done{0}: IO.pure(ReceiveWork,ReceivedResult{Done{Received{Connection{pipe,suite,group,alpn,True{}},[]}}})
    case value: recv_failed(pipe,peer_alert_result(value))

def application_alert(boundary: Boundary, suite: U32, group: U32, alpn: Bool, bytes: List<&2,U32>) -> IO(ReceiveWork):
  match boundary:
    case Boundary{pipe,False{}}: recv_failed(pipe,Error{10,"interleaved-alert",True{}})
    case Boundary{pipe,True{}}: application_alert_parsed(pipe,suite,group,alpn,C.parse_alert(bytes))

def feed_post(pipe: Pipe, suite: U32, group: U32, alpn: Bool, bytes: List<&2,U32>) -> IO(ReceiveWork):
  match pipe:
    case Pipe{socket,read,write,decoder,deadline}: post_batch(socket,read,write,deadline,suite,group,alpn,HS.feed(decoder,bytes))

def application_record(pipe: Pipe, suite: U32, group: U32, alpn: Bool, result: Result<&2,&2,Error,R.Record>) -> IO(ReceiveWork):
  match result:
    case Fail{error}: recv_failed(pipe,error)
    case Done{R.Record{22,bytes,_}}: feed_post(pipe,suite,group,alpn,bytes)
    case Done{R.Record{23,bytes,_}}: application_data(aligned(pipe),suite,group,alpn,bytes)
    case Done{R.Record{21,bytes,_}}: application_alert(aligned(pipe),suite,group,alpn,bytes)
    case Done{_}: recv_failed(pipe,Error{10,"unexpected-application-record",True{}})

def application_pair(pair: Pipe & Result<&2,&2,Error,R.Record>, suite: U32, group: U32, alpn: Bool) -> IO(ReceiveWork):
  (pipe,result) = pair
  application_record(pipe,suite,group,alpn,result)

def receive_work(connection: Connection) -> IO(ReceiveWork):
  match connection:
    case Connection{pipe,suite,group,alpn,True{}}: IO.pure(ReceiveWork,ReceivedResult{Done{Received{Connection{pipe,suite,group,alpn,True{}},[]}}})
    case Connection{pipe,suite,group,alpn,False{}}:
      do IO<ReceiveWork>:
        pair : Pipe & Result<&2,&2,Error,R.Record> <- receive(pipe)
        application_pair(pair,suite,group,alpn)

def receive_budget(work: ReceiveWork) -> IO(Result<&2,&1,Error,Received>):
  match work:
    case ReceivedResult{result}: IO.pure(Result<&2,&1,Error,Received>,result)
    case ReadMore{Connection{pipe,_,_,_,_}}:
      do IO<Result<&2,&1,Error,Received>>:
        abort(pipe,Error{80,"receive-budget",True{}})
        IO.pure(Result<&2,&1,Error,Received>,Fail{Error{80,"receive-budget",True{}}})
    case Post{pipe,_,_,_,_}:
      do IO<Result<&2,&1,Error,Received>>:
        abort(pipe,Error{80,"receive-budget",True{}})
        IO.pure(Result<&2,&1,Error,Received>,Fail{Error{80,"receive-budget",True{}}})

def receive_loop(fuel: Nat, +server: Bool, work: ReceiveWork) -> IO(Result<&2,&1,Error,Received>):
  match fuel work:
    case _ ReceivedResult{result}: IO.pure(Result<&2,&1,Error,Received>,result)
    case 0n work: receive_budget(work)
    case 1n+p ReadMore{connection}: IO.bind(ReceiveWork,Result<&2,&1,Error,Received>,receive_work(connection),next => receive_loop(p,server,next))
    case 1n+p Post{pipe,suite,group,alpn,values}: IO.bind(ReceiveWork,Result<&2,&1,Error,Received>,post_messages(server,pipe,suite,group,alpn,values),next => receive_loop(p,server,next))

def recv(connection: Connection) -> IO(Result<&2,&1,Error,Received>):
  receive_loop(1048576n,False{},ReadMore{connection})

# Shared record lifecycle with server-role post-handshake admission.
def recv_server(connection: Connection) -> IO(Result<&2,&1,Error,Received>):
  receive_loop(1048576n,True{},ReadMore{connection})

def close(connection: Connection) -> IO(Unit):
  match connection:
    case Connection{pipe,_,_,_,_}: IO.bind(Pipe & Result<&2,&2,Error,Unit>,Unit,transmit(pipe,21,[1,0]),abort_sent)
