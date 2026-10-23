import Base
import ./bend_tls_client.bend as Transport
import ./tls_server_handshake.bend as N
import ./tls_server_flight.bend as F
import ./tls_handshake_codec.bend as C
import ./tls_handshake_stream.bend as HS
import ./tls_transcript.bend as X
import ./tls_schedule.bend as S
import ./tls_key_share.bend as K
import ./tls_hello.bend as H
import ./tls_client.bend as Client
import ./tls_record.bend as R
import ./wire.bend as W
import ../crypto/credential.bend as Cred
import ../crypto/private_key.bend as P
import ../crypto/pem.bend as PEM
import ../crypto/traffic.bend as T
import ../crypto/bytes.bend as B

# Synthetic credentials only. accept consumes an already connected byte socket
# and one credential owner. All failures close the socket, returning no owner.
type Config is Type:
  Config{credential: Cred.Credential, intermediates: List<&2,List<&2,U32>>, policy: N.Policy, deadline: Nat}

type Connection is Type:
  Connection{transport: Transport.Connection, sni: List<&2,U32>}

type Received is Type:
  Received{connection: Connection, bytes: List<&2,U32>}

def imported(policy: N.Policy, at: Nat, intermediates: List<&2,List<&2,U32>>, value: Result<&2,&1,PEM.Error,Cred.Credential>) -> Result<&2,&1,PEM.Error,Config>:
  match value:
    case Fail{error}: Fail{error}
    case Done{credential}: Done{Config{credential,intermediates,policy,at}}

def import_chain(policy: N.Policy, at: Nat, key: List<&2,U32>, chain: List<&2,List<&2,U32>>, encoded: Maybe<&2,List<&2,U32>>) -> Result<&2,&1,PEM.Error,Config>:
  match chain encoded:
    case Con{leaf,rest} Some{_}: imported(policy,at,rest,Cred.import_pem(leaf,key))
    case _ _: Fail{PEM.Malformed{}}

def pem_part(value: Result<&2,&1,PEM.Error,PEM.Block>, rest: List<&2,List<&2,U32>>, out: List<&2,List<&2,U32>>, next: List<&2,List<&2,U32>> -> List<&2,List<&2,U32>> -> Result<&2,&2,PEM.Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,PEM.Error,List<&2,List<&2,U32>>>:
  match value:
    case Fail{error}: Fail{error}
    case Done{PEM.Block{PEM.Certificate{},der}}: next(rest,Con{der,out})
    case _: Fail{PEM.Malformed{}}

def pem_chain(fuel: Nat, chain: List<&2,List<&2,U32>>, out: List<&2,List<&2,U32>>) -> Result<&2,&2,PEM.Error,List<&2,List<&2,U32>>>:
  match fuel chain:
    case _ Nil{}: Done{List.reverse(&2,List<&2,U32>,out)}
    case 0n _: Fail{PEM.TooLarge{}}
    case 1n+p Con{pem,rest}: pem_part(PEM.decode(pem),rest,out,r => o => pem_chain(p,r,o))

def pem_imported(policy: N.Policy, at: Nat, key: List<&2,U32>, value: Result<&2,&2,PEM.Error,List<&2,List<&2,U32>>>) -> Result<&2,&1,PEM.Error,Config>:
  match value:
    case Fail{error}: Fail{error}
    case Done{+chain}: import_chain(policy,at,key,chain,C.certificate([],chain))

def within(+allowed: List<&2,U32>, values: List<&2,U32>) -> Bool:
  match values:
    case Nil{}: True{}
    case Con{value,rest}: Bool.and(C.member(value,allowed),within(allowed,rest))

def policy_valid(policy: N.Policy) -> Bool:
  match policy:
    case N.Policy{+suites,+groups,_}:
      Bool.and(Bool.and(Nat.is_gt(B.length(suites),0n),Nat.is_le(B.length(suites),2n)),
        Bool.and(Bool.and(Nat.is_gt(B.length(groups),0n),Nat.is_le(B.length(groups),2n)),
          Bool.and(within([4865,4867],suites),within([29,23],groups))))

def pem_valid(valid: Bool, chain: List<&2,List<&2,U32>>, key: List<&2,U32>, policy: N.Policy, at: Nat) -> Result<&2,&1,PEM.Error,Config>:
  match valid:
    case False{}: Fail{PEM.Malformed{}}
    case True{}: pem_imported(policy,at,key,pem_chain(16n,chain,[]))

# One PEM certificate block per list entry, leaf first; private PEM is unencrypted.
# No filesystem, ambient trust, hostname choice or implicit clock enters import.
def from_pem(chain: List<&2,List<&2,U32>>, key: List<&2,U32>, +policy: N.Policy, at: Nat) -> Result<&2,&1,PEM.Error,Config>:
  pem_valid(policy_valid(policy),chain,key,policy,at)

type Work is Type:
  Hello{pipe: Transport.Pipe, config: Config, transcript: X.Transcript, first: List<&2,U32>, cookie: List<&2,U32>}
  Finished{pipe: Transport.Pipe, client: S.FinishedKey, hash: List<&2,U32>, read: T.ReadKey, choice: N.Choice}
  Complete{result: Result<&2,&1,Transport.Error,Connection>}

type MessageWork is Type:
  Reading{pipe: Transport.Pipe}
  Message{pipe: Transport.Pipe, result: Result<&2,&2,Transport.Error,List<&2,U32>>}

def failure(pipe: Transport.Pipe, +error: Transport.Error) -> IO(Work):
  do IO<Work>:
    Transport.abort(pipe,error)
    IO.pure(Work,Complete{Fail{error}})

def message_failure(pipe: Transport.Pipe, +alert: U32, +reason: String) -> IO(MessageWork):
  IO.pure(MessageWork,Message{pipe,Fail{Transport.Error{alert,reason,True{}}}})

def message_boundary(value: Transport.Boundary, +messages: List<&2,List<&2,U32>>) -> IO(MessageWork):
  match value messages:
    case Transport.Boundary{pipe,True{}} Con{message,Nil{}}: IO.pure(MessageWork,Message{pipe,Done{message}})
    case Transport.Boundary{pipe,_} _: message_failure(pipe,10,"handshake-record-boundary")

def message_batch(socket: Socket, read: Maybe<&1,T.ReadKey>, write: Maybe<&1,T.WriteKey>, +at: Nat, result: Result<&2,&1,HS.Error,HS.Batch>) -> IO(MessageWork):
  match result:
    case Fail{error}: IO.pure(MessageWork,Message{Transport.Pipe{socket,read,write,HS.start(),at},Fail{Transport.framing_error(error)}})
    case Done{HS.Batch{decoder,Nil{}}}: IO.pure(MessageWork,Reading{Transport.Pipe{socket,read,write,decoder,at}})
    case Done{HS.Batch{decoder,messages}}: message_boundary(Transport.aligned(Transport.Pipe{socket,read,write,decoder,at}),messages)

def message_feed(pipe: Transport.Pipe, bytes: List<&2,U32>) -> IO(MessageWork):
  match pipe:
    case Transport.Pipe{socket,read,write,decoder,at}: message_batch(socket,read,write,at,HS.feed(decoder,bytes))

def message_ccs(ccs: Bool, pipe: Transport.Pipe) -> IO(MessageWork):
  match ccs:
    case True{}: IO.pure(MessageWork,Reading{pipe})
    case False{}: message_failure(pipe,10,"ccs-before-client-hello")

def message_record(+ccs: Bool, pipe: Transport.Pipe, result: Result<&2,&2,Transport.Error,R.Record>) -> IO(MessageWork):
  match result:
    case Fail{error}: IO.pure(MessageWork,Message{pipe,Fail{error}})
    case Done{R.Record{22,Nil{},_}}: message_failure(pipe,10,"empty-handshake-record")
    case Done{R.Record{22,bytes,_}}: message_feed(pipe,bytes)
    case Done{R.Record{20,[1],_}}: message_ccs(ccs,pipe)
    case Done{R.Record{21,bytes,_}}: IO.pure(MessageWork,Message{pipe,Fail{Transport.peer_alert(bytes)}})
    case _: message_failure(pipe,10,"unexpected-handshake-record")

def message_pair(+ccs: Bool, pair: Transport.Pipe & Result<&2,&2,Transport.Error,R.Record>) -> IO(MessageWork):
  (pipe,result) = pair
  message_record(ccs,pipe,result)

def message_loop(+fuel: Nat, +ccs: Bool, work: MessageWork) -> IO(MessageWork):
  match fuel work:
    case _ Message{pipe,result}: IO.pure(MessageWork,Message{pipe,result})
    case 0n Reading{pipe}: message_failure(pipe,80,"handshake-read-budget")
    case 1n+p Reading{pipe}:
      do IO<MessageWork>:
        pair : Transport.Pipe & Result<&2,&2,Transport.Error,R.Record> <- Transport.receive(pipe)
        next : MessageWork <- message_pair(ccs,pair)
        message_loop(p,ccs,next)

def next_message(pipe: Transport.Pipe, +ccs: Bool) -> IO(MessageWork):
  message_loop(1048576n,ccs,Reading{pipe})

def finished_valid(+valid: Bool, pipe: Transport.Pipe, read: T.ReadKey, +choice: N.Choice) -> IO(Work):
  match valid pipe choice:
    case True{} Transport.Pipe{socket,_,write,_,at} N.Choice{suite,group,_,sni,alpn}:
      IO.pure(Work,Complete{Done{Connection{Transport.Connection{Transport.Pipe{socket,Some{read},write,HS.start(),at},suite,group,alpn,False{}},sni}}})
    case _ pipe _: failure(pipe,Transport.Error{51,"client-finished",True{}})

def finished_parsed(pipe: Transport.Pipe, cf: S.FinishedKey, +hash: List<&2,U32>, read: T.ReadKey, +choice: N.Choice, value: Result<&2,&2,U32,C.Message>) -> IO(Work):
  match value:
    case Done{C.Finished{data}}: finished_valid(S.verify_finished(cf,hash,data),pipe,read,choice)
    case Fail{code}: failure(pipe,Transport.Error{code,"client-finished-codec",True{}})
    case _: failure(pipe,Transport.Error{10,"expected-client-finished",True{}})

def finished_message(cf: S.FinishedKey, +hash: List<&2,U32>, read: T.ReadKey, +choice: N.Choice, work: MessageWork) -> IO(Work):
  match work:
    case Message{pipe,Fail{error}}: failure(pipe,error)
    case Message{pipe,Done{message}}: finished_parsed(pipe,cf,hash,read,choice,C.parse(message))
    case Reading{pipe}: failure(pipe,Transport.Error{80,"handshake-read-budget",True{}})

def flight_sent(cf: S.FinishedKey, +hash: List<&2,U32>, read: T.ReadKey, write: T.WriteKey, +choice: N.Choice, pair: Transport.Pipe & Result<&2,&2,Transport.Error,Unit>) -> IO(Work):
  (pipe,result) = pair
  match pipe result:
    case pipe Fail{error}: failure(pipe,error)
    case Transport.Pipe{socket,hs_read,_,decoder,at} Done{Unit{}}:
      IO.pure(Work,Finished{Transport.Pipe{socket,hs_read,Some{write},decoder,at},cf,hash,read,choice})

def hello_sent(+bytes: List<&2,U32>, hs_read: T.ReadKey, hs_write: T.WriteKey, app_read: T.ReadKey, app_write: T.WriteKey, cf: S.FinishedKey, +hash: List<&2,U32>, +choice: N.Choice, pair: Transport.Pipe & Result<&2,&2,Transport.Error,Unit>) -> IO(Work):
  (pipe,result) = pair
  match pipe result:
    case pipe Fail{error}: failure(pipe,error)
    case Transport.Pipe{socket,_,_,decoder,at} Done{Unit{}}:
      IO.bind(Transport.Pipe & Result<&2,&2,Transport.Error,Unit>,Work,Transport.write_records(Transport.Pipe{socket,Some{hs_read},Some{hs_write},decoder,at},22,bytes),pair => flight_sent(cf,hash,app_read,app_write,choice,pair))

def flight_built(pipe: Transport.Pipe, value: Maybe<&1,F.Flight>) -> IO(Work):
  match value:
    case None{}: failure(pipe,Transport.Error{80,"server-flight",True{}})
    case Some{F.Flight{hello,bytes,read,write,app_read,app_write,cf,hash,choice}}:
      IO.bind(Transport.Pipe & Result<&2,&2,Transport.Error,Unit>,Work,Transport.write_records(pipe,22,hello),pair => hello_sent(bytes,read,write,app_read,app_write,cf,hash,choice,pair))

def shared(pipe: Transport.Pipe, transcript: X.Transcript, +choice: N.Choice, +session: List<&2,U32>, +chain: List<&2,List<&2,U32>>, key: P.Private, +scheme: U32, +random: List<&2,U32>, +public: List<&2,U32>, value: Maybe<&1,List<&2,U32>>) -> IO(Work):
  match value:
    case None{}: failure(pipe,Transport.Error{47,"invalid-key-share",True{}})
    case Some{shared}: IO.bind(Maybe<&1,F.Flight>,Work,F.start(transcript,choice,session,chain,key,scheme,shared,random,public),value => flight_built(pipe,value))

def generated(pipe: Transport.Pipe, transcript: X.Transcript, +choice: N.Choice, +session: List<&2,U32>, +chain: List<&2,List<&2,U32>>, key: P.Private, +scheme: U32, random: Result<&1,&1,U32 & String,List<&2,U32>>, offer: Maybe<&1,K.Offer>) -> IO(Work):
  match choice random offer:
    case N.Choice{suite,group,+peer,sni,alpn} Done{random} Some{K.Offer{private,public}}:
      shared(pipe,transcript,N.Choice{suite,group,peer,sni,alpn},session,chain,key,scheme,random,public,K.shared(private,peer))
    case _ _ _: failure(pipe,Transport.Error{80,"random",True{}})

def negotiate_flight(pipe: Transport.Pipe, transcript: X.Transcript, +choice: N.Choice, +session: List<&2,U32>, config: Config, +scheme: U32) -> IO(Work):
  match choice config:
    case N.Choice{suite,+group,share,sni,alpn} Config{Cred.Credential{leaf,key},intermediates,_,_}:
      do IO<Work>:
        random : Result<&1,&1,U32 & String,List<&2,U32>> <- W.wire_random_bytes(32)
        offer : Maybe<&1,K.Offer> <- K.generate(Bool.pick(K.Group,U32.is_eq(group,29),K.X25519{},K.P256{}))
        generated(pipe,transcript,N.Choice{suite,group,share,sni,alpn},session,Con{leaf,intermediates},key,scheme,random,offer)

def retry_sent(config: Config, transcript: X.Transcript, +first: List<&2,U32>, +cookie: List<&2,U32>, pair: Transport.Pipe & Result<&2,&2,Transport.Error,Unit>) -> IO(Work):
  (pipe,result) = pair
  match result:
    case Fail{error}: failure(pipe,error)
    case Done{Unit{}}: IO.pure(Work,Hello{pipe,config,transcript,first,cookie})

def retry_transcript(pipe: Transport.Pipe, config: Config, +first: List<&2,U32>, +cookie: List<&2,U32>, +bytes: List<&2,U32>, transcript: Maybe<&1,X.Transcript>) -> IO(Work):
  match transcript:
    case None{}: failure(pipe,Transport.Error{80,"retry-transcript",True{}})
    case Some{transcript}: IO.bind(Transport.Pipe & Result<&2,&2,Transport.Error,Unit>,Work,Transport.write_records(pipe,22,bytes),pair => retry_sent(config,transcript,first,cookie,pair))

def retry_encoded(pipe: Transport.Pipe, config: Config, +first: List<&2,U32>, +cookie: List<&2,U32>, transcript: X.Transcript, bytes: Maybe<&2,List<&2,U32>>) -> IO(Work):
  match bytes:
    case None{}: failure(pipe,Transport.Error{80,"retry-encoding",True{}})
    case Some{+bytes}: retry_transcript(pipe,config,first,cookie,bytes,X.append(transcript,bytes))

def retry_random(pipe: Transport.Pipe, config: Config, +first: List<&2,U32>, transcript: X.Transcript, +session: List<&2,U32>, +suite: U32, +group: U32, value: Result<&1,&1,U32 & String,List<&2,U32>>) -> IO(Work):
  match value:
    case Fail{_}: failure(pipe,Transport.Error{80,"random",True{}})
    case Done{bytes}:
      +cookie = C.vector16(bytes)
      retry_encoded(pipe,config,first,cookie,transcript,C.hello_server(H.retry_random(),session,suite,
        B.append(C.extension(43,[3,4]),B.append(C.extension(51,[U32.shrn(group,8n),U32.and(group,255)]),C.extension(44,cookie)))))

def hello_choice(pipe: Transport.Pipe, config: Config, transcript: X.Transcript, +first: List<&2,U32>, +cookie: List<&2,U32>, +message: List<&2,U32>, +session: List<&2,U32>, +scheme: U32, +choice: N.Choice) -> IO(Work):
  match first choice:
    case Nil{} N.Choice{suite,group,Nil{},_,_}:
      IO.bind(Result<&1,&1,U32 & String,List<&2,U32>>,Work,W.wire_random_bytes(32),random => retry_random(pipe,config,message,transcript,session,suite,group,random))
    case _ N.Choice{_,_,Nil{},_,_}: failure(pipe,Transport.Error{47,"retry-missing-share",True{}})
    case _ choice: negotiate_flight(pipe,transcript,choice,session,config,scheme)

def hello_appended(pipe: Transport.Pipe, config: Config, +first: List<&2,U32>, +cookie: List<&2,U32>, +message: List<&2,U32>, +session: List<&2,U32>, +scheme: U32, +choice: N.Choice, transcript: Maybe<&1,X.Transcript>) -> IO(Work):
  match transcript:
    case None{}: failure(pipe,Transport.Error{80,"transcript",True{}})
    case Some{transcript}: hello_choice(pipe,config,transcript,first,cookie,message,session,scheme,choice)

def hello_retry_checked(+valid: Bool, pipe: Transport.Pipe, config: Config, transcript: X.Transcript, +first: List<&2,U32>, +cookie: List<&2,U32>, +message: List<&2,U32>, +session: List<&2,U32>, +scheme: U32, +choice: N.Choice) -> IO(Work):
  match valid:
    case False{}: failure(pipe,Transport.Error{47,"client-hello-retry-change-or-cookie",True{}})
    case True{}: hello_appended(pipe,config,first,cookie,message,session,scheme,choice,X.append(transcript,message))

def hello_negotiated(pipe: Transport.Pipe, config: Config, transcript: X.Transcript, +first: List<&2,U32>, +cookie: List<&2,U32>, +message: List<&2,U32>, +scheme: U32, choice: Result<&2,&2,U32,N.Choice>, hello: Result<&2,&2,H.Error,H.Hello>) -> IO(Work):
  match first choice hello:
    case _ Fail{code} _: failure(pipe,Transport.Error{code,"client-hello-negotiation",True{}})
    case Nil{} Done{choice} Done{H.Client{_,session,_,extensions}}:
      hello_retry_checked(Bool.not(N.present(Client.find(44,extensions))),pipe,config,transcript,[],cookie,message,session,scheme,choice)
    case first Done{N.Choice{suite,+group,share,sni,alpn}} Done{H.Client{_,session,_,_}}:
      hello_retry_checked(N.retry_valid(first,message,cookie,group),pipe,config,transcript,first,cookie,message,session,scheme,N.Choice{suite,group,share,sni,alpn})
    case _ _ _: failure(pipe,Transport.Error{50,"client-hello",True{}})

def scheme(credential: Cred.Credential) -> Cred.Credential & U32:
  match credential:
    case Cred.Credential{leaf,P.P256{scalar,public}}: (Cred.Credential{leaf,P.P256{scalar,public}},1027)
    case Cred.Credential{leaf,P.Rsa{key}}: (Cred.Credential{leaf,P.Rsa{key}},2052)

def hello_scheme(pipe: Transport.Pipe, +intermediates: List<&2,List<&2,U32>>, +policy: N.Policy, +at: Nat, transcript: X.Transcript, +first: List<&2,U32>, +cookie: List<&2,U32>, +message: List<&2,U32>, pair: Cred.Credential & U32) -> IO(Work):
  (credential,+scheme) = pair
  hello_negotiated(pipe,Config{credential,intermediates,policy,at},transcript,first,cookie,message,scheme,N.negotiate(policy,scheme,message),H.parse(message))

def hello_message(config: Config, transcript: X.Transcript, +first: List<&2,U32>, +cookie: List<&2,U32>, work: MessageWork) -> IO(Work):
  match config work:
    case _ Message{pipe,Fail{error}}: failure(pipe,error)
    case Config{credential,intermediates,policy,at} Message{pipe,Done{message}}:
      hello_scheme(pipe,intermediates,policy,at,transcript,first,cookie,message,scheme(credential))
    case _ Reading{pipe}: failure(pipe,Transport.Error{80,"handshake-read-budget",True{}})

def exhausted(pipe: Transport.Pipe) -> IO(Result<&2,&1,Transport.Error,Connection>):
  do IO<Result<&2,&1,Transport.Error,Connection>>:
    Transport.abort(pipe,Transport.Error{80,"handshake-budget",True{}})
    IO.pure(Result<&2,&1,Transport.Error,Connection>,Fail{Transport.Error{80,"handshake-budget",True{}}})

def handshake_loop(+fuel: Nat, work: Work) -> IO(Result<&2,&1,Transport.Error,Connection>):
  match fuel work:
    case _ Complete{result}: IO.pure(Result<&2,&1,Transport.Error,Connection>,result)
    case 0n Hello{pipe,_,_,_,_}: exhausted(pipe)
    case 0n Finished{pipe,_,_,_,_}: exhausted(pipe)
    case 1n+p Hello{pipe,config,transcript,+first,cookie}:
      do IO<Result<&2,&1,Transport.Error,Connection>>:
        message : MessageWork <- next_message(pipe,Bool.not(Nat.is_eq(B.length(first),0n)))
        next : Work <- hello_message(config,transcript,first,cookie,message)
        handshake_loop(p,next)
    case 1n+p Finished{pipe,cf,hash,read,choice}:
      do IO<Result<&2,&1,Transport.Error,Connection>>:
        message : MessageWork <- next_message(pipe,True{})
        next : Work <- finished_message(cf,hash,read,choice,message)
        handshake_loop(p,next)

def accept_valid(valid: Bool, socket: Socket, config: Config) -> IO(Result<&2,&1,Transport.Error,Connection>):
  match valid:
    case False{}:
      do IO<Result<&2,&1,Transport.Error,Connection>>:
        Socket.close(socket)
        IO.pure(Result<&2,&1,Transport.Error,Connection>,Fail{Transport.Error{80,"invalid-server-policy",False{}}})
    case True{}:
      match config:
        case Config{credential,intermediates,policy,+at}:
          handshake_loop(4n,Hello{Transport.Pipe{socket,None{},None{},HS.start(),at},Config{credential,intermediates,policy,at},X.start(),[],[]})

def accept(socket: Socket, config: Config) -> IO(Result<&2,&1,Transport.Error,Connection>):
  match config:
    case Config{credential,intermediates,+policy,at}: accept_valid(policy_valid(policy),socket,Config{credential,intermediates,policy,at})

def wrapped(+sni: List<&2,U32>, value: Result<&2,&1,Transport.Error,Transport.Connection>) -> IO(Result<&2,&1,Transport.Error,Connection>):
  match value:
    case Fail{error}: IO.pure(Result<&2,&1,Transport.Error,Connection>,Fail{error})
    case Done{connection}: IO.pure(Result<&2,&1,Transport.Error,Connection>,Done{Connection{connection,sni}})

def send(connection: Connection, +bytes: List<&2,U32>) -> IO(Result<&2,&1,Transport.Error,Connection>):
  match connection:
    case Connection{connection,sni}: IO.bind(Result<&2,&1,Transport.Error,Transport.Connection>,Result<&2,&1,Transport.Error,Connection>,Transport.send(connection,bytes),value => wrapped(sni,value))

def key_update(connection: Connection, +request: Bool) -> IO(Result<&2,&1,Transport.Error,Connection>):
  match connection:
    case Connection{connection,sni}: IO.bind(Result<&2,&1,Transport.Error,Transport.Connection>,Result<&2,&1,Transport.Error,Connection>,Transport.key_update(connection,request),value => wrapped(sni,value))

def received(+sni: List<&2,U32>, value: Result<&2,&1,Transport.Error,Transport.Received>) -> IO(Result<&2,&1,Transport.Error,Received>):
  match value:
    case Fail{error}: IO.pure(Result<&2,&1,Transport.Error,Received>,Fail{error})
    case Done{Transport.Received{connection,bytes}}: IO.pure(Result<&2,&1,Transport.Error,Received>,Done{Received{Connection{connection,sni},bytes}})

def recv(connection: Connection) -> IO(Result<&2,&1,Transport.Error,Received>):
  match connection:
    case Connection{connection,sni}: IO.bind(Result<&2,&1,Transport.Error,Transport.Received>,Result<&2,&1,Transport.Error,Received>,Transport.recv_server(connection),value => received(sni,value))

def deadline(connection: Connection, +at: Nat) -> Connection:
  match connection:
    case Connection{connection,sni}: Connection{Transport.deadline(connection,at),sni}

def close(connection: Connection) -> IO(Unit):
  match connection:
    case Connection{connection,_}: Transport.close(connection)
