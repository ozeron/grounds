import Base
import ./wire.bend as W
import ./tls_handshake_codec.bend as C
import ./tls_server_handshake.bend as N
import ./tls_client.bend as Client
import ./tls_transcript.bend as X
import ./tls_schedule.bend as S
import ./tls_certificate_verify.bend as V
import ../crypto/private_key.bend as P
import ../crypto/rsa_private.bend as RSA
import ../crypto/rsa_integer.bend as PublicRSA
import ../crypto/traffic.bend as T
import ../crypto/bytes.bend as B

# All snapshots/epochs are taken at their TLS 1.3 transcript boundaries.
# Credential, ECDHE, signing and Finished owners are consumed on every result.
type Keys is Type:
  Keys{read: T.ReadKey, write: T.WriteKey, next: S.ToApplication, client: S.FinishedKey, server: S.FinishedKey}

type EndKeys is Type:
  EndKeys{read: T.ReadKey, write: T.WriteKey, next: S.ToApplication, client: S.FinishedKey}

type Work is Type:
  Work{transcript: X.Transcript, keys: Keys, hello: List<&2,U32>, bytes: List<&2,U32>, choice: N.Choice}

type Flight is Type:
  Flight{hello: List<&2,U32>, bytes: List<&2,U32>, read: T.ReadKey, write: T.WriteKey, app_read: T.ReadKey, app_write: T.WriteKey, finished: S.FinishedKey, hash: List<&2,U32>, choice: N.Choice}

def appended_transcript(value: Maybe<&1,X.Transcript>, keys: Keys, +hello: List<&2,U32>, +bytes: List<&2,U32>, +choice: N.Choice) -> Maybe<&1,Work>:
  match value:
    case None{}: None{}
    case Some{transcript}: Some{Work{transcript,keys,hello,bytes,choice}}

def appended(work: Work, encoded: Maybe<&2,List<&2,U32>>) -> Maybe<&1,Work>:
  match work encoded:
    case Work{transcript,keys,hello,bytes,choice} Some{+message}:
      appended_transcript(X.append(transcript,message),keys,hello,B.append(bytes,message),choice)
    case _ _: None{}

def ee(+alpn: Bool, +sni: List<&2,U32>) -> List<&2,U32>:
  B.append(Bool.pick(List<&2,U32>,alpn,C.extension(16,C.vector16(Con{8,Client.http11()})),[]),
    Bool.pick(List<&2,U32>,Nat.is_eq(B.length(sni),0n),[],C.extension(0,[])))

def append_certificate(work: Maybe<&1,Work>, +chain: List<&2,List<&2,U32>>) -> Maybe<&1,Work>:
  match work:
    case None{}: None{}
    case Some{work}: appended(work,C.certificate([],chain))

def signed_entropy(key: RSA.Private, +hash: List<&2,U32>, salt: Result<&1,&1,U32 & String,List<&2,U32>>, blind: Result<&1,&1,U32 & String,List<&2,U32>>) -> Maybe<&1,List<&2,U32>>:
  match salt blind:
    case Done{salt} Done{blind}: V.sign_rsa(key,V.Server{},hash,salt,blind)
    case _ _: None{}

def blind_candidate(valid: Bool, key: RSA.Private, hash: List<&2,U32>, blind: List<&2,U32>, next: RSA.Private -> List<&2,U32> -> IO(Maybe<&1,List<&2,U32>>)) -> IO(Maybe<&1,List<&2,U32>>):
  match valid:
    case False{}: next(key,hash)
    case True{}:
      do IO<Maybe<&1,List<&2,U32>>>:
        salt : Result<&1,&1,U32 & String,List<&2,U32>> <- W.wire_random_bytes(32)
        IO.pure(Maybe<&1,List<&2,U32>>,signed_entropy(key,hash,salt,Done{blind}))

def blind_drawn(key: RSA.Private, +n: List<&2,U32>, hash: List<&2,U32>, value: Result<&1,&1,U32 & String,List<&2,U32>>, next: RSA.Private -> List<&2,U32> -> IO(Maybe<&1,List<&2,U32>>)) -> IO(Maybe<&1,List<&2,U32>>):
  match value:
    case Fail{_}: IO.pure(Maybe<&1,List<&2,U32>>,None{})
    case Done{+blind}: blind_candidate(Bool.and(PublicRSA.less(PublicRSA.encode(B.length(n),PublicRSA.one()),blind),PublicRSA.less(blind,n)),key,hash,blind,next)

# Rejection-sample entropy against the PUBLIC modulus before handing the
# private owner to its one signing attempt. No reduction bias or key retry.
# A signing/inverse/fault failure still consumes the owner and aborts.
def blind_loop(fuel: Nat, key: RSA.Private, +hash: List<&2,U32>) -> IO(Maybe<&1,List<&2,U32>>):
  match fuel key:
    case 0n _: IO.pure(Maybe<&1,List<&2,U32>>,None{})
    case 1n+p RSA.Private{+n,e,d,a,b,dp,dq,qi}:
      IO.bind(Result<&1,&1,U32 & String,List<&2,U32>>,Maybe<&1,List<&2,U32>>,W.wire_random_bytes(U32.from_nat(B.length(n))),
        value => blind_drawn(RSA.Private{n,e,d,a,b,dp,dq,qi},n,hash,value,k => h => blind_loop(p,k,h)))

def sign(key: P.Private, +hash: List<&2,U32>) -> IO(Maybe<&1,List<&2,U32>>):
  match key:
    case P.P256{scalar,_}: IO.pure(Maybe<&1,List<&2,U32>>,V.sign_ecdsa(V.EcdsaPrivate{scalar},V.Server{},hash))
    case P.Rsa{key}: blind_loop(32n,key,hash)

def final_keys(+hello: List<&2,U32>, +bytes: List<&2,U32>, read: T.ReadKey, write: T.WriteKey, cf: S.FinishedKey, +hash: List<&2,U32>, +choice: N.Choice, app_read: Maybe<&1,T.ReadKey>, app_write: Maybe<&1,T.WriteKey>) -> Maybe<&1,Flight>:
  match app_read app_write:
    case Some{app_read} Some{app_write}: Some{Flight{hello,bytes,read,write,app_read,app_write,cf,hash,choice}}
    case _ _: None{}

def final_traffic(+hello: List<&2,U32>, +bytes: List<&2,U32>, read: T.ReadKey, write: T.WriteKey, cf: S.FinishedKey, +hash: List<&2,U32>, +choice: N.Choice, value: Maybe<&1,S.ApplicationTraffic>) -> Maybe<&1,Flight>:
  match choice value:
    case N.Choice{+suite,group,share,sni,alpn} Some{S.ApplicationTraffic{client,server}}:
      final_keys(hello,bytes,read,write,cf,hash,N.Choice{suite,group,share,sni,alpn},Client.new_read(suite,client),Client.new_write(suite,server))
    case _ _: None{}

def final_snapshot(keys: EndKeys, +hello: List<&2,U32>, +bytes: List<&2,U32>, +choice: N.Choice, hash: Maybe<&2,List<&2,U32>>) -> Maybe<&1,Flight>:
  match keys hash:
    case EndKeys{read,write,next,cf} Some{+hash}: final_traffic(hello,bytes,read,write,cf,hash,choice,S.application(next,hash))
    case _ _: None{}

def final_transcript(transcript: Maybe<&1,X.Transcript>, keys: EndKeys, +hello: List<&2,U32>, +bytes: List<&2,U32>, +choice: N.Choice) -> Maybe<&1,Flight>:
  match transcript:
    case None{}: None{}
    case Some{transcript}: final_snapshot(keys,hello,bytes,choice,X.finish(transcript))

def final_encoded(transcript: X.Transcript, keys: EndKeys, +hello: List<&2,U32>, +bytes: List<&2,U32>, +choice: N.Choice, message: Maybe<&2,List<&2,U32>>) -> Maybe<&1,Flight>:
  match message:
    case None{}: None{}
    case Some{+message}: final_transcript(X.append(transcript,message),keys,hello,B.append(bytes,message),choice)

def finished_data(transcript: X.Transcript, keys: EndKeys, +hello: List<&2,U32>, +bytes: List<&2,U32>, +choice: N.Choice, data: Maybe<&2,List<&2,U32>>) -> Maybe<&1,Flight>:
  match data:
    case None{}: None{}
    case Some{data}: final_encoded(transcript,keys,hello,bytes,choice,C.finished(data))

def finished_hash(keys: Keys, +hello: List<&2,U32>, +bytes: List<&2,U32>, +choice: N.Choice, snapshot: X.Transcript & Maybe<&2,List<&2,U32>>) -> Maybe<&1,Flight>:
  match keys:
    case Keys{read,write,next,cf,sf}:
      (transcript,hash) = snapshot
      match hash:
        case Some{hash}: finished_data(transcript,EndKeys{read,write,next,cf},hello,bytes,choice,S.finished(sf,hash))
        case _: None{}

def finish(work: Maybe<&1,Work>) -> Maybe<&1,Flight>:
  match work:
    case None{}: None{}
    case Some{Work{transcript,keys,hello,bytes,choice}}: finished_hash(keys,hello,bytes,choice,X.snapshot(transcript))

def signed(work: Work, +scheme: U32, signature: Maybe<&1,List<&2,U32>>) -> IO(Maybe<&1,Flight>):
  match signature:
    case None{}: IO.pure(Maybe<&1,Flight>,None{})
    case Some{signature}: IO.pure(Maybe<&1,Flight>,finish(appended(work,C.certificate_verify(scheme,signature))))

def sign_snapshot(keys: Keys, +hello: List<&2,U32>, +bytes: List<&2,U32>, +choice: N.Choice, key: P.Private, +scheme: U32, snapshot: X.Transcript & Maybe<&2,List<&2,U32>>) -> IO(Maybe<&1,Flight>):
  (transcript,hash) = snapshot
  match hash:
    case None{}: IO.pure(Maybe<&1,Flight>,None{})
    case Some{hash}:
      IO.bind(Maybe<&1,List<&2,U32>>,Maybe<&1,Flight>,sign(key,hash),signature => signed(Work{transcript,keys,hello,bytes,choice},scheme,signature))

def sign_work(work: Maybe<&1,Work>, key: P.Private, +scheme: U32) -> IO(Maybe<&1,Flight>):
  match work:
    case None{}: IO.pure(Maybe<&1,Flight>,None{})
    case Some{Work{transcript,keys,hello,bytes,choice}}: sign_snapshot(keys,hello,bytes,choice,key,scheme,X.snapshot(transcript))

def installed(transcript: X.Transcript, next: S.ToApplication, cf: S.FinishedKey, sf: S.FinishedKey, +hello: List<&2,U32>, +choice: N.Choice, +chain: List<&2,List<&2,U32>>, key: P.Private, +scheme: U32, read: Maybe<&1,T.ReadKey>, write: Maybe<&1,T.WriteKey>) -> IO(Maybe<&1,Flight>):
  match choice read write:
    case N.Choice{suite,group,share,+sni,+alpn} Some{read} Some{write}:
      sign_work(append_certificate(appended(Work{transcript,Keys{read,write,next,cf,sf},hello,[],N.Choice{suite,group,share,sni,alpn}},C.encrypted_extensions(ee(alpn,sni))),chain),key,scheme)
    case _ _ _: IO.pure(Maybe<&1,Flight>,None{})

def scheduled(transcript: X.Transcript, +hello: List<&2,U32>, +choice: N.Choice, +chain: List<&2,List<&2,U32>>, key: P.Private, +scheme: U32, schedule: Maybe<&1,S.Handshake>) -> IO(Maybe<&1,Flight>):
  match choice schedule:
    case N.Choice{+suite,group,share,sni,alpn} Some{S.Handshake{next,S.HandshakeTraffic{client,server},cf,sf}}:
      installed(transcript,next,cf,sf,hello,N.Choice{suite,group,share,sni,alpn},chain,key,scheme,Client.new_read(suite,client),Client.new_write(suite,server))
    case _ _: IO.pure(Maybe<&1,Flight>,None{})

def schedule_hash(+hello: List<&2,U32>, +choice: N.Choice, +chain: List<&2,List<&2,U32>>, key: P.Private, +scheme: U32, +shared: List<&2,U32>, snapshot: X.Transcript & Maybe<&2,List<&2,U32>>) -> IO(Maybe<&1,Flight>):
  (transcript,hash) = snapshot
  match hash:
    case None{}: IO.pure(Maybe<&1,Flight>,None{})
    case Some{hash}: scheduled(transcript,hello,choice,chain,key,scheme,S.start(shared,hash))

def schedule_hello(transcript: Maybe<&1,X.Transcript>, +hello: List<&2,U32>, +choice: N.Choice, +chain: List<&2,List<&2,U32>>, key: P.Private, +scheme: U32, +shared: List<&2,U32>) -> IO(Maybe<&1,Flight>):
  match transcript:
    case None{}: IO.pure(Maybe<&1,Flight>,None{})
    case Some{transcript}: schedule_hash(hello,choice,chain,key,scheme,shared,X.snapshot(transcript))

def hello_encoded(transcript: X.Transcript, +choice: N.Choice, +chain: List<&2,List<&2,U32>>, key: P.Private, +scheme: U32, +shared: List<&2,U32>, hello: Maybe<&2,List<&2,U32>>) -> IO(Maybe<&1,Flight>):
  match hello:
    case None{}: IO.pure(Maybe<&1,Flight>,None{})
    case Some{+hello}: schedule_hello(X.append(transcript,hello),hello,choice,chain,key,scheme,shared)

def start(transcript: X.Transcript, +choice: N.Choice, +session: List<&2,U32>, +chain: List<&2,List<&2,U32>>, key: P.Private, +scheme: U32, +shared: List<&2,U32>, +random: List<&2,U32>, +public: List<&2,U32>) -> IO(Maybe<&1,Flight>):
  match choice:
    case N.Choice{+suite,+group,share,sni,alpn}:
      hello_encoded(transcript,N.Choice{suite,group,share,sni,alpn},chain,key,scheme,shared,
        C.hello_server(random,session,suite,B.append(C.extension(43,[3,4]),C.extension(51,B.append([U32.shrn(group,8n),U32.and(group,255)],C.vector16(public))))))
