import Base
import ./tls_handshake_codec.bend as C
import ./tls_hello.bend as H
import ./tls_extensions.bend as E
import ./tls_key_share.bend as K
import ./tls_transcript.bend as X
import ./tls_schedule.bend as S
import ./tls_certificate_verify.bend as V
import ../crypto/traffic.bend as T
import ../crypto/bytes.bend as B
import ../crypto/x509_chain.bend as A
import ../crypto/x509_certificate.bend as Cert
import ../crypto/x509_public_key.bend as Pub
import ../crypto/unicode32_prepare.bend as U

# Certificate/ECDHE client, TLS 1.3 only. Every transition consumes its state.
# Exact encoded messages, never records/CCS, enter the transcript. Socket and
# record-boundary enforcement belong to bend_tls_client. Synthetic keys only.
type Auth is Type:
  Auth{tables: U.Tables, anchors: List<&2, List<&2, U32>>, identity: A.Identity, now: Nat, alpn: Bool}

type Keys is Type:
  Keys{next: S.ToApplication, client: S.FinishedKey, server: S.FinishedKey}

type State is Type:
  Hello{auth: Auth, transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, random: List<&2,U32>, group: U32, retry_suite: U32}
  Flight{auth: Auth, transcript: X.Transcript, keys: Keys, phase: U32, requested: Bool, leaf: List<&2,U32>, suite: U32, group: U32, alpn: Bool}

type Action is Type:
  Failed{alert: U32, reason: String}
  Continue{state: State}
  Retry{auth: Auth, transcript: X.Transcript, private: Maybe<&1,K.Ephemeral>, public: List<&2,U32>, random: List<&2,U32>, group: U32, suite: U32, cookie: List<&2,U32>}
  SendHello{state: State, bytes: List<&2,U32>}
  Install{state: State, read: T.ReadKey, write: T.WriteKey}
  Complete{read: T.ReadKey, write: T.WriteKey, last_flight: List<&2,U32>, suite: U32, group: U32, alpn: Bool}

def find_selected(equal: Bool, bytes: List<&2,U32>, next: Maybe<&2,List<&2,U32>>) -> Maybe<&2,List<&2,U32>>:
  match equal:
    case True{}: Some{bytes}
    case False{}: next

def find(+kind: U32, values: List<&2,E.Extension>) -> Maybe<&2,List<&2,U32>>:
  match values:
    case Nil{}: None{}
    case Con{E.Extension{other, bytes}, rest}: find_selected(U32.is_eq(kind, other),bytes,find(kind,rest))

def offered_alpn(alpn: Bool, sni: List<&2,U32>) -> List<&2,U32>:
  match alpn:
    case True{}: Con{16,sni}
    case False{}: sni

def offered(identity: A.Identity, alpn: Bool) -> List<&2,U32>:
  match identity:
    case A.Dns{_}: offered_alpn(alpn,[0,10,13,43,50,51])
    case A.Ip{_}: offered_alpn(alpn,[10,13,43,50,51])

def http11() -> List<&2,U32>:
  [104,116,116,112,47,49,46,49]

def extensions_cookie(cookie: List<&2,U32>, protocols: List<&2,U32>) -> List<&2,U32>:
  match cookie:
    case Nil{}: protocols
    case bytes: B.append(protocols,C.extension(44,bytes))

def extensions_alpn(alpn: Bool, sni: List<&2,U32>, cookie: List<&2,U32>) -> List<&2,U32>:
  match alpn:
    case True{}: extensions_cookie(cookie,B.append(C.extension(16,C.vector16(Con{8,http11()})),sni))
    case False{}: extensions_cookie(cookie,sni)

def extensions_sni(identity: A.Identity, alpn: Bool, base: List<&2,U32>, cookie: List<&2,U32>) -> List<&2,U32>:
  match identity:
    case A.Dns{name}: extensions_alpn(alpn,B.append(C.extension(0,C.vector16(Con{0,C.vector16(name)})),base),cookie)
    case A.Ip{_}: extensions_alpn(alpn,base,cookie)

def extensions(identity: A.Identity, alpn: Bool, +group: U32, public: List<&2,U32>, cookie: List<&2,U32>) -> List<&2,U32>:
  base = B.append(C.extension(43,[2,3,4]), B.append(C.extension(10,[0,4,0,29,0,23]),
    B.append(C.extension(13,[0,4,4,3,8,4]), B.append(C.extension(50,[0,8,4,3,8,4,8,9,4,1]),
      C.extension(51,C.vector16(B.append([U32.shrn(group,8n),U32.and(group,255)],C.vector16(public))))))))
  extensions_sni(identity,alpn,base,cookie)

def hello_encoded(auth: Auth, transcript: Maybe<&1,X.Transcript>, private: K.Ephemeral,
  public: List<&2,U32>, random: List<&2,U32>, group: U32, retry_suite: U32, bytes: Maybe<&2,List<&2,U32>>) -> Action:
  match transcript bytes:
    case Some{transcript} Some{bytes}: SendHello{Hello{auth,transcript,private,public,random,group,retry_suite},bytes}
    case _ _: Failed{80,"hello-encoding"}

def hello_bytes(auth: Auth, transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, random: List<&2,U32>, group: U32, retry_suite: U32, bytes: Maybe<&2,List<&2,U32>>) -> Action:
  match bytes:
    case None{}: Failed{80,"hello-encoding"}
    case Some{+bytes}: hello_encoded(auth,X.append(transcript,bytes),private,public,random,group,retry_suite,Some{bytes})

def hello(auth: Auth, transcript: X.Transcript, private: K.Ephemeral, +public: List<&2,U32>, +random: List<&2,U32>, +group: U32, retry_suite: U32, cookie: List<&2,U32>) -> Action:
  match auth:
    case Auth{tables,+anchors,+identity,+now,+alpn}:
      hello_bytes(Auth{tables,anchors,identity,now,alpn},transcript,private,public,random,group,retry_suite,
        C.hello_client(random,[],extensions(identity,alpn,group,public,cookie)))

def start(auth: Auth, random: List<&2,U32>, offer: K.Offer) -> Action:
  match offer:
    case K.Offer{private,public}: hello(auth,X.start(),private,public,random,29,0,[])

def retry_offer(auth: Auth, transcript: X.Transcript, random: List<&2,U32>, group: U32, suite: U32, cookie: List<&2,U32>, offer: Maybe<&1,K.Offer>) -> Action:
  match offer:
    case None{}: Failed{80,"key-generation"}
    case Some{K.Offer{private,public}}: hello(auth,transcript,private,public,random,group,suite,cookie)

def new_read(suite: U32, secret: List<&2,U32>) -> Maybe<&1,T.ReadKey>:
  match suite:
    case 4865: T.new_aes128_read(secret)
    case 4867: T.new_read(secret)
    case _: None{}

def new_write(suite: U32, secret: List<&2,U32>) -> Maybe<&1,T.WriteKey>:
  match suite:
    case 4865: T.new_aes128_write(secret)
    case 4867: T.new_write(secret)
    case _: None{}

def installed(state: State, read: Maybe<&1,T.ReadKey>, write: Maybe<&1,T.WriteKey>) -> Action:
  match read write:
    case Some{read} Some{write}: Install{state,read,write}
    case _ _: Failed{80,"handshake-keys"}

def schedule(auth: Auth, transcript: X.Transcript, +suite: U32, group: U32, value: Maybe<&1,S.Handshake>) -> Action:
  match value:
    case None{}: Failed{80,"handshake-schedule"}
    case Some{S.Handshake{next,S.HandshakeTraffic{client,server},cf,sf}}:
      installed(Flight{auth,transcript,Keys{next,cf,sf},8,False{},[],suite,group,False{}},new_read(suite,server),new_write(suite,client))

def agreed_snapshot(auth: Auth, suite: U32, group: U32, shared: List<&2,U32>, snapshot: X.Transcript & Maybe<&2,List<&2,U32>>) -> Action:
  (transcript,hash) = snapshot
  match hash:
    case None{}: Failed{80,"transcript"}
    case Some{hash}: schedule(auth,transcript,suite,group,S.start(shared,hash))

def agreed(auth: Auth, transcript: X.Transcript, suite: U32, group: U32, value: Maybe<&1,List<&2,U32>>) -> Action:
  match value:
    case None{}: Failed{47,"invalid-key-share"}
    case Some{shared}: agreed_snapshot(auth,suite,group,shared,X.snapshot(transcript))

def server_share_valid(valid: Bool, auth: Auth, transcript: X.Transcript, private: K.Ephemeral, suite: U32, group: U32, peer: List<&2,U32>) -> Action:
  match valid:
    case False{}: Failed{47,"server-key-share"}
    case True{}: agreed(auth,transcript,suite,group,K.shared(private,peer))

def server_share(auth: Auth, transcript: Maybe<&1,X.Transcript>, private: K.Ephemeral, suite: U32, +group: U32, data: Maybe<&2,List<&2,U32>>) -> Action:
  match transcript data:
    case Some{transcript} Some{Con{high,Con{low,Con{a,Con{b,+peer}}}}}:
      server_share_valid(Bool.and(U32.is_eq(E.number(high,low),group),Nat.is_eq(U32.to_nat(E.number(a,b)),B.length(peer))),auth,transcript,private,suite,group,peer)
    case _ _: Failed{109,"missing-key-share"}

def cookie_valid(bytes: List<&2,U32>) -> Bool:
  match bytes:
    case Con{a,Con{b,+body}}: Bool.and(Nat.is_gt(B.length(body),0n),Nat.is_eq(U32.to_nat(E.number(a,b)),B.length(body)))
    case _: False{}

def retry_valid(valid: Bool, auth: Auth, transcript: Maybe<&1,X.Transcript>, private: Maybe<&1,K.Ephemeral>, public: List<&2,U32>, random: List<&2,U32>, group: U32, suite: U32, cookie: List<&2,U32>) -> Action:
  match valid transcript:
    case True{} Some{transcript}: Retry{auth,transcript,private,public,random,group,suite,cookie}
    case _ _: Failed{47,"retry-parameters"}

def retry_cookie(auth: Auth, transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, random: List<&2,U32>, group: U32, suite: U32, message: List<&2,U32>, selected: Maybe<&2,List<&2,U32>>, cookie: Maybe<&2,List<&2,U32>>) -> Action:
  match selected cookie:
    case Some{[0,23]} None{}:
      retry_valid(U32.is_eq(group,29),auth,X.append(transcript,message),None{},[],random,23,suite,[])
    case Some{[0,23]} Some{+cookie}:
      retry_valid(Bool.and(U32.is_eq(group,29),cookie_valid(cookie)),auth,X.append(transcript,message),None{},[],random,23,suite,cookie)
    case None{} Some{+cookie}:
      retry_valid(cookie_valid(cookie),auth,X.append(transcript,message),Some{private},public,random,group,suite,cookie)
    case _ _: Failed{47,"unnecessary-or-invalid-retry"}

def hello_choice(valid: Bool, retry: Bool, auth: Auth, transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, random: List<&2,U32>, group: U32, retry_suite: U32, suite: U32, +extensions: List<&2,E.Extension>, message: List<&2,U32>) -> Action:
  match valid retry:
    case False{} _: Failed{47,"server-selection"}
    case True{} True{}:
      match retry_suite:
        case 0: retry_cookie(auth,transcript,private,public,random,group,suite,message,find(51,extensions),find(44,extensions))
        case _: Failed{10,"second-hello-retry-request"}
    case True{} False{}: server_share(auth,X.append(transcript,message),private,suite,group,find(51,extensions))

def hello_version(auth: Auth, transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, random: List<&2,U32>, group: U32, +retry_suite: U32, +suite: U32, extensions: List<&2,E.Extension>, message: List<&2,U32>, retry: Bool, version: Maybe<&2,List<&2,U32>>) -> Action:
  match version:
    case None{}: Failed{70,"missing-supported-versions"}
    case Some{[3,4]}:
      hello_choice(Bool.and(Bool.or(U32.is_eq(suite,4865),U32.is_eq(suite,4867)),Bool.or(U32.is_eq(retry_suite,0),U32.is_eq(retry_suite,suite))),retry,auth,transcript,private,public,random,group,retry_suite,suite,extensions,message)
    case _: Failed{47,"server-version"}

def hello_extensions(error: Maybe<&2,U32>, auth: Auth, transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, random: List<&2,U32>, group: U32, retry_suite: U32, +suite: U32, +extensions: List<&2,E.Extension>, message: List<&2,U32>, retry: Bool) -> Action:
  match error:
    case Some{alert}: Failed{alert,"hello-extensions"}
    case None{}: hello_version(auth,transcript,private,public,random,group,retry_suite,suite,extensions,message,retry,find(43,extensions))

def server_hello(auth: Auth, transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, random: List<&2,U32>, group: U32, retry_suite: U32, value: H.Hello, message: List<&2,U32>) -> Action:
  match value:
    case H.Server{+server_random,Nil{},suite,+extensions}:
      +retry = H.same(server_random,H.retry_random(),True{})
      context = Bool.pick(U32,retry,6,2)
      hello_extensions(C.validate_extensions(context,[43,51],extensions),auth,transcript,private,public,random,group,retry_suite,suite,extensions,message,retry)
    case _: Failed{47,"session-id-echo"}

def chain_alert(value: A.Verification) -> U32:
  match value:
    case A.Success{}: 0
    case A.Expired{}: 45
    case A.NotYetValid{}: 45
    case A.Untrusted{}: 48
    case A.WrongIssuer{}: 48
    case A.UnsupportedCriticalExtension{}: 43
    case A.UnsupportedNameConstraints{}: 43
    case _: 42

def leaf_key(value: Maybe<&1,Cert.Certificate>) -> Maybe<&1,Pub.PublicKey>:
  match value:
    case Some{Cert.Certificate{Cert.Tbs{_,Cert.Identity{_,_,_,spki},_},_,_}}: Pub.decode(spki)
    case _: None{}

def authenticated(result: U.Tables & A.Verification, anchors: List<&2,List<&2,U32>>, identity: A.Identity, now: Nat, offered_alpn: Bool, transcript: Maybe<&1,X.Transcript>, keys: Keys, requested: Bool, leaf: List<&2,U32>, suite: U32, group: U32, alpn: Bool) -> Action:
  (tables,result) = result
  match result transcript:
    case A.Success{} Some{transcript}: Continue{Flight{Auth{tables,anchors,identity,now,offered_alpn},transcript,keys,15,requested,leaf,suite,group,alpn}}
    case +reason _: Failed{chain_alert(reason),"certificate:" ++ A.show(reason)}

def certificate(auth: Auth, transcript: X.Transcript, keys: Keys, requested: Bool, suite: U32, group: U32, alpn: Bool, +chain: List<&2,List<&2,U32>>, message: List<&2,U32>) -> Action:
  match auth chain:
    case Auth{tables,+anchors,+identity,+now,+offered_alpn} Con{+leaf,_}:
      authenticated(A.verify(tables,chain,anchors,identity,A.ServerAuth{},now),anchors,identity,now,offered_alpn,X.append(transcript,message),keys,requested,leaf,suite,group,alpn)
    case _ _: Failed{50,"empty-server-certificate"}

def continued(auth: Auth, transcript: Maybe<&1,X.Transcript>, keys: Keys, phase: U32, requested: Bool, leaf: List<&2,U32>, suite: U32, group: U32, alpn: Bool) -> Action:
  match transcript:
    case None{}: Failed{80,"transcript"}
    case Some{transcript}: Continue{Flight{auth,transcript,keys,phase,requested,leaf,suite,group,alpn}}

def verified(valid: Bool, auth: Auth, transcript: X.Transcript, keys: Keys, requested: Bool, leaf: List<&2,U32>, suite: U32, group: U32, alpn: Bool, message: List<&2,U32>) -> Action:
  match valid:
    case False{}: Failed{51,"certificate-verify"}
    case True{}: continued(auth,X.append(transcript,message),keys,20,requested,leaf,suite,group,alpn)

def certificate_verify_hash(auth: Auth, snapshot: X.Transcript & Maybe<&2,List<&2,U32>>, keys: Keys, requested: Bool, leaf: List<&2,U32>, suite: U32, group: U32, alpn: Bool, scheme: U32, signature: List<&2,U32>, message: List<&2,U32>, key: Maybe<&1,Pub.PublicKey>) -> Action:
  (transcript,hash) = snapshot
  match hash key:
    case Some{hash} Some{key}: verified(V.verify(scheme,key,V.Server{},hash,signature),auth,transcript,keys,requested,leaf,suite,group,alpn,message)
    case _ _: Failed{42,"certificate-key"}

def certificate_verify_scheme(valid: Bool, auth: Auth, transcript: X.Transcript, keys: Keys, requested: Bool, +leaf: List<&2,U32>, suite: U32, group: U32, alpn: Bool, scheme: U32, signature: List<&2,U32>, message: List<&2,U32>) -> Action:
  match valid:
    case False{}: Failed{47,"unoffered-signature-scheme"}
    case True{}: certificate_verify_hash(auth,X.snapshot(transcript),keys,requested,leaf,suite,group,alpn,scheme,signature,message,leaf_key(Cert.decode(leaf)))

def certificate_verify(auth: Auth, transcript: X.Transcript, keys: Keys, requested: Bool, leaf: List<&2,U32>, suite: U32, group: U32, alpn: Bool, +scheme: U32, signature: List<&2,U32>, message: List<&2,U32>) -> Action:
  certificate_verify_scheme(Bool.or(U32.is_eq(scheme,1027),U32.is_eq(scheme,2052)),auth,transcript,keys,requested,leaf,suite,group,alpn,scheme,signature,message)

def completed(read: Maybe<&1,T.ReadKey>, write: Maybe<&1,T.WriteKey>, bytes: Maybe<&2,List<&2,U32>>, suite: U32, group: U32, alpn: Bool) -> Action:
  match read write bytes:
    case Some{read} Some{write} Some{bytes}: Complete{read,write,bytes,suite,group,alpn}
    case _ _ _: Failed{80,"application-keys"}

def client_finished_encoded(client: List<&2,U32>, server: List<&2,U32>, prefix: List<&2,U32>, +suite: U32, group: U32, alpn: Bool, encoded: Maybe<&2,List<&2,U32>>) -> Action:
  match encoded:
    case None{}: Failed{80,"finished-encoding"}
    case Some{bytes}: completed(new_read(suite,server),new_write(suite,client),Some{B.append(prefix,bytes)},suite,group,alpn)

def client_finished(traffic: Maybe<&1,S.ApplicationTraffic>, data: Maybe<&2,List<&2,U32>>, prefix: List<&2,U32>, +suite: U32, group: U32, alpn: Bool) -> Action:
  match traffic data:
    case Some{S.ApplicationTraffic{client,server}} Some{data}:
      client_finished_encoded(client,server,prefix,suite,group,alpn,C.finished(data))
    case _ _: Failed{80,"finished-schedule"}

def finish_prefix_hash(cf: S.FinishedKey, traffic: Maybe<&1,S.ApplicationTraffic>, prefix: List<&2,U32>, suite: U32, group: U32, alpn: Bool, hash: Maybe<&2,List<&2,U32>>) -> Action:
  match hash:
    case None{}: Failed{80,"transcript"}
    case Some{hash}: client_finished(traffic,S.finished(cf,hash),prefix,suite,group,alpn)

def finish_prefix_updated(cf: S.FinishedKey, traffic: Maybe<&1,S.ApplicationTraffic>, prefix: List<&2,U32>, suite: U32, group: U32, alpn: Bool, updated: Maybe<&1,X.Transcript>) -> Action:
  match updated:
    case None{}: Failed{80,"transcript"}
    case Some{transcript}: finish_prefix_hash(cf,traffic,prefix,suite,group,alpn,X.finish(transcript))

def finish_prefix_append(transcript: X.Transcript, cf: S.FinishedKey, traffic: Maybe<&1,S.ApplicationTraffic>, prefix: List<&2,U32>, suite: U32, group: U32, alpn: Bool) -> Action:
  match prefix:
    case Nil{}: finish_prefix_updated(cf,traffic,[],suite,group,alpn,Some{transcript})
    case +bytes: finish_prefix_updated(cf,traffic,bytes,suite,group,alpn,X.append(transcript,bytes))

def finish_prefix(transcript: X.Transcript, cf: S.FinishedKey, traffic: Maybe<&1,S.ApplicationTraffic>, prefix: Maybe<&2,List<&2,U32>>, suite: U32, group: U32, alpn: Bool) -> Action:
  match prefix:
    case None{}: Failed{80,"certificate-encoding"}
    case Some{prefix}: finish_prefix_append(transcript,cf,traffic,prefix,suite,group,alpn)

def server_finished_snapshot(next: S.ToApplication, cf: S.FinishedKey, requested: Bool, suite: U32, group: U32, alpn: Bool, snapshot: X.Transcript & Maybe<&2,List<&2,U32>>) -> Action:
  (transcript,hash) = snapshot
  match hash:
    case None{}: Failed{80,"transcript"}
    case Some{hash}: finish_prefix(transcript,cf,S.application(next,hash),Bool.pick(Maybe<&2,List<&2,U32>>,requested,C.certificate([],[]),Some{[]}),suite,group,alpn)

def server_finished(valid: Bool, transcript: Maybe<&1,X.Transcript>, next: S.ToApplication, cf: S.FinishedKey, requested: Bool, suite: U32, group: U32, alpn: Bool) -> Action:
  match valid transcript:
    case True{} Some{transcript}: server_finished_snapshot(next,cf,requested,suite,group,alpn,X.snapshot(transcript))
    case _ _: Failed{51,"finished"}

def finished_snapshot(keys: Keys, requested: Bool, suite: U32, group: U32, alpn: Bool, data: List<&2,U32>, message: List<&2,U32>, snapshot: X.Transcript & Maybe<&2,List<&2,U32>>) -> Action:
  match keys:
    case Keys{next,cf,sf}:
      (transcript,hash) = snapshot
      match hash:
        case Some{hash}: server_finished(S.verify_finished(sf,hash,data),X.append(transcript,message),next,cf,requested,suite,group,alpn)
        case None{}: Failed{80,"transcript"}

def finished(transcript: X.Transcript, keys: Keys, requested: Bool, suite: U32, group: U32, alpn: Bool, data: List<&2,U32>, message: List<&2,U32>) -> Action:
  finished_snapshot(keys,requested,suite,group,alpn,data,message,X.snapshot(transcript))

def ee_alpn(auth: Auth, transcript: X.Transcript, keys: Keys, suite: U32, group: U32, message: List<&2,U32>, protocol: Maybe<&2,List<&2,U32>>) -> Action:
  match protocol:
    case None{}: continued(auth,X.append(transcript,message),keys,13,False{},[],suite,group,False{})
    case Some{[0,9,8,104,116,116,112,47,49,46,49]}: continued(auth,X.append(transcript,message),keys,13,False{},[],suite,group,True{})
    case _: Failed{120,"alpn-selection"}

def ee_body_valid(valid: Bool, next: Maybe<&2,U32>) -> Maybe<&2,U32>:
  match valid:
    case True{}: next
    case False{}: Some{50}

def ee_bodies(values: List<&2,E.Extension>) -> Maybe<&2,U32>:
  match values:
    case Nil{}: None{}
    case Con{E.Extension{0,Nil{}},rest}: ee_bodies(rest)
    case Con{E.Extension{10,Con{a,Con{b,+body}}},rest}:
      ee_body_valid(Bool.and(Nat.is_eq(U32.to_nat(E.number(a,b)),B.length(body)),Bool.and(Nat.is_ge(B.length(body),2n),Nat.is_eq(Nat.mod(B.length(body),2n),0n))),ee_bodies(rest))
    case Con{E.Extension{16,_},rest}: ee_bodies(rest)
    case _: Some{50}

def ee_body_checked(error: Maybe<&2,U32>, auth: Auth, transcript: X.Transcript, keys: Keys, suite: U32, group: U32, extensions: List<&2,E.Extension>, message: List<&2,U32>) -> Action:
  match error:
    case Some{code}: Failed{code,"extension-body"}
    case None{}: ee_alpn(auth,transcript,keys,suite,group,message,find(16,extensions))

def ee_checked(error: Maybe<&2,U32>, auth: Auth, transcript: X.Transcript, keys: Keys, suite: U32, group: U32, +extensions: List<&2,E.Extension>, message: List<&2,U32>) -> Action:
  match error:
    case Some{code}: Failed{code,"encrypted-extensions"}
    case None{}: ee_body_checked(ee_bodies(extensions),auth,transcript,keys,suite,group,extensions,message)

def request_schemes(value: Maybe<&2,List<&2,U32>>) -> Bool:
  match value:
    case Some{Con{a,Con{b,+bytes}}}: Bool.and(Nat.is_eq(B.length(bytes),U32.to_nat(E.number(a,b))),Bool.and(Nat.is_ge(B.length(bytes),2n),Nat.is_eq(Nat.mod(B.length(bytes),2n),0n)))
    case _: False{}

def request_valid(valid: Bool, auth: Auth, transcript: X.Transcript, keys: Keys, leaf: List<&2,U32>, suite: U32, group: U32, alpn: Bool, message: List<&2,U32>) -> Action:
  match valid:
    case False{}: Failed{50,"certificate-request-signatures"}
    case True{}: continued(auth,X.append(transcript,message),keys,11,True{},leaf,suite,group,alpn)

def request_found(auth: Auth, transcript: X.Transcript, keys: Keys, leaf: List<&2,U32>, suite: U32, group: U32, alpn: Bool, message: List<&2,U32>, value: Maybe<&2,List<&2,U32>>) -> Action:
  match value:
    case None{}: Failed{109,"certificate-request-signatures"}
    case bytes: request_valid(request_schemes(bytes),auth,transcript,keys,leaf,suite,group,alpn,message)

def ee_auth(auth: Auth, transcript: X.Transcript, keys: Keys, suite: U32, group: U32, +extensions: List<&2,E.Extension>, message: List<&2,U32>) -> Action:
  match auth:
    case Auth{tables,+anchors,+identity,+now,+offer_alpn}: ee_checked(C.validate_extensions(8,offered(identity,offer_alpn),extensions),Auth{tables,anchors,identity,now,offer_alpn},transcript,keys,suite,group,extensions,message)

def request_extensions(error: Maybe<&2,U32>, auth: Auth, transcript: X.Transcript, keys: Keys, leaf: List<&2,U32>, suite: U32, group: U32, alpn: Bool, message: List<&2,U32>, extensions: List<&2,E.Extension>) -> Action:
  match error:
    case Some{code}: Failed{code,"certificate-request-extensions"}
    case None{}: request_found(auth,transcript,keys,leaf,suite,group,alpn,message,find(13,extensions))

def flight(auth: Auth, transcript: X.Transcript, keys: Keys, phase: U32, requested: Bool, leaf: List<&2,U32>, suite: U32, group: U32, alpn: Bool, value: C.Message, message: List<&2,U32>) -> Action:
  match phase value:
    case 8 C.EncryptedExtensions{extensions}: ee_auth(auth,transcript,keys,suite,group,extensions,message)
    case 13 C.CertificateRequest{Nil{},+extensions}:
      request_extensions(C.validate_extensions(13,[],extensions),auth,transcript,keys,leaf,suite,group,alpn,message,extensions)
    case 13 C.Certificate{Nil{},chain}: certificate(auth,transcript,keys,requested,suite,group,alpn,chain,message)
    case 11 C.Certificate{Nil{},chain}: certificate(auth,transcript,keys,requested,suite,group,alpn,chain,message)
    case 13 C.CertificateRequest{_,_}: Failed{47,"certificate-request-context"}
    case 13 C.Certificate{_,_}: Failed{47,"certificate-context"}
    case 11 C.Certificate{_,_}: Failed{47,"certificate-context"}
    case 15 C.CertificateVerify{scheme,signature}: certificate_verify(auth,transcript,keys,requested,leaf,suite,group,alpn,scheme,signature,message)
    case 20 C.Finished{data}: finished(transcript,keys,requested,suite,group,alpn,data,message)
    case _ _: Failed{10,"handshake-order"}

def parsed(state: State, value: Result<&2,&2,U32,C.Message>, message: List<&2,U32>) -> Action:
  match state value:
    case _ Fail{alert}: Failed{alert,"handshake-codec"}
    case Hello{auth,transcript,private,public,random,group,retry_suite} Done{C.ServerHello{hello}}:
      server_hello(auth,transcript,private,public,random,group,retry_suite,hello,message)
    case Hello{_,_,_,_,_,_,_} Done{_}: Failed{10,"expected-server-hello"}
    case Flight{auth,transcript,keys,phase,requested,leaf,suite,group,alpn} Done{value}:
      flight(auth,transcript,keys,phase,requested,leaf,suite,group,alpn,value,message)

def step(state: State, +message: List<&2,U32>) -> Action:
  parsed(state,C.parse(message),message)
