import Base
import ./tls_handshake_codec.bend as C
import ./tls_extensions.bend as E
import ./tls_hello.bend as H
import ./tls_key_share.bend as K
import ./tls_transcript.bend as X
import ./tls12_signature.bend as S
import ../crypto/tls12_prf.bend as P
import ../crypto/traffic.bend as T
import ../crypto/bytes.bend as B
import ../crypto/x509_chain.bend as A
import ../crypto/x509_certificate.bend as Cert
import ../crypto/x509_public_key.bend as Pub
import ../crypto/x509_algorithm.bend as Alg
import ../crypto/unicode32_prepare.bend as U

# TLS 1.2 client handshake (M7): RFC 5246 full handshake with ECDHE and AEAD
# only (RFC 8422, RFC 5288/5289, RFC 7905), RFC 7627 extended master secret
# required, RFC 8446 4.1.3 downgrade sentinels refused, no resumption,
# tickets, renegotiation, compression or client certificates (an empty
# Certificate answers a CertificateRequest). Entered from tls_client when a
# ServerHello carries no supported_versions. Every transition consumes its
# state; exact encoded messages enter the suite-hash transcript. Socket,
# record and ChangeCipherSpec boundaries belong to bend_tls_client.

type Auth is Type:
  Auth{tables: U.Tables, anchors: List<&2,List<&2,U32>>, identity: A.Identity, now: Nat, alpn: Bool}

type Hello is Data:
  Hello{version: U32, random: List<&2,U32>, suite: U32, compression: U32, extensions: List<&2,E.Extension>}

type Randoms is Data:
  Randoms{client: List<&2,U32>, server: List<&2,U32>}

type State is Type:
  Certificate{auth: Auth, transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, randoms: Randoms, suite: U32, alpn: Bool}
  Exchange{transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, randoms: Randoms, suite: U32, alpn: Bool, key: Pub.PublicKey}
  Keyed{transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, peer: List<&2,U32>, randoms: Randoms, suite: U32, group: U32, alpn: Bool, requested: Bool}
  Generating{transcript: X.Transcript, peer: List<&2,U32>, randoms: Randoms, suite: U32, group: U32, alpn: Bool}
  Ccs{expected: List<&2,U32>, read: T.ReadKey, suite: U32, group: U32, alpn: Bool}
  Finish{expected: List<&2,U32>, suite: U32, group: U32, alpn: Bool}

type Action is Type:
  Failed{alert: U32, reason: String}
  Continue{state: State}
  # Generate a fresh P-256 share, then call keyed.
  Keygen{state: State}
  # Send plain (Certificate? ClientKeyExchange) records, ChangeCipherSpec,
  # install write, then send finished under it.
  Flight{state: State, plain: List<&2,U32>, finished: List<&2,U32>, write: T.WriteKey}
  # Server ChangeCipherSpec at a message boundary: install read.
  Read{state: State, read: T.ReadKey}
  Established{suite: U32, group: U32, alpn: Bool}

type Check is Data:
  Pass{}
  Stop{alert: U32, reason: String}

def check(ok: Bool, alert: U32, reason: String, next: Check) -> Check:
  match ok:
    case True{}: next
    case False{}: Stop{alert,reason}

def first(a: Check, b: Check) -> Check:
  match a:
    case Pass{}: b
    case a: a

# ---- suites ----
# ECDHE_ECDSA/RSA with AES_128_GCM_SHA256, CHACHA20_POLY1305_SHA256,
# AES_256_GCM_SHA384, in that preference (as the TLS 1.3 suites).
def suites() -> List<&2,U32>:
  [192,43,192,47,204,169,204,168,192,44,192,48]

def is_suite(+suite: U32) -> Bool:
  C.member(suite,[49195,49199,52393,52392,49196,49200])

def large(+suite: U32) -> Bool:
  Bool.or(U32.is_eq(suite,49196),U32.is_eq(suite,49200))

def chacha(+suite: U32) -> Bool:
  Bool.or(U32.is_eq(suite,52393),U32.is_eq(suite,52392))

def ecdsa(+suite: U32) -> Bool:
  C.member(suite,[49195,49196,52393])

def key_length(+suite: U32) -> Nat:
  Bool.pick(Nat,Bool.or(U32.is_eq(suite,49195),U32.is_eq(suite,49199)),16n,32n)

def iv_length(+suite: U32) -> Nat:
  Bool.pick(Nat,chacha(suite),12n,4n)

def find_selected(equal: Bool, bytes: List<&2,U32>, next: Maybe<&2,List<&2,U32>>) -> Maybe<&2,List<&2,U32>>:
  match equal:
    case True{}: Some{bytes}
    case False{}: next

def find(+kind: U32, values: List<&2,E.Extension>) -> Maybe<&2,List<&2,U32>>:
  match values:
    case Nil{}: None{}
    case Con{E.Extension{other,bytes},rest}: find_selected(U32.is_eq(kind,other),bytes,find(kind,rest))

def present(kind: U32, values: List<&2,E.Extension>) -> Bool:
  Bool.not(Maybe.is_none(&2,List<&2,U32>,find(kind,values)))

# ---- ServerHello ----
def hello.parsed(version: U32, random: List<&2,U32>, suite: U32, compression: U32, value: Maybe<&2,List<&2,E.Extension>>) -> Maybe<&2,Hello>:
  match value:
    case None{}: None{}
    case Some{+extensions}: Bool.pick(Maybe<&2,Hello>,present(43,extensions),None{},Some{Hello{version,random,suite,compression,extensions}})

def hello.extensions(version: U32, random: List<&2,U32>, suite: U32, compression: U32, rest: List<&2,U32>) -> Maybe<&2,Hello>:
  match rest:
    case Nil{}: Some{Hello{version,random,suite,compression,[]}}
    case bytes: hello.parsed(version,random,suite,compression,E.parse(bytes))

def hello.session(valid: Bool, version: U32, random: List<&2,U32>, value: Maybe<&2,E.Parts>) -> Maybe<&2,Hello>:
  match valid value:
    case True{} Some{E.Parts{_,Con{high,Con{low,Con{compression,rest}}}}}: hello.extensions(version,random,E.number(high,low),compression,rest)
    case _ _: None{}

def hello.random(version: U32, value: Maybe<&2,E.Parts>) -> Maybe<&2,Hello>:
  match value:
    case Some{E.Parts{random,Con{+size,rest}}}: hello.session(U32.is_le(size,32),version,random,E.take(U32.to_nat(size),rest,[]))
    case _: None{}

def hello.body(valid: Bool, body: List<&2,U32>) -> Maybe<&2,Hello>:
  match valid body:
    case True{} Con{high,Con{low,rest}}: hello.random(E.number(high,low),E.take(32n,rest,[]))
    case _ _: None{}

# Some only for a well-formed ServerHello without supported_versions; any
# other message keeps the unchanged TLS 1.3 path and its diagnostics.
def hello(message: List<&2,U32>) -> Maybe<&2,Hello>:
  match message:
    case Con{2,Con{a,Con{b,Con{c,+body}}}}: hello.body(Bool.and(B.valid(body),Nat.is_eq(C.length24(a,b,c),B.length(body))),body)
    case _: None{}

def sentinel.tail(value: Maybe<&2,E.Parts>) -> Bool:
  match value:
    case Some{E.Parts{_,+tail}}: Bool.or(H.same(tail,[68,79,87,78,71,82,68,1],True{}),H.same(tail,[68,79,87,78,71,82,68,0],True{}))
    case None{}: False{}

# RFC 8446 4.1.3: DOWNGRD followed by 01 (TLS 1.2) or 00 (TLS 1.1 or below).
def sentinel(random: List<&2,U32>) -> Bool:
  sentinel.tail(E.take(24n,random,[]))

def point_formats(bytes: List<&2,U32>) -> Check:
  match bytes:
    case Con{+size,+formats}:
      check(Bool.and(U32.is_gt(size,0),Nat.is_eq(U32.to_nat(size),B.length(formats))),50,"ec-point-formats",
        check(C.member(0,formats),47,"ec-point-formats",Pass{}))
    case _: Stop{50,"ec-point-formats"}

def alpn_selected(+bytes: List<&2,U32>) -> Check:
  check(C.alpn_field(bytes),50,"alpn",check(H.same(bytes,[0,9,8,104,116,116,112,47,49,46,49],True{}),120,"alpn-selection",Pass{}))

def extension(kind: U32, +data: List<&2,U32>, +sni: Bool, +alpn: Bool) -> Check:
  match kind:
    case 0: check(sni,110,"unsolicited-extension",check(Maybe.is_none(&2,U32,List.head(&2,U32,data)),50,"server-name",Pass{}))
    case 11: point_formats(data)
    case 16: check(alpn,110,"unsolicited-extension",alpn_selected(data))
    case 23: check(Maybe.is_none(&2,U32,List.head(&2,U32,data)),50,"extended-master-secret",Pass{})
    case 65281: check(H.same(data,[0],True{}),40,"renegotiation-info",Pass{})
    case _: Stop{110,"unsolicited-extension"}

def extension_list(values: List<&2,E.Extension>, +sni: Bool, +alpn: Bool) -> Check:
  match values:
    case Nil{}: Pass{}
    case Con{E.Extension{kind,data},rest}: first(extension(kind,data,sni,alpn),extension_list(rest,sni,alpn))

def sni_offered(identity: A.Identity) -> A.Identity & Bool:
  match identity:
    case A.Dns{name}: (A.Dns{name},True{})
    case A.Ip{address}: (A.Ip{address},False{})

def hello_checks(+version: U32, +retry_suite: U32, +random: List<&2,U32>, +suite: U32, +compression: U32, +extensions: List<&2,E.Extension>, sni: Bool, alpn: Bool) -> Check:
  check(U32.is_eq(version,771),70,"server-version",
    check(U32.is_eq(retry_suite,0),70,"missing-supported-versions",
      check(Bool.not(C.member(suite,[4865,4866,4867])),70,"missing-supported-versions",
        check(Bool.not(sentinel(random)),47,"downgrade-sentinel",
          check(Bool.not(H.same(random,H.retry_random(),True{})),47,"server-selection",
            check(is_suite(suite),47,"server-selection",
              check(U32.is_eq(compression,0),47,"compression",
                first(extension_list(extensions,sni,alpn),
                  check(present(23,extensions),40,"extended-master-secret-required",Pass{})))))))))

def hello_transcript(auth: Auth, transcript: Maybe<&1,X.Transcript>, private: K.Ephemeral, public: List<&2,U32>, randoms: Randoms, suite: U32, alpn: Bool) -> Action:
  match transcript:
    case None{}: Failed{80,"transcript"}
    case Some{transcript}: Continue{Certificate{auth,transcript,private,public,randoms,suite,alpn}}

def hello_checked(result: Check, auth: Auth, transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, randoms: Randoms, +suite: U32, alpn: Bool, message: List<&2,U32>) -> Action:
  match result:
    case Stop{alert,reason}: Failed{alert,reason}
    case Pass{}: hello_transcript(auth,X.append(X.select(large(suite),transcript),message),private,public,randoms,suite,alpn)

def hello_identity(pair: A.Identity & Bool, tables: U.Tables, anchors: List<&2,List<&2,U32>>, now: Nat, +offered: Bool, transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, client: List<&2,U32>, retry_suite: U32, value: Hello, message: List<&2,U32>) -> Action:
  (identity,sni) = pair
  match value:
    case Hello{version,+random,+suite,compression,+extensions}:
      hello_checked(hello_checks(version,retry_suite,random,suite,compression,extensions,sni,offered),Auth{tables,anchors,identity,now,offered},
        transcript,private,public,Randoms{client,random},suite,present(16,extensions),message)

def hello_auth(auth: Auth, transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, client: List<&2,U32>, retry_suite: U32, value: Hello, message: List<&2,U32>) -> Action:
  match auth:
    case Auth{tables,anchors,identity,now,offered}:
      hello_identity(sni_offered(identity),tables,anchors,now,offered,transcript,private,public,client,retry_suite,value,message)

# The ClientHello offered TLS 1.3 and 1.2 with an X25519 share; group is the
# share's group (P-256 only after a HelloRetryRequest, which is refused here).
def server_hello(auth: Auth, transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, client: List<&2,U32>, retry_suite: U32, value: Hello, message: List<&2,U32>) -> Action:
  hello_auth(auth,transcript,private,public,client,retry_suite,value,message)

# ---- Certificate (RFC 5246 7.4.2) ----
type Entry is Data:
  End{}
  Bad{}
  Next{certificate: List<&2,U32>, rest: List<&2,U32>}

def entry.split(valid: Bool, value: Maybe<&2,E.Parts>) -> Entry:
  match valid value:
    case True{} Some{E.Parts{certificate,rest}}: Next{certificate,rest}
    case _ _: Bad{}

def entry(bytes: List<&2,U32>) -> Entry:
  match bytes:
    case Nil{}: End{}
    case Con{a,Con{b,Con{c,rest}}}:
      +size = C.length24(a,b,c)
      entry.split(Bool.and(Nat.is_gt(size,0n),Nat.is_le(size,65535n)),C.split(size,rest))
    case _: Bad{}

def chain.go(fuel: Nat, step: Entry, reversed: List<&2,List<&2,U32>>) -> Maybe<&2,List<&2,List<&2,U32>>>:
  match fuel step:
    case _ End{}: Some{List.reverse(&2,List<&2,U32>,reversed)}
    case 1n+p Next{certificate,rest}: chain.go(p,entry(rest),Con{certificate,reversed})
    case _ _: None{}

# At most 16 certificates, each 1..65535 bytes, 512 KiB in all (as TLS 1.3).
def chain.body(valid: Bool, bytes: List<&2,U32>) -> Maybe<&2,List<&2,List<&2,U32>>>:
  match valid:
    case False{}: None{}
    case True{}: chain.go(16n,entry(bytes),[])

def chain(message: List<&2,U32>) -> Maybe<&2,List<&2,List<&2,U32>>>:
  match message:
    case Con{_,Con{a,Con{b,Con{c,Con{x,Con{y,Con{z,+list}}}}}}}:
      chain.body(Bool.and(Nat.is_eq(C.length24(a,b,c),Nat.add(B.length(list),3n)),Bool.and(Nat.is_eq(C.length24(x,y,z),B.length(list)),Nat.is_le(B.length(list),524288n))),list)
    case _: None{}

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

# ECDHE_ECDSA needs a P-256/P-384 leaf, ECDHE_RSA an rsaEncryption leaf.
def key_suite(+suite: U32, key: Pub.PublicKey) -> Bool:
  match key:
    case Pub.P256{_}: ecdsa(suite)
    case Pub.P384{_}: ecdsa(suite)
    case Pub.Rsa{Alg.Rsa{},_,_}: Bool.not(ecdsa(suite))
    case _: False{}

def certificate_suited(valid: Bool, transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, randoms: Randoms, suite: U32, alpn: Bool, key: Pub.PublicKey) -> Action:
  match valid:
    case True{}: Continue{Exchange{transcript,private,public,randoms,suite,alpn,key}}
    case False{}: Failed{43,"certificate-key-suite"}

def certificate_key(transcript: Maybe<&1,X.Transcript>, private: K.Ephemeral, public: List<&2,U32>, randoms: Randoms, +suite: U32, alpn: Bool, value: Maybe<&1,Pub.PublicKey>) -> Action:
  match transcript value:
    case None{} _: Failed{80,"transcript"}
    case _ None{}: Failed{42,"certificate-key"}
    case Some{transcript} Some{+key}: certificate_suited(key_suite(suite,key),transcript,private,public,randoms,suite,alpn,key)

def authenticated(result: U.Tables & A.Verification, transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, randoms: Randoms, suite: U32, alpn: Bool, leaf: List<&2,U32>, +message: List<&2,U32>) -> Action:
  (_,verification) = result
  match verification:
    case A.Success{}: certificate_key(X.append(transcript,message),private,public,randoms,suite,alpn,leaf_key(Cert.decode(leaf)))
    case +reason: Failed{chain_alert(reason),"certificate:" ++ A.show(reason)}

def certificate(auth: Auth, transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, randoms: Randoms, suite: U32, alpn: Bool, value: Maybe<&2,List<&2,List<&2,U32>>>, message: List<&2,U32>) -> Action:
  match auth value:
    case _ None{}: Failed{50,"certificate-decode"}
    case _ Some{Nil{}}: Failed{50,"empty-server-certificate"}
    case Auth{tables,anchors,identity,now,_} Some{Con{+leaf,+rest}}:
      authenticated(A.verify(tables,Con{leaf,rest},anchors,identity,A.ServerAuth{},now),transcript,private,public,randoms,suite,alpn,leaf,message)

# ---- ServerKeyExchange (RFC 8422 5.4) ----
type Params is Data:
  Params{curve: U32, group: U32, point: List<&2,U32>, scheme: U32, signature: List<&2,U32>}

def exchange.signed(curve: U32, group: U32, value: Maybe<&2,E.Parts>) -> Maybe<&2,Params>:
  match value:
    case Some{E.Parts{point,Con{a,Con{b,Con{high,Con{low,+signature}}}}}}:
      Bool.pick(Maybe<&2,Params>,Bool.and(Nat.is_gt(B.length(signature),0n),Nat.is_eq(U32.to_nat(E.number(high,low)),B.length(signature))),
        Some{Params{curve,group,point,E.number(a,b),signature}},None{})
    case _: None{}

def exchange.body(valid: Bool, body: List<&2,U32>) -> Maybe<&2,Params>:
  match valid body:
    case True{} Con{curve,Con{high,Con{low,Con{size,rest}}}}: exchange.signed(curve,E.number(high,low),C.split(U32.to_nat(size),rest))
    case _ _: None{}

def exchange(message: List<&2,U32>) -> Maybe<&2,Params>:
  match message:
    case Con{_,Con{a,Con{b,Con{c,+body}}}}: exchange.body(Nat.is_eq(C.length24(a,b,c),B.length(body)),body)
    case _: None{}

def params(+group: U32, +point: List<&2,U32>) -> List<&2,U32>:
  Con{3,Con{U32.shrn(group,8n),Con{U32.and(group,255),Con{U32.from_nat(B.length(point)),point}}}}

def point_shape(+group: U32, +point: List<&2,U32>) -> Bool:
  Bool.or(Bool.and(U32.is_eq(group,29),Nat.is_eq(B.length(point),32n)),
    Bool.and(U32.is_eq(group,23),Bool.and(Nat.is_eq(B.length(point),65n),U32.is_eq(Maybe.default(&2,U32,List.head(&2,U32,point),0),4))))

def exchange_checks(+curve: U32, +group: U32, +point: List<&2,U32>, +scheme: U32, +suite: U32) -> Check:
  check(U32.is_eq(curve,3),47,"server-key-exchange-curve-type",
    check(Bool.or(U32.is_eq(group,29),U32.is_eq(group,23)),47,"unoffered-group",
      check(point_shape(group,point),47,"invalid-key-share",
        check(C.member(scheme,S.offered()),47,"unoffered-signature-scheme",
          check(Bool.pick(Bool,ecdsa(suite),S.ecdsa_scheme(scheme),S.rsa_scheme(scheme)),47,"signature-scheme-suite",Pass{})))))

def exchanged(transcript: Maybe<&1,X.Transcript>, private: K.Ephemeral, public: List<&2,U32>, point: List<&2,U32>, randoms: Randoms, suite: U32, group: U32, alpn: Bool) -> Action:
  match transcript group:
    case None{} _: Failed{80,"transcript"}
    case Some{transcript} 29: Continue{Keyed{transcript,private,public,point,randoms,suite,29,alpn,False{}}}
    case Some{transcript} group: Keygen{Generating{transcript,point,randoms,suite,group,alpn}}

def exchange_verified(valid: Bool, transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, point: List<&2,U32>, randoms: Randoms, suite: U32, group: U32, alpn: Bool, message: List<&2,U32>) -> Action:
  match valid:
    case False{}: Failed{51,"server-key-exchange-signature"}
    case True{}: exchanged(X.append(transcript,message),private,public,point,randoms,suite,group,alpn)

def exchange_checked(result: Check, transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, randoms: Randoms, suite: U32, alpn: Bool, key: Pub.PublicKey, value: Params, message: List<&2,U32>) -> Action:
  match result randoms value:
    case Stop{alert,reason} _ _: Failed{alert,reason}
    case Pass{} Randoms{+client,+server} Params{_,+group,+point,scheme,signature}:
      exchange_verified(S.verify(scheme,key,S.content(client,server,params(group,point)),signature),transcript,private,public,point,Randoms{client,server},suite,group,alpn,message)

def server_exchange(transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, randoms: Randoms, +suite: U32, alpn: Bool, key: Pub.PublicKey, value: Maybe<&2,Params>, message: List<&2,U32>) -> Action:
  match value:
    case None{}: Failed{50,"server-key-exchange"}
    case Some{Params{+curve,+group,+point,+scheme,signature}}:
      exchange_checked(exchange_checks(curve,group,point,scheme,suite),transcript,private,public,randoms,suite,alpn,key,Params{curve,group,point,scheme,signature},message)

# The driver generates the P-256 share requested by Keygen.
def keyed(state: State, offer: Maybe<&1,K.Offer>) -> Action:
  match state offer:
    case Generating{transcript,peer,randoms,suite,group,alpn} Some{K.Offer{private,public}}: Continue{Keyed{transcript,private,public,peer,randoms,suite,group,alpn,False{}}}
    case Generating{_,_,_,_,_,_} None{}: Failed{80,"key-generation"}
    case _ _: Failed{80,"unexpected-key-generation"}

# ---- CertificateRequest (RFC 5246 7.4.4) and ServerHelloDone ----
def request_authorities(value: Maybe<&2,E.Parts>) -> Bool:
  match value:
    case Some{E.Parts{_,Con{high,Con{low,+authorities}}}}: Nat.is_eq(U32.to_nat(E.number(high,low)),B.length(authorities))
    case _: False{}

def request_algorithms(value: Maybe<&2,E.Parts>) -> Bool:
  match value:
    case Some{E.Parts{_,Con{high,Con{low,+rest}}}}:
      +size = U32.to_nat(E.number(high,low))
      Bool.and(Bool.and(Nat.is_ge(size,2n),Nat.is_eq(Nat.mod(size,2n),0n)),request_authorities(C.split(size,rest)))
    case _: False{}

def request_valid(message: List<&2,U32>) -> Bool:
  match message:
    case Con{_,Con{a,Con{b,Con{c,Con{+types,+rest}}}}}:
      Bool.and(Nat.is_eq(C.length24(a,b,c),Nat.add(1n,B.length(rest))),Bool.and(U32.is_gt(types,0),request_algorithms(C.split(U32.to_nat(types),rest))))
    case _: False{}

def keyed_transcript(transcript: Maybe<&1,X.Transcript>, private: K.Ephemeral, public: List<&2,U32>, peer: List<&2,U32>, randoms: Randoms, suite: U32, group: U32, alpn: Bool) -> Action:
  match transcript:
    case None{}: Failed{80,"transcript"}
    case Some{transcript}: Continue{Keyed{transcript,private,public,peer,randoms,suite,group,alpn,True{}}}

# ---- client flight ----
type Keys is Data:
  Keys{client_key: List<&2,U32>, server_key: List<&2,U32>, client_iv: List<&2,U32>, server_iv: List<&2,U32>}

def drop(left: Nat, bytes: List<&2,U32>) -> List<&2,U32>:
  match left bytes:
    case 0n bytes: bytes
    case 1n+p Con{_,rest}: drop(p,rest)
    case _ _: []

def slice(start: Nat, length: Nat, bytes: List<&2,U32>) -> List<&2,U32>:
  List.take(&2,U32,drop(start,bytes),length)

def keys(+key: Nat, +iv: Nat, +block: List<&2,U32>) -> Keys:
  Keys{slice(0n,key,block),slice(key,key,block),slice(Nat.mul(2n,key),iv,block),slice(Nat.add(Nat.mul(2n,key),iv),iv,block)}

def flight_keys(expected: Maybe<&2,List<&2,U32>>, read: Maybe<&1,T.ReadKey>, write: Maybe<&1,T.WriteKey>, plain: List<&2,U32>, finished: List<&2,U32>, suite: U32, group: U32, alpn: Bool) -> Action:
  match expected read write:
    case Some{expected} Some{read} Some{write}: Flight{Ccs{expected,read,suite,group,alpn},plain,finished,write}
    case _ _ _: Failed{80,"handshake-keys"}

def flight_split(expected: Maybe<&2,List<&2,U32>>, value: Keys, plain: List<&2,U32>, finished: List<&2,U32>, +suite: U32, group: U32, alpn: Bool) -> Action:
  match value:
    case Keys{ck,sk,civ,siv}:
      flight_keys(expected,T.new12_read(chacha(suite),sk,siv),T.new12_write(chacha(suite),ck,civ),plain,finished,suite,group,alpn)

def flight_finished(large: Bool, master: List<&2,U32>, hash: Maybe<&2,List<&2,U32>>, block: Maybe<&2,List<&2,U32>>, plain: List<&2,U32>, finished: List<&2,U32>, +suite: U32, group: U32, alpn: Bool) -> Action:
  match hash block:
    case Some{hash} Some{block}:
      flight_split(P.verify_data(large,False{},master,hash),keys(key_length(suite),iv_length(suite),block),plain,finished,suite,group,alpn)
    case _ _: Failed{80,"finished-schedule"}

def flight_server(+large: Bool, +master: List<&2,U32>, randoms: Randoms, transcript: Maybe<&1,X.Transcript>, plain: List<&2,U32>, finished: List<&2,U32>, +suite: U32, group: U32, alpn: Bool) -> Action:
  match randoms transcript:
    case _ None{}: Failed{80,"transcript"}
    case Randoms{client,server} Some{transcript}:
      flight_finished(large,master,X.finish(transcript),P.key_block(large,master,server,client,Nat.add(Nat.mul(2n,key_length(suite)),Nat.mul(2n,iv_length(suite)))),plain,finished,suite,group,alpn)

def flight_client(large: Bool, master: List<&2,U32>, randoms: Randoms, transcript: X.Transcript, plain: List<&2,U32>, data: Maybe<&2,List<&2,U32>>, suite: U32, group: U32, alpn: Bool) -> Action:
  match data:
    case Some{data}:
      +finished = B.append([20,0,0,12],data)
      flight_server(large,master,randoms,X.append(transcript,finished),plain,finished,suite,group,alpn)
    case None{}: Failed{80,"finished-schedule"}

def flight_master(+large: Bool, master: Maybe<&2,List<&2,U32>>, +hash: List<&2,U32>, randoms: Randoms, transcript: X.Transcript, plain: List<&2,U32>, suite: U32, group: U32, alpn: Bool) -> Action:
  match master:
    case None{}: Failed{80,"master-secret"}
    case Some{+master}: flight_client(large,master,randoms,transcript,plain,P.verify_data(large,True{},master,hash),suite,group,alpn)

def flight_snapshot(shared: List<&2,U32>, randoms: Randoms, plain: List<&2,U32>, +suite: U32, group: U32, alpn: Bool, snapshot: X.Transcript & Maybe<&2,List<&2,U32>>) -> Action:
  (transcript,hash) = snapshot
  match hash:
    case None{}: Failed{80,"transcript"}
    case Some{+hash}: flight_master(large(suite),P.master_secret(large(suite),shared,hash),hash,randoms,transcript,plain,suite,group,alpn)

def flight_appended(shared: Maybe<&1,List<&2,U32>>, transcript: Maybe<&1,X.Transcript>, randoms: Randoms, plain: List<&2,U32>, suite: U32, group: U32, alpn: Bool) -> Action:
  match shared transcript:
    case None{} _: Failed{47,"invalid-key-share"}
    case _ None{}: Failed{80,"transcript"}
    case Some{shared} Some{transcript}: flight_snapshot(shared,randoms,plain,suite,group,alpn,X.snapshot(transcript))

def flight_certificate(requested: Bool, transcript: Maybe<&1,X.Transcript>) -> Maybe<&1,X.Transcript>:
  match requested transcript:
    case True{} Some{transcript}: X.append(transcript,[11,0,0,3,0,0,0])
    case _ transcript: transcript

# RFC 7627: session_hash covers the messages through ClientKeyExchange, which
# is also the client Finished hash (no client CertificateVerify is sent).
def flight_exchange(transcript: Maybe<&1,X.Transcript>, private: K.Ephemeral, +exchange: List<&2,U32>, peer: List<&2,U32>, randoms: Randoms, suite: U32, group: U32, alpn: Bool, requested: Bool) -> Action:
  match transcript:
    case None{}: Failed{80,"transcript"}
    case Some{transcript}:
      flight_appended(K.shared(private,peer),X.append(transcript,exchange),randoms,
        B.append(Bool.pick(List<&2,U32>,requested,[11,0,0,3,0,0,0],[]),exchange),suite,group,alpn)

def flight(transcript: Maybe<&1,X.Transcript>, private: K.Ephemeral, +public: List<&2,U32>, peer: List<&2,U32>, randoms: Randoms, suite: U32, group: U32, alpn: Bool, +requested: Bool) -> Action:
  flight_exchange(flight_certificate(requested,transcript),private,
    Con{16,Con{0,Con{0,Con{U32.from_nat(Nat.add(B.length(public),1n)),Con{U32.from_nat(B.length(public)),public}}}}},peer,randoms,suite,group,alpn,requested)

def keyed_request(valid: Bool, transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, peer: List<&2,U32>, randoms: Randoms, suite: U32, group: U32, alpn: Bool, message: List<&2,U32>) -> Action:
  match valid:
    case True{}: keyed_transcript(X.append(transcript,message),private,public,peer,randoms,suite,group,alpn)
    case False{}: Failed{50,"certificate-request"}

def keyed_done(valid: Bool, transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, peer: List<&2,U32>, randoms: Randoms, suite: U32, group: U32, alpn: Bool, requested: Bool, message: List<&2,U32>) -> Action:
  match valid:
    case True{}: flight(X.append(transcript,message),private,public,peer,randoms,suite,group,alpn,requested)
    case False{}: Failed{50,"server-hello-done"}

def keyed_message(transcript: X.Transcript, private: K.Ephemeral, public: List<&2,U32>, peer: List<&2,U32>, randoms: Randoms, suite: U32, group: U32, alpn: Bool, requested: Bool, +message: List<&2,U32>) -> Action:
  match requested message:
    case _ Con{14,_}: keyed_done(Nat.is_eq(B.length(message),4n),transcript,private,public,peer,randoms,suite,group,alpn,requested,message)
    case False{} Con{13,_}: keyed_request(request_valid(message),transcript,private,public,peer,randoms,suite,group,alpn,message)
    case _ _: Failed{10,"handshake-order"}

# ---- server Finished ----
def finished_compared(sized: Bool, same: Bool, suite: U32, group: U32, alpn: Bool) -> Action:
  match sized same:
    case True{} True{}: Established{suite,group,alpn}
    case True{} False{}: Failed{51,"finished"}
    case False{} _: Failed{50,"finished"}

# verify_data is compared in full before deciding (P.same).
def finished(expected: List<&2,U32>, suite: U32, group: U32, alpn: Bool, message: List<&2,U32>) -> Action:
  match message:
    case Con{20,Con{0,Con{0,Con{12,+data}}}}: finished_compared(Nat.is_eq(B.length(data),12n),P.same(expected,data),suite,group,alpn)
    case Con{20,_}: Failed{50,"finished"}
    case _: Failed{10,"handshake-order"}

def step(state: State, +message: List<&2,U32>) -> Action:
  match state:
    case Certificate{auth,transcript,private,public,randoms,suite,alpn}:
      match message:
        case Con{11,_}: certificate(auth,transcript,private,public,randoms,suite,alpn,chain(message),message)
        case _: Failed{10,"handshake-order"}
    case Exchange{transcript,private,public,randoms,suite,alpn,key}:
      match message:
        case Con{12,_}: server_exchange(transcript,private,public,randoms,suite,alpn,key,exchange(message),message)
        case _: Failed{10,"handshake-order"}
    case Keyed{transcript,private,public,peer,randoms,suite,group,alpn,requested}:
      keyed_message(transcript,private,public,peer,randoms,suite,group,alpn,requested,message)
    case Finish{expected,suite,group,alpn}: finished(expected,suite,group,alpn,message)
    case _: Failed{10,"handshake-order"}

# A ChangeCipherSpec is accepted only after the client Finished was sent.
def change_cipher_spec(state: State) -> Action:
  match state:
    case Ccs{expected,read,suite,group,alpn}: Read{Finish{expected,suite,group,alpn},read}
    case _: Failed{10,"unexpected-change-cipher-spec"}
