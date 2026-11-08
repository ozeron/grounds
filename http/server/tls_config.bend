import Base
import ../../wire/bend_tls_server.bend as TLS
import ../../wire/bend_tls_client.bend as T
import ../../wire/tls_server_handshake.bend as N
import ../../crypto/credential.bend as C
import ../../crypto/private_key.bend as K
import ../../crypto/rsa_private.bend as R
import ../../crypto/bytes.bend as B
import ../../crypto/pem.bend as PEM
import ../../crypto/x509_certificate.bend as X
import ../../crypto/x509_extensions.bend as XE
import ../../crypto/x509_hostname.bend as XH
import ../../wire/tls_server_names.bend as Names
import ./transport.bend as Tr
import ../../io/io.bend as Io

# Explicit process-lifetime synthetic credential owner. Import and validate once
# before listen. Each accept issues a new affine signing owner; no new key or
# PEM import, no shared connection state, no physical-erasure claim.
type Key is Data:
  EC{scalar: List<&2,U32>, public: List<&2,U32>}
  RSA{n: List<&2,U32>, e: List<&2,U32>, d: List<&2,U32>, p: List<&2,U32>, q: List<&2,U32>, dp: List<&2,U32>, dq: List<&2,U32>, qi: List<&2,U32>}

# Hosts is the SNI multi-certificate owner; see with_bend_tls_hosts.
type Prepared is Data:
  Prepared{leaf: List<&2,U32>, key: Key, intermediates: List<&2,List<&2,U32>>, policy: N.Policy}
  Hosts{entries: List<&2,Entry>, policy: N.Policy}

# One SNI credential: PEM file paths (leaf first) and the server names it
# answers. Empty names: the leaf's SAN dNSName entries.
type Host is Data:
  Host{names: List<&2,String>, chain: List<&2,String>, key: String}

type Entry is Data:
  Entry{leaf: List<&2,U32>, key: Key, intermediates: List<&2,List<&2,U32>>, names: List<&2,List<&2,U32>>, label: List<&2,U32>, default: Bool}

def retained(leaf: List<&2,U32>, rest: List<&2,List<&2,U32>>, policy: N.Policy, key: K.Private) -> Prepared:
  match key:
    case K.P256{scalar,public}: Prepared{leaf,EC{scalar,public},rest,policy}
    case K.Rsa{R.Private{n,e,d,p,q,dp,dq,qi}}: Prepared{leaf,RSA{n,e,d,p,q,dp,dq,qi},rest,policy}

def imported(native: U32, value: Result<&2,&1,PEM.Error,TLS.Config>) -> IO(Prepared):
  match native value:
    case _ Fail{_}: IO.die(Prepared,1,"http: invalid Bend TLS credential or policy")
    case 0 Done{TLS.Config{C.Credential{_,K.Rsa{_}},_,_,_}}:
      IO.die(Prepared,1,"http: RSA certificates on Bun are unsupported for latency reasons; use P-256 ECDSA")
    case _ Done{TLS.Config{C.Credential{leaf,key},rest,policy,_}}: IO.pure(Prepared,retained(leaf,rest,policy,key))

def read_chain(paths: List<&2,String>) -> IO(List<&2,List<&2,U32>>):
  match paths:
    case Nil{}: IO.pure(List<&2,List<&2,U32>>,[])
    case Con{path,rest}:
      do IO<List<&2,List<&2,U32>>>:
        leaf : List<&2,U32> <- Io.read_bytes(path)
        tail : List<&2,List<&2,U32>> <- read_chain(rest)
        return Con{leaf,tail}

def load(paths: List<&2,String>, key: String, suites: List<&2,U32>) -> IO(Prepared):
  do IO<Prepared>:
    chain : List<&2,List<&2,U32>> <- read_chain(paths)
    bytes : List<&2,U32> <- Io.read_bytes(key)
    native : U32 <- Tr.http_native_target()
    imported(native,TLS.from_pem(chain,bytes,N.Policy{suites,[29,23],True{}},0n))

def issue(key: Key) -> K.Private:
  match key:
    case EC{scalar,public}: K.P256{scalar,public}
    case RSA{n,e,d,p,q,dp,dq,qi}: K.Rsa{R.Private{n,e,d,p,q,dp,dq,qi}}


def accepted(value: Result<&2,&1,T.Error,TLS.Connection>) -> IO(Maybe<&1,Tr.Connection>):
  match value:
    case Fail{_}: IO.pure(Maybe<&1,Tr.Connection>,None{})
    case Done{connection}: IO.pure(Maybe<&1,Tr.Connection>,Some{Tr.Bend{connection}})

# SNI selection
# -------------

def scheme(key: Key) -> U32:
  match key:
    case EC{_,_}: 1027
    case RSA{_,_,_,_,_,_,_,_}: 2052

def names_of(entries: List<&2,Entry>) -> List<&2,Names.Entry>:
  match entries:
    case Nil{}: []
    case Con{Entry{_,key,_,names,_,default},rest}: Con{Names.Entry{names,scheme(key),default},names_of(rest)}

def nth(entries: List<&2,Entry>, +index: Nat) -> Maybe<&1,TLS.Selected>:
  match entries index:
    case Nil{} _: None{}
    case Con{Entry{leaf,key,rest,_,label,_},_} 0n: Some{TLS.Selected{C.Credential{leaf,issue(key)},rest,label}}
    case Con{_,tail} 1n+p: nth(tail,p)

def chosen(entries: List<&2,Entry>, index: Maybe<&2,Nat>) -> Maybe<&1,TLS.Selected>:
  match index:
    case Some{index}: nth(entries,index)
    case None{}: None{}

# Each accept issues a fresh affine owner only for the selected credential.
def selected(+entries: List<&2,Entry>, +sni: List<&2,U32>, +sigs: List<&2,U32>) -> Maybe<&1,TLS.Selected>:
  chosen(entries,Names.select(names_of(entries),sni,sigs))

# SAN dNSName (GeneralName tag 130) entries of a leaf, in certificate order.
def san_kept(+keep: Bool, bytes: List<&2,U32>, rest: List<&2,List<&2,U32>>) -> List<&2,List<&2,U32>>:
  match keep:
    case True{}: Con{bytes,rest}
    case False{}: rest

def san_names(names: List<&2,XH.Name>) -> List<&2,List<&2,U32>>:
  match names:
    case Nil{}: []
    case Con{XH.Name{+tag,bytes},rest}: san_kept(U32.is_eq(tag,130),bytes,san_names(rest))

def san_framed(value: Maybe<&1,List<&2,XH.Name>>) -> List<&2,List<&2,U32>>:
  match value:
    case Some{names}: san_names(names)
    case None{}: []

def san_bytes(value: Maybe<&2,List<&2,U32>>) -> List<&2,List<&2,U32>>:
  match value:
    case Some{bytes}: san_framed(XH.frame(bytes))
    case None{}: []

def san_extensions(entries: Maybe<&1,List<&1,XE.Extension>>) -> List<&2,List<&2,U32>>:
  match entries:
    case Some{entries}: san_bytes(XH.find(entries))
    case None{}: []

def san_decoded(value: Maybe<&1,X.Certificate>) -> List<&2,List<&2,U32>>:
  match value:
    case Some{X.Certificate{X.Tbs{_,_,X.Tail{_,_,bytes}},_,_}}: san_extensions(XE.optional(bytes))
    case None{}: []

def leaf_names(leaf: List<&2,U32>) -> List<&2,List<&2,U32>>:
  san_decoded(X.decode(leaf))

def text_bytes(text: String) -> List<&2,U32>:
  match text:
    case SNil{}: []
    case SCon{Chr{+byte},rest}: Con{byte,text_bytes(rest)}

def given_names(names: List<&2,String>) -> List<&2,List<&2,U32>>:
  match names:
    case Nil{}: []
    case Con{name,rest}: Con{Names.lower(text_bytes(name)),given_names(rest)}

def lowered(names: List<&2,List<&2,U32>>) -> List<&2,List<&2,U32>>:
  match names:
    case Nil{}: []
    case Con{name,rest}: Con{Names.lower(name),lowered(rest)}

def host_names(+given: List<&2,List<&2,U32>>, +leaf: List<&2,U32>) -> List<&2,List<&2,U32>>:
  match given:
    case Nil{}: lowered(leaf_names(leaf))
    case _: given

# Exposed label: "p256:" or "rsa:" then the first name, or "default".
def primary(names: List<&2,List<&2,U32>>) -> List<&2,U32>:
  match names:
    case Con{name,_}: name
    case Nil{}: [100,101,102,97,117,108,116]

def label(key: Key, +names: List<&2,List<&2,U32>>) -> List<&2,U32>:
  match key:
    case EC{_,_}: B.append([112,50,53,54,58],primary(names))
    case RSA{_,_,_,_,_,_,_,_}: B.append([114,115,97,58],primary(names))

def entry(leaf: List<&2,U32>, rest: List<&2,List<&2,U32>>, +names: List<&2,List<&2,U32>>, +default: Bool, key: K.Private) -> Entry:
  match key:
    case K.P256{scalar,public}: Entry{leaf,EC{scalar,public},rest,names,label(EC{[],[]},names),default}
    case K.Rsa{R.Private{n,e,d,p,q,dp,dq,qi}}: Entry{leaf,RSA{n,e,d,p,q,dp,dq,qi},rest,names,label(RSA{[],[],[],[],[],[],[],[]},names),default}

def host_imported(+native: U32, +given: List<&2,List<&2,U32>>, +default: Bool, value: Result<&2,&1,PEM.Error,TLS.Config>) -> IO(Entry):
  match native value:
    case _ Fail{_}: IO.die(Entry,1,"http: invalid Bend TLS host credential or policy")
    case 0 Done{TLS.Config{C.Credential{_,K.Rsa{_}},_,_,_}}:
      IO.die(Entry,1,"http: RSA certificates on Bun are unsupported for latency reasons; use P-256 ECDSA")
    case _ Done{TLS.Config{C.Credential{+leaf,key},rest,_,_}}: IO.pure(Entry,entry(leaf,rest,host_names(given,leaf),default,key))

def load_host(+native: U32, +policy: N.Policy, +default: Bool, host: Host) -> IO(Entry):
  match host:
    case Host{names,paths,key}:
      do IO<Entry>:
        chain : List<&2,List<&2,U32>> <- read_chain(paths)
        bytes : List<&2,U32> <- Io.read_bytes(key)
        host_imported(native,given_names(names),default,TLS.from_pem(chain,bytes,policy,0n))

def load_list(+native: U32, +policy: N.Policy, hosts: List<&2,Host>, fallback: Maybe<&2,Host>) -> IO(List<&2,Entry>):
  match hosts fallback:
    case Nil{} None{}: IO.pure(List<&2,Entry>,[])
    case Nil{} Some{host}:
      do IO<List<&2,Entry>>:
        one : Entry <- load_host(native,policy,True{},host)
        return [one]
    case Con{host,rest} fallback:
      do IO<List<&2,Entry>>:
        one : Entry <- load_host(native,policy,False{},host)
        tail : List<&2,Entry> <- load_list(native,policy,rest,fallback)
        return Con{one,tail}

def hosts_checked(problem: Maybe<&2,String>, entries: List<&2,Entry>, policy: N.Policy) -> IO(Prepared):
  match problem:
    case Some{reason}: IO.die(Prepared,1,"http: " ++ reason)
    case None{}: IO.pure(Prepared,Hosts{entries,policy})

def hosts_loaded(+entries: List<&2,Entry>, policy: N.Policy) -> IO(Prepared):
  hosts_checked(Names.validate(names_of(entries)),entries,policy)

def host_count(hosts: List<&2,Host>, fallback: Maybe<&2,Host>) -> Nat:
  match hosts fallback:
    case Nil{} None{}: 0n
    case Nil{} Some{_}: 1n
    case Con{_,rest} fallback: Nat.add(1n,host_count(rest,fallback))

def load_hosts_bounded(+within: Bool, +hosts: List<&2,Host>, +fallback: Maybe<&2,Host>, +suites: List<&2,U32>) -> IO(Prepared):
  match within:
    case False{}: IO.die(Prepared,1,"http: between 1 and 64 Bend TLS host credentials are required")
    case True{}:
      do IO<Prepared>:
        native : U32 <- Tr.http_native_target()
        entries : List<&2,Entry> <- load_list(native,N.Policy{suites,[29,23],True{}},hosts,fallback)
        hosts_loaded(entries,N.Policy{suites,[29,23],True{}})

# Startup-only: at most 64 credentials, each validated as for load (leaf SPKI
# matches the key), names validated and de-duplicated per key type.
def load_hosts(+hosts: List<&2,Host>, +fallback: Maybe<&2,Host>, +suites: List<&2,U32>) -> IO(Prepared):
  +count = host_count(hosts,fallback)
  load_hosts_bounded(Bool.and(Nat.is_gt(count,0n),Nat.is_le(count,Names.max_credentials())),hosts,fallback,suites)

def single(leaf: List<&2,U32>, key: Key, rest: List<&2,List<&2,U32>>, policy: N.Policy, socket: Socket, ms: U32) -> IO(Maybe<&1,Tr.Connection>):
  do IO<Maybe<&1,Tr.Connection>>:
    now : Nat <- IO.now()
    value : Result<&2,&1,T.Error,TLS.Connection> <- TLS.accept(socket,TLS.Config{C.Credential{leaf,issue(key)},rest,policy,Nat.add(now,U32.to_nat(ms))})
    accepted(value)

def hosts(entries: List<&2,Entry>, +policy: N.Policy, socket: Socket, ms: U32) -> IO(Maybe<&1,Tr.Connection>):
  do IO<Maybe<&1,Tr.Connection>>:
    now : Nat <- IO.now()
    value : Result<&2,&1,T.Error,TLS.Connection> <- TLS.accept_select(socket,policy,Nat.add(now,U32.to_nat(ms)),sni => sigs => selected(entries,sni,sigs))
    accepted(value)

def accept(prepared: Prepared, socket: Socket, ms: U32) -> IO(Maybe<&1,Tr.Connection>):
  match prepared:
    case Prepared{leaf,key,rest,policy}: single(leaf,key,rest,policy,socket,ms)
    case Hosts{entries,policy}: hosts(entries,policy,socket,ms)
