import Base
import ../../wire/bend_tls_server.bend as TLS
import ../../wire/bend_tls_client.bend as T
import ../../wire/tls_server_handshake.bend as N
import ../../crypto/credential.bend as C
import ../../crypto/private_key.bend as K
import ../../crypto/rsa_private.bend as R
import ../../crypto/pem.bend as PEM
import ./transport.bend as Tr
import ../../io/io.bend as Io

# Explicit process-lifetime synthetic credential owner. Import and validate once
# before listen. Each accept issues a new affine signing owner; no new key or
# PEM import, no shared connection state, no physical-erasure claim.
type Key is Data:
  EC{scalar: List<&2,U32>, public: List<&2,U32>}
  RSA{n: List<&2,U32>, e: List<&2,U32>, d: List<&2,U32>, p: List<&2,U32>, q: List<&2,U32>, dp: List<&2,U32>, dq: List<&2,U32>, qi: List<&2,U32>}

type Prepared is Data:
  Prepared{leaf: List<&2,U32>, key: Key, intermediates: List<&2,List<&2,U32>>, policy: N.Policy}

def retained(leaf: List<&2,U32>, rest: List<&2,List<&2,U32>>, policy: N.Policy, key: K.Private) -> Prepared:
  match key:
    case K.P256{scalar,public}: Prepared{leaf,EC{scalar,public},rest,policy}
    case K.Rsa{R.Private{n,e,d,p,q,dp,dq,qi}}: Prepared{leaf,RSA{n,e,d,p,q,dp,dq,qi},rest,policy}

def imported(value: Result<&2,&1,PEM.Error,TLS.Config>) -> IO(Prepared):
  match value:
    case Fail{_}: IO.die(Prepared,1,"http: invalid Bend TLS credential or policy")
    case Done{TLS.Config{C.Credential{leaf,key},rest,policy,_}}: IO.pure(Prepared,retained(leaf,rest,policy,key))

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
    imported(TLS.from_pem(chain,bytes,N.Policy{suites,[29,23],True{}},0n))

def issue(key: Key) -> K.Private:
  match key:
    case EC{scalar,public}: K.P256{scalar,public}
    case RSA{n,e,d,p,q,dp,dq,qi}: K.Rsa{R.Private{n,e,d,p,q,dp,dq,qi}}

def config(prepared: Prepared, at: Nat) -> TLS.Config:
  match prepared:
    case Prepared{leaf,key,rest,policy}: TLS.Config{C.Credential{leaf,issue(key)},rest,policy,at}

def accepted(value: Result<&2,&1,T.Error,TLS.Connection>) -> IO(Maybe<&1,Tr.Connection>):
  match value:
    case Fail{_}: IO.pure(Maybe<&1,Tr.Connection>,None{})
    case Done{connection}: IO.pure(Maybe<&1,Tr.Connection>,Some{Tr.Bend{connection}})

def accept(prepared: Prepared, socket: Socket, ms: U32) -> IO(Maybe<&1,Tr.Connection>):
  do IO<Maybe<&1,Tr.Connection>>:
    now : Nat <- IO.now()
    value : Result<&2,&1,T.Error,TLS.Connection> <- TLS.accept(socket,config(prepared,Nat.add(now,U32.to_nat(ms))))
    accepted(value)
