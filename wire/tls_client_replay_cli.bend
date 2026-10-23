import Base
import ./tls_client.bend as C
import ./tls_key_share.bend as K
import ./tls_transcript.bend as X
import ../crypto/traffic.bend as T
import ../crypto/bytes.bend as B
import ../crypto/x509_chain.bend as A
import ../crypto/unicode32_prepare.bend as U
import ../crypto/unicode32_prepare_cli.bend as Tables
import ../io/io.bend as Io

# Synthetic published-key diagnostics only. Seed the exact RFC ClientHello,
# whose offer differs from the frozen live-client profile. Every subsequent
# message goes through the unchanged production client transition function.
# Public constructors suffice: no test hook or certificate-policy bypass.
def epoch(value: T.Epoch) -> IO(Unit):
  match value:
    case T.AesReady{secret,key,iv,T.Counter{0,0}}:
      do IO<Unit>:
        IO.print(B.hex(secret))
        IO.print(B.hex(key))
        IO.print(B.hex(iv))
    case _: IO.die(Unit,2,"expected fresh AES-128 handshake epoch")

def onward(next: Maybe<&1,C.State>, resume: C.State -> IO(Unit)) -> IO(Unit):
  match next:
    case None{}: IO.pure(Unit,Unit{})
    case Some{state}: resume(state)

def checkpoint_hash(state: C.State, phase: U32, hash: Maybe<&2,List<&2,U32>>) -> IO(Maybe<&1,C.State>):
  match hash:
    case None{}: IO.die(Maybe<&1,C.State>,2,"invalid transcript snapshot")
    case Some{hash}:
      do IO<Maybe<&1,C.State>>:
        IO.print("hash:" ++ B.hex(hash))
        IO.print("phase:" ++ U32.show(phase))
        IO.pure(Maybe<&1,C.State>,Some{state})

def checkpoint_snapshot(auth: C.Auth, keys: C.Keys, +phase: U32, requested: Bool, leaf: List<&2,U32>, suite: U32, group: U32, alpn: Bool, snapshot: X.Transcript & Maybe<&2,List<&2,U32>>) -> IO(Maybe<&1,C.State>):
  (transcript,hash) = snapshot
  checkpoint_hash(C.Flight{auth,transcript,keys,phase,requested,leaf,suite,group,alpn},phase,hash)

def checkpoint(state: C.State) -> IO(Maybe<&1,C.State>):
  match state:
    case C.Flight{auth,transcript,keys,+phase,requested,leaf,suite,group,alpn}:
      checkpoint_snapshot(auth,keys,phase,requested,leaf,suite,group,alpn,X.snapshot(transcript))
    case _: IO.die(Maybe<&1,C.State>,2,"unexpected pre-ServerHello checkpoint")

def action(value: C.Action) -> IO(Maybe<&1,C.State>):
  match value:
    case C.Failed{alert,reason}:
      do IO<Maybe<&1,C.State>>:
        IO.print("fail:" ++ U32.show(alert) ++ ":" ++ reason)
        IO.pure(Maybe<&1,C.State>,None{})
    case C.Continue{state}:
      do IO<Maybe<&1,C.State>>:
        IO.print("continue")
        checkpoint(state)
    case C.Install{state,T.ReadKey{read},T.WriteKey{write,T.Generation{0,0}}}:
      do IO<Maybe<&1,C.State>>:
        IO.print("install")
        epoch(read)
        epoch(write)
        checkpoint(state)
    case _: IO.die(Maybe<&1,C.State>,2,"unexpected handshake action")

def feed(messages: List<&2,List<&2,U32>>, state: C.State) -> IO(Unit):
  match messages:
    case Nil{}: IO.pure(Unit,Unit{})
    case Con{message,rest}:
      do IO<Unit>:
        next : Maybe<&1,C.State> <- action(C.step(state,message))
        onward(next,s => feed(rest,s))

def seeded(tables: U.Tables, private: List<&2,U32>, public: List<&2,U32>, random: List<&2,U32>, messages: List<&2,List<&2,U32>>, transcript: Maybe<&1,X.Transcript>) -> IO(Unit):
  match transcript:
    case None{}: IO.die(Unit,2,"invalid published ClientHello")
    case Some{transcript}:
      # 2018-01-01, within the published synthetic certificate's validity.
      feed(messages,C.Hello{C.Auth{tables,[],A.Dns{[115,101,114,118,101,114]},Nat.add(Nat.mul(63650n,1000000n),361600n),False{}},
        transcript,K.XPrivate{private},public,random,29,0})

def seed(tables: U.Tables, values: List<&2,List<&2,U32>>) -> IO(Unit):
  match values:
    case Con{private,Con{public,Con{random,Con{hello,messages}}}}:
      seeded(tables,private,public,random,messages,X.append(X.start(),hello))
    case _: IO.die(Unit,2,"expected private/public/random/ClientHello and messages")

def read_files(paths: List<String>) -> IO(List<&2,List<&2,U32>>):
  match paths:
    case Nil{}: IO.pure(List<&2,List<&2,U32>>,[])
    case Con{path,rest}:
      do IO<List<&2,List<&2,U32>>>:
        bytes : List<&2,U32> <- Io.read_bytes(path)
        tail : List<&2,List<&2,U32>> <- read_files(rest)
        IO.pure(List<&2,List<&2,U32>>,Con{bytes,tail})

def loaded(tables: Maybe<&1,U.Tables>, values: List<&2,List<&2,U32>>) -> IO(Unit):
  match tables:
    case None{}: IO.die(Unit,2,"invalid Unicode assets")
    case Some{tables}: seed(tables,values)

def command(args: List<String>) -> IO(Unit):
  match args:
    case Con{"run",Con{nfkc,Con{profile,paths}}}:
      do IO<Unit>:
        tables : Maybe<&1,U.Tables> <- Tables.read_tables(nfkc,profile)
        values : List<&2,List<&2,U32>> <- read_files(paths)
        loaded(tables,values)
    case _: IO.die(Unit,2,"run nfkc profile private public random ClientHello messages...")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{"run",rest}: command(Con{"run",rest})
    case Con{_,rest}: command(rest)
    case _: command([])

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- Io.args()
    dispatch(args)
