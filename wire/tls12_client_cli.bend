import Base
import ./tls12_client.bend as L
import ./tls_key_share.bend as K
import ./tls_transcript.bend as X
import ../crypto/traffic.bend as T
import ../crypto/bytes.bend as B
import ../crypto/x509_chain.bend as A
import ../crypto/unicode32_prepare.bend as U
import ../crypto/unicode32_prepare_cli.bend as Tables
import ../io/io.bend as Io

# Synthetic TLS 1.2 transition evaluator (M7). Seeds the production
# tls12_client state from a caller-chosen X25519/P-256 scalar, client random
# and ClientHello, then feeds server messages through the unchanged
# transition functions. A zero-length message file stands for one received
# ChangeCipherSpec. Prints every action, including fresh epoch key material,
# so an independent oracle can check transcript, EMS and key block.

def text(s: String, reversed: List<&2,U32>) -> List<&2,U32>:
  match s:
    case SNil{}: List.reverse(&2,U32,reversed)
    case SCon{Chr{c},rest}: text(rest,Con{c,reversed})

def decimal.go(bytes: String, +acc: Nat, valid: Bool) -> Maybe<&2,Nat>:
  match bytes:
    case SNil{}: Bool.pick(Maybe<&2,Nat>,valid,Some{acc},None{})
    case SCon{Chr{+c},rest}: decimal.go(rest,Nat.add(Nat.mul(acc,10n),U32.to_nat(U32.sub(c,48))),Bool.and(valid,Bool.and(U32.is_ge(c,48),U32.is_le(c,57))))

def number(s: String) -> Nat:
  Maybe.default(&2,Nat,decimal.go(s,0n,True{}),0n)

def epoch(label: String, value: T.Epoch) -> IO(Unit):
  match value:
    case T.Aes12Ready{key,salt,T.Counter{0,0}}: IO.print(label ++ ":" ++ B.hex(key) ++ ":" ++ B.hex(salt))
    case T.Chacha12Ready{key,iv,T.Counter{0,0}}: IO.print(label ++ ":" ++ B.hex(key) ++ ":" ++ B.hex(iv))
    case _: IO.die(Unit,2,"expected a fresh TLS 1.2 epoch")

def simple(value: L.Action) -> IO(Maybe<&1,L.State>):
  match value:
    case L.Failed{alert,reason}:
      do IO<Maybe<&1,L.State>>:
        IO.print("fail:" ++ U32.show(alert) ++ ":" ++ reason)
        IO.pure(Maybe<&1,L.State>,None{})
    case L.Continue{state}:
      do IO<Maybe<&1,L.State>>:
        IO.print("continue")
        IO.pure(Maybe<&1,L.State>,Some{state})
    case _: IO.die(Maybe<&1,L.State>,2,"unexpected action after key generation")

def action(value: L.Action, p256: List<&2,U32>) -> IO(Maybe<&1,L.State>):
  match value:
    case L.Keygen{state}:
      do IO<Maybe<&1,L.State>>:
        IO.print("keygen")
        simple(L.keyed(state,K.from_random(K.P256{},p256)))
    case L.Flight{state,plain,finished,T.WriteKey{write,_}}:
      do IO<Maybe<&1,L.State>>:
        IO.print("flight:" ++ B.hex(plain))
        IO.print("finished:" ++ B.hex(finished))
        epoch("write",write)
        IO.pure(Maybe<&1,L.State>,Some{state})
    case L.Read{state,T.ReadKey{read}}:
      do IO<Maybe<&1,L.State>>:
        epoch("read",read)
        IO.pure(Maybe<&1,L.State>,Some{state})
    case L.Established{suite,group,alpn}:
      do IO<Maybe<&1,L.State>>:
        IO.print("established:" ++ U32.show(suite) ++ ":" ++ U32.show(group) ++ ":" ++ Bool.pick(String,alpn,"true","false"))
        IO.pure(Maybe<&1,L.State>,None{})
    case value: simple(value)

def message(bytes: List<&2,U32>, state: L.State, p256: List<&2,U32>) -> IO(Maybe<&1,L.State>):
  match bytes:
    case Nil{}: action(L.change_cipher_spec(state),p256)
    case bytes: action(L.step(state,bytes),p256)

def onward(next: Maybe<&1,L.State>, resume: L.State -> IO(Unit)) -> IO(Unit):
  match next:
    case None{}: IO.pure(Unit,Unit{})
    case Some{state}: resume(state)

def feed(messages: List<&2,List<&2,U32>>, +p256: List<&2,U32>, state: L.State) -> IO(Unit):
  match messages:
    case Nil{}: IO.print("pending")
    case Con{bytes,rest}:
      do IO<Unit>:
        next : Maybe<&1,L.State> <- message(bytes,state,p256)
        onward(next,s => feed(rest,p256,s))

def hello(auth: L.Auth, transcript: Maybe<&1,X.Transcript>, offer: Maybe<&1,K.Offer>, random: List<&2,U32>, value: Maybe<&2,L.Hello>, +server: List<&2,U32>, rest: List<&2,List<&2,U32>>, +p256: List<&2,U32>) -> IO(Unit):
  match transcript offer value:
    case Some{transcript} Some{K.Offer{private,public}} Some{parsed}:
      do IO<Unit>:
        next : Maybe<&1,L.State> <- action(L.server_hello(auth,transcript,private,public,random,0,parsed,server),p256)
        onward(next,s => feed(rest,p256,s))
    case _ _ None{}: IO.print("not-tls12")
    case _ _ _: IO.die(Unit,2,"invalid seed")

def seeded(tables: U.Tables, anchor: List<&2,U32>, identity: String, now: Nat, values: List<&2,List<&2,U32>>) -> IO(Unit):
  match values:
    case Con{x25519,Con{p256,Con{random,Con{client,Con{+server,rest}}}}}:
      hello(L.Auth{tables,[anchor],A.Dns{text(identity,[])},now,True{}},X.append(X.start(),client),K.from_random(K.X25519{},x25519),random,L.hello(server),server,rest,p256)
    case _: IO.die(Unit,2,"expected x25519 p256 random ClientHello ServerHello messages...")

def read_files(paths: List<String>) -> IO(List<&2,List<&2,U32>>):
  match paths:
    case Nil{}: IO.pure(List<&2,List<&2,U32>>,[])
    case Con{path,rest}:
      do IO<List<&2,List<&2,U32>>>:
        bytes : List<&2,U32> <- Io.read_bytes(path)
        tail : List<&2,List<&2,U32>> <- read_files(rest)
        IO.pure(List<&2,List<&2,U32>>,Con{bytes,tail})

def loaded(tables: Maybe<&1,U.Tables>, anchor: List<&2,U32>, identity: String, now: Nat, values: List<&2,List<&2,U32>>) -> IO(Unit):
  match tables:
    case None{}: IO.die(Unit,2,"invalid Unicode assets")
    case Some{tables}: seeded(tables,anchor,identity,now,values)

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{"run",Con{nfkc,Con{profile,Con{anchor,Con{identity,Con{now,paths}}}}}}:
      do IO<Unit>:
        tables : Maybe<&1,U.Tables> <- Tables.read_tables(nfkc,profile)
        anchor : List<&2,U32> <- Io.read_bytes(anchor)
        values : List<&2,List<&2,U32>> <- read_files(paths)
        loaded(tables,anchor,identity,number(now),values)
    case _: IO.die(Unit,2,"run nfkc profile anchor identity civil-seconds x25519 p256 random ClientHello ServerHello messages...")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- Io.args()
    dispatch(args)
