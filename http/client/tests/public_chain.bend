import Base
import ../bend_transport.bend as Tr
import ../client.bend as Legacy
import ../../../crypto/x509_chain.bend as C
import ../../../crypto/x509_chain_cli.bend as F
import ../../../crypto/x509_validity.bend as V
import ../../../crypto/unicode32_prepare.bend as U
import ../../../io/io.bend as Io

def printed(result: U.Tables & C.Verification, started: Nat) -> IO(Unit):
  (tables,reason) = result
  do IO<Unit>:
    ended : Nat <- IO.now()
    IO.print(C.show(reason) ++ ":" ++ Nat.show(Nat.sub(ended,started)))

def verify(tables: U.Tables, roots: List<&2,List<&2,U32>>, time: Maybe<&1,Nat>, id: List<&2,U32>, peers: Maybe<F.Parts>) -> IO(Unit):
  match time id peers:
    case Some{+now} Con{0,dns} Some{F.Parts{peers,Nil{}}}:
      do IO<Unit>:
        at : Nat <- IO.now()
        printed(C.verify(tables,peers,roots,C.Dns{dns},C.ServerAuth{},now),at)
    case _ _ _: IO.die(Unit,2,"invalid public chain record")

def record(tables: U.Tables, roots: List<&2,List<&2,U32>>, value: Maybe<F.Parts>) -> IO(Unit):
  match value:
    case Some{F.Parts{[time,id,peers],Nil{}}}: verify(tables,roots,V.decode_time(time),id,F.list(peers))
    case _: IO.die(Unit,2,"invalid public chain fixture")

def ready(value: Maybe<&1,U.Tables>, roots: List<&2,List<&2,U32>>, fixture: Maybe<F.Parts>) -> IO(Unit):
  match value:
    case Some{tables}: record(tables,roots,fixture)
    case None{}: IO.die(Unit,2,"invalid Unicode assets")

def loaded(value: Legacy.R(Tr.Policy), fixture: String) -> IO(Unit):
  match value:
    case Fail{Legacy.Tls{reason}}: IO.print(reason)
    case Fail{_}: IO.die(Unit,2,"bundle load failed")
    case Done{Tr.Policy{nfkc,profile,roots,_}}:
      do IO<Unit>:
        bytes : List<&2,U32> <- Io.read_bytes(fixture)
        ready(U.tables(nfkc,profile),roots,F.list(bytes))

def command(args: List<String>) -> IO(Unit):
  match args:
    case [nfkc,profile,bundle,fixture]:
      do IO<Unit>:
        a : List<&2,U32> <- Io.read_bytes(nfkc)
        b : List<&2,U32> <- Io.read_bytes(profile)
        policy : Legacy.R(Tr.Policy) <- Tr.from_bundle_file(a,b,bundle,Tr.Clock{0n,0n})
        loaded(policy,fixture)
    case _: IO.die(Unit,2,"nfkc profile explicit-bundle.pem fixture")

def main() -> IO(Unit):
  IO.bind(List<String>,Unit,Io.args(),command)
