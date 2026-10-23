import Base
import ../bend_client.bend as C
import ../bend_pool.bend as Pool
import ../../../io/io.bend as Io
import ../../../wire/bend_tls_client_cli.bend as Number
import ../bend_transport.bend as Tr
# Native CPU-only diagnostic. IO.now's monotonic millisecond resolution is
# recorded by the driver. Startup, source loading and pool warmup are excluded.
def reply(r: C.R(C.Reply)) -> IO(Unit):
  match r:
    case Done{C.Reply{200,_,[112,101,114,102,32,111,107,10]}}: IO.pure(Unit,Unit{})
    case _: IO.die(Unit,1,"perf response differs")

def requests(+p: Pool.Pool, +url: String, left: Nat) -> IO(Unit):
  match left:
    case 0n: IO.pure(Unit,Unit{})
    case 1n+n:
      do IO<Unit>:
        value : C.R(C.Reply) <- Pool.send(p,C.get(url))
        reply(value)
        requests(p,url,n)

def pooled(+p: Pool.Pool, +url: String) -> IO(Unit):
  do IO<Unit>:
    requests(p,url,5n)
    before : Nat <- IO.now()
    requests(p,url,200n)
    after : Nat <- IO.now()
    IO.print("requests:200:" ++ Nat.show(Nat.sub(after,before)))

def closed(value: C.Opened, before: Nat, observed: Bool) -> IO(Unit):
  match value:
    case C.NotOpened{_}: IO.die(Unit,1,"perf handshake failed")
    case C.Opened{socket,tls}:
      do IO<Unit>:
        after : Nat <- IO.now()
        C.shut(tls,socket)
        IO.bind(Unit,Unit,Bool.pick(IO(Unit),observed,IO.print("handshake:" ++ Nat.show(Nat.sub(after,before))),IO.pure(Unit,Unit{})),u => IO.pure(Unit,Unit{}))

def handshakes(+policy: Tr.Policy, +port: U32, left: Nat, +observed: Bool) -> IO(Unit):
  match left:
    case 0n: IO.pure(Unit,Unit{})
    case 1n+n:
      do IO<Unit>:
        +before : Nat <- IO.now()
        value : C.Opened <- C.open(True{},"localhost",port,Nat.add(before,10000n),policy)
        closed(value,before,observed)
        handshakes(policy,port,n,observed)

def execute(+policy: Tr.Policy, +port: U32, +url: String) -> IO(Unit):
  do IO<Unit>:
    handshakes(policy,port,5n,False{})
    handshakes(policy,port,50n,True{})
    Pool.with(Unit,C.default(policy),1,p => pooled(p,url))

def prepared(value: C.R(Tr.Policy), port: U32, url: String) -> IO(Unit):
  match value:
    case Fail{_}: IO.die(Unit,1,"perf policy failed")
    case Done{policy}: execute(policy,port,url)

def command(args: List<String>) -> IO(Unit):
  match args:
    case [nfkc,profile,ca,now,port,url]:
      do IO<Unit>:
        at : Nat <- IO.now()
        normalization : List<&2,U32> <- Io.read_bytes(nfkc)
        tables : List<&2,U32> <- Io.read_bytes(profile)
        pem : List<&2,U32> <- Io.read_bytes(ca)
        prepared(Tr.from_pem(normalization,tables,[pem],Tr.Clock{Number.number(now),at}),U32.from_nat(Number.number(port)),url)
    case _: IO.die(Unit,2,"nfkc profile anchor.pem civil-seconds port url")

def main() -> IO(Unit):
  IO.bind(List<String>,Unit,Io.args(),command)
