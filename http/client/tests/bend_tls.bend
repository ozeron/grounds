import Base
import ../bend_client.bend as C
import ../bend_pool.bend as Pool
import ../bend_transport.bend as Tr
import ../client.bend as Legacy
import ../../../io/io.bend as Io
import ../../../crypto/bytes.bend as Bytes
import ../../../wire/bend_tls_client_cli.bend as Number
import ../../../json/json.bend as J
import ../../core/event.bend as Ev

def count(bytes: List<&2,U32>, +n: U32) -> U32:
  match bytes:
    case Nil{}: n
    case Con{_,rest}: count(rest,U32.inc(n))

def error(e: Legacy.Err) -> String:
  match e:
    case Legacy.Tls{why}: "error:tls:" ++ why
    case Legacy.Timeout{}: "error:timeout"
    case Legacy.Closed{}: "error:closed"
    case other: "error:" ++ C.show(other)

def reply(r: C.R(C.Reply)) -> IO(Unit):
  match r:
    case Done{C.Reply{status,_,body}}: IO.print("ok:" ++ U32.show(status) ++ ":" ++ U32.show(count(body,0)))
    case Fail{why}: IO.print(error(why))

def pooled(+cfg: C.Config, +url: String, +p: Pool.Pool) -> IO(Unit):
  do IO<Unit>:
    a : C.R(C.Reply) <- Pool.send(p,C.get(url))
    reply(a)
    b : C.R(C.Reply) <- Pool.send(p,C.get(url))
    reply(b)
    c : C.R(C.Reply) <- Pool.send(p,C.get(url))
    reply(c)

def tally(bytes: List<&2,U32>) -> IO(Bool):
  IO.bind(Unit,Bool,IO.print("part:" ++ Bytes.hex(bytes)),u => IO.pure(Bool,True{}))

def streamed(r: C.R(C.Head)) -> IO(Unit):
  match r:
    case Done{C.Head{status,_}}: IO.print("ok:" ++ U32.show(status))
    case Fail{why}: IO.print(error(why))

def event(e: Ev.Message) -> IO(Bool):
  match e:
    case Ev.Message{name,+data,id}:
      do IO<Bool>:
        IO.print("event:" ++ name ++ ":" ++ data ++ ":" ++ Maybe.default(&2,String,id,""))
        IO.pure(Bool,Bool.not(String.eq(data,"stop")))

def ended(r: C.R(C.Ended)) -> IO(Unit):
  match r:
    case Done{C.Ended{last,n}}: IO.print("ended:" ++ Maybe.default(&2,String,last,"") ++ ":" ++ U32.show(n))
    case Fail{why}: IO.print(error(why))

def decode(j: J.Json) -> Result<&2,&2,J.Access,String>:
  J.string_at(j,[J.Name{"name"}])

def json_result(r: C.R(String)) -> IO(Unit):
  match r:
    case Done{value}: IO.print("json:" ++ value)
    case Fail{why}: IO.print(error(why))

def execute(+cfg: C.Config, +url: String, mode: String) -> IO(Unit):
  match mode:
    case "pool": Pool.with(Unit,cfg,1,p => pooled(cfg,url,p))
    case "json": IO.bind(C.R(String),Unit,C.send_json(String,cfg,C.post(url,C.json(J.JObj{[J.Field{"name",J.JStr{"cup"}}]})),decode),json_result)
    case "form": IO.bind(C.R(C.Reply),Unit,C.send(cfg,C.post(url,C.form([("q","a b"),("n","2")]))),reply)
    case "stream": IO.bind(C.R(C.Head),Unit,C.stream(~tally,cfg,C.get(url)),streamed)
    case "pool-stream": Pool.with(Unit,cfg,1,p => IO.bind(C.R(C.Head),Unit,Pool.stream(~tally,p,C.get(url)),streamed))
    case "events": IO.bind(C.R(C.Ended),Unit,C.events(~event,cfg,C.get(url)),ended)
    case "events-retry": IO.bind(C.R(C.Ended),Unit,C.events_retry(~event,cfg,C.get(url),1),ended)
    case "pool-events": Pool.with(Unit,cfg,1,p => IO.bind(C.R(C.Ended),Unit,Pool.events_retry(~event,p,C.get(url),1),ended))
    case "timeout": IO.bind(C.R(C.Reply),Unit,C.send(C.with_timeout(cfg,200),C.get(url)),reply)
    case _: IO.bind(C.R(C.Reply),Unit,C.send(cfg,C.with(C.get(url),[("Authorization","secret"),("Cookie","secret")])),reply)

def prepared(value: Legacy.R(Tr.Policy), url: String, mode: String) -> IO(Unit):
  match value:
    case Fail{why}: IO.print(error(why))
    case Done{policy}: execute(C.with_timeout(C.default(policy),3000),url,mode)

def command(args: List<String>) -> IO(Unit):
  match args:
    case [nfkc,profile,ca,now,url,mode]:
      do IO<Unit>:
        at : Nat <- IO.now()
        normalization : List<&2,U32> <- Io.read_bytes(nfkc)
        tables : List<&2,U32> <- Io.read_bytes(profile)
        pem : List<&2,U32> <- Io.read_bytes(ca)
        prepared(Tr.from_pem(normalization,tables,[pem],Tr.Clock{Number.number(now),at}),url,mode)
    case _: IO.die(Unit,2,"nfkc profile anchor.pem civil-seconds url mode")

def main() -> IO(Unit):
  IO.bind(List<String>,Unit,Io.args(),command)
