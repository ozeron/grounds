import Base
import ../bend_client.bend as C
import ../bend_transport.bend as Tr
import ../client.bend as Legacy
import ../../../io/io.bend as Io

# Native public HTTPS. Every trust/clock/Unicode input is supplied by caller;
# no host TLS, ambient CA discovery or local client credential; redirects
# only when asked ("follow").
# Parse only the caller's trusted clock argument; avoid importing the synthetic
# TLS command-line evaluator into this small public example.
def clock_digits(text: String, +acc: Nat, valid: Bool) -> Maybe<&2,Nat>:
  match text:
    case SNil{}: Bool.pick(Maybe<&2,Nat>,valid,Some{acc},None{})
    case SCon{Chr{+c},rest}:
      clock_digits(rest,Nat.add(Nat.mul(acc,10n),U32.to_nat(U32.sub(c,48))),
        Bool.and(valid,Bool.and(U32.is_ge(c,48),U32.is_le(c,57))))

def number(text: String) -> Nat:
  Maybe.default(&2,Nat,clock_digits(text,0n,True{}),0n)

def reply(value: C.R(C.Reply)) -> IO(Unit):
  match value:
    case Done{C.Reply{status,_,body}}:
      IO.print("ok:" ++ U32.show(status) ++ ":" ++ Nat.show(List.length(&2,U32,body)))
    case Fail{Legacy.Tls{reason}}: IO.print("error:tls:" ++ reason)
    case Fail{why}: IO.print("error:" ++ C.show(why))

def prepared(value: Legacy.R(Tr.Policy), url: String, hops: U32) -> IO(Unit):
  match value:
    case Fail{Legacy.Tls{reason}}: IO.print("error:bundle:" ++ reason)
    case Fail{why}: IO.print("error:" ++ C.show(why))
    case Done{policy}: IO.bind(C.R(C.Reply),Unit,C.send(C.with_redirects(C.default(policy),hops),C.get(url)),reply)

def load(nfkc: String, profile: String, bundle: String, civil: String, url: String, hops: U32) -> IO(Unit):
  do IO<Unit>:
    at : Nat <- IO.now()
    a : List<&2,U32> <- Io.read_bytes(nfkc)
    b : List<&2,U32> <- Io.read_bytes(profile)
    value : Legacy.R(Tr.Policy) <- Tr.from_bundle_file(a,b,bundle,Tr.Clock{number(civil),at})
    prepared(value,url,hops)

# redirects are not followed unless a sixth argument says "follow"
def command(args: List<String>) -> IO(Unit):
  match args:
    case [nfkc,profile,bundle,civil,url]: load(nfkc,profile,bundle,civil,url,0)
    case [nfkc,profile,bundle,civil,url,follow]: load(nfkc,profile,bundle,civil,url,Bool.pick(U32,String.eq(follow,"follow"),5,0))
    case _: IO.die(Unit,2,"nfkc profile explicit-bundle.pem trusted-civil-seconds http(s)-url [follow]")

def main() -> IO(Unit):
  IO.bind(List<String>,Unit,Io.args(),command)
