import Base
import ../client.bend as C
import ../../../io/io.bend as Io

# tests/fuzz.py's client: N GETs to its run-local URL, one line each, "ok
# CODE LEN SUM" or "err KIND", for the reference to compare

def sum(bs: List<&2, U32>, +s: U32, +n: U32) -> String:
  match bs:
    case Nil{}:
      U32.show(n) ++ " " ++ U32.show(s)
    case Con{+b, t}:
      sum(t, (((s * 31) : U32) + b : U32), (n + 1 : U32))

def kind(e: C.Err) -> String:
  match e:
    case C.TooLarge{}:
      "toolarge"
    case C.BadResponse{}:
      "bad"
    case C.Closed{}:
      "closed"
    case C.Timeout{}:
      "timeout"
    case other:
      C.show(other)

def says(r: C.R(C.Reply)) -> String:
  match r:
    case Done{C.Reply{+c, _, b}}:
      "ok " ++ U32.show(c) ++ " " ++ sum(b, 0, 0)
    case Fail{e}:
      "err " ++ kind(e)

def cfg() -> C.Config:
  C.with_redirects(C.with_timeout(C.default(), 20000), 0)

def run(n: Nat, +url: String) -> IO(Unit):
  match n:
    case 0n:
      IO.pure(Unit, Unit{})
    case 1n+p:
      do IO<Unit>:
        r : C.R(C.Reply) <- C.send(cfg(), C.get(url))
        x : Unit <- IO.print(says(r))
        run(p, url)

def args(a: List<String>) -> IO(Unit):
  match a:
    case Con{s, Con{url, _}}:
      run(U32.to_nat(C.port.num.of(s)), url)
    case other:
      IO.print("expected N URL")

def main() -> IO(Unit):
  IO.bind(List<String>, Unit, Io.args(), a => args(a))
