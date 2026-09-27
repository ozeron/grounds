import Base
import ../client.bend as C
import ../../core/method.bend as M
import ../../core/response.bend as Res
import ../../core/status.bend as S

# tests/fuzz.py's client: N GETs to 127.0.0.1:7400, one line each, "ok
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

def says(r: C.R()) -> String:
  match r:
    case Done{Res.Response{S.Status{+c}, _, b}}:
      "ok " ++ U32.show(c) ++ " " ++ sum(b, 0, 0)
    case Fail{e}:
      "err " ++ kind(e)

def cfg() -> C.Config:
  C.with_redirects(C.with_timeout(C.default(), 5000), 0)

def run(n: Nat) -> IO(Unit):
  match n:
    case 0n:
      IO.pure(Unit, Unit{})
    case 1n+p:
      do IO<Unit>:
        r : C.R() <- C.request(cfg(), M.MGet{}, "http://127.0.0.1:7400/", [], [])
        x : Unit <- IO.print(says(r))
        run(p)

def count(a: List<String>) -> Nat:
  match a:
    case Con{s, _}:
      U32.to_nat(C.port.num.of(s))
    case Nil{}:
      100n

def main() -> IO(Unit):
  IO.bind(List<String>, Unit, IO.args(), a => run(count(a)))
