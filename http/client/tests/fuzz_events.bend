import Base
import ../client.bend as C
import ../../core/event.bend as Ev

# tests/fuzz_events.py's client: N event streams from 127.0.0.1:7401, one
# line per event and one per end, each string as its code points, for the
# reference to compare

def codes(s: String) -> String:
  match s:
    case SNil{}:
      ""
    case SCon{Chr{+x}, t}:
      U32.show(x) ++ "." ++ codes(t)

def id.show(m: Maybe<&2, String>) -> String:
  match m:
    case Some{s}:
      "=" ++ codes(s)
    case None{}:
      "-"

def on(e: Ev.Message) -> IO(Bool):
  match e:
    case Ev.Message{n, d, i}:
      IO.bind(Unit, Bool, IO.print("ev " ++ codes(n) ++ " " ++ codes(d) ++ " " ++ id.show(i)), u => IO.pure(Bool, True{}))

def says(r: C.R(C.Ended)) -> String:
  match r:
    case Done{C.Ended{l, _}}:
      "end " ++ id.show(l)
    case Fail{e}:
      "err " ++ C.show(e)

def cfg() -> C.Config:
  C.with_timeout(C.default(), 20000)

def run(n: Nat) -> IO(Unit):
  match n:
    case 0n:
      IO.pure(Unit, Unit{})
    case 1n+p:
      do IO<Unit>:
        r : C.R(C.Ended) <- C.events(~on, cfg(), C.get("http://127.0.0.1:7401/"))
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
