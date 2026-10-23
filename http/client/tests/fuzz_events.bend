import Base
import ../client.bend as C
import ../../core/event.bend as Ev
import ../../../io/io.bend as Io

# tests/fuzz_events.py's client: N event streams from its run-local URL, one
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

def run(n: Nat, +url: String) -> IO(Unit):
  match n:
    case 0n:
      IO.pure(Unit, Unit{})
    case 1n+p:
      do IO<Unit>:
        r : C.R(C.Ended) <- C.events(~on, cfg(), C.get(url))
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
