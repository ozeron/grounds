import Base
import ../client.bend as C
import ../pool.bend as Pool
import ../../core/event.bend as Ev
import ../../core/text.bend as T

# events and events_retry against tests/fake.py's event stream on 7317:
# one line per event and per end, which check.sh compares with
# tests/events.out

def esc.char(lf: Bool, +x: U32, acc: String) -> String:
  match lf:
    case True{}:
      SCon{'n', SCon{'\\', acc}}
    case False{}:
      SCon{Chr{x}, acc}

def esc(s: String, acc: String) -> String:
  match s:
    case SNil{}:
      String.reverse(acc)
    case SCon{Chr{+x}, t}:
      esc(t, esc.char(U32.is_eq(x, 10), x, acc))

def id.show(m: Maybe<&2, String>) -> String:
  match m:
    case Some{s}:
      s
    case None{}:
      "-"

def line(e: Ev.Message) -> String:
  match e:
    case Ev.Message{n, d, i}:
      "  " ++ n ++ " | " ++ esc(d, "") ++ " | " ++ id.show(i)

def show(e: Ev.Message) -> IO(Bool):
  IO.bind(Unit, Bool, IO.print(line(e)), u => IO.pure(Bool, True{}))

def keep.going(d: String) -> Bool:
  Bool.not(T.same(d, "3", True{}))

def until3.go(l: String, go: Bool) -> IO(Bool):
  IO.bind(Unit, Bool, IO.print(l), u => IO.pure(Bool, go))

def until3(e: Ev.Message) -> IO(Bool):
  match e:
    case Ev.Message{n, +d, i}:
      until3.go("  " ++ n ++ " | " ++ esc(d, "") ++ " | " ++ id.show(i), keep.going(d))

def ended(r: C.R(C.Ended)) -> String:
  match r:
    case Done{C.Ended{l, +n}}:
      "ended: last id " ++ id.show(l) ++ ", " ++ U32.show(n) ++ " reconnects"
    case Fail{e}:
      "error: " ++ C.show(e)

def one(name: String, act: IO(C.R(C.Ended))) -> IO(Unit):
  do IO<Unit>:
    x : Unit <- IO.print(name)
    r : C.R(C.Ended) <- act
    IO.print(ended(r))

def cfg() -> C.Config:
  C.with_timeout(C.default(), 3000)

def pooled(+p: Pool.Pool) -> IO(Unit):
  do IO<Unit>:
    a : Unit <- one("through a pool", Pool.events(~show, p, C.get("http://127.0.0.1:7317/ev")))
    one("through a pool, reconnecting", Pool.events_retry(~show, p, C.get("http://127.0.0.1:7317/drop"), 1))

def main() -> IO(Unit):
  do IO<Unit>:
    a : Unit <- one("a stream, a byte at a time", C.events(~show, cfg(), C.get("http://127.0.0.1:7317/ev")))
    b : Unit <- one("stop at the third", C.events(~until3, cfg(), C.get("http://127.0.0.1:7317/stop")))
    c : Unit <- one("not an event stream", C.events(~show, cfg(), C.get("http://127.0.0.1:7317/html")))
    d : Unit <- one("a 404", C.events(~show, cfg(), C.get("http://127.0.0.1:7317/404")))
    e : Unit <- one("reconnecting, twice", C.events_retry(~show, C.with_retries(cfg(), 0, 2000), C.get("http://127.0.0.1:7317/drop"), 2))
    f : Unit <- one("no reconnect after a 404", C.events_retry(~show, cfg(), C.get("http://127.0.0.1:7317/404"), 3))
    Pool.with(Unit, cfg(), 2, p => pooled(p))
