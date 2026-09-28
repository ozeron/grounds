import Base
import ../client.bend as C
import ../../core/event.bend as Ev

# prints each event of a stream, reconnecting up to 5 times

def on(e: Ev.Message) -> IO(Bool):
  match e:
    case Ev.Message{n, d, _}:
      IO.bind(Unit, Bool, IO.print(n ++ ": " ++ d), u => IO.pure(Bool, True{}))

def said(r: C.R(C.Ended)) -> String:
  match r:
    case Done{C.Ended{_, +n}}:
      "ended after " ++ U32.show(n) ++ " reconnects"
    case Fail{e}:
      C.show(e)

def main() -> IO(Unit):
  IO.bind(C.R(C.Ended), Unit, C.events_retry(~on, C.default(), C.get("http://127.0.0.1:8086/events"), 5), r => IO.print_err(said(r)))
