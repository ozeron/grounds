import Base
import ../stun_retry.bend as Retry

def output(waits: List<&2, U32>) -> IO(Unit):
  match waits:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{+ms, tail}:
      do IO<Unit>:
        x : Unit <- IO.print(U32.show(ms))
        output(tail)

def show(waits: Maybe<&2, List<&2, U32>>) -> IO(Unit):
  match waits:
    case None{}: IO.print("invalid")
    case Some{values}: output(values)

def parsed(rto: Maybe<&2, U32>, requests: Maybe<&2, U32>, factor: Maybe<&2, U32>) -> IO(Unit):
  match rto requests factor:
    case Some{r} Some{c} Some{m}: show(Retry.intervals(Retry.Policy{r, c, m}))
    case _ _ _: IO.print("invalid")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [rto, requests, factor]: parsed(U32.read(rto), U32.read(requests), U32.read(factor))
    case _: IO.die(Unit, 2, "usage: retry_schedule <rto> <requests> <final_factor>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
