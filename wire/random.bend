import Base
import ./wire.bend as W

# Local synthetic RNG evaluator. Printing sampled bytes proves the adapter's
# shape/range and lets an independent peer inspect them, not entropy quality.
def digit(+n: U32) -> Char:
  Char.from_u32(Bool.pick(U32, U32.is_lt(n, 10), U32.add(n, 48), U32.add(n, 87)))

def hex(bytes: List<&2, U32>, reversed: String) -> String:
  match bytes:
    case Nil{}: String.reverse(reversed)
    case Con{+b, tail}:
      hex(tail, SCon{digit(U32.and(b, 15)), SCon{digit(U32.shrn(b, 4n)), reversed}})

def emit(value: Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Unit):
  match value:
    case Done{bytes}: IO.print("bytes:" ++ hex(bytes, ""))
    case Fail{(code, _)}: IO.print("failed:" ++ U32.show(code))

def parsed(value: Maybe<&2, U32>) -> IO(Unit):
  match value:
    case Some{count}: IO.bind(Result<&1, &1, U32 & String, List<&2, U32>>, Unit, W.wire_random_bytes(count), emit)
    case None{}: IO.die(Unit, 2, "count must be a U32")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [count]: parsed(U32.read(count))
    case _: IO.die(Unit, 2, "usage: random <count>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
