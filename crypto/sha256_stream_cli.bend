import Base
import ./sha256_stream.bend as S
import ./sha256_file.bend as FileSha
import ./sha256.bend as Sha
import ./bytes.bend as B
import ../io/io.bend as Io

# Test adapter: caller-chosen chunk boundaries and synthetic counter limits.
def emit(value: Maybe<&2, List<&2, U32>>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{bytes}: IO.print(B.hex(bytes))

def finish(owner: Maybe<&1, S.Stream>) -> Maybe<&2, List<&2, U32>>:
  match owner:
    case None{}: None{}
    case Some{stream}: S.finish(stream)

def part(bytes: List<&2, U32>, owner: Maybe<&1, S.Stream>) -> Maybe<&1, S.Stream>:
  match owner:
    case None{}: None{}
    case Some{stream}: S.update(bytes, stream)

def split(bytes: List<&2, U32>, +next_size: Nat, remaining: Nat, pending: List<&2, U32>, owner: Maybe<&1, S.Stream>) -> Maybe<&2, List<&2, U32>>:
  match bytes remaining:
    case Nil{} _: finish(part(List.reverse(&2, U32, pending), owner))
    case Con{byte, tail} 0n:
      split(tail, next_size, next_size, [byte], part(List.reverse(&2, U32, pending), owner))
    case Con{byte, tail} 1n+rest:
      split(tail, next_size, rest, Con{byte, pending}, owner)

def split.valid(valid: Bool, +size: Nat, bytes: List<&2, U32>) -> IO(Unit):
  match valid:
    case False{}: IO.die(Unit, 2, "positive chunk size required")
    case True{}: emit(split(bytes, Nat.sub(size, 1n), size, [], Some{S.start()}))

def split.read(size: Maybe<&2, U32>, path: String) -> IO(Unit):
  match size:
    case None{}: IO.die(Unit, 2, "invalid chunk size")
    case Some{+n}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        split.valid(U32.is_gt(n, 0), U32.to_nat(n), bytes)

def emit_owner(owner: Maybe<&1, S.Stream>) -> IO(Unit):
  match owner:
    case None{}: IO.print("invalid")
    case Some{S.Stream{_, pending, used, high, low}}:
      IO.print(U32.show(high) ++ ":" ++ U32.show(low) ++ ":" ++ U32.show(used) ++ ":" ++ B.hex(pending))

def guards() -> IO(Unit):
  do IO<Unit>:
    emit(finish(S.update([], S.start())))
    emit_owner(S.update([256], S.start()))
    emit_owner(S.update([0, 4294967295], S.start()))
    emit_owner(S.update([1], S.Stream{Sha.initial(), List.replicate(U32, 63n, 0), 63, 0, 4294967295}))
    emit_owner(S.update([1, 2], S.Stream{Sha.initial(), List.replicate(U32, 62n, 0), 62, 0, 4294967294}))
    emit_owner(S.update([1], S.Stream{Sha.initial(), List.replicate(U32, 63n, 0), 63, 536870911, 4294967295}))
    emit_owner(S.update([], S.Stream{Sha.initial(), [], 0, 536870912, 0}))
    emit_owner(S.update([], S.Stream{Sha.initial(), List.replicate(U32, 64n, 0), 64, 0, 64}))
    emit_owner(S.update([], S.Stream{Sha.initial(), [], 1, 0, 1}))
    emit_owner(S.update([], S.Stream{Sha.initial(), [256], 1, 0, 1}))
    emit(S.finish(S.Stream{Sha.initial(), [], 1, 0, 1}))
    emit(S.finish(S.Stream{Sha.initial(), [], 0, 536870912, 0}))

def length.valid(valid: Bool, high: U32, low: U32) -> IO(Unit):
  match valid:
    case False{}: IO.print("invalid")
    case True{}: IO.print(B.hex(S.bit_length(high, low)))

def length.got(high: Maybe<&2, U32>, low: Maybe<&2, U32>) -> IO(Unit):
  match high low:
    case Some{+h} Some{l}: length.valid(S.count_ok(h), h, l)
    case _ _: IO.die(Unit, 2, "invalid counter")

def file.emit(value: Maybe<&2, String>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{hex}: IO.print(hex)

def file.refuel(path: String) -> IO(Unit):
  do IO<Unit>:
    file : File <- IO.try(File, File.open(path, "r"))
    value : File & Result<&1, &1, U32 & String, List<&2, U32>> <- File.read_bytes(file, 4096)
    result : Maybe<&2, String> <- FileSha.loop(2n, 0n, value, Some{S.start()})
    file.emit(result)

def file.overflow(path: String) -> IO(Unit):
  do IO<Unit>:
    file : File <- IO.try(File, File.open(path, "r"))
    value : File & Result<&1, &1, U32 & String, List<&2, U32>> <- File.read_bytes(file, 4096)
    result : Maybe<&2, String> <- FileSha.loop(2n, 1n, value,
      Some{S.Stream{Sha.initial(), List.replicate(U32, 63n, 0), 63, 536870911, 4294967295}})
    file.emit(result)

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{"split", Con{size, Con{path, tail}}}:
      do IO<Unit>:
        split.read(U32.read(size), path)
        dispatch(tail)
    case Con{"length", Con{high, Con{low, tail}}}:
      do IO<Unit>:
        length.got(U32.read(high), U32.read(low))
        dispatch(tail)
    case Con{"file", Con{path, tail}}:
      do IO<Unit>:
        result : Maybe<&2, String> <- FileSha.digest_hex(path)
        file.emit(result)
        dispatch(tail)
    case Con{"refuel", Con{path, tail}}:
      do IO<Unit>:
        file.refuel(path)
        dispatch(tail)
    case Con{"overflow", Con{path, tail}}:
      do IO<Unit>:
        file.overflow(path)
        dispatch(tail)
    case Con{"guards", tail}:
      do IO<Unit>:
        guards()
        dispatch(tail)
    case _: IO.die(Unit, 2, "stream test adapter arguments")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
