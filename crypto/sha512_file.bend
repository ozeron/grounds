import Base
import ./sha512.bend as S512
import ./sha384.bend as S384
import ./sha512_stream.bend as S

# OS file reads only; SHA state, buffering, length and final padding are Bend.
# Two decreasing counters cover more reads than the SHA byte-length limit,
# including one-byte short reads. They satisfy Bend's recursion check.
def loop(+epochs: Nat, fuel: Nat, value: File & Result<&1, &1, U32 & String, List<&2, U32>>, owner: Maybe<&1, S.Stream>) -> IO(Maybe<&2, List<&2, U32>>):
  match epochs fuel value owner:
    case _ _ Tuple{f, Fail{error}} _:
      do IO<Maybe<&2, List<&2, U32>>>:
        File.close(f)
        IO.pass(Maybe<&2, List<&2, U32>>, Fail{error})
    case _ _ Tuple{f, Done{_}} None{}:
      do IO<Maybe<&2, List<&2, U32>>>:
        File.close(f)
        IO.pure(Maybe<&2, List<&2, U32>>, None{})
    case _ _ Tuple{f, Done{Nil{}}} Some{stream}:
      do IO<Maybe<&2, List<&2, U32>>>:
        File.close(f)
        IO.pure(Maybe<&2, List<&2, U32>>, S.finish(stream))
    case 0n _ Tuple{f, Done{_}} Some{_}:
      do IO<Maybe<&2, List<&2, U32>>>:
        File.close(f)
        IO.die(Maybe<&2, List<&2, U32>>, 1, "SHA file read limit")
    case 1n+p 0n current state:
      loop(p, 4294967295n, current, state)
    case 1n+p 1n+rest Tuple{f, Done{Con{byte, tail}}} Some{stream}:
      do IO<Maybe<&2, List<&2, U32>>>:
        next : File & Result<&1, &1, U32 & String, List<&2, U32>> <- File.read_bytes(f, 4096)
        loop(epochs, rest, next, S.update(Con{byte, tail}, stream))

def read_digest(state: S512.State, path: String) -> IO(Maybe<&2, List<&2, U32>>):
  do IO<Maybe<&2, List<&2, U32>>>:
    file : File <- IO.try(File, File.open(path, "r"))
    value : File & Result<&1, &1, U32 & String, List<&2, U32>> <- File.read_bytes(file, 4096)
    loop(4294967295n, 4294967295n, value, Some{S.start(state)})

def initial(sha384: Bool) -> S512.State:
  match sha384:
    case True{}: S512.initial384()
    case False{}: S512.initial()

def output(sha384: Bool, value: Maybe<&2, List<&2, U32>>) -> Maybe<&2, String>:
  match sha384:
    case True{}: S512.digest_hex.got(S384.truncate(value))
    case False{}: S512.digest_hex.got(value)

def digest_hex(+sha384: Bool, path: String) -> IO(Maybe<&2, String>):
  do IO<Maybe<&2, String>>:
    result : Maybe<&2, List<&2, U32>> <- read_digest(initial(sha384), path)
    IO.pure(Maybe<&2, String>, output(sha384, result))
