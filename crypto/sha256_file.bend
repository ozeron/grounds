import Base
import ./sha256_stream.bend as S

# OS file reads only; SHA state, buffering, length and final padding are Bend.
# Two decreasing counters cover more reads than the SHA byte-length limit,
# including one-byte short reads. They satisfy Bend's recursion check.
def loop(+epochs: Nat, fuel: Nat, value: File & Result<&1, &1, U32 & String, List<&2, U32>>, owner: Maybe<&1, S.Stream>) -> IO(Maybe<&2, String>):
  match epochs fuel value owner:
    case _ _ Tuple{f, Fail{error}} _:
      do IO<Maybe<&2, String>>:
        File.close(f)
        IO.pass(Maybe<&2, String>, Fail{error})
    case _ _ Tuple{f, Done{_}} None{}:
      do IO<Maybe<&2, String>>:
        File.close(f)
        IO.pure(Maybe<&2, String>, None{})
    case _ _ Tuple{f, Done{Nil{}}} Some{stream}:
      do IO<Maybe<&2, String>>:
        File.close(f)
        IO.pure(Maybe<&2, String>, S.finish_hex(stream))
    case 0n _ Tuple{f, Done{_}} Some{_}:
      do IO<Maybe<&2, String>>:
        File.close(f)
        IO.die(Maybe<&2, String>, 1, "SHA file read limit")
    case 1n+p 0n current state:
      loop(p, 4294967295n, current, state)
    case 1n+p 1n+rest Tuple{f, Done{Con{byte, tail}}} Some{stream}:
      do IO<Maybe<&2, String>>:
        next : File & Result<&1, &1, U32 & String, List<&2, U32>> <- File.read_bytes(f, 4096)
        loop(epochs, rest, next, S.update(Con{byte, tail}, stream))

def digest_hex(path: String) -> IO(Maybe<&2, String>):
  do IO<Maybe<&2, String>>:
    file : File <- IO.try(File, File.open(path, "r"))
    value : File & Result<&1, &1, U32 & String, List<&2, U32>> <- File.read_bytes(file, 4096)
    loop(4294967295n, 4294967295n, value, Some{S.start()})
