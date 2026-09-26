import Base

# grounds-io: whole-file reads, as text or as raw bytes.
#
#   import ../io/io.bend as Io
#   Io.read_text(path, limit)   # Got{text}, or TooBig{size} past limit bytes
#   Io.read_bytes(path)         # the bytes as they are, 0..255
#
# A path is used once: a String used twice is shared, and sharing any
# String makes every String in the program reference counted.

# a read text, or the file's size when it was over the limit
type Read is Data:
  Got{text: String}
  TooBig{size: U32}

def over(limit: Maybe<&2, U32>, +n: U32) -> Bool:
  match limit:
    case None{}:
      False{}
    case Some{x}:
      U32.is_gt(n, x)

law text.close:
  for m: File & Result<&1, &1, (U32 & String), String>
  IO(Read)

def text.close(m):
  (f, r) = m
  do IO<Read>:
    text : String <- IO.pass(String, r)
    x : Unit <- File.close(f)
    return Got{text}

def text.check(big: Bool, f: File, +n: U32) -> IO(Read):
  match big:
    case True{}:
      do IO<Read>:
        x : Unit <- File.close(f)
        return TooBig{n}
    case False{}:
      do IO<Read>:
        t : File & Result<&1, &1, (U32 & String), String> <- File.read(f, (n + 1 : U32))
        text.close(t)

law text.size:
  for m: File & Result<&1, &1, (U32 & String), U32>
  for limit: Maybe<&2, U32>
  IO(Read)

def text.size(m, limit):
  (f, r) = m
  do IO<Read>:
    +n : U32 <- IO.pass(U32, r)
    text.check(over(limit, n), f, n)

# the file as text, decoded by the runtime, which turns each bad UTF-8
# sequence into U+FFFD; None reads any size
def read_text(path: String, limit: Maybe<&2, U32>) -> IO(Read):
  do IO<Read>:
    f : File <- IO.try(File, File.open(path, "r"))
    m : File & Result<&1, &1, (U32 & String), U32> <- File.size(f)
    text.size(m, limit)

law bytes.close:
  for m: File & Result<&1, &1, (U32 & String), List<&2, U32>>
  IO(List<&2, U32>)

def bytes.close(m):
  (f, r) = m
  do IO<List<&2, U32>>:
    bs : List<&2, U32> <- IO.pass(List<&2, U32>, r)
    x : Unit <- File.close(f)
    return bs

law bytes.size:
  for m: File & Result<&1, &1, (U32 & String), U32>
  IO(List<&2, U32>)

def bytes.size(m):
  (f, r) = m
  do IO<List<&2, U32>>:
    n : U32 <- IO.pass(U32, r)
    t : File & Result<&1, &1, (U32 & String), List<&2, U32>> <- File.read_bytes(f, (n + 1 : U32))
    bytes.close(t)

# the file's bytes as they are (0..255), one list cell each
def read_bytes(path: String) -> IO(List<&2, U32>):
  do IO<List<&2, U32>>:
    f : File <- IO.try(File, File.open(path, "r"))
    m : File & Result<&1, &1, (U32 & String), U32> <- File.size(f)
    bytes.size(m)
