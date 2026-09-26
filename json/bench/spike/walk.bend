import Base

# count quote chars: the cheapest loop that touches every element

def count_s(s: String, +n: U32) -> U32:
  match s:
    case SNil{}:
      n
    case SCon{'"', t}:
      count_s(t, (n + 1 : U32))
    case SCon{_, t}:
      count_s(t, n)

def count_b(bs: List<&2, U32>, +n: U32) -> U32:
  match bs:
    case Nil{}:
      n
    case Con{+b, t}:
      count_b(t, (n + Bool.to_u32(U32.is_eq(b, 34)) : U32))

law text.go:
  for m: File & Result<&1, &1, (U32 & String), String>
  IO(Unit)

def text.go(m):
  (f, r) = m
  do IO<Unit>:
    s : String <- IO.pass(String, r)
    IO.print(U32.show(count_s(s, 0)))

law whole.go:
  for m: File & Result<&1, &1, (U32 & String), List<&2, U32>>
  IO(Unit)

def whole.go(m):
  (f, r) = m
  do IO<Unit>:
    bs : List<&2, U32> <- IO.pass(List<&2, U32>, r)
    IO.print(U32.show(count_b(bs, 0)))

type C is Data:
  C{n: U32, len: U32}

def count_c(bs: List<&2, U32>, +n: U32, +len: U32) -> C:
  match bs:
    case Nil{}:
      C{n, len}
    case Con{+b, t}:
      count_c(t, (n + Bool.to_u32(U32.is_eq(b, 34)) : U32), (len + 1 : U32))

def C.len(c: C) -> U32:
  match c:
    case C{_, l}:
      l

def C.n(c: C) -> U32:
  match c:
    case C{n, _}:
      n

# count a chunk that was read, then read the next, until one is empty
law chunks:
  for fuel: Nat
  for +n: U32
  for m: File & Result<&1, &1, (U32 & String), List<&2, U32>>
  IO(Unit)

def chunks(fuel, n, m):
  match fuel:
    case 0n:
      IO.print(U32.show(n))
    case 1n+p:
      (f, r) = m
      do IO<Unit>:
        bs : List<&2, U32> <- IO.pass(List<&2, U32>, r)
        +c : C = count_c(bs, n, 0)
        Bool.pick(IO(Unit), U32.is_eq(C.len(c), 0), IO.print(U32.show(C.n(c))), IO.bind(File & Result<&1, &1, (U32 & String), List<&2, U32>>, Unit, File.read_bytes(f, 1048576), x => chunks(p, C.n(c), x)))

def pick(mode: String, f: File) -> IO(Unit):
  match mode:
    case SCon{'t', _}:
      do IO<Unit>:
        m : File & Result<&1, &1, (U32 & String), String> <- File.read(f, 200000000)
        text.go(m)
    case SCon{'w', _}:
      do IO<Unit>:
        m : File & Result<&1, &1, (U32 & String), List<&2, U32>> <- File.read_bytes(f, 200000000)
        whole.go(m)
    case _:
      do IO<Unit>:
        m : File & Result<&1, &1, (U32 & String), List<&2, U32>> <- File.read_bytes(f, 1048576)
        chunks(100000n, 0, m)

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{mode, Con{path, _}}:
      do IO<Unit>:
        f : File <- IO.try(File, File.open(path, "r"))
        pick(mode, f)
    case _:
      IO.die(Unit, 2, "walk text|whole|chunk file")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
