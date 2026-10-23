import Base
import ./decimal.bend as D

def check(name: String, ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.pure(Unit, Unit{})
    case False{}:
      IO.print("FAIL " ++ name)

def same(a: String, b: String) -> Bool:
  String.eq(a, b)

def reads.go(got: Maybe<&2, U32>, want: Maybe<&2, U32>) -> Bool:
  match got want:
    case Some{x} Some{y}:
      U32.is_eq(x, y)
    case None{} None{}:
      True{}
    case _ _:
      False{}

def reads(s: String, want: Maybe<&2, U32>) -> Bool:
  reads.go(D.read_u32(s), want)

def agrees.go(m: Maybe<&2, U32>, +x: U32, same_text: Bool) -> Bool:
  match m:
    case Some{y}:
      Bool.and(same_text, U32.is_eq(x, y))
    case None{}:
      False{}

# show_u32 writes what U32.show writes, and read_u32 reads it back
def agrees(+x: U32) -> Bool:
  agrees.go(D.read_u32(U32.show(x)), x, same(D.show_u32(x), U32.show(x)))

# n values spread over the range by a step coprime to 2^32
def sweep(n: Nat, +x: U32, ok: Bool) -> Bool:
  match n:
    case 0n:
      ok
    case 1n+p:
      sweep(p, U32.add(x, 2654435761), Bool.and(ok, agrees(x)))

def main() -> IO(Unit):
  do IO<Unit>:
    check("show 0", same(D.show_u32(0), "0"))
    check("show 7", same(D.show_u32(7), "7"))
    check("show 10", same(D.show_u32(10), "10"))
    check("show 1234567890", same(D.show_u32(1234567890), "1234567890"))
    check("show max", same(D.show_u32(4294967295), "4294967295"))
    check("show matches U32.show", same(D.show_u32(305419896), U32.show(305419896)))
    check("show keeps leading zeros", same(D.show(D.DCon{D.D7{}, D.DCon{D.D0{}, D.DNil{}}}), "07"))
    check("read 0", reads("0", Some{0}))
    check("read 000", reads("000", Some{0}))
    check("read 007", reads("007", Some{7}))
    check("read 42", reads("42", Some{42}))
    check("read max", reads("4294967295", Some{4294967295}))
    check("read max + 1", reads("4294967296", None{}))
    check("read 20 digits", reads("99999999999999999999", None{}))
    check("read leading zeros past 10 digits", reads("000000000000042", Some{42}))
    check("read empty", reads("", None{}))
    check("read sign", reads("-1", None{}))
    check("read space", reads(" 1", None{}))
    check("read letter", reads("1a", None{}))
    check("value 1000", Nat.is_eq(D.value(D.of_u32(1000)), 1000n))
    check("inc 999", same(D.show(D.inc(D.of_u32(999))), "1000"))
    check("trim 0", same(D.show(D.trim(D.DCon{D.D0{}, D.DNil{}})), "0"))
    check("sweep agrees with U32.show", sweep(20000n, 1, True{}))
    IO.print("decimal: ok")
