import Base
import ./json.bend as J
import ../decimal/decimal.bend as D

# The reader from 04e3888 is a runtime oracle. Large bounds stay out of
# proofs. This catches changes to fractional/exponent and range behavior.
def old.fits.go(ok: Bool, +v: Nat) -> Result<&2, &2, J.Access, U32>:
  match ok:
    case True{}:
      Done{U32.from_nat(v)}
    case False{}:
      Fail{J.OutOfRange{[]}}

def old.fits(+v: Nat) -> Result<&2, &2, J.Access, U32>:
  old.fits.go(Nat.is_le(v, 4294967295n), v)

def old.whole(ok: Bool, sig: List<&2, J.Digit>, +shift: Nat) -> Result<&2, &2, J.Access, U32>:
  match ok:
    case True{}:
      old.fits(J.times10(shift, J.dvalue(sig, 0n)))
    case False{}:
      Fail{J.OutOfRange{[]}}

# hi is where the point falls plus the leading zeros and the negative
# exponent moved across; lo is the digits' count plus the same
def old.sig(+k: Nat, neg: Bool, sig: List<&2, J.Digit>, +hi: Nat, +low: Nat) -> Result<&2, &2, J.Access, U32>:
  match neg sig:
    case _ Nil{}:
      Done{0}
    case True{} Con{_, _}:
      Fail{J.OutOfRange{[]}}
    case False{} Con{d, t}:
      old.whole(Bool.and(Nat.is_ge(hi, Nat.add(k, low)), Nat.is_le(hi, Nat.add(10n, low))), Con{d, t}, Nat.sub(hi, Nat.add(k, low)))

def old.trail(neg: Bool, +sig: List<&2, J.Digit>, +hi: Nat, +low: Nat) -> Result<&2, &2, J.Access, U32>:
  old.sig(J.dlen(sig, 0n), neg, sig, hi, low)

def old.lead(neg: Bool, l: J.Lead0, +point: Nat, +up: Nat, +down: Nat) -> Result<&2, &2, J.Access, U32>:
  match l:
    case J.Lead0{ds, z}:
      old.trail(neg, J.strip_trailing(ds), Nat.add(point, up), Nat.add(z, down))

def old.digits(neg: Bool, d: J.Digits, +e: J.Exp) -> Result<&2, &2, J.Access, U32>:
  match d:
    case J.Digits{ds, point}:
      old.lead(neg, J.drop_lead(ds, 0n), point, J.exp_up(e), J.exp_down(e))

def old.num(n: J.Number) -> Result<&2, &2, J.Access, U32>:
  match n:
    case J.Number{neg, i, f, e}:
      old.digits(neg, J.with_point(i, f), e)

# a whole number from 0 to 2^32 - 1, however it is written: 1e2, 100.0
def old(j: J.Json) -> Result<&2, &2, J.Access, U32>:
  match j:
    case J.JNum{n}:
      old.num(n)
    case other:
      Fail{J.expected(J.KNumber{}, other)}


def read_text(r: Result<&2, &2, J.Access, U32>) -> String:
  match r:
    case Done{x}:
      U32.show(x)
    case Fail{e}:
      J.message_access(e)

def text_number(s: String) -> J.Json:
  J.num_u32.go(J.num(s))

def same_read(+s: String) -> Bool:
  String.eq(read_text(J.u32(text_number(s))), read_text(old(text_number(s))))

# encode is injective by round_trip, so equality here means the same Json,
# including sign, leading digit, fraction and exponent constructors.
def same_number(+x: U32) -> Bool:
  String.eq(J.encode(J.num_u32(x)), J.encode(J.num_u32.go(J.num(U32.show(x)))))

def round_trip(+x: U32) -> Bool:
  String.eq(read_text(J.u32(J.num_u32(x))), U32.show(x))

def agrees(+x: U32) -> Bool:
  Bool.and(same_number(x), Bool.and(round_trip(x),
    Bool.and(same_read(U32.show(x)),
    Bool.and(same_read(U32.show(x) ++ ".0"),
    Bool.and(same_read(U32.show(x) ++ "e0"),
    Bool.and(same_read(U32.show(x) ++ "0e-1"),
    Bool.and(same_read("0." ++ U32.show(x) ++ "e10"),
    Bool.and(same_read(U32.show(x) ++ "e-3"),
    Bool.and(same_read("-" ++ U32.show(x)),
             same_read(U32.show(x) ++ "e3"))))))))))

def sweep(n: Nat, +x: U32, ok: Bool) -> Bool:
  match n:
    case 0n:
      ok
    case 1n+p:
      sweep(p, U32.add(x, 2654435761), Bool.and(ok, agrees(x)))

def same_bool(a: Bool, b: Bool) -> Bool:
  match a b:
    case True{} True{}:
      True{}
    case False{} False{}:
      True{}
    case _ _:
      False{}

def boundary(+x: U32) -> Bool:
  Bool.and(agrees(x), Bool.and(
    same_bool(D.fits(U32.to_nat(x)), Nat.is_le(U32.to_nat(x), 4294967295n)),
    same_bool(D.fits(Nat.add(U32.to_nat(x), 4294967295n)), Nat.is_le(Nat.add(U32.to_nat(x), 4294967295n), 4294967295n))))

def edge() -> Bool:
  Bool.and(boundary(0), Bool.and(boundary(1), Bool.and(boundary(9),
  Bool.and(boundary(10), Bool.and(boundary(99), Bool.and(boundary(100),
  Bool.and(boundary(999999999), Bool.and(boundary(1000000000),
  Bool.and(boundary(4294967294), boundary(4294967295))))))))))

def report(ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.print("numbers: 20,000 constructor/text and legacy-reader cases pass")
    case False{}:
      IO.die(Unit, 1, "numbers: constructor/text or legacy-reader mismatch")

def main() -> IO(Unit):
  report(Bool.and(edge(), sweep(20000n, 1, True{})))
