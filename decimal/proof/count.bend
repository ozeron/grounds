import Base
import ../decimal.bend as D
import ./nat.bend as N

# What of_u32 counts, and that to_u32 reads it back: doubling a Dec doubles
# its value, so of_word counts the word's bits; every word is at most
# top(n), so to_u32 never gives up on one; and from_nat rebuilds the word.

def bit(c: Bool) -> Nat:
  match c:
    case True{}:
      1n
    case False{}:
      0n

def ten(c: Bool) -> Nat:
  match c:
    case True{}:
      10n
    case False{}:
      0n

# Doubling
# --------

# 10 (c + 2v) == 10c + 2 (10 v)
law mul_ten:
  for +c: Bool
  for +v: Nat
  {Nat.mul(10n, Nat.add(bit(c), Nat.double(v))) == Nat.add(ten(c), Nat.double(Nat.mul(10n, v))) : Nat}

def mul_ten(c, v):
  match c:
    case True{}:
      %Equal.sym(Nat, Nat.mul(10n, 1n+Nat.double(v)), Nat.add(10n, Nat.mul(10n, Nat.double(v))), N.mul_succ(10n, Nat.double(v))) : {_ == Nat.add(10n, Nat.double(Nat.mul(10n, v))) : Nat}
      Equal.cong(Nat, Nat, y => Nat.add(10n, y), Nat.mul(10n, Nat.double(v)), Nat.double(Nat.mul(10n, v)), N.mul_double(10n, v))
    case False{}:
      N.mul_double(10n, v)

# one digit doubled: the table in dbl.dig and dbl.carry is 2x + c
law dbl_digit:
  for +x: D.Dig
  for +c: Bool
  for +m: Nat
  {Nat.add(D.dig.val(D.dbl.dig(x, c)), Nat.add(ten(D.dbl.carry(x)), Nat.double(m))) == Nat.add(bit(c), Nat.double(Nat.add(D.dig.val(x), m))) : Nat}

def dbl_digit(x, c, m):
  match x c:
    case D.D0{} False{}:
      {==}
    case D.D0{} True{}:
      {==}
    case D.D1{} False{}:
      {==}
    case D.D1{} True{}:
      {==}
    case D.D2{} False{}:
      {==}
    case D.D2{} True{}:
      {==}
    case D.D3{} False{}:
      {==}
    case D.D3{} True{}:
      {==}
    case D.D4{} False{}:
      {==}
    case D.D4{} True{}:
      {==}
    case D.D5{} False{}:
      {==}
    case D.D5{} True{}:
      {==}
    case D.D6{} False{}:
      {==}
    case D.D6{} True{}:
      {==}
    case D.D7{} False{}:
      {==}
    case D.D7{} True{}:
      {==}
    case D.D8{} False{}:
      {==}
    case D.D8{} True{}:
      {==}
    case D.D9{} False{}:
      {==}
    case D.D9{} True{}:
      {==}

law dbl_value:
  for +d: D.Dec
  for +c: Bool
  {D.value(D.dbl(d, c)) == Nat.add(bit(c), Nat.double(D.value(d))) : Nat}

def dbl_value(d, c):
  match d:
    case D.DNil{}:
      match c:
        case True{}:
          {==}
        case False{}:
          {==}
    case D.DCon{x, t}:
      %Equal.sym(Nat, D.value(D.dbl(t, D.dbl.carry(x))), Nat.add(bit(D.dbl.carry(x)), Nat.double(D.value(t))), dbl_value(t, D.dbl.carry(x))) : {Nat.add(D.dig.val(D.dbl.dig(x, c)), Nat.mul(10n, _)) == Nat.add(bit(c), Nat.double(Nat.add(D.dig.val(x), Nat.mul(10n, D.value(t))))) : Nat}
      %Equal.sym(Nat, Nat.mul(10n, Nat.add(bit(D.dbl.carry(x)), Nat.double(D.value(t)))), Nat.add(ten(D.dbl.carry(x)), Nat.double(Nat.mul(10n, D.value(t)))), mul_ten(D.dbl.carry(x), D.value(t))) : {Nat.add(D.dig.val(D.dbl.dig(x, c)), _) == Nat.add(bit(c), Nat.double(Nat.add(D.dig.val(x), Nat.mul(10n, D.value(t))))) : Nat}
      dbl_digit(x, c, Nat.mul(10n, D.value(t)))

law of_word_value:
  for +n: Nat
  for +w: Word(n)
  {D.value(D.of_word(n, w)) == Word.to_nat(n, w) : Nat}

def of_word_value(n, w):
  match n:
    case 0n:
      match w:
        case WNil{}:
          {==}
    case 1n+p:
      match w:
        case WCon{True{}, t}:
          %Equal.sym(Nat, D.value(D.dbl(D.of_word(p, t), True{})), 1n+Nat.double(D.value(D.of_word(p, t))), dbl_value(D.of_word(p, t), True{})) : {_ == 1n+Nat.double(Word.to_nat(p, t)) : Nat}
          Equal.cong(Nat, Nat, y => 1n+Nat.double(y), D.value(D.of_word(p, t)), Word.to_nat(p, t), of_word_value(p, t))
        case WCon{False{}, t}:
          %Equal.sym(Nat, D.value(D.dbl(D.of_word(p, t), False{})), Nat.double(D.value(D.of_word(p, t))), dbl_value(D.of_word(p, t), False{})) : {_ == Nat.double(Word.to_nat(p, t)) : Nat}
          Equal.cong(Nat, Nat, y => Nat.double(y), D.value(D.of_word(p, t)), Word.to_nat(p, t), of_word_value(p, t))

# Words from counts
# -----------------

# the word that counts k, by k increments from zero
def wf(+n: Nat, k: Nat) -> Word(n):
  match k:
    case 0n:
      Word.zero(n)
    case 1n+p:
      Word.inc(n, wf(n, p))

law from_nat_wf:
  for +k: Nat
  {U32.from_nat(k) == U32{wf(32n, k)} : U32}

def from_nat_wf(k):
  match k:
    case 0n:
      {==}
    case 1n+p:
      %Equal.sym(U32, U32.from_nat(p), U32{wf(32n, p)}, from_nat_wf(p)) : {U32.inc(_) == U32{Word.inc(32n, wf(32n, p))} : U32}
      {==}

law wf_even:
  for +p: Nat
  for +m: Nat
  {wf(1n+p, Nat.double(m)) == WCon{False{}, wf(p, m)} : Word(1n+p)}

def wf_even(p, m):
  match m:
    case 0n:
      {==}
    case 1n+q:
      %Equal.sym(Word(1n+p), wf(1n+p, Nat.double(q)), WCon{False{}, wf(p, q)}, wf_even(p, q)) : {Word.inc(1n+p, Word.inc(1n+p, _)) == WCon{False{}, Word.inc(p, wf(p, q))} : Word(1n+p)}
      {==}

law wf_odd:
  for +p: Nat
  for +m: Nat
  {wf(1n+p, 1n+Nat.double(m)) == WCon{True{}, wf(p, m)} : Word(1n+p)}

def wf_odd(p, m):
  %Equal.sym(Word(1n+p), wf(1n+p, Nat.double(m)), WCon{False{}, wf(p, m)}, wf_even(p, m)) : {Word.inc(1n+p, _) == WCon{True{}, wf(p, m)} : Word(1n+p)}
  {==}

law wf_to_nat:
  for +n: Nat
  for +w: Word(n)
  {wf(n, Word.to_nat(n, w)) == w : Word(n)}

def wf_to_nat(n, w):
  match n:
    case 0n:
      match w:
        case WNil{}:
          {==}
    case 1n+p:
      match w:
        case WCon{True{}, t}:
          %Equal.sym(Word(1n+p), wf(1n+p, 1n+Nat.double(Word.to_nat(p, t))), WCon{True{}, wf(p, Word.to_nat(p, t))}, wf_odd(p, Word.to_nat(p, t))) : {_ == WCon{True{}, t} : Word(1n+p)}
          Equal.cong(Word(p), Word(1n+p), y => WCon{True{}, y}, wf(p, Word.to_nat(p, t)), t, wf_to_nat(p, t))
        case WCon{False{}, t}:
          %Equal.sym(Word(1n+p), wf(1n+p, Nat.double(Word.to_nat(p, t))), WCon{False{}, wf(p, Word.to_nat(p, t))}, wf_even(p, Word.to_nat(p, t))) : {_ == WCon{False{}, t} : Word(1n+p)}
          Equal.cong(Word(p), Word(1n+p), y => WCon{False{}, y}, wf(p, Word.to_nat(p, t)), t, wf_to_nat(p, t))

# Fitting
# -------
# every u up to some word's count survives the trip through that word

def par(n: Nat) -> Bool:
  match n:
    case 0n:
      False{}
    case 1n+p:
      match p:
        case 0n:
          True{}
        case 1n+q:
          par(q)

def half(n: Nat) -> Nat:
  match n:
    case 0n:
      0n
    case 1n+p:
      match p:
        case 0n:
          0n
        case 1n+q:
          1n+half(q)

law split:
  for +n: Nat
  {Nat.add(bit(par(n)), Nat.double(half(n))) == n : Nat}

def split(n):
  match n:
    case 0n:
      {==}
    case 1n+p:
      match p:
        case 0n:
          {==}
        case 1n+q:
          %Equal.sym(Nat, Nat.add(bit(par(q)), 2n+Nat.double(half(q))), 1n+Nat.add(bit(par(q)), 1n+Nat.double(half(q))), N.add_succ(bit(par(q)), 1n+Nat.double(half(q)))) : {_ == 2n+q : Nat}
          %Equal.sym(Nat, Nat.add(bit(par(q)), 1n+Nat.double(half(q))), 1n+Nat.add(bit(par(q)), Nat.double(half(q))), N.add_succ(bit(par(q)), Nat.double(half(q)))) : {1n+_ == 2n+q : Nat}
          Equal.cong(Nat, Nat, y => 2n+y, Nat.add(bit(par(q)), Nat.double(half(q))), q, split(q))

def top_bit(b: Bool, v: Nat) -> Nat:
  match b:
    case True{}:
      1n+Nat.double(v)
    case False{}:
      Nat.double(v)

law even_le:
  for +b: Bool
  for +h: Nat
  for +v: Nat
  for e: {Nat.is_le(Nat.double(h), top_bit(b, v)) == True{} : Bool}
  {Nat.is_le(h, v) == True{} : Bool}

def even_le(b, h, v, e):
  match b:
    case True{}:
      %N.le_double_odd(h, v) : {_ == True{} : Bool}
      e
    case False{}:
      %N.le_double(h, v) : {_ == True{} : Bool}
      e

law odd_le:
  for +b: Bool
  for +h: Nat
  for +v: Nat
  for e: {Nat.is_le(1n+Nat.double(h), top_bit(b, v)) == True{} : Bool}
  {Nat.is_le(h, v) == True{} : Bool}

def odd_le(b, h, v, e):
  match b:
    case True{}:
      %N.le_double(h, v) : {_ == True{} : Bool}
      e
    case False{}:
      N.le_odd_double(h, v, e)

# c + 2h, at most what w counts, survives the trip through w: the low bit
# is c, and h goes on through the rest of w
law wf_bits:
  for +n: Nat
  for +w: Word(n)
  for +c: Bool
  for +h: Nat
  for e: {Nat.is_le(Nat.add(bit(c), Nat.double(h)), Word.to_nat(n, w)) == True{} : Bool}
  {Word.to_nat(n, wf(n, Nat.add(bit(c), Nat.double(h)))) == Nat.add(bit(c), Nat.double(h)) : Nat}

def wf_bits(n, w, c, h, e):
  match n:
    case 0n:
      match w:
        case WNil{}:
          match c h:
            case False{} 0n:
              {==}
            case False{} 1n+q:
              N.absurd({Word.to_nat(0n, wf(0n, Nat.double(1n+q))) == Nat.double(1n+q) : Nat}, e)
            case True{} _:
              N.absurd({Word.to_nat(0n, wf(0n, 1n+Nat.double(h))) == 1n+Nat.double(h) : Nat}, e)
    case 1n+p:
      match w c:
        case WCon{True{}, t} True{}:
          %Equal.sym(Word(1n+p), wf(1n+p, 1n+Nat.double(h)), WCon{True{}, wf(p, h)}, wf_odd(p, h)) : {Word.to_nat(1n+p, _) == 1n+Nat.double(h) : Nat}
          %split(h) : {1n+Nat.double(Word.to_nat(p, wf(p, _))) == 1n+Nat.double(_) : Nat}
          %Equal.sym(Nat, Word.to_nat(p, wf(p, Nat.add(bit(par(h)), Nat.double(half(h))))), Nat.add(bit(par(h)), Nat.double(half(h))), wf_bits(p, t, par(h), half(h), N.le_subst(Nat.add(bit(par(h)), Nat.double(half(h))), h, Word.to_nat(p, t), split(h), odd_le(True{}, h, Word.to_nat(p, t), e)))) : {1n+Nat.double(_) == 1n+Nat.double(Nat.add(bit(par(h)), Nat.double(half(h)))) : Nat}
          {==}
        case WCon{True{}, t} False{}:
          %Equal.sym(Word(1n+p), wf(1n+p, Nat.double(h)), WCon{False{}, wf(p, h)}, wf_even(p, h)) : {Word.to_nat(1n+p, _) == Nat.double(h) : Nat}
          %split(h) : {Nat.double(Word.to_nat(p, wf(p, _))) == Nat.double(_) : Nat}
          %Equal.sym(Nat, Word.to_nat(p, wf(p, Nat.add(bit(par(h)), Nat.double(half(h))))), Nat.add(bit(par(h)), Nat.double(half(h))), wf_bits(p, t, par(h), half(h), N.le_subst(Nat.add(bit(par(h)), Nat.double(half(h))), h, Word.to_nat(p, t), split(h), even_le(True{}, h, Word.to_nat(p, t), e)))) : {Nat.double(_) == Nat.double(Nat.add(bit(par(h)), Nat.double(half(h)))) : Nat}
          {==}
        case WCon{False{}, t} True{}:
          %Equal.sym(Word(1n+p), wf(1n+p, 1n+Nat.double(h)), WCon{True{}, wf(p, h)}, wf_odd(p, h)) : {Word.to_nat(1n+p, _) == 1n+Nat.double(h) : Nat}
          %split(h) : {1n+Nat.double(Word.to_nat(p, wf(p, _))) == 1n+Nat.double(_) : Nat}
          %Equal.sym(Nat, Word.to_nat(p, wf(p, Nat.add(bit(par(h)), Nat.double(half(h))))), Nat.add(bit(par(h)), Nat.double(half(h))), wf_bits(p, t, par(h), half(h), N.le_subst(Nat.add(bit(par(h)), Nat.double(half(h))), h, Word.to_nat(p, t), split(h), odd_le(False{}, h, Word.to_nat(p, t), e)))) : {1n+Nat.double(_) == 1n+Nat.double(Nat.add(bit(par(h)), Nat.double(half(h)))) : Nat}
          {==}
        case WCon{False{}, t} False{}:
          %Equal.sym(Word(1n+p), wf(1n+p, Nat.double(h)), WCon{False{}, wf(p, h)}, wf_even(p, h)) : {Word.to_nat(1n+p, _) == Nat.double(h) : Nat}
          %split(h) : {Nat.double(Word.to_nat(p, wf(p, _))) == Nat.double(_) : Nat}
          %Equal.sym(Nat, Word.to_nat(p, wf(p, Nat.add(bit(par(h)), Nat.double(half(h))))), Nat.add(bit(par(h)), Nat.double(half(h))), wf_bits(p, t, par(h), half(h), N.le_subst(Nat.add(bit(par(h)), Nat.double(half(h))), h, Word.to_nat(p, t), split(h), even_le(False{}, h, Word.to_nat(p, t), e)))) : {Nat.double(_) == Nat.double(Nat.add(bit(par(h)), Nat.double(half(h)))) : Nat}
          {==}

# every u up to what w counts survives the trip through w
law wf_nat:
  for +n: Nat
  for +w: Word(n)
  for +u: Nat
  for e: {Nat.is_le(u, Word.to_nat(n, w)) == True{} : Bool}
  {Word.to_nat(n, wf(n, u)) == u : Nat}

def wf_nat(n, w, u, e):
  %split(u) : {Word.to_nat(n, wf(n, _)) == _ : Nat}
  wf_bits(n, w, par(u), half(u), N.le_subst(Nat.add(bit(par(u)), Nat.double(half(u))), u, Word.to_nat(n, w), split(u), e))

law fits_le:
  for +w: Word(32n)
  for +u: Nat
  for e: {Nat.is_le(u, Word.to_nat(32n, w)) == True{} : Bool}
  {D.fits(u) == True{} : Bool}

def fits_le(w, u, e):
  %Equal.sym(U32, U32.from_nat(u), U32{wf(32n, u)}, from_nat_wf(u)) : {Nat.is_eq(U32.to_nat(_), u) == True{} : Bool}
  %Equal.sym(Nat, Word.to_nat(32n, wf(32n, u)), u, wf_nat(32n, w, u, e)) : {Nat.is_eq(_, u) == True{} : Bool}
  %Equal.sym(Cmp, Nat.cmp(u, u), EQ{}, N.cmp_refl(u)) : {Cmp.is_eq(_) == True{} : Bool}
  {==}

# v <= x + 10v
law le_ten:
  for +x: D.Dig
  for +v: Nat
  {Nat.is_le(v, Nat.add(D.dig.val(x), Nat.mul(10n, v))) == True{} : Bool}

def le_ten(x, v):
  %Equal.sym(Nat, Nat.add(D.dig.val(x), Nat.add(v, Nat.mul(9n, v))), Nat.add(v, Nat.add(D.dig.val(x), Nat.mul(9n, v))), N.add_swap(D.dig.val(x), v, Nat.mul(9n, v))) : {Nat.is_le(v, _) == True{} : Bool}
  N.le_add(v, Nat.add(D.dig.val(x), Nat.mul(9n, v)))

# to_u32 gives up only past 2^32 - 1: when d counts at most some word,
# so does every prefix of it
law go_value:
  for +d: D.Dec
  for +w: Word(32n)
  for +e: {Nat.is_le(D.value(d), Word.to_nat(32n, w)) == True{} : Bool}
  {D.to_u32.go(d) == Some{D.value(d)} : Maybe<&2, Nat>}

def go_value(d, w, e):
  match d:
    case D.DNil{}:
      {==}
    case D.DCon{x, t}:
      %Equal.sym(Maybe<&2, Nat>, D.to_u32.go(t), Some{D.value(t)}, go_value(t, w, N.le_trans(D.value(t), Nat.add(D.dig.val(x), Nat.mul(10n, D.value(t))), Word.to_nat(32n, w), le_ten(x, D.value(t)), e))) : {D.to_u32.step(x, _) == Some{Nat.add(D.dig.val(x), Nat.mul(10n, D.value(t)))} : Maybe<&2, Nat>}
      %Equal.sym(Bool, D.fits(Nat.add(D.dig.val(x), Nat.mul(10n, D.value(t)))), True{}, fits_le(w, Nat.add(D.dig.val(x), Nat.mul(10n, D.value(t))), e)) : {D.to_u32.keep(_, Nat.add(D.dig.val(x), Nat.mul(10n, D.value(t)))) == Some{Nat.add(D.dig.val(x), Nat.mul(10n, D.value(t)))} : Maybe<&2, Nat>}
      {==}

# Reading back
# ------------

law of_u32_value:
  for +x: U32
  {D.value(D.of_u32(x)) == U32.to_nat(x) : Nat}

def of_u32_value(x):
  match x:
    case U32{w}:
      of_word_value(32n, w)

law u32_round_trip:
  for +x: U32
  {D.to_u32(D.of_u32(x)) == Some{x} : Maybe<&2, U32>}

def u32_round_trip(x):
  match x:
    case U32{w}:
      %Equal.sym(Maybe<&2, Nat>, D.to_u32.go(D.of_word(32n, w)), Some{D.value(D.of_word(32n, w))}, go_value(D.of_word(32n, w), w, N.le_subst(D.value(D.of_word(32n, w)), Word.to_nat(32n, w), Word.to_nat(32n, w), of_word_value(32n, w), N.le_refl(Word.to_nat(32n, w))))) : {D.to_u32.fin(_) == Some{U32{w}} : Maybe<&2, U32>}
      %Equal.sym(Nat, D.value(D.of_word(32n, w)), Word.to_nat(32n, w), of_word_value(32n, w)) : {Some{U32.from_nat(_)} == Some{U32{w}} : Maybe<&2, U32>}
      %Equal.sym(U32, U32.from_nat(Word.to_nat(32n, w)), U32{wf(32n, Word.to_nat(32n, w))}, from_nat_wf(Word.to_nat(32n, w))) : {Some{_} == Some{U32{w}} : Maybe<&2, U32>}
      %Equal.sym(Word(32n), wf(32n, Word.to_nat(32n, w)), w, wf_to_nat(32n, w)) : {Some{U32{_}} == Some{U32{w}} : Maybe<&2, U32>}
      {==}
