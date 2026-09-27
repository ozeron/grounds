import Base
import ../json.bend as J
import ../LAWS.bend as L

# Reads: a key compared with itself matches, so get finds it; and each
# read's failures other than mistyped (a missing item, a number out of
# range) are never mistyped.

law word_refl:
  for +n: Nat
  for +w: Word(n)
  {Word.cmp(n, w, w) == EQ{} : Cmp}

def word_refl(n, w):
  match n:
    case 0n:
      {==}
    case 1n+p:
      match w:
        case WCon{True{}, t}:
          %Equal.sym(Cmp, Word.cmp(p, t, t), EQ{}, word_refl(p, t)) : {Word.cmp.fin(True{}, True{}, _) == EQ{} : Cmp}
          {==}
        case WCon{False{}, t}:
          %Equal.sym(Cmp, Word.cmp(p, t, t), EQ{}, word_refl(p, t)) : {Word.cmp.fin(False{}, False{}, _) == EQ{} : Cmp}
          {==}

law char_refl:
  for +c: Char
  {Char.is_eq(c, c) == True{} : Bool}

def char_refl(c):
  match c:
    case Chr{x}:
      match x:
        case U32{w}:
          %Equal.sym(Cmp, Word.cmp(32n, w, w), EQ{}, word_refl(32n, w)) : {Cmp.is_eq(_) == True{} : Bool}
          {==}

law and_true:
  for +b: Bool
  {Bool.and(b, True{}) == b : Bool}

def and_true(b):
  match b:
    case True{}:
      {==}
    case False{}:
      {==}

law same_refl:
  for +k: String
  for +ok: Bool
  {J.same(k, k, ok) == ok : Bool}

def same_refl(k, ok):
  match k:
    case SNil{}:
      {==}
    case SCon{c, t}:
      %Equal.sym(Bool, Char.is_eq(c, c), True{}, char_refl(c)) : {J.same(t, t, Bool.and(ok, _)) == ok : Bool}
      %Equal.sym(Bool, Bool.and(ok, True{}), ok, and_true(ok)) : {J.same(t, t, _) == ok : Bool}
      same_refl(t, ok)

law go_last:
  for +fs: List<&2, J.Field>
  for +k: String
  for +v: J.Json
  for +found: Maybe<&2, J.Json>
  {J.get.go(List.append(&2, J.Field, fs, [J.Field{k, v}]), k, found) == Some{v} : Maybe<&2, J.Json>}

def go_last(fs, k, v, found):
  match fs:
    case Nil{}:
      %Equal.sym(Bool, J.same(k, k, True{}), True{}, same_refl(k, True{})) : {J.get.keep(_, v, found) == Some{v} : Maybe<&2, J.Json>}
      {==}
    case Con{J.Field{fk, fv}, t}:
      go_last(t, k, v, J.get.keep(J.same(fk, k, True{}), fv, found))

law get_last:
  for +k: String
  for +v: J.Json
  for +fs: List<&2, J.Field>
  {J.get(J.JObj{List.append(&2, J.Field, fs, [J.Field{k, v}])}, k) == Done{v} : Result<&2, &2, J.Access, J.Json>}

def get_last(k, v, fs):
  %Equal.sym(Maybe<&2, J.Json>, J.get.go(List.append(&2, J.Field, fs, [J.Field{k, v}]), k, None{}), Some{v}, go_last(fs, k, v, None{})) : {J.get.fin(_, k) == Done{v} : Result<&2, &2, J.Access, J.Json>}
  {==}

law fits_ok:
  for +b: Bool
  for +v: Nat
  {L.mistyped(U32, J.u32.fits.go(b, v)) == False{} : Bool}

def fits_ok(b, v):
  match b:
    case True{}:
      {==}
    case False{}:
      {==}

law whole_ok:
  for +ok: Bool
  for +sig: List<&2, J.Digit>
  for +shift: Nat
  {L.mistyped(U32, J.u32.whole(ok, sig, shift)) == False{} : Bool}

def whole_ok(ok, sig, shift):
  match ok:
    case True{}:
      fits_ok(Nat.is_le(J.times10(shift, J.dvalue(sig, 0n)), 4294967295n), J.times10(shift, J.dvalue(sig, 0n)))
    case False{}:
      {==}

law sig_ok:
  for +neg: Bool
  for +sig: List<&2, J.Digit>
  for +k: Nat
  for +hi: Nat
  for +low: Nat
  {L.mistyped(U32, J.u32.sig(k, neg, sig, hi, low)) == False{} : Bool}

def sig_ok(neg, sig, k, hi, low):
  match neg sig:
    case True{} Nil{}:
      {==}
    case False{} Nil{}:
      {==}
    case True{} Con{_, _}:
      {==}
    case False{} Con{d, t}:
      whole_ok(Bool.and(Nat.is_ge(hi, Nat.add(k, low)), Nat.is_le(hi, Nat.add(10n, low))), Con{d, t}, Nat.sub(hi, Nat.add(k, low)))

law lead_ok:
  for +neg: Bool
  for +l: J.Lead0
  for +point: Nat
  for +up: Nat
  for +down: Nat
  {L.mistyped(U32, J.u32.lead(neg, l, point, up, down)) == False{} : Bool}

def lead_ok(neg, l, point, up, down):
  match l:
    case J.Lead0{ds, z}:
      sig_ok(neg, J.strip_trailing(ds), J.dlen(J.strip_trailing(ds), 0n), Nat.add(point, up), Nat.add(z, down))

law num_ok.digits:
  for +neg: Bool
  for +d: J.Digits
  for +e: J.Exp
  {L.mistyped(U32, J.u32.digits(neg, d, e)) == False{} : Bool}

def num_ok.digits(neg, d, e):
  match d:
    case J.Digits{ds, point}:
      lead_ok(neg, J.drop_lead(ds, 0n), point, J.exp_up(e), J.exp_down(e))

law num_ok:
  for +n: J.Number
  {L.mistyped(U32, J.u32.num(n)) == False{} : Bool}

def num_ok(n):
  match n:
    case J.Number{neg, i, f, e}:
      num_ok.digits(neg, J.with_point(i, f), e)

law fin_mt:
  for +b: Bool
  for +x: F32
  {L.mistyped(F32, J.f32.fin(b, x)) == False{} : Bool}

def fin_mt(b, x):
  match b:
    case True{}:
      {==}
    case False{}:
      {==}

law f32_range:
  for +m: Maybe<&2, F32>
  {L.mistyped(F32, J.f32.go(m)) == False{} : Bool}

def f32_range(m):
  match m:
    case Some{x}:
      fin_mt(J.finite(x), x)
    case None{}:
      {==}

# f32 hands back only what finite passed
law fin_ok:
  for +b: Bool
  for +x: F32
  for e: {b == J.finite(x) : Bool}
  {L.f32_ok(J.f32.fin(b, x)) == True{} : Bool}

def fin_ok(b, x, e):
  match b:
    case True{}:
      Equal.sym(Bool, True{}, J.finite(x), e)
    case False{}:
      {==}

law go_ok:
  for +m: Maybe<&2, F32>
  {L.f32_ok(J.f32.go(m)) == True{} : Bool}

def go_ok(m):
  match m:
    case Some{x}:
      fin_ok(J.finite(x), x, {==})
    case None{}:
      {==}

law index_found:
  for +xs: List<&2, J.Json>
  for +n: Nat
  for +i: U32
  {L.mistyped(J.Json, J.index.go(xs, n, i)) == False{} : Bool}

def index_found(xs, n, i):
  match xs n:
    case Con{_, _} 0n:
      {==}
    case Con{_, t} 1n+p:
      index_found(t, p, i)
    case Nil{} _:
      {==}

law get_found:
  for +m: Maybe<&2, J.Json>
  for +k: String
  {L.mistyped(J.Json, J.get.fin(m, k)) == False{} : Bool}

def get_found(m, k):
  match m:
    case Some{_}:
      {==}
    case None{}:
      {==}

# u32 across forms of one number
# ------------------------------

def D() -> Data:
  List<&2, J.Digit>

def app(a: List<&2, J.Digit>, b: List<&2, J.Digit>) -> List<&2, J.Digit>:
  List.append(&2, J.Digit, a, b)

law app_nil:
  for +ds: D()
  {app(ds, []) == ds : D()}

def app_nil(ds):
  match ds:
    case Nil{}:
      {==}
    case Con{d, t}:
      Equal.cong(D(), D(), x => Con{d, x}, app(t, []), t, app_nil(t))

law rev_app:
  for +xs: D()
  for +ys: D()
  for +acc: D()
  {J.rev_digits(app(xs, ys), acc) == J.rev_digits(ys, J.rev_digits(xs, acc)) : D()}

def rev_app(xs, ys, acc):
  match xs:
    case Nil{}:
      {==}
    case Con{d, t}:
      rev_app(t, ys, Con{d, acc})

# a zero put at the end is a trailing zero
law st_snoc:
  for +xs: D()
  {J.strip_trailing(app(xs, [J.D0{}])) == J.strip_trailing(xs) : D()}

def st_snoc(xs):
  %Equal.sym(D(), J.rev_digits(app(xs, [J.D0{}]), []), J.rev_digits([J.D0{}], J.rev_digits(xs, [])), rev_app(xs, [J.D0{}], [])) : {J.rev_digits(J.drop_zeros(_), []) == J.strip_trailing(xs) : D()}
  {==}

# a leading digit is never a zero
law lead_drop:
  for +l: J.Lead
  for +x: D()
  {J.drop_lead(Con{J.lead_digit(l), x}, 0n) == J.Lead0{Con{J.lead_digit(l), x}, 0n} : J.Lead0}

def lead_drop(l, x):
  match l:
    case J.L1{}:
      {==}
    case J.L2{}:
      {==}
    case J.L3{}:
      {==}
    case J.L4{}:
      {==}
    case J.L5{}:
      {==}
    case J.L6{}:
      {==}
    case J.L7{}:
      {==}
    case J.L8{}:
      {==}
    case J.L9{}:
      {==}

law dl_snoc:
  for +ds: D()
  for +a: J.Digit
  for +n: Nat
  {J.dlen(app(ds, [a]), n) == 1n+J.dlen(ds, n) : Nat}

def dl_snoc(ds, a, n):
  match ds:
    case Nil{}:
      {==}
    case Con{_, t}:
      dl_snoc(t, a, 1n+n)

law add_zero:
  for +n: Nat
  {Nat.add(n, 0n) == n : Nat}

def add_zero(n):
  match n:
    case 0n:
      {==}
    case 1n+p:
      Equal.cong(Nat, Nat, x => 1n+x, Nat.add(p, 0n), p, add_zero(p))

law add_one:
  for +n: Nat
  {Nat.add(n, 1n) == 1n+n : Nat}

def add_one(n):
  match n:
    case 0n:
      {==}
    case 1n+p:
      Equal.cong(Nat, Nat, x => 1n+x, Nat.add(p, 1n), 1n+p, add_one(p))

def R() -> Type:
  Result<&2, &2, J.Access, U32>

# the u32 of l.ds followed by the fraction digits x: after the leading
# digit it is the trail of the stripped digits
law lead_trail:
  for neg: Bool
  for +l: J.Lead
  for +x: D()
  for +p: Nat
  for +up: Nat
  for +down: Nat
  {J.u32.lead(neg, J.drop_lead(Con{J.lead_digit(l), x}, 0n), p, up, down) == J.u32.trail(neg, J.strip_trailing(Con{J.lead_digit(l), x}), Nat.add(p, up), Nat.add(0n, down)) : R()}

def lead_trail(neg, l, x, p, up, down):
  %Equal.sym(J.Lead0, J.drop_lead(Con{J.lead_digit(l), x}, 0n), J.Lead0{Con{J.lead_digit(l), x}, 0n}, lead_drop(l, x)) : {J.u32.lead(neg, _, p, up, down) == J.u32.trail(neg, J.strip_trailing(Con{J.lead_digit(l), x}), Nat.add(p, up), Nat.add(0n, down)) : R()}
  {==}

law frac_zero.non:
  for +neg: Bool
  for +l: J.Lead
  for +ds: D()
  for +e: J.Exp
  {J.u32(J.JNum{J.Number{neg, J.INon{l, ds}, J.FSome{J.D0{}, []}, e}}) == J.u32(J.JNum{J.Number{neg, J.INon{l, ds}, J.FNone{}, e}}) : R()}

def frac_zero.non(neg, l, ds, e):
  +d : J.Digit = J.lead_digit(l)
  +p : Nat = 1n+J.dlen(ds, 0n)
  +up : Nat = J.exp_up(e)
  +down : Nat = J.exp_down(e)
  +hi : Nat = Nat.add(p, up)
  +lo : Nat = Nat.add(0n, down)
  Equal.trans(R(), J.u32.lead(neg, J.drop_lead(Con{d, app(ds, [J.D0{}])}, 0n), p, up, down),
    J.u32.trail(neg, J.strip_trailing(Con{d, app(ds, [J.D0{}])}), hi, lo),
    J.u32.lead(neg, J.drop_lead(Con{d, app(ds, [])}, 0n), p, up, down),
    lead_trail(neg, l, app(ds, [J.D0{}]), p, up, down),
    Equal.trans(R(), J.u32.trail(neg, J.strip_trailing(Con{d, app(ds, [J.D0{}])}), hi, lo),
      J.u32.trail(neg, J.strip_trailing(Con{d, ds}), hi, lo),
      J.u32.lead(neg, J.drop_lead(Con{d, app(ds, [])}, 0n), p, up, down),
      Equal.cong(D(), R(), y => J.u32.trail(neg, y, hi, lo), J.strip_trailing(Con{d, app(ds, [J.D0{}])}), J.strip_trailing(Con{d, ds}), st_snoc(Con{d, ds})),
      Equal.trans(R(), J.u32.trail(neg, J.strip_trailing(Con{d, ds}), hi, lo),
        J.u32.trail(neg, J.strip_trailing(Con{d, app(ds, [])}), hi, lo),
        J.u32.lead(neg, J.drop_lead(Con{d, app(ds, [])}, 0n), p, up, down),
        Equal.cong(D(), R(), y => J.u32.trail(neg, J.strip_trailing(Con{d, y}), hi, lo), ds, app(ds, []), Equal.sym(D(), app(ds, []), ds, app_nil(ds))),
        Equal.sym(R(), J.u32.lead(neg, J.drop_lead(Con{d, app(ds, [])}, 0n), p, up, down), J.u32.trail(neg, J.strip_trailing(Con{d, app(ds, [])}), hi, lo), lead_trail(neg, l, app(ds, []), p, up, down)))))

law frac_zero:
  for +neg: Bool
  for +i: J.Int
  for +e: J.Exp
  {J.u32(J.JNum{J.Number{neg, i, J.FSome{J.D0{}, []}, e}}) == J.u32(J.JNum{J.Number{neg, i, J.FNone{}, e}}) : R()}

def frac_zero(neg, i, e):
  match neg i:
    case True{} J.IZero{}:
      {==}
    case False{} J.IZero{}:
      {==}
    case _ J.INon{l, ds}:
      frac_zero.non(neg, l, ds, e)

law exp_zero.d:
  for +neg: Bool
  for +d: J.Digits
  for +u: Bool
  for +s: J.Sign
  {J.u32.digits(neg, d, J.ESome{u, s, J.D0{}, []}) == J.u32.digits(neg, d, J.ENone{}) : R()}

def exp_zero.d(neg, d, u, s):
  match d:
    case J.Digits{ds, point}:
      match s:
        case J.NoSign{}:
          {==}
        case J.Plus{}:
          {==}
        case J.Minus{}:
          {==}

law exp_zero:
  for +neg: Bool
  for +i: J.Int
  for +f: J.Frac
  for +u: Bool
  for +s: J.Sign
  {J.u32(J.JNum{J.Number{neg, i, f, J.ESome{u, s, J.D0{}, []}}}) == J.u32(J.JNum{J.Number{neg, i, f, J.ENone{}}}) : R()}

def exp_zero(neg, i, f, u, s):
  exp_zero.d(neg, J.with_point(i, f), u, s)

# the two sides of shift after the leading digit: the same digits once
# the zeros are stripped, and the point one further right on both
law shift.eq:
  for +d: J.Digit
  for +ds: D()
  for +lo: Nat
  {J.u32.trail(False{}, J.strip_trailing(Con{d, app(ds, [])}), Nat.add(1n+J.dlen(ds, 0n), 1n), lo) == J.u32.trail(False{}, J.strip_trailing(Con{d, app(app(ds, [J.D0{}]), [])}), Nat.add(1n+J.dlen(app(ds, [J.D0{}]), 0n), 0n), lo) : R()}

def shift.eq(d, ds, lo):
  +ds0 : D() = app(ds, [J.D0{}])
  +s : D() = J.strip_trailing(Con{d, ds})
  +len : Nat = J.dlen(ds, 0n)
  Equal.trans(R(), J.u32.trail(False{}, J.strip_trailing(Con{d, app(ds, [])}), Nat.add(1n+len, 1n), lo),
    J.u32.trail(False{}, s, Nat.add(1n+len, 1n), lo),
    J.u32.trail(False{}, J.strip_trailing(Con{d, app(ds0, [])}), Nat.add(1n+J.dlen(ds0, 0n), 0n), lo),
    Equal.cong(D(), R(), x => J.u32.trail(False{}, J.strip_trailing(Con{d, x}), Nat.add(1n+len, 1n), lo), app(ds, []), ds, app_nil(ds)),
    Equal.trans(R(), J.u32.trail(False{}, s, Nat.add(1n+len, 1n), lo),
      J.u32.trail(False{}, s, 1n+1n+len, lo),
      J.u32.trail(False{}, J.strip_trailing(Con{d, app(ds0, [])}), Nat.add(1n+J.dlen(ds0, 0n), 0n), lo),
      Equal.cong(Nat, R(), y => J.u32.trail(False{}, s, y, lo), Nat.add(1n+len, 1n), 1n+1n+len, add_one(1n+len)),
      Equal.trans(R(), J.u32.trail(False{}, s, 1n+1n+len, lo),
        J.u32.trail(False{}, s, Nat.add(1n+J.dlen(ds0, 0n), 0n), lo),
        J.u32.trail(False{}, J.strip_trailing(Con{d, app(ds0, [])}), Nat.add(1n+J.dlen(ds0, 0n), 0n), lo),
        Equal.cong(Nat, R(), y => J.u32.trail(False{}, s, y, lo), 1n+1n+len, Nat.add(1n+J.dlen(ds0, 0n), 0n),
          Equal.sym(Nat, Nat.add(1n+J.dlen(ds0, 0n), 0n), 1n+1n+len,
            Equal.trans(Nat, Nat.add(1n+J.dlen(ds0, 0n), 0n), 1n+J.dlen(ds0, 0n), 1n+1n+len,
              add_zero(1n+J.dlen(ds0, 0n)),
              Equal.cong(Nat, Nat, z => 1n+z, J.dlen(ds0, 0n), 1n+len, dl_snoc(ds, J.D0{}, 0n))))),
        Equal.cong(D(), R(), x => J.u32.trail(False{}, x, Nat.add(1n+J.dlen(ds0, 0n), 0n), lo), s, J.strip_trailing(Con{d, app(ds0, [])}),
          Equal.sym(D(), J.strip_trailing(Con{d, app(ds0, [])}), s,
            Equal.trans(D(), J.strip_trailing(Con{d, app(ds0, [])}), J.strip_trailing(Con{d, ds0}), s,
              Equal.cong(D(), D(), x => J.strip_trailing(Con{d, x}), app(ds0, []), ds0, app_nil(ds0)),
              st_snoc(Con{d, ds})))))))

# e1 moves the point one digit right: the same as a 0 put at the end
law shift:
  for +l: J.Lead
  for +ds: D()
  {J.u32(J.JNum{J.Number{False{}, J.INon{l, ds}, J.FNone{}, J.ESome{False{}, J.NoSign{}, J.D1{}, []}}}) == J.u32(J.JNum{J.Number{False{}, J.INon{l, app(ds, [J.D0{}])}, J.FNone{}, J.ENone{}}}) : R()}

def shift(l, ds):
  +d : J.Digit = J.lead_digit(l)
  +ds0 : D() = app(ds, [J.D0{}])
  +p1 : Nat = 1n+J.dlen(ds, 0n)
  +p2 : Nat = 1n+J.dlen(ds0, 0n)
  +lo : Nat = Nat.add(0n, 0n)
  Equal.trans(R(), J.u32.lead(False{}, J.drop_lead(Con{d, app(ds, [])}, 0n), p1, 1n, 0n),
    J.u32.trail(False{}, J.strip_trailing(Con{d, app(ds, [])}), Nat.add(p1, 1n), lo),
    J.u32.lead(False{}, J.drop_lead(Con{d, app(ds0, [])}, 0n), p2, 0n, 0n),
    lead_trail(False{}, l, app(ds, []), p1, 1n, 0n),
    Equal.trans(R(), J.u32.trail(False{}, J.strip_trailing(Con{d, app(ds, [])}), Nat.add(p1, 1n), lo),
      J.u32.trail(False{}, J.strip_trailing(Con{d, app(ds0, [])}), Nat.add(p2, 0n), lo),
      J.u32.lead(False{}, J.drop_lead(Con{d, app(ds0, [])}, 0n), p2, 0n, 0n),
      shift.eq(d, ds, lo),
      Equal.sym(R(), J.u32.lead(False{}, J.drop_lead(Con{d, app(ds0, [])}, 0n), p2, 0n, 0n), J.u32.trail(False{}, J.strip_trailing(Con{d, app(ds0, [])}), Nat.add(p2, 0n), lo), lead_trail(False{}, l, app(ds0, []), p2, 0n, 0n))))
