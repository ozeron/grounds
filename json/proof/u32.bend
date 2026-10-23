import Base
import ../json.bend as J
import ./access.bend as A
import ../../decimal/decimal.bend as D
import ../../decimal/proof/nat.bend as N
import ../../decimal/proof/count.bend as Count
import ../../decimal/proof/text.bend as Text

# The bridge is structural: JSON keeps its public digit types, while
# decimal supplies the bounded count. No large Nat bound is unfolded.
def Ds() -> Data:
  List<&2, J.Digit>

def R() -> Type:
  Result<&2, &2, J.Access, U32>

def app(a: Ds(), b: Ds()) -> Ds():
  List.append(&2, J.Digit, a, b)

def msf(d: D.Dec) -> Ds():
  match d:
    case D.DNil{}:
      []
    case D.DCon{x, t}:
      app(msf(t), [J.decimal_digit(x)])

def int_digits(i: J.Int) -> Ds():
  match i:
    case J.IZero{}:
      []
    case J.INon{l, ds}:
      Con{J.lead_digit(l), ds}

def snoc(x: D.Dig, ds: Ds()) -> Ds():
  match x ds:
    case D.D0{} Nil{}:
      []
    case d Nil{}:
      [J.decimal_digit(d)]
    case d Con{h, t}:
      app(Con{h, t}, [J.decimal_digit(d)])

law snoc_app:
  for +x: D.Dig
  for +ds: Ds()
  for +y: J.Digit
  {snoc(x, app(ds, [y])) == app(app(ds, [y]), [J.decimal_digit(x)]) : Ds()}

def snoc_app(x, ds, y):
  match x ds:
    case D.D0{} Nil{}:
      {==}
    case D.D0{} Con{h, t}:
      {==}
    case D.D1{} Nil{}:
      {==}
    case D.D1{} Con{h, t}:
      {==}
    case D.D2{} Nil{}:
      {==}
    case D.D2{} Con{h, t}:
      {==}
    case D.D3{} Nil{}:
      {==}
    case D.D3{} Con{h, t}:
      {==}
    case D.D4{} Nil{}:
      {==}
    case D.D4{} Con{h, t}:
      {==}
    case D.D5{} Nil{}:
      {==}
    case D.D5{} Con{h, t}:
      {==}
    case D.D6{} Nil{}:
      {==}
    case D.D6{} Con{h, t}:
      {==}
    case D.D7{} Nil{}:
      {==}
    case D.D7{} Con{h, t}:
      {==}
    case D.D8{} Nil{}:
      {==}
    case D.D8{} Con{h, t}:
      {==}
    case D.D9{} Nil{}:
      {==}
    case D.D9{} Con{h, t}:
      {==}

law int_con:
  for +x: D.Dig
  for +i: J.Int
  {int_digits(J.decimal_int.con(x, i)) == snoc(x, int_digits(i)) : Ds()}

def int_con(x, i):
  match x i:
    case D.D0{} J.IZero{}:
      {==}
    case D.D1{} J.IZero{}:
      {==}
    case D.D2{} J.IZero{}:
      {==}
    case D.D3{} J.IZero{}:
      {==}
    case D.D4{} J.IZero{}:
      {==}
    case D.D5{} J.IZero{}:
      {==}
    case D.D6{} J.IZero{}:
      {==}
    case D.D7{} J.IZero{}:
      {==}
    case D.D8{} J.IZero{}:
      {==}
    case D.D9{} J.IZero{}:
      {==}
    case D.D0{} J.INon{l, ds}:
      {==}
    case D.D1{} J.INon{l, ds}:
      {==}
    case D.D2{} J.INon{l, ds}:
      {==}
    case D.D3{} J.INon{l, ds}:
      {==}
    case D.D4{} J.INon{l, ds}:
      {==}
    case D.D5{} J.INon{l, ds}:
      {==}
    case D.D6{} J.INon{l, ds}:
      {==}
    case D.D7{} J.INon{l, ds}:
      {==}
    case D.D8{} J.INon{l, ds}:
      {==}
    case D.D9{} J.INon{l, ds}:
      {==}

law trim_con:
  for +x: D.Dig
  for +d: D.Dec
  {msf(D.trim.con(x, d)) == snoc(x, msf(d)) : Ds()}

def trim_con(x, d):
  match x d:
    case D.D0{} D.DNil{}:
      {==}
    case D.D1{} D.DNil{}:
      {==}
    case D.D2{} D.DNil{}:
      {==}
    case D.D3{} D.DNil{}:
      {==}
    case D.D4{} D.DNil{}:
      {==}
    case D.D5{} D.DNil{}:
      {==}
    case D.D6{} D.DNil{}:
      {==}
    case D.D7{} D.DNil{}:
      {==}
    case D.D8{} D.DNil{}:
      {==}
    case D.D9{} D.DNil{}:
      {==}
    case y D.DCon{z, t}:
      Equal.sym(Ds(), snoc(y, app(msf(t), [J.decimal_digit(z)])), app(app(msf(t), [J.decimal_digit(z)]), [J.decimal_digit(y)]), snoc_app(y, msf(t), J.decimal_digit(z)))

law int_trim:
  for +d: D.Dec
  {int_digits(J.decimal_int(d)) == msf(D.trim(d)) : Ds()}

def int_trim(d):
  match d:
    case D.DNil{}:
      {==}
    case D.DCon{x, t}:
      %Equal.sym(Ds(), int_digits(J.decimal_int.con(x, J.decimal_int(t))), snoc(x, int_digits(J.decimal_int(t))), int_con(x, J.decimal_int(t))) : {_ == msf(D.trim.con(x, D.trim(t))) : Ds()}
      %Equal.sym(Ds(), int_digits(J.decimal_int(t)), msf(D.trim(t)), int_trim(t)) : {snoc(x, _) == msf(D.trim.con(x, D.trim(t))) : Ds()}
      Equal.sym(Ds(), msf(D.trim.con(x, D.trim(t))), snoc(x, msf(D.trim(t))), trim_con(x, D.trim(t)))

law digit_back:
  for +x: D.Dig
  {J.digit_decimal(J.decimal_digit(x)) == x : D.Dig}

def digit_back(x):
  match x:
    case D.D0{}:
      {==}
    case D.D1{}:
      {==}
    case D.D2{}:
      {==}
    case D.D3{}:
      {==}
    case D.D4{}:
      {==}
    case D.D5{}:
      {==}
    case D.D6{}:
      {==}
    case D.D7{}:
      {==}
    case D.D8{}:
      {==}
    case D.D9{}:
      {==}

# Most significant JSON digits pushed onto a low-digit-first decimal.
def digits_decimal(ds: List<&2, J.Digit>, acc: D.Dec) -> D.Dec:
  match ds:
    case Nil{}:
      acc
    case Con{d, t}:
      digits_decimal(t, D.DCon{J.digit_decimal(d), acc})

law digits_app:
  for +a: Ds()
  for +b: Ds()
  for +acc: D.Dec
  {digits_decimal(app(a, b), acc) == digits_decimal(b, digits_decimal(a, acc)) : D.Dec}

def digits_app(a, b, acc):
  match a:
    case Nil{}:
      {==}
    case Con{x, t}:
      digits_app(t, b, D.DCon{J.digit_decimal(x), acc})

law digits_msf:
  for +d: D.Dec
  for +acc: D.Dec
  {digits_decimal(msf(d), acc) == Text.cat(d, acc) : D.Dec}

def digits_msf(d, acc):
  match d:
    case D.DNil{}:
      {==}
    case D.DCon{x, t}:
      %Equal.sym(D.Dec, digits_decimal(app(msf(t), [J.decimal_digit(x)]), acc), digits_decimal([J.decimal_digit(x)], digits_decimal(msf(t), acc)), digits_app(msf(t), [J.decimal_digit(x)], acc)) : {_ == D.DCon{x, Text.cat(t, acc)} : D.Dec}
      %Equal.sym(D.Dig, J.digit_decimal(J.decimal_digit(x)), x, digit_back(x)) : {D.DCon{_, digits_decimal(msf(t), acc)} == D.DCon{x, Text.cat(t, acc)} : D.Dec}
      Equal.cong(D.Dec, D.Dec, y => D.DCon{x, y}, digits_decimal(msf(t), acc), Text.cat(t, acc), digits_msf(t, acc))

law digits_msf_nil:
  for +d: D.Dec
  {digits_decimal(msf(d), D.DNil{}) == d : D.Dec}

def digits_msf_nil(d):
  Equal.trans(D.Dec, digits_decimal(msf(d), D.DNil{}), Text.cat(d, D.DNil{}), d, digits_msf(d, D.DNil{}), Text.cat_nil(d))

# The streaming reader equals the decimal reader, including failure.
law count_nil:
  for +m: Maybe<&2, Nat>
  {J.u32.count([], m) == m : Maybe<&2, Nat>}

def count_nil(m):
  match m:
    case None{}:
      {==}
    case Some{v}:
      {==}

law count_none:
  for +ds: Ds()
  {J.u32.count(ds, None{}) == None{} : Maybe<&2, Nat>}

def count_none(ds):
  match ds:
    case Nil{}:
      {==}
    case Con{x, t}:
      {==}

law count_con:
  for +m: Maybe<&2, Nat>
  for +x: J.Digit
  for +ds: Ds()
  {J.u32.count(Con{x, ds}, m) == J.u32.count(ds, D.to_u32.step(J.digit_decimal(x), m)) : Maybe<&2, Nat>}

def count_con(m, x, ds):
  match m:
    case None{}:
      Equal.sym(Maybe<&2, Nat>, J.u32.count(ds, None{}), None{}, count_none(ds))
    case Some{v}:
      {==}

law count_decimal:
  for +ds: Ds()
  for +acc: D.Dec
  {J.u32.count(ds, D.to_u32.go(acc)) == D.to_u32.go(digits_decimal(ds, acc)) : Maybe<&2, Nat>}

def count_decimal(ds, acc):
  match ds:
    case Nil{}:
      count_nil(D.to_u32.go(acc))
    case Con{x, t}:
      %Equal.sym(Maybe<&2, Nat>, J.u32.count(Con{x, t}, D.to_u32.go(acc)), J.u32.count(t, D.to_u32.step(J.digit_decimal(x), D.to_u32.go(acc))), count_con(D.to_u32.go(acc), x, t)) : {_ == D.to_u32.go(digits_decimal(t, D.DCon{J.digit_decimal(x), acc})) : Maybe<&2, Nat>}
      count_decimal(t, D.DCon{J.digit_decimal(x), acc})

law len_acc:
  for +ds: Ds()
  for +n: Nat
  {J.dlen(ds, 1n+n) == 1n+J.dlen(ds, n) : Nat}

def len_acc(ds, n):
  match ds:
    case Nil{}:
      {==}
    case Con{x, t}:
      len_acc(t, 1n+n)

law ge_add:
  for +k: Nat
  for +s: Nat
  {Nat.is_ge(Nat.add(k, s), k) == True{} : Bool}

def ge_add(k, s):
  match k:
    case 0n:
      match s:
        case 0n:
          {==}
        case 1n+p:
          {==}
    case 1n+p:
      ge_add(p, s)

law sub_add:
  for +k: Nat
  for +s: Nat
  {Nat.sub(Nat.add(k, s), k) == s : Nat}

def sub_add(k, s):
  match k s:
    case 0n 0n:
      {==}
    case 0n 1n+q:
      {==}
    case 1n+p q:
      sub_add(p, q)

law scale_zero:
  for +n: Nat
  {J.u32.scale(n, Some{0n}) == Done{0} : R()}

def scale_zero(n):
  match n:
    case 0n:
      {==}
    case 1n+p:
      scale_zero(p)

law scale_succ:
  for +n: Nat
  for +m: Maybe<&2, Nat>
  {J.u32.scale(1n+n, m) == J.u32.scale(n, D.to_u32.step(D.D0{}, m)) : R()}

def scale_succ(n, m):
  match n m:
    case 0n None{}:
      {==}
    case 1n+p None{}:
      {==}
    case _ Some{v}:
      {==}

law trail_whole_count:
  for +ds: Ds()
  for +s: Nat
  {J.u32.trail(False{}, ds, Nat.add(J.dlen(ds, 0n), s), 0n) == J.u32.scale(s, J.u32.count(ds, Some{0n})) : R()}

def trail_whole_count(ds, s):
  match ds:
    case Nil{}:
      Equal.sym(R(), J.u32.scale(s, Some{0n}), Done{0}, scale_zero(s))
    case Con{x, t}:
      +k : Nat = 1n+J.dlen(t, 0n)
      %Equal.sym(Nat, J.dlen(t, 1n), 1n+J.dlen(t, 0n), len_acc(t, 0n)) : {J.u32.sig(_, False{}, Con{x, t}, Nat.add(_, s), 0n) == J.u32.scale(s, J.u32.count(Con{x, t}, Some{0n})) : R()}
      %Equal.sym(Nat, Nat.add(k, 0n), k, N.add_zero(k)) : {J.u32.whole(Nat.is_ge(Nat.add(k, s), _), Con{x, t}, Nat.sub(Nat.add(k, s), _)) == J.u32.scale(s, J.u32.count(Con{x, t}, Some{0n})) : R()}
      %Equal.sym(Bool, Nat.is_ge(Nat.add(k, s), k), True{}, ge_add(k, s)) : {J.u32.whole(_, Con{x, t}, Nat.sub(Nat.add(k, s), k)) == J.u32.scale(s, J.u32.count(Con{x, t}, Some{0n})) : R()}
      %Equal.sym(Nat, Nat.sub(Nat.add(k, s), k), s, sub_add(k, s)) : {J.u32.scale(_, J.u32.count(Con{x, t}, Some{0n})) == J.u32.scale(s, J.u32.count(Con{x, t}, Some{0n})) : R()}
      {==}

law trail_whole:
  for +ds: Ds()
  for +s: Nat
  {J.u32.trail(False{}, ds, Nat.add(J.dlen(ds, 0n), s), 0n) == J.u32.scale(s, D.to_u32.go(digits_decimal(ds, D.DNil{}))) : R()}

def trail_whole(ds, s):
  %count_decimal(ds, D.DNil{}) : {J.u32.trail(False{}, ds, Nat.add(J.dlen(ds, 0n), s), 0n) == J.u32.scale(s, _) : R()}
  trail_whole_count(ds, s)

law rev_twice:
  for +a: Ds()
  for +b: Ds()
  for +out: Ds()
  {J.rev_digits(J.rev_digits(a, b), out) == J.rev_digits(b, app(a, out)) : Ds()}

def rev_twice(a, b, out):
  match a:
    case Nil{}:
      {==}
    case Con{x, t}:
      rev_twice(t, Con{x, b}, out)

def strip_end(x: D.Dig, ds: Ds()) -> Ds():
  match x:
    case D.D0{}:
      J.strip_trailing(ds)
    case y:
      app(ds, [J.decimal_digit(y)])

law strip_snoc:
  for +x: D.Dig
  for +ds: Ds()
  {J.strip_trailing(app(ds, [J.decimal_digit(x)])) == strip_end(x, ds) : Ds()}

def strip_snoc(x, ds):
  match x:
    case D.D0{}:
      A.st_snoc(ds)
    case D.D1{}:
      %Equal.sym(Ds(), J.rev_digits(app(ds, [J.D1{}]), []), J.rev_digits([J.D1{}], J.rev_digits(ds, [])), A.rev_app(ds, [J.D1{}], [])) : {J.rev_digits(J.drop_zeros(_), []) == app(ds, [J.D1{}]) : Ds()}
      rev_twice(ds, [], [J.D1{}])
    case D.D2{}:
      %Equal.sym(Ds(), J.rev_digits(app(ds, [J.D2{}]), []), J.rev_digits([J.D2{}], J.rev_digits(ds, [])), A.rev_app(ds, [J.D2{}], [])) : {J.rev_digits(J.drop_zeros(_), []) == app(ds, [J.D2{}]) : Ds()}
      rev_twice(ds, [], [J.D2{}])
    case D.D3{}:
      %Equal.sym(Ds(), J.rev_digits(app(ds, [J.D3{}]), []), J.rev_digits([J.D3{}], J.rev_digits(ds, [])), A.rev_app(ds, [J.D3{}], [])) : {J.rev_digits(J.drop_zeros(_), []) == app(ds, [J.D3{}]) : Ds()}
      rev_twice(ds, [], [J.D3{}])
    case D.D4{}:
      %Equal.sym(Ds(), J.rev_digits(app(ds, [J.D4{}]), []), J.rev_digits([J.D4{}], J.rev_digits(ds, [])), A.rev_app(ds, [J.D4{}], [])) : {J.rev_digits(J.drop_zeros(_), []) == app(ds, [J.D4{}]) : Ds()}
      rev_twice(ds, [], [J.D4{}])
    case D.D5{}:
      %Equal.sym(Ds(), J.rev_digits(app(ds, [J.D5{}]), []), J.rev_digits([J.D5{}], J.rev_digits(ds, [])), A.rev_app(ds, [J.D5{}], [])) : {J.rev_digits(J.drop_zeros(_), []) == app(ds, [J.D5{}]) : Ds()}
      rev_twice(ds, [], [J.D5{}])
    case D.D6{}:
      %Equal.sym(Ds(), J.rev_digits(app(ds, [J.D6{}]), []), J.rev_digits([J.D6{}], J.rev_digits(ds, [])), A.rev_app(ds, [J.D6{}], [])) : {J.rev_digits(J.drop_zeros(_), []) == app(ds, [J.D6{}]) : Ds()}
      rev_twice(ds, [], [J.D6{}])
    case D.D7{}:
      %Equal.sym(Ds(), J.rev_digits(app(ds, [J.D7{}]), []), J.rev_digits([J.D7{}], J.rev_digits(ds, [])), A.rev_app(ds, [J.D7{}], [])) : {J.rev_digits(J.drop_zeros(_), []) == app(ds, [J.D7{}]) : Ds()}
      rev_twice(ds, [], [J.D7{}])
    case D.D8{}:
      %Equal.sym(Ds(), J.rev_digits(app(ds, [J.D8{}]), []), J.rev_digits([J.D8{}], J.rev_digits(ds, [])), A.rev_app(ds, [J.D8{}], [])) : {J.rev_digits(J.drop_zeros(_), []) == app(ds, [J.D8{}]) : Ds()}
      rev_twice(ds, [], [J.D8{}])
    case D.D9{}:
      %Equal.sym(Ds(), J.rev_digits(app(ds, [J.D9{}]), []), J.rev_digits([J.D9{}], J.rev_digits(ds, [])), A.rev_app(ds, [J.D9{}], [])) : {J.rev_digits(J.drop_zeros(_), []) == app(ds, [J.D9{}]) : Ds()}
      rev_twice(ds, [], [J.D9{}])

law trail_zero:
  for +ds: Ds()
  for +s: Nat
  {J.u32.trail(False{}, J.strip_trailing(app(ds, [J.D0{}])), Nat.add(J.dlen(app(ds, [J.D0{}]), 0n), s), 0n) == J.u32.trail(False{}, J.strip_trailing(ds), Nat.add(J.dlen(ds, 0n), 1n+s), 0n) : R()}

def trail_zero(ds, s):
  %Equal.sym(Ds(), J.strip_trailing(app(ds, [J.D0{}])), J.strip_trailing(ds), A.st_snoc(ds)) : {J.u32.trail(False{}, _, Nat.add(J.dlen(app(ds, [J.D0{}]), 0n), s), 0n) == J.u32.trail(False{}, J.strip_trailing(ds), Nat.add(J.dlen(ds, 0n), 1n+s), 0n) : R()}
  %Equal.sym(Nat, J.dlen(app(ds, [J.D0{}]), 0n), 1n+J.dlen(ds, 0n), A.dl_snoc(ds, J.D0{}, 0n)) : {J.u32.trail(False{}, J.strip_trailing(ds), Nat.add(_, s), 0n) == J.u32.trail(False{}, J.strip_trailing(ds), Nat.add(J.dlen(ds, 0n), 1n+s), 0n) : R()}
  %N.add_succ(J.dlen(ds, 0n), s) : {J.u32.trail(False{}, J.strip_trailing(ds), _, 0n) == J.u32.trail(False{}, J.strip_trailing(ds), Nat.add(J.dlen(ds, 0n), 1n+s), 0n) : R()}
  {==}

law trail_kept:
  for +d: D.Dec
  for +s: Nat
  for e: {J.strip_trailing(msf(d)) == msf(d) : Ds()}
  {J.u32.trail(False{}, J.strip_trailing(msf(d)), Nat.add(J.dlen(msf(d), 0n), s), 0n) == J.u32.scale(s, D.to_u32.go(d)) : R()}

def trail_kept(d, s, e):
  %Equal.sym(Ds(), J.strip_trailing(msf(d)), msf(d), e) : {J.u32.trail(False{}, _, Nat.add(J.dlen(msf(d), 0n), s), 0n) == J.u32.scale(s, D.to_u32.go(d)) : R()}
  %Equal.sym(R(), J.u32.trail(False{}, msf(d), Nat.add(J.dlen(msf(d), 0n), s), 0n), J.u32.scale(s, D.to_u32.go(digits_decimal(msf(d), D.DNil{}))), trail_whole(msf(d), s)) : {_ == J.u32.scale(s, D.to_u32.go(d)) : R()}
  %Equal.sym(D.Dec, digits_decimal(msf(d), D.DNil{}), d, digits_msf_nil(d)) : {J.u32.scale(s, D.to_u32.go(_)) == J.u32.scale(s, D.to_u32.go(d)) : R()}
  {==}

law trail_msf:
  for +d: D.Dec
  for +s: Nat
  {J.u32.trail(False{}, J.strip_trailing(msf(d)), Nat.add(J.dlen(msf(d), 0n), s), 0n) == J.u32.scale(s, D.to_u32.go(d)) : R()}

def trail_msf(d, s):
  match d:
    case D.DNil{}:
      Equal.sym(R(), J.u32.scale(s, Some{0n}), Done{0}, scale_zero(s))
    case D.DCon{D.D0{}, t}:
      %Equal.sym(R(), J.u32.trail(False{}, J.strip_trailing(app(msf(t), [J.D0{}])), Nat.add(J.dlen(app(msf(t), [J.D0{}]), 0n), s), 0n), J.u32.trail(False{}, J.strip_trailing(msf(t)), Nat.add(J.dlen(msf(t), 0n), 1n+s), 0n), trail_zero(msf(t), s)) : {_ == J.u32.scale(s, D.to_u32.go(D.DCon{D.D0{}, t})) : R()}
      %Equal.sym(R(), J.u32.trail(False{}, J.strip_trailing(msf(t)), Nat.add(J.dlen(msf(t), 0n), 1n+s), 0n), J.u32.scale(1n+s, D.to_u32.go(t)), trail_msf(t, 1n+s)) : {_ == J.u32.scale(s, D.to_u32.go(D.DCon{D.D0{}, t})) : R()}
      scale_succ(s, D.to_u32.go(t))
    case D.DCon{D.D1{}, t}:
      trail_kept(D.DCon{D.D1{}, t}, s, strip_snoc(D.D1{}, msf(t)))
    case D.DCon{D.D2{}, t}:
      trail_kept(D.DCon{D.D2{}, t}, s, strip_snoc(D.D2{}, msf(t)))
    case D.DCon{D.D3{}, t}:
      trail_kept(D.DCon{D.D3{}, t}, s, strip_snoc(D.D3{}, msf(t)))
    case D.DCon{D.D4{}, t}:
      trail_kept(D.DCon{D.D4{}, t}, s, strip_snoc(D.D4{}, msf(t)))
    case D.DCon{D.D5{}, t}:
      trail_kept(D.DCon{D.D5{}, t}, s, strip_snoc(D.D5{}, msf(t)))
    case D.DCon{D.D6{}, t}:
      trail_kept(D.DCon{D.D6{}, t}, s, strip_snoc(D.D6{}, msf(t)))
    case D.DCon{D.D7{}, t}:
      trail_kept(D.DCon{D.D7{}, t}, s, strip_snoc(D.D7{}, msf(t)))
    case D.DCon{D.D8{}, t}:
      trail_kept(D.DCon{D.D8{}, t}, s, strip_snoc(D.D8{}, msf(t)))
    case D.DCon{D.D9{}, t}:
      trail_kept(D.DCon{D.D9{}, t}, s, strip_snoc(D.D9{}, msf(t)))

law int_read:
  for +i: J.Int
  {J.u32.num(J.Number{False{}, i, J.FNone{}, J.ENone{}}) == J.u32.trail(False{}, J.strip_trailing(int_digits(i)), J.dlen(int_digits(i), 0n), 0n) : R()}

def int_read(i):
  match i:
    case J.IZero{}:
      {==}
    case J.INon{l, ds}:
      %Equal.sym(Ds(), app(ds, []), ds, A.app_nil(ds)) : {J.u32.digits(False{}, J.Digits{Con{J.lead_digit(l), _}, 1n+J.dlen(ds, 0n)}, J.ENone{}) == J.u32.trail(False{}, J.strip_trailing(Con{J.lead_digit(l), ds}), J.dlen(ds, 1n), 0n) : R()}
      %Equal.sym(J.Lead0, J.drop_lead(Con{J.lead_digit(l), ds}, 0n), J.Lead0{Con{J.lead_digit(l), ds}, 0n}, A.lead_drop(l, ds)) : {J.u32.lead(False{}, _, 1n+J.dlen(ds, 0n), 0n, 0n) == J.u32.trail(False{}, J.strip_trailing(Con{J.lead_digit(l), ds}), J.dlen(ds, 1n), 0n) : R()}
      %Equal.sym(Nat, Nat.add(1n+J.dlen(ds, 0n), 0n), 1n+J.dlen(ds, 0n), N.add_zero(1n+J.dlen(ds, 0n))) : {J.u32.trail(False{}, J.strip_trailing(Con{J.lead_digit(l), ds}), _, 0n) == J.u32.trail(False{}, J.strip_trailing(Con{J.lead_digit(l), ds}), J.dlen(ds, 1n), 0n) : R()}
      %Equal.sym(Nat, J.dlen(ds, 1n), 1n+J.dlen(ds, 0n), len_acc(ds, 0n)) : {J.u32.trail(False{}, J.strip_trailing(Con{J.lead_digit(l), ds}), 1n+J.dlen(ds, 0n), 0n) == J.u32.trail(False{}, J.strip_trailing(Con{J.lead_digit(l), ds}), _, 0n) : R()}
      {==}

def result(m: Maybe<&2, U32>) -> R():
  match m:
    case None{}:
      Fail{J.OutOfRange{[]}}
    case Some{x}:
      Done{x}

law scale_fin:
  for +m: Maybe<&2, Nat>
  {J.u32.scale(0n, m) == result(D.to_u32.fin(m)) : R()}

def scale_fin(m):
  match m:
    case None{}:
      {==}
    case Some{v}:
      {==}

law u32_round_trip:
  for +x: U32
  {J.u32(J.num_u32(x)) == Done{x} : R()}

def u32_round_trip(x):
  match x:
    case U32{w}:
      +d : D.Dec = D.of_word(32n, w)
      %Equal.sym(R(), J.u32.num(J.Number{False{}, J.decimal_int(d), J.FNone{}, J.ENone{}}), J.u32.trail(False{}, J.strip_trailing(int_digits(J.decimal_int(d))), J.dlen(int_digits(J.decimal_int(d)), 0n), 0n), int_read(J.decimal_int(d))) : {_ == Done{U32{w}} : R()}
      %Equal.sym(Ds(), int_digits(J.decimal_int(d)), msf(D.trim(d)), int_trim(d)) : {J.u32.trail(False{}, J.strip_trailing(_), J.dlen(_, 0n), 0n) == Done{U32{w}} : R()}
      %Equal.sym(D.Dec, D.trim(d), d, Text.of_word_trim(32n, w)) : {J.u32.trail(False{}, J.strip_trailing(msf(_)), J.dlen(msf(_), 0n), 0n) == Done{U32{w}} : R()}
      %N.add_zero(J.dlen(msf(d), 0n)) : {J.u32.trail(False{}, J.strip_trailing(msf(d)), _, 0n) == Done{U32{w}} : R()}
      %Equal.sym(R(), J.u32.trail(False{}, J.strip_trailing(msf(d)), Nat.add(J.dlen(msf(d), 0n), 0n), 0n), J.u32.scale(0n, D.to_u32.go(d)), trail_msf(d, 0n)) : {_ == Done{U32{w}} : R()}
      %Equal.sym(R(), J.u32.scale(0n, D.to_u32.go(d)), result(D.to_u32(d)), scale_fin(D.to_u32.go(d))) : {_ == Done{U32{w}} : R()}
      %Equal.sym(Maybe<&2, U32>, D.to_u32(d), Some{U32{w}}, Count.u32_round_trip(U32{w})) : {result(_) == Done{U32{w}} : R()}
      {==}
