import Base
import ../../decimal/proof/nat.bend as M
import ../../decimal/decimal.bend as D
import ../resp.bend as R
import ./nat.bend as N

# a length line reads back as the count it was written from

# the digits pushed onto acc, as line.go pushes them: least significant on top
def push(d: D.Dec, acc: R.Buf) -> R.Buf:
  match d:
    case D.DNil{}:
      acc
    case D.DCon{x, t}:
      R.BCon{R.dig.byte(x), push(t, acc)}

law line_step:
  for +x: D.Dig
  for +t: R.Buf
  for +a: R.Buf
  {R.line.go(R.BCon{R.dig.byte(x), t}, a) == R.line.go(t, R.BCon{R.dig.byte(x), a}) : R.Line}

def line_step(x, t, a):
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

law line_digits:
  for +d: D.Dec
  for +t: R.Buf
  for +acc: R.Buf
  {R.line.go(R.render(d, t), acc) == R.line.go(t, push(d, acc)) : R.Line}

def line_digits(d, t, acc):
  match d:
    case D.DNil{}:
      {==}
    case D.DCon{x, u}:
      Equal.trans(R.Line, R.line.go(R.render(u, R.BCon{R.dig.byte(x), t}), acc), R.line.go(R.BCon{R.dig.byte(x), t}, push(u, acc)), R.line.go(t, R.BCon{R.dig.byte(x), push(u, acc)}),
        line_digits(u, R.BCon{R.dig.byte(x), t}, acc),
        line_step(x, t, push(u, acc)))

law rev_push:
  for +d: D.Dec
  for +t: R.Buf
  {R.buf.rev(push(d, R.BNil{}), t) == R.render(d, t) : R.Buf}

def rev_push(d, t):
  match d:
    case D.DNil{}:
      {==}
    case D.DCon{x, u}:
      rev_push(u, R.BCon{R.dig.byte(x), t})

# the length line: its digits, and what follows the CR LF
law length_line:
  for +d: D.Dec
  for +x: R.Buf
  {R.line.go(R.render0(d, R.crlf(x)), R.BNil{}) == R.LOk{R.render0(d, R.BNil{}), x} : R.Line}

def length_line(d, x):
  match d:
    case D.DNil{}:
      {==}
    case D.DCon{y, u}:
      Equal.trans(R.Line, R.line.go(R.render(D.DCon{y, u}, R.crlf(x)), R.BNil{}), R.line.go(R.crlf(x), push(D.DCon{y, u}, R.BNil{})), R.LOk{R.render(D.DCon{y, u}, R.BNil{}), x},
        line_digits(D.DCon{y, u}, R.crlf(x), R.BNil{}),
        Equal.cong(R.Buf, R.Line, l => R.LOk{l, x}, R.buf.rev(push(D.DCon{y, u}, R.BNil{}), R.BNil{}), R.render(D.DCon{y, u}, R.BNil{}), rev_push(D.DCon{y, u}, R.BNil{})))

law len_render:
  for +d: D.Dec
  for +t: R.Buf
  for +n: Nat
  {R.buf.len(R.render(d, t), n) == R.buf.len(t, Nat.add(N.dlen(d), n)) : Nat}

def len_render(d, t, n):
  match d:
    case D.DNil{}:
      {==}
    case D.DCon{x, u}:
      len_render(u, R.BCon{R.dig.byte(x), t}, n)

# a line of digits never starts with -
law num_pos:
  for +u: D.Dec
  for +x: D.Dig
  for +t: R.Buf
  {R.num(R.render(D.DCon{x, u}, t)) == R.num.pos(R.render(D.DCon{x, u}, t)) : R.Num}

def num_pos(u, x, t):
  match u x:
    case D.DNil{} D.D0{}:
      {==}
    case D.DNil{} D.D1{}:
      {==}
    case D.DNil{} D.D2{}:
      {==}
    case D.DNil{} D.D3{}:
      {==}
    case D.DNil{} D.D4{}:
      {==}
    case D.DNil{} D.D5{}:
      {==}
    case D.DNil{} D.D6{}:
      {==}
    case D.DNil{} D.D7{}:
      {==}
    case D.DNil{} D.D8{}:
      {==}
    case D.DNil{} D.D9{}:
      {==}
    case D.DCon{y, v} w:
      num_pos(v, y, R.BCon{R.dig.byte(w), t})

law digit_step:
  for +x: D.Dig
  for +t: R.Buf
  for +acc: Nat
  for +any: Bool
  {R.digits(R.BCon{R.dig.byte(x), t}, acc, True{}, any) == R.digits(t, Nat.add(Nat.mul(10n, acc), D.dig.val(x)), True{}, True{}) : R.Num}

def digit_step(x, t, acc, any):
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

def after(any: Bool, d: D.Dec) -> Bool:
  match d:
    case D.DNil{}:
      any
    case D.DCon{_, _}:
      True{}

# Horner, digit by digit
law digits_hor:
  for +d: D.Dec
  for +t: R.Buf
  for +acc: Nat
  for +any: Bool
  {R.digits(R.render(d, t), acc, True{}, any) == R.digits(t, N.hor(acc, d), True{}, after(any, d)) : R.Num}

def digits_hor(d, t, acc, any):
  match d:
    case D.DNil{}:
      {==}
    case D.DCon{x, u}:
      Equal.trans(R.Num, R.digits(R.render(u, R.BCon{R.dig.byte(x), t}), acc, True{}, any), R.digits(R.BCon{R.dig.byte(x), t}, N.hor(acc, u), True{}, after(any, u)), R.digits(t, N.hor(acc, D.DCon{x, u}), True{}, True{}),
        digits_hor(u, R.BCon{R.dig.byte(x), t}, acc, any),
        digit_step(x, t, N.hor(acc, u), after(any, u)))

law num_small:
  for +x: D.Dig
  for +u: D.Dec
  for e: {Nat.is_le(N.dlen(D.DCon{x, u}), 10n) == True{} : Bool}
  {R.num.pos(R.render(D.DCon{x, u}, R.BNil{})) == R.NOk{False{}, N.hor(0n, D.DCon{x, u})} : R.Num}

def num_small(x, u, e):
  %Equal.sym(Nat, R.buf.len(R.render(D.DCon{x, u}, R.BNil{}), 0n), N.dlen(D.DCon{x, u}), Equal.trans(Nat, R.buf.len(R.render(D.DCon{x, u}, R.BNil{}), 0n), Nat.add(N.dlen(D.DCon{x, u}), 0n), N.dlen(D.DCon{x, u}), len_render(D.DCon{x, u}, R.BNil{}, 0n), M.add_zero(N.dlen(D.DCon{x, u})))) : {R.num.len(Nat.is_le(_, 10n), R.render(D.DCon{x, u}, R.BNil{})) == R.NOk{False{}, N.hor(0n, D.DCon{x, u})} : R.Num}
  %Equal.sym(Bool, Nat.is_le(N.dlen(D.DCon{x, u}), 10n), True{}, e) : {R.num.len(_, R.render(D.DCon{x, u}, R.BNil{})) == R.NOk{False{}, N.hor(0n, D.DCon{x, u})} : R.Num}
  digits_hor(D.DCon{x, u}, R.BNil{}, 0n, False{})

# a length line of at most ten digits reads as the count
law num_count:
  for +d: D.Dec
  for e: {Nat.is_le(N.dlen(d), 10n) == True{} : Bool}
  {R.num(R.render0(d, R.BNil{})) == R.NOk{False{}, N.hor(0n, d)} : R.Num}

def num_count(d, e):
  match d:
    case D.DNil{}:
      {==}
    case D.DCon{x, u}:
      Equal.trans(R.Num, R.num(R.render(D.DCon{x, u}, R.BNil{})), R.num.pos(R.render(D.DCon{x, u}, R.BNil{})), R.NOk{False{}, N.hor(0n, D.DCon{x, u})},
        num_pos(u, x, R.BNil{}),
        num_small(x, u, e))

# Bodies
# ------

law rev_rev:
  for +a: R.Buf
  for +acc: R.Buf
  {R.buf.rev(R.buf.rev(a, acc), R.BNil{}) == R.buf.rev(acc, a) : R.Buf}

def rev_rev(a, acc):
  match a:
    case R.BNil{}:
      {==}
    case R.BCon{b, t}:
      rev_rev(t, R.BCon{b, acc})

# take reads exactly the bytes of a, whatever follows them
law take_all:
  for +a: R.Buf
  for +r: R.Buf
  for +acc: R.Buf
  {R.take(N.blen(a), R.cat(a, r), acc) == R.Took{R.buf.rev(R.buf.rev(a, acc), R.BNil{}), r} : R.Took}

def take_all(a, r, acc):
  match a:
    case R.BNil{}:
      {==}
    case R.BCon{b, t}:
      take_all(t, r, R.BCon{b, acc})

law take_arg:
  for +a: R.Buf
  for +r: R.Buf
  {R.take(N.blen(a), R.cat(a, r), R.BNil{}) == R.Took{a, r} : R.Took}

def take_arg(a, r):
  %rev_rev(a, R.BNil{}) : {R.take(N.blen(a), R.cat(a, r), R.BNil{}) == R.Took{_, r} : R.Took}
  take_all(a, r, R.BNil{})
