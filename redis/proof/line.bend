import Base
import ../resp.bend as R
import ./nat.bend as N

# a length line reads back as the count it was written from

# the digits pushed onto acc, as line.go pushes them: least significant on top
def push(d: R.Dec, acc: R.Buf) -> R.Buf:
  match d:
    case R.DNil{}:
      acc
    case R.DCon{x, t}:
      R.BCon{R.dig.byte(x), push(t, acc)}

law line_step:
  for +x: R.Dig
  for +t: R.Buf
  for +a: R.Buf
  {R.line.go(R.BCon{R.dig.byte(x), t}, a) == R.line.go(t, R.BCon{R.dig.byte(x), a}) : R.Line}

def line_step(x, t, a):
  match x:
    case R.D0{}:
      {==}
    case R.D1{}:
      {==}
    case R.D2{}:
      {==}
    case R.D3{}:
      {==}
    case R.D4{}:
      {==}
    case R.D5{}:
      {==}
    case R.D6{}:
      {==}
    case R.D7{}:
      {==}
    case R.D8{}:
      {==}
    case R.D9{}:
      {==}

law line_digits:
  for +d: R.Dec
  for +t: R.Buf
  for +acc: R.Buf
  {R.line.go(R.render(d, t), acc) == R.line.go(t, push(d, acc)) : R.Line}

def line_digits(d, t, acc):
  match d:
    case R.DNil{}:
      {==}
    case R.DCon{x, u}:
      Equal.trans(R.Line, R.line.go(R.render(u, R.BCon{R.dig.byte(x), t}), acc), R.line.go(R.BCon{R.dig.byte(x), t}, push(u, acc)), R.line.go(t, R.BCon{R.dig.byte(x), push(u, acc)}),
        line_digits(u, R.BCon{R.dig.byte(x), t}, acc),
        line_step(x, t, push(u, acc)))

law rev_push:
  for +d: R.Dec
  for +t: R.Buf
  {R.buf.rev(push(d, R.BNil{}), t) == R.render(d, t) : R.Buf}

def rev_push(d, t):
  match d:
    case R.DNil{}:
      {==}
    case R.DCon{x, u}:
      rev_push(u, R.BCon{R.dig.byte(x), t})

# the length line: its digits, and what follows the CR LF
law length_line:
  for +d: R.Dec
  for +x: R.Buf
  {R.line.go(R.render0(d, R.crlf(x)), R.BNil{}) == R.LOk{R.render0(d, R.BNil{}), x} : R.Line}

def length_line(d, x):
  match d:
    case R.DNil{}:
      {==}
    case R.DCon{y, u}:
      Equal.trans(R.Line, R.line.go(R.render(R.DCon{y, u}, R.crlf(x)), R.BNil{}), R.line.go(R.crlf(x), push(R.DCon{y, u}, R.BNil{})), R.LOk{R.render(R.DCon{y, u}, R.BNil{}), x},
        line_digits(R.DCon{y, u}, R.crlf(x), R.BNil{}),
        Equal.cong(R.Buf, R.Line, l => R.LOk{l, x}, R.buf.rev(push(R.DCon{y, u}, R.BNil{}), R.BNil{}), R.render(R.DCon{y, u}, R.BNil{}), rev_push(R.DCon{y, u}, R.BNil{})))

law len_render:
  for +d: R.Dec
  for +t: R.Buf
  for +n: Nat
  {R.buf.len(R.render(d, t), n) == R.buf.len(t, Nat.add(N.dlen(d), n)) : Nat}

def len_render(d, t, n):
  match d:
    case R.DNil{}:
      {==}
    case R.DCon{x, u}:
      len_render(u, R.BCon{R.dig.byte(x), t}, n)

# a line of digits never starts with -
law num_pos:
  for +u: R.Dec
  for +x: R.Dig
  for +t: R.Buf
  {R.num(R.render(R.DCon{x, u}, t)) == R.num.pos(R.render(R.DCon{x, u}, t)) : R.Num}

def num_pos(u, x, t):
  match u x:
    case R.DNil{} R.D0{}:
      {==}
    case R.DNil{} R.D1{}:
      {==}
    case R.DNil{} R.D2{}:
      {==}
    case R.DNil{} R.D3{}:
      {==}
    case R.DNil{} R.D4{}:
      {==}
    case R.DNil{} R.D5{}:
      {==}
    case R.DNil{} R.D6{}:
      {==}
    case R.DNil{} R.D7{}:
      {==}
    case R.DNil{} R.D8{}:
      {==}
    case R.DNil{} R.D9{}:
      {==}
    case R.DCon{y, v} w:
      num_pos(v, y, R.BCon{R.dig.byte(w), t})

law digit_step:
  for +x: R.Dig
  for +t: R.Buf
  for +acc: Nat
  for +any: Bool
  {R.digits(R.BCon{R.dig.byte(x), t}, acc, True{}, any) == R.digits(t, Nat.add(Nat.mul(10n, acc), N.dv(x)), True{}, True{}) : R.Num}

def digit_step(x, t, acc, any):
  match x:
    case R.D0{}:
      {==}
    case R.D1{}:
      {==}
    case R.D2{}:
      {==}
    case R.D3{}:
      {==}
    case R.D4{}:
      {==}
    case R.D5{}:
      {==}
    case R.D6{}:
      {==}
    case R.D7{}:
      {==}
    case R.D8{}:
      {==}
    case R.D9{}:
      {==}

def after(any: Bool, d: R.Dec) -> Bool:
  match d:
    case R.DNil{}:
      any
    case R.DCon{_, _}:
      True{}

# Horner, digit by digit
law digits_hor:
  for +d: R.Dec
  for +t: R.Buf
  for +acc: Nat
  for +any: Bool
  {R.digits(R.render(d, t), acc, True{}, any) == R.digits(t, N.hor(acc, d), True{}, after(any, d)) : R.Num}

def digits_hor(d, t, acc, any):
  match d:
    case R.DNil{}:
      {==}
    case R.DCon{x, u}:
      Equal.trans(R.Num, R.digits(R.render(u, R.BCon{R.dig.byte(x), t}), acc, True{}, any), R.digits(R.BCon{R.dig.byte(x), t}, N.hor(acc, u), True{}, after(any, u)), R.digits(t, N.hor(acc, R.DCon{x, u}), True{}, True{}),
        digits_hor(u, R.BCon{R.dig.byte(x), t}, acc, any),
        digit_step(x, t, N.hor(acc, u), after(any, u)))

law num_small:
  for +x: R.Dig
  for +u: R.Dec
  for e: {Nat.is_le(N.dlen(R.DCon{x, u}), 10n) == True{} : Bool}
  {R.num.pos(R.render(R.DCon{x, u}, R.BNil{})) == R.NOk{False{}, N.hor(0n, R.DCon{x, u})} : R.Num}

def num_small(x, u, e):
  %Equal.sym(Nat, R.buf.len(R.render(R.DCon{x, u}, R.BNil{}), 0n), N.dlen(R.DCon{x, u}), Equal.trans(Nat, R.buf.len(R.render(R.DCon{x, u}, R.BNil{}), 0n), Nat.add(N.dlen(R.DCon{x, u}), 0n), N.dlen(R.DCon{x, u}), len_render(R.DCon{x, u}, R.BNil{}, 0n), N.add_zero(N.dlen(R.DCon{x, u})))) : {R.num.len(Nat.is_le(_, 10n), R.render(R.DCon{x, u}, R.BNil{})) == R.NOk{False{}, N.hor(0n, R.DCon{x, u})} : R.Num}
  %Equal.sym(Bool, Nat.is_le(N.dlen(R.DCon{x, u}), 10n), True{}, e) : {R.num.len(_, R.render(R.DCon{x, u}, R.BNil{})) == R.NOk{False{}, N.hor(0n, R.DCon{x, u})} : R.Num}
  digits_hor(R.DCon{x, u}, R.BNil{}, 0n, False{})

# a length line of at most ten digits reads as the count
law num_count:
  for +d: R.Dec
  for e: {Nat.is_le(N.dlen(d), 10n) == True{} : Bool}
  {R.num(R.render0(d, R.BNil{})) == R.NOk{False{}, N.hor(0n, d)} : R.Num}

def num_count(d, e):
  match d:
    case R.DNil{}:
      {==}
    case R.DCon{x, u}:
      Equal.trans(R.Num, R.num(R.render(R.DCon{x, u}, R.BNil{})), R.num.pos(R.render(R.DCon{x, u}, R.BNil{})), R.NOk{False{}, N.hor(0n, R.DCon{x, u})},
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
