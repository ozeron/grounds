import Base
import ../resp.bend as R
import ./nat.bend as N
import ./line.bend as L
import ./spec.bend as S

# a command reads back as the array of bulk strings it was built from

# one argument: its length line, then its bytes, then CR LF
law arg_read:
  for +a: R.Buf
  for +y: R.Buf
  for +stack: List<&2, R.Frame>
  for +max: Nat
  for +f: Nat
  for +ef: {Nat.is_le(N.dlen(R.count(a, R.DNil{})), 10n) == True{} : Bool}
  for +em: {Nat.is_le(N.blen(a), max) == True{} : Bool}
  {R.parse.go(1n+1n+f, max, R.MItem{R.enc.arg(a, y), stack}) == R.parse.go(f, max, R.MValue{R.Bulk{R.buf.list(a)}, y, stack}) : R.Parsed}

def arg_read(a, y, stack, max, f, ef, em):
  %Equal.sym(R.Line, R.line.go(R.render0(R.count(a, R.DNil{}), R.crlf(R.cat(a, R.crlf(y)))), R.BNil{}), R.LOk{R.render0(R.count(a, R.DNil{}), R.BNil{}), R.cat(a, R.crlf(y))}, L.length_line(R.count(a, R.DNil{}), R.cat(a, R.crlf(y)))) : {R.item.line(36, _, stack, max, n => R.parse.go(1n+f, max, n)) == R.parse.go(f, max, R.MValue{R.Bulk{R.buf.list(a)}, y, stack}) : R.Parsed}
  %Equal.sym(R.Num, R.num(R.render0(R.count(a, R.DNil{}), R.BNil{})), R.NOk{False{}, N.hor(0n, R.count(a, R.DNil{}))}, L.num_count(R.count(a, R.DNil{}), ef)) : {R.bulk.head(R.BBulk{}, _, R.cat(a, R.crlf(y)), stack, max, n => R.parse.go(1n+f, max, n)) == R.parse.go(f, max, R.MValue{R.Bulk{R.buf.list(a)}, y, stack}) : R.Parsed}
  %Equal.sym(Nat, N.hor(0n, R.count(a, R.DNil{})), N.blen(a), N.arg_len(a)) : {R.bulk.fits(Nat.is_le(_, max), R.BBulk{}, _, R.cat(a, R.crlf(y)), stack, n => R.parse.go(1n+f, max, n)) == R.parse.go(f, max, R.MValue{R.Bulk{R.buf.list(a)}, y, stack}) : R.Parsed}
  %Equal.sym(Bool, Nat.is_le(N.blen(a), max), True{}, em) : {R.bulk.fits(_, R.BBulk{}, N.blen(a), R.cat(a, R.crlf(y)), stack, n => R.parse.go(1n+f, max, n)) == R.parse.go(f, max, R.MValue{R.Bulk{R.buf.list(a)}, y, stack}) : R.Parsed}
  %Equal.sym(R.Took, R.take(N.blen(a), R.cat(a, R.crlf(y)), R.BNil{}), R.Took{a, R.crlf(y)}, L.take_arg(a, R.crlf(y))) : {R.bulk.took(R.BBulk{}, N.blen(a), _, stack, n => R.parse.go(f, max, n)) == R.parse.go(f, max, R.MValue{R.Bulk{R.buf.list(a)}, y, stack}) : R.Parsed}
  {==}

law lrev:
  for +xs: List<&2, R.Reply>
  for +acc: List<&2, R.Reply>
  {List.reverse.go(&2, R.Reply, List.reverse.go(&2, R.Reply, xs, acc), []) == List.reverse.go(&2, R.Reply, acc, xs) : List<&2, R.Reply>}

def lrev(xs, acc):
  match xs:
    case Nil{}:
      {==}
    case Con{x, t}:
      lrev(t, Con{x, acc})

def Arrd(acc: List<&2, R.Reply>, xs: R.Args) -> R.Reply:
  R.Arr{List.reverse(&2, R.Reply, List.reverse.go(&2, R.Reply, S.bulks(xs), acc))}

# the arguments, one after another, into the array's frame
law args_read:
  for +t: R.Args
  for +a: R.Buf
  for +acc: List<&2, R.Reply>
  for +up: List<&2, R.Frame>
  for +tail: R.Buf
  for +max: Nat
  for +g: Nat
  for +e: {S.fits(R.ACon{a, t}, max) == True{} : Bool}
  {R.parse.go(Nat.add(S.steps(R.ACon{a, t}), g), max, R.MItem{R.enc.args(R.ACon{a, t}, tail), Con{R.Frame{R.KArr{}, N.alen(R.ACon{a, t}), acc}, up}}) == R.parse.go(g, max, R.MValue{Arrd(acc, R.ACon{a, t}), tail, up}) : R.Parsed}

def args_read(t, a, acc, up, tail, max, g, e):
  match t:
    case R.ANil{}:
      Equal.trans(R.Parsed,
        R.parse.go(1n+1n+1n+Nat.add(0n, g), max, R.MItem{R.enc.arg(a, tail), Con{R.Frame{R.KArr{}, 1n+0n, acc}, up}}),
        R.parse.go(1n+Nat.add(0n, g), max, R.MValue{R.Bulk{R.buf.list(a)}, tail, Con{R.Frame{R.KArr{}, 1n+0n, acc}, up}}),
        R.parse.go(g, max, R.MValue{Arrd(acc, R.ACon{a, R.ANil{}}), tail, up}),
        arg_read(a, tail, Con{R.Frame{R.KArr{}, 1n+0n, acc}, up}, max, 1n+Nat.add(0n, g),
          N.and_l(Nat.is_le(N.dlen(R.count(a, R.DNil{})), 10n), Nat.is_le(N.blen(a), max), N.and_l(S.fit(a, max), True{}, e)),
          N.and_r(Nat.is_le(N.dlen(R.count(a, R.DNil{})), 10n), Nat.is_le(N.blen(a), max), N.and_l(S.fit(a, max), True{}, e))),
        {==})
    case R.ACon{b, u}:
      Equal.trans(R.Parsed,
        R.parse.go(1n+1n+1n+Nat.add(S.steps(R.ACon{b, u}), g), max, R.MItem{R.enc.arg(a, R.enc.args(R.ACon{b, u}, tail)), Con{R.Frame{R.KArr{}, 1n+N.alen(R.ACon{b, u}), acc}, up}}),
        R.parse.go(1n+Nat.add(S.steps(R.ACon{b, u}), g), max, R.MValue{R.Bulk{R.buf.list(a)}, R.enc.args(R.ACon{b, u}, tail), Con{R.Frame{R.KArr{}, 1n+N.alen(R.ACon{b, u}), acc}, up}}),
        R.parse.go(g, max, R.MValue{Arrd(acc, R.ACon{a, R.ACon{b, u}}), tail, up}),
        arg_read(a, R.enc.args(R.ACon{b, u}, tail), Con{R.Frame{R.KArr{}, 1n+N.alen(R.ACon{b, u}), acc}, up}, max, 1n+Nat.add(S.steps(R.ACon{b, u}), g),
          N.and_l(Nat.is_le(N.dlen(R.count(a, R.DNil{})), 10n), Nat.is_le(N.blen(a), max), N.and_l(S.fit(a, max), S.fits(R.ACon{b, u}, max), e)),
          N.and_r(Nat.is_le(N.dlen(R.count(a, R.DNil{})), 10n), Nat.is_le(N.blen(a), max), N.and_l(S.fit(a, max), S.fits(R.ACon{b, u}, max), e))),
        args_read(u, b, Con{R.Bulk{R.buf.list(a)}, acc}, up, tail, max, g, N.and_r(S.fit(a, max), S.fits(R.ACon{b, u}, max), e)))

# after the header: the array, empty or not
law head_read:
  for +xs: R.Args
  for +tail: R.Buf
  for +max: Nat
  for +f: Nat
  for +ea: {Nat.is_le(N.alen(xs), max) == True{} : Bool}
  for +e: {S.fits(xs, max) == True{} : Bool}
  {R.agg.head(R.KArr{}, False{}, R.NOk{False{}, N.alen(xs)}, R.enc.args(xs, tail), [], max, n => R.parse.go(Nat.add(S.steps(xs), 1n+f), max, n)) == R.Parsed{R.Arr{S.bulks(xs)}, tail} : R.Parsed}

def head_read(xs, tail, max, f, ea, e):
  match xs:
    case R.ANil{}:
      {==}
    case R.ACon{a, t}:
      %Equal.sym(Bool, Nat.is_le(N.alen(R.ACon{a, t}), max), True{}, ea) : {R.agg.fits(_, R.KArr{}, R.agg.items(False{}, 1n+N.alen(t)), R.enc.args(R.ACon{a, t}, tail), [], n => R.parse.go(Nat.add(S.steps(R.ACon{a, t}), 1n+f), max, n)) == R.Parsed{R.Arr{S.bulks(R.ACon{a, t})}, tail} : R.Parsed}
      Equal.trans(R.Parsed,
        R.parse.go(Nat.add(S.steps(R.ACon{a, t}), 1n+f), max, R.MItem{R.enc.args(R.ACon{a, t}, tail), Con{R.Frame{R.KArr{}, N.alen(R.ACon{a, t}), []}, []}}),
        R.parse.go(1n+f, max, R.MValue{Arrd([], R.ACon{a, t}), tail, []}),
        R.Parsed{R.Arr{S.bulks(R.ACon{a, t})}, tail},
        args_read(t, a, [], [], tail, max, 1n+f, e),
        Equal.cong(List<&2, R.Reply>, R.Parsed, xs2 => R.Parsed{R.Arr{xs2}, tail}, List.reverse(&2, R.Reply, List.reverse.go(&2, R.Reply, S.bulks(R.ACon{a, t}), [])), S.bulks(R.ACon{a, t}), lrev(S.bulks(R.ACon{a, t}), [])))
