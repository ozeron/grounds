import Base
import ./LAWS.bend as Laws
import ./resp.bend as R
import ./proof/nat.bend as N
import ./proof/spec.bend as S
import ./proof/line.bend as L
import ./proof/cmd.bend as C

def Laws.command_reads_back(xs, tail, max, f, e):
  %Equal.sym(R.Line, R.line.go(R.render0(R.nargs(xs, R.DNil{}), R.crlf(R.enc.args(xs, tail))), R.BNil{}), R.LOk{R.render0(R.nargs(xs, R.DNil{}), R.BNil{}), R.enc.args(xs, tail)}, L.length_line(R.nargs(xs, R.DNil{}), R.enc.args(xs, tail))) : {R.item.line(42, _, [], max, n => R.parse.go(Nat.add(S.steps(xs), 1n+f), max, n)) == R.Parsed{R.Arr{S.bulks(xs)}, tail} : R.Parsed}
  %Equal.sym(R.Num, R.num(R.render0(R.nargs(xs, R.DNil{}), R.BNil{})), R.NOk{False{}, N.hor(0n, R.nargs(xs, R.DNil{}))}, L.num_count(R.nargs(xs, R.DNil{}), N.and_l(Nat.is_le(N.dlen(R.nargs(xs, R.DNil{})), 10n), Nat.is_le(N.alen(xs), max), N.and_l(Bool.and(Nat.is_le(N.dlen(R.nargs(xs, R.DNil{})), 10n), Nat.is_le(N.alen(xs), max)), S.fits(xs, max), e)))) : {R.agg.head(R.KArr{}, False{}, _, R.enc.args(xs, tail), [], max, n => R.parse.go(Nat.add(S.steps(xs), 1n+f), max, n)) == R.Parsed{R.Arr{S.bulks(xs)}, tail} : R.Parsed}
  %Equal.sym(Nat, N.hor(0n, R.nargs(xs, R.DNil{})), N.alen(xs), N.count_args(xs)) : {R.agg.head(R.KArr{}, False{}, R.NOk{False{}, _}, R.enc.args(xs, tail), [], max, n => R.parse.go(Nat.add(S.steps(xs), 1n+f), max, n)) == R.Parsed{R.Arr{S.bulks(xs)}, tail} : R.Parsed}
  C.head_read(xs, tail, max, f,
    N.and_r(Nat.is_le(N.dlen(R.nargs(xs, R.DNil{})), 10n), Nat.is_le(N.alen(xs), max), N.and_l(Bool.and(Nat.is_le(N.dlen(R.nargs(xs, R.DNil{})), 10n), Nat.is_le(N.alen(xs), max)), S.fits(xs, max), e)),
    N.and_r(Bool.and(Nat.is_le(N.dlen(R.nargs(xs, R.DNil{})), 10n), Nat.is_le(N.alen(xs), max)), S.fits(xs, max), e))

def Laws.bulk_framed(a, tail, max, f, e):
  C.arg_read(a, tail, [], max, 1n+f,
    N.and_l(Nat.is_le(N.dlen(R.count(a, R.DNil{})), 10n), Nat.is_le(N.blen(a), max), e),
    N.and_r(Nat.is_le(N.dlen(R.count(a, R.DNil{})), 10n), Nat.is_le(N.blen(a), max), e))

# take, short of bytes, reads them all and says how many are missing
law take_short:
  for +p: R.Buf
  for +n: Nat
  for +acc: R.Buf
  for +e: {Nat.is_lt(N.blen(p), n) == True{} : Bool}
  {R.take(n, p, acc) == R.Short{R.buf.rev(p, acc), Nat.sub(n, N.blen(p))} : R.Took}

def take_short(p, n, acc, e):
  match p n:
    case R.BNil{} 0n:
      N.absurd({R.take(0n, R.BNil{}, acc) == R.Short{R.buf.rev(R.BNil{}, acc), Nat.sub(0n, 0n)} : R.Took}, e)
    case R.BNil{} 1n+m:
      {==}
    case R.BCon{b, t} 0n:
      N.absurd({R.take(0n, R.BCon{b, t}, acc) == R.Short{R.buf.rev(R.BCon{b, t}, acc), Nat.sub(0n, N.blen(R.BCon{b, t}))} : R.Took}, e)
    case R.BCon{b, t} 1n+m:
      take_short(t, m, R.BCon{b, acc}, e)

def Laws.bulk_cut(a, p, max, f, e, short):
  %Equal.sym(R.Line, R.line.go(R.render0(R.count(a, R.DNil{}), R.crlf(p)), R.BNil{}), R.LOk{R.render0(R.count(a, R.DNil{}), R.BNil{}), p}, L.length_line(R.count(a, R.DNil{}), p)) : {Laws.is_more(R.item.line(36, _, [], max, n => R.parse.go(1n+f, max, n))) == True{} : Bool}
  %Equal.sym(R.Num, R.num(R.render0(R.count(a, R.DNil{}), R.BNil{})), R.NOk{False{}, N.hor(0n, R.count(a, R.DNil{}))}, L.num_count(R.count(a, R.DNil{}), N.and_l(Nat.is_le(N.dlen(R.count(a, R.DNil{})), 10n), Nat.is_le(N.blen(a), max), e))) : {Laws.is_more(R.bulk.head(R.BBulk{}, _, p, [], max, n => R.parse.go(1n+f, max, n))) == True{} : Bool}
  %Equal.sym(Nat, N.hor(0n, R.count(a, R.DNil{})), N.blen(a), N.arg_len(a)) : {Laws.is_more(R.bulk.fits(Nat.is_le(_, max), R.BBulk{}, _, p, [], n => R.parse.go(1n+f, max, n))) == True{} : Bool}
  %Equal.sym(Bool, Nat.is_le(N.blen(a), max), True{}, N.and_r(Nat.is_le(N.dlen(R.count(a, R.DNil{})), 10n), Nat.is_le(N.blen(a), max), e)) : {Laws.is_more(R.bulk.fits(_, R.BBulk{}, N.blen(a), p, [], n => R.parse.go(1n+f, max, n))) == True{} : Bool}
  %Equal.sym(R.Took, R.take(N.blen(a), p, R.BNil{}), R.Short{R.buf.rev(p, R.BNil{}), Nat.sub(N.blen(a), N.blen(p))}, take_short(p, N.blen(a), R.BNil{}, short)) : {Laws.is_more(R.bulk.took(R.BBulk{}, N.blen(a), _, [], n => R.parse.go(f, max, n))) == True{} : Bool}
  {==}

def Laws.null_bulk(rest, max, f):
  {==}

def Laws.empty_bulk(rest, max, f):
  match max:
    case 0n:
      {==}
    case 1n+m:
      {==}
