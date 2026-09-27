import Base
import ../resp.bend as R
import ../../utf8/utf8.bend as U
import ./nat.bend as N

# Bufs and Lists hold the same bytes: the List API is the Buf one

def tolist(b: R.Buf) -> List<&2, U32>:
  match b:
    case R.BNil{}:
      []
    case R.BCon{x, t}:
      Con{x, tolist(t)}

def fromlist(l: List<&2, U32>) -> R.Buf:
  match l:
    case Nil{}:
      R.BNil{}
    case Con{x, t}:
      R.BCon{x, fromlist(t)}

law list_go:
  for +b: R.Buf
  for +acc: List<&2, U32>
  {R.buf.list.go(b, acc) == List.reverse.go(&2, U32, acc, tolist(b)) : List<&2, U32>}

def list_go(b, acc):
  match b:
    case R.BNil{}:
      {==}
    case R.BCon{x, t}:
      list_go(t, Con{x, acc})

law of_go:
  for +l: List<&2, U32>
  for +acc: R.Buf
  {R.buf.of.go(l, acc) == R.buf.rev(acc, fromlist(l)) : R.Buf}

def of_go(l, acc):
  match l:
    case Nil{}:
      {==}
    case Con{x, t}:
      of_go(t, R.BCon{x, acc})

law of_tolist:
  for +b: R.Buf
  for +acc: R.Buf
  {R.buf.of.go(tolist(b), acc) == R.buf.rev(acc, b) : R.Buf}

def of_tolist(b, acc):
  match b:
    case R.BNil{}:
      {==}
    case R.BCon{x, t}:
      of_tolist(t, R.BCon{x, acc})

law to_from:
  for +l: List<&2, U32>
  {tolist(fromlist(l)) == l : List<&2, U32>}

def to_from(l):
  match l:
    case Nil{}:
      {==}
    case Con{x, t}:
      Equal.cong(List<&2, U32>, List<&2, U32>, y => Con{x, y}, tolist(fromlist(t)), t, to_from(t))

# a Buf to a List and back
law of_list:
  for +b: R.Buf
  {R.buf.of(R.buf.list(b)) == b : R.Buf}

def of_list(b):
  %Equal.sym(List<&2, U32>, R.buf.list.go(b, []), tolist(b), list_go(b, [])) : {R.buf.of(_) == b : R.Buf}
  of_tolist(b, R.BNil{})

# a List to a Buf and back
law list_of:
  for +l: List<&2, U32>
  {R.buf.list(R.buf.of(l)) == l : List<&2, U32>}

def list_of(l):
  %Equal.sym(R.Buf, R.buf.of.go(l, R.BNil{}), fromlist(l), of_go(l, R.BNil{})) : {R.buf.list(_) == l : List<&2, U32>}
  Equal.trans(List<&2, U32>, R.buf.list.go(fromlist(l), []), tolist(fromlist(l)), l, list_go(fromlist(l), []), to_from(l))

# k <= n: n is k and what is left
law le_split:
  for +k: Nat
  for +n: Nat
  for +e: {Nat.is_le(k, n) == True{} : Bool}
  {n == Nat.add(k, Nat.sub(n, k)) : Nat}

def le_split(k, n, e):
  match k n:
    case 0n 0n:
      {==}
    case 0n 1n+m:
      {==}
    case 1n+j 0n:
      N.absurd({0n == Nat.add(1n+j, Nat.sub(0n, 1n+j)) : Nat}, e)
    case 1n+j 1n+m:
      Equal.cong(Nat, Nat, y => 1n+y, m, Nat.add(j, Nat.sub(m, j)), le_split(j, m, e))
