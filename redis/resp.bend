import Base
import ../utf8/utf8.bend as U

# RESP2, the Redis protocol: a command is an array of bulk strings, a reply
# one value (https://redis.io/docs/latest/develop/reference/protocol-spec/)

# a reply. Bulk strings are bytes (0..255): Redis values are binary
type Reply is Data:
  Simple{text: String}
  Error{text: String}
  Int{neg: Bool, n: Nat}
  Bulk{data: List<&2, U32>}
  RNil{}
  Arr{items: List<&2, Reply>}

# bytes as a list type of its own, read without taking it
type Buf is Data:
  BNil{}
  BCon{head: U32, tail: Buf}

def buf.rev(bs: Buf, acc: Buf) -> Buf:
  match bs:
    case BNil{}:
      acc
    case BCon{b, t}:
      buf.rev(t, BCon{b, acc})

def buf.of.go(xs: List<&2, U32>, acc: Buf) -> Buf:
  match xs:
    case Nil{}:
      buf.rev(acc, BNil{})
    case Con{x, t}:
      buf.of.go(t, BCon{x, acc})

def buf.of(xs: List<&2, U32>) -> Buf:
  buf.of.go(xs, BNil{})

def buf.list.go(bs: Buf, acc: List<&2, U32>) -> List<&2, U32>:
  match bs:
    case BNil{}:
      List.reverse(&2, U32, acc)
    case BCon{b, t}:
      buf.list.go(t, Con{b, acc})

def buf.list(bs: Buf) -> List<&2, U32>:
  buf.list.go(bs, [])

def buf.app(a: Buf, b: Buf) -> Buf:
  buf.rev(buf.rev(a, BNil{}), b)

# Commands
# --------

def push_text(s: String, out: List<&2, U32>) -> List<&2, U32>:
  List.reverse.go(&2, U32, U.encode(s), out)

def push_bytes(bs: List<&2, U32>, out: List<&2, U32>) -> List<&2, U32>:
  List.reverse.go(&2, U32, bs, out)

def count(xs: List<&2, U32>, +n: U32, acc: List<&2, U32>) -> Counted:
  match xs:
    case Nil{}:
      Counted{n, List.reverse(&2, U32, acc)}
    case Con{x, t}:
      count(t, (n + 1 : U32), Con{x, acc})

# bytes and their count, from one read
type Counted is Data:
  Counted{n: U32, bytes: List<&2, U32>}

def arg.push(c: Counted, out: List<&2, U32>) -> List<&2, U32>:
  match c:
    case Counted{n, bs}:
      push_text("\r\n", push_bytes(bs, push_text("\r\n", push_text(U32.show(n), push_text("$", out)))))

def args.go(xs: List<&2, String>, +n: U32, out: List<&2, U32>) -> Counted:
  match xs:
    case Nil{}:
      Counted{n, out}
    case Con{x, t}:
      args.go(t, (n + 1 : U32), arg.push(count(U.encode(x), 0, []), out))

def encode.head(c: Counted) -> List<&2, U32>:
  match c:
    case Counted{n, out}:
      List.reverse.go(&2, U32, push_text("\r\n", push_text(U32.show(n), push_text("*", []))), List.reverse(&2, U32, out))

# a command on the wire: *N, then $len and the bytes of each argument
def encode(args: List<&2, String>) -> List<&2, U32>:
  encode.head(args.go(args, 0, []))

# Replies
# -------

# a line up to CR LF, and the bytes after it
type Line is Data:
  LOk{line: Buf, rest: Buf}
  LMore{}
  LBad{}

def line.go(bs: Buf, acc: Buf) -> Line:
  match bs:
    case BCon{13, BCon{10, t}}:
      LOk{buf.rev(acc, BNil{}), t}
    case BCon{13, BNil{}}:
      LMore{}
    case BCon{13, _}:
      LBad{}
    case BCon{10, _}:
      LBad{}
    case BCon{b, t}:
      line.go(t, BCon{b, acc})
    case BNil{}:
      LMore{}

def latin1(bs: Buf, acc: String) -> String:
  match bs:
    case BNil{}:
      String.reverse(acc)
    case BCon{b, t}:
      latin1(t, SCon{Chr{b}, acc})

type Num is Data:
  NOk{neg: Bool, n: Nat}
  NBad{}

def digits.end(ok: Bool, +n: Nat) -> Maybe<&2, Nat>:
  match ok:
    case True{}:
      Some{n}
    case False{}:
      None{}

# the digits' value; None unless all digits and at least one
def digits(bs: Buf, +acc: Nat, ok: Bool, any: Bool) -> Maybe<&2, Nat>:
  match bs:
    case BNil{}:
      digits.end(Bool.and(ok, any), acc)
    case BCon{+b, t}:
      digits(t, Nat.add(Nat.mul(10n, acc), Nat.sub(U32.to_nat(b), 48n)), Bool.and(ok, Bool.and(U32.is_ge(b, 48), U32.is_le(b, 57))), True{})

def num.of(neg: Bool, m: Maybe<&2, Nat>) -> Num:
  match m:
    case Some{n}:
      NOk{neg, n}
    case None{}:
      NBad{}

# a signed whole number, as :, $ and * lines hold
def num(bs: Buf) -> Num:
  match bs:
    case BCon{45, t}:
      num.of(True{}, digits(t, 0n, True{}, False{}))
    case other:
      num.of(False{}, digits(other, 0n, True{}, False{}))

type Took is Data:
  Took{body: Buf, rest: Buf}
  Short{}

def take(n: Nat, bs: Buf, acc: Buf) -> Took:
  match n bs:
    case 0n rest:
      Took{buf.rev(acc, BNil{}), rest}
    case 1n+m BCon{b, t}:
      take(m, t, BCon{b, acc})
    case 1n+m BNil{}:
      Short{}

# the array being read: how many items are left, and those read, reversed
type Frame is Data:
  Frame{left: Nat, acc: List<&2, Reply>}

# one reply and the bytes after it; More when it has not all come
type Parsed is Data:
  Parsed{reply: Reply, rest: List<&2, U32>}
  More{}
  Bad{why: String}

def K() -> Type:
  Buf -> List<&2, Frame> -> Maybe<&2, Reply> -> Parsed

def frame.fill(l: Nat, acc: List<&2, Reply>, up: List<&2, Frame>, bs: Buf, k: K()) -> Parsed:
  match l:
    case 0n:
      k(bs, up, Some{Arr{List.reverse(&2, Reply, acc)}})
    case 1n+m:
      k(bs, Con{Frame{1n+m, acc}, up}, None{})

# a value is read: the reply, or the next item of the array it is in
def done(stack: List<&2, Frame>, v: Reply, bs: Buf, k: K()) -> Parsed:
  match stack:
    case Nil{}:
      Parsed{v, buf.list(bs)}
    case Con{Frame{0n, acc}, up}:
      frame.fill(0n, Con{v, acc}, up, bs, k)
    case Con{Frame{1n+l, acc}, up}:
      frame.fill(l, Con{v, acc}, up, bs, k)

def bulk.end(t: Took, stack: List<&2, Frame>, k: K()) -> Parsed:
  match t:
    case Short{}:
      More{}
    case Took{body, BCon{13, BCon{10, after}}}:
      k(after, stack, Some{Bulk{buf.list(body)}})
    case Took{_, BNil{}}:
      More{}
    case Took{_, BCon{13, BNil{}}}:
      More{}
    case Took{_, _}:
      Bad{"bulk string not ended by CR LF"}

def bulk(n: Num, rest: Buf, stack: List<&2, Frame>, k: K()) -> Parsed:
  match n:
    case NOk{True{}, 1n}:
      k(rest, stack, Some{RNil{}})
    case NOk{False{}, +len}:
      bulk.end(take(len, rest, BNil{}), stack, k)
    case _:
      Bad{"bad bulk length"}

def array(n: Num, rest: Buf, stack: List<&2, Frame>, k: K()) -> Parsed:
  match n:
    case NOk{True{}, 1n}:
      k(rest, stack, Some{RNil{}})
    case NOk{False{}, 0n}:
      k(rest, stack, Some{Arr{[]}})
    case NOk{False{}, 1n+m}:
      k(rest, Con{Frame{1n+m, []}, stack}, None{})
    case _:
      Bad{"bad array length"}

def integer(n: Num, rest: Buf, stack: List<&2, Frame>, k: K()) -> Parsed:
  match n:
    case NOk{neg, v}:
      k(rest, stack, Some{Int{neg, v}})
    case NBad{}:
      Bad{"bad integer"}

def typed(t: U32, line: Buf, rest: Buf, stack: List<&2, Frame>, k: K()) -> Parsed:
  match t:
    case 43:
      k(rest, stack, Some{Simple{latin1(line, "")}})
    case 45:
      k(rest, stack, Some{Error{latin1(line, "")}})
    case 58:
      integer(num(line), rest, stack, k)
    case 36:
      bulk(num(line), rest, stack, k)
    case 42:
      array(num(line), rest, stack, k)
    case _:
      Bad{"unknown reply type"}

def item.line(t: U32, l: Line, stack: List<&2, Frame>, k: K()) -> Parsed:
  match l:
    case LOk{line, rest}:
      typed(t, line, rest, stack, k)
    case LMore{}:
      More{}
    case LBad{}:
      Bad{"bare CR or LF"}

def item(bs: Buf, stack: List<&2, Frame>, k: K()) -> Parsed:
  match bs:
    case BCon{t, rest}:
      item.line(t, line.go(rest, BNil{}), stack, k)
    case BNil{}:
      More{}

def step(p: Maybe<&2, Reply>, bs: Buf, stack: List<&2, Frame>, k: K()) -> Parsed:
  match p:
    case Some{v}:
      done(stack, v, bs, k)
    case None{}:
      item(bs, stack, k)

# fuel bounds the steps: one per value, and one more per array
def parse.go(fuel: Nat, bs: Buf, stack: List<&2, Frame>, p: Maybe<&2, Reply>) -> Parsed:
  match fuel:
    case 0n:
      Bad{"reply too long"}
    case 1n+f:
      step(p, bs, stack, b => s => q => parse.go(f, b, s, q))

# one reply from the bytes received so far; nested arrays use a stack of
# their own, so no depth overflows
def parse(bs: List<&2, U32>) -> Parsed:
  parse.go(4294967295n, buf.of(bs), [], None{})

def show.sep(first: Bool) -> String:
  match first:
    case True{}:
      ""
    case False{}:
      ", "

def text.of(t: U.Text) -> String:
  match t:
    case U.TOk{s}:
      s
    case U.TBad{_, before}:
      String.reverse(before)

def sign(neg: Bool) -> String:
  match neg:
    case True{}:
      "-"
    case False{}:
      ""

def show.flat(r: Reply) -> String:
  match r:
    case Simple{t}:
      t
    case Error{t}:
      "(error) " ++ t
    case Int{neg, n}:
      sign(neg) ++ Nat.show(n)
    case Bulk{bs}:
      "\"" ++ text.of(U.decode(bs)) ++ "\""
    case RNil{}:
      "(nil)"
    case Arr{_}:
      "[...]"

def show.items(xs: List<&2, Reply>, out: String, first: Bool) -> String:
  match xs:
    case Nil{}:
      out ++ "]"
    case Con{x, t}:
      show.items(t, out ++ show.sep(first) ++ show.flat(x), False{})

# a reply as redis-cli would print it; arrays inside arrays as [...]
def show(r: Reply) -> String:
  match r:
    case Arr{xs}:
      show.items(xs, "[", True{})
    case other:
      show.flat(other)

def text(r: Reply) -> Maybe<&2, String>:
  match r:
    case Simple{t}:
      Some{t}
    case Bulk{bs}:
      Some{text.of(U.decode(bs))}
    case _:
      None{}

def buf.copy(bs: Buf, acc: Buf) -> Buf:
  match bs:
    case BNil{}:
      buf.rev(acc, BNil{})
    case BCon{b, t}:
      buf.copy(t, BCon{b, acc})

def buf.empty(bs: Buf) -> Bool:
  match bs:
    case BNil{}:
      True{}
    case _:
      False{}

# parse, from bytes already in a Buf
def parse.buf(bs: Buf) -> Parsed:
  parse.go(4294967295n, bs, [], None{})
