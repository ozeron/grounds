import Base
import ../utf8/utf8.bend as U

# RESP, the Redis protocol (docs/resp.md): a command is an array of bulk
# strings, a reply one value. RESP2 and RESP3 replies both parse

# a reply. Bulk strings are bytes (0..255): Redis values are binary. A map
# holds its keys and values alternating: k1, v1, k2, v2
type Reply is Data:
  Simple{text: String}
  Error{text: String}
  Int{neg: Bool, n: Nat}
  Bulk{data: List<&2, U32>}
  RNil{}
  Arr{items: List<&2, Reply>}
  RBool{value: Bool}
  RDouble{text: String}
  RBig{neg: Bool, n: Nat}
  BulkError{data: List<&2, U32>}
  Verbatim{format: String, data: List<&2, U32>}
  RMap{items: List<&2, Reply>}
  RSet{items: List<&2, Reply>}
  RPush{items: List<&2, Reply>}

# Bytes
# -----

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

# a before tail
def cat(a: Buf, tail: Buf) -> Buf:
  match a:
    case BNil{}:
      tail
    case BCon{b, t}:
      BCon{b, cat(t, tail)}

def buf.len(bs: Buf, +n: Nat) -> Nat:
  match bs:
    case BNil{}:
      n
    case BCon{_, t}:
      buf.len(t, 1n+n)

# bytes from a socket and how many: counted as they are copied
type Counted is Data:
  Counted{n: Nat, bs: Buf}

def counted.go(xs: List<&2, U32>, +n: Nat, acc: Buf) -> Counted:
  match xs:
    case Nil{}:
      Counted{n, buf.rev(acc, BNil{})}
    case Con{x, t}:
      counted.go(t, 1n+n, BCon{x, acc})

def counted(xs: List<&2, U32>) -> Counted:
  counted.go(xs, 0n, BNil{})

# Lengths, in decimal
# -------------------

type Dig is Data:
  D0{}
  D1{}
  D2{}
  D3{}
  D4{}
  D5{}
  D6{}
  D7{}
  D8{}
  D9{}

# a count in decimal, least significant digit first; DNil is 0
type Dec is Data:
  DNil{}
  DCon{d: Dig, t: Dec}

def inc(d: Dec) -> Dec:
  match d:
    case DNil{}:
      DCon{D1{}, DNil{}}
    case DCon{D0{}, t}:
      DCon{D1{}, t}
    case DCon{D1{}, t}:
      DCon{D2{}, t}
    case DCon{D2{}, t}:
      DCon{D3{}, t}
    case DCon{D3{}, t}:
      DCon{D4{}, t}
    case DCon{D4{}, t}:
      DCon{D5{}, t}
    case DCon{D5{}, t}:
      DCon{D6{}, t}
    case DCon{D6{}, t}:
      DCon{D7{}, t}
    case DCon{D7{}, t}:
      DCon{D8{}, t}
    case DCon{D8{}, t}:
      DCon{D9{}, t}
    case DCon{D9{}, t}:
      DCon{D0{}, inc(t)}

def dig.byte(x: Dig) -> U32:
  match x:
    case D0{}:
      48
    case D1{}:
      49
    case D2{}:
      50
    case D3{}:
      51
    case D4{}:
      52
    case D5{}:
      53
    case D6{}:
      54
    case D7{}:
      55
    case D8{}:
      56
    case D9{}:
      57

# the digits, most significant first, before tail
def render(d: Dec, tail: Buf) -> Buf:
  match d:
    case DNil{}:
      tail
    case DCon{x, t}:
      render(t, BCon{dig.byte(x), tail})

def render0(d: Dec, tail: Buf) -> Buf:
  match d:
    case DNil{}:
      BCon{48, tail}
    case DCon{x, t}:
      render(t, BCon{dig.byte(x), tail})

# the number of bytes, plus d
def count(bs: Buf, d: Dec) -> Dec:
  match bs:
    case BNil{}:
      d
    case BCon{_, t}:
      count(t, inc(d))

# Commands
# --------

# a command's arguments, each as bytes: a list type of its own, counted and
# then written without being shared
type Args is Data:
  ANil{}
  ACon{head: Buf, tail: Args}

def nargs(xs: Args, d: Dec) -> Dec:
  match xs:
    case ANil{}:
      d
    case ACon{_, t}:
      nargs(t, inc(d))

def crlf(tail: Buf) -> Buf:
  BCon{13, BCon{10, tail}}

# $len CR LF, the bytes, CR LF
def enc.arg(+a: Buf, tail: Buf) -> Buf:
  BCon{36, render0(count(a, DNil{}), crlf(cat(a, crlf(tail))))}

def enc.args(xs: Args, tail: Buf) -> Buf:
  match xs:
    case ANil{}:
      tail
    case ACon{a, t}:
      enc.arg(a, enc.args(t, tail))

# a command before tail: *N CR LF, then each argument as a bulk string
def encode.buf(+xs: Args, tail: Buf) -> Buf:
  BCon{42, render0(nargs(xs, DNil{}), crlf(enc.args(xs, tail)))}

def args.text(xs: List<&2, String>) -> Args:
  match xs:
    case Nil{}:
      ANil{}
    case Con{x, t}:
      ACon{buf.of(U.encode(x)), args.text(t)}

def args.bytes(xs: List<&2, List<&2, U32>>) -> Args:
  match xs:
    case Nil{}:
      ANil{}
    case Con{x, t}:
      ACon{buf.of(x), args.bytes(t)}

# a command on the wire; each argument as UTF-8, or as bytes
def encode(xs: List<&2, String>) -> List<&2, U32>:
  buf.list(encode.buf(args.text(xs), BNil{}))

def encode_bytes(xs: List<&2, List<&2, U32>>) -> List<&2, U32>:
  buf.list(encode.buf(args.bytes(xs), BNil{}))

# Replies
# -------

# a line up to CR LF and the bytes after it; LMore keeps what it read,
# reversed, so a read that needs more gives the bytes back
type Line is Data:
  LOk{line: Buf, rest: Buf}
  LMore{read: Buf}
  LBad{}

def line.go(bs: Buf, acc: Buf) -> Line:
  match bs:
    case BCon{13, BCon{10, t}}:
      LOk{buf.rev(acc, BNil{}), t}
    case BCon{13, BNil{}}:
      LMore{BCon{13, acc}}
    case BCon{13, _}:
      LBad{}
    case BCon{10, _}:
      LBad{}
    case BCon{b, t}:
      line.go(t, BCon{b, acc})
    case BNil{}:
      LMore{acc}

def text.of(t: U.Text) -> String:
  match t:
    case U.TOk{s}:
      s
    case U.TBad{_, before}:
      String.reverse(before)

def text(bs: Buf) -> String:
  text.of(U.decode(buf.list(bs)))

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

# a signed whole number, as :, $, * and ( lines hold
def num(bs: Buf) -> Num:
  match bs:
    case BCon{45, t}:
      num.of(True{}, digits(t, 0n, True{}, False{}))
    case other:
      num.of(False{}, digits(other, 0n, True{}, False{}))

type Took is Data:
  Took{body: Buf, rest: Buf}
  Short{read: Buf, missing: Nat}

def take(n: Nat, bs: Buf, acc: Buf) -> Took:
  match n bs:
    case 0n rest:
      Took{buf.rev(acc, BNil{}), rest}
    case 1n+m BCon{b, t}:
      take(m, t, BCon{b, acc})
    case 1n+m BNil{}:
      Short{acc, 1n+m}

type Agg is Data:
  KArr{}
  KMap{}
  KSet{}
  KPush{}
  KAttr{}

type BKind is Data:
  BBulk{}
  BErr{}
  BVerb{}

# the aggregate being read: how many items are left, and those read, reversed
type Frame is Data:
  Frame{kind: Agg, left: Nat, acc: List<&2, Reply>}

# where the parser is: at the start of an item, holding a value read, or
# inside a bulk string of len bytes
type Mode is Data:
  MItem{bs: Buf, stack: List<&2, Frame>}
  MValue{v: Reply, bs: Buf, stack: List<&2, Frame>}
  MBulk{kind: BKind, len: Nat, bs: Buf, stack: List<&2, Frame>}

# one reply and the bytes after it; More when it has not all come, with
# where to go on and how many bytes are missing at least
type Parsed is Data:
  Parsed{reply: Reply, rest: Buf}
  More{at: Mode, missing: Nat}
  Bad{why: String}
  TooLarge{}

def K() -> Type:
  Mode -> Parsed

def agg.make(kind: Agg, items: List<&2, Reply>, bs: Buf, up: List<&2, Frame>) -> Mode:
  match kind:
    case KArr{}:
      MValue{Arr{items}, bs, up}
    case KMap{}:
      MValue{RMap{items}, bs, up}
    case KSet{}:
      MValue{RSet{items}, bs, up}
    case KPush{}:
      MValue{RPush{items}, bs, up}
    case KAttr{}:
      MItem{bs, up}

def fill(kind: Agg, l: Nat, acc: List<&2, Reply>, up: List<&2, Frame>, bs: Buf, k: K()) -> Parsed:
  match l:
    case 0n:
      k(agg.make(kind, List.reverse(&2, Reply, acc), bs, up))
    case 1n+m:
      k(MItem{bs, Con{Frame{kind, 1n+m, acc}, up}})

# a value is read: the reply, or the next item of the aggregate it is in.
# Attributes (|) come before the value they describe and are dropped
def done(stack: List<&2, Frame>, v: Reply, bs: Buf, k: K()) -> Parsed:
  match stack:
    case Nil{}:
      Parsed{v, bs}
    case Con{Frame{kind, 1n+l, acc}, up}:
      fill(kind, l, Con{v, acc}, up, bs, k)
    case Con{Frame{_, 0n, _}, _}:
      Bad{"empty frame"}

def verb.split(bs: Buf) -> Reply:
  match bs:
    case BCon{a, BCon{b, BCon{c, BCon{58, rest}}}}:
      Verbatim{text(BCon{a, BCon{b, BCon{c, BNil{}}}}), buf.list(rest)}
    case other:
      Verbatim{"", buf.list(other)}

def bulk.make(kind: BKind, body: Buf) -> Reply:
  match kind:
    case BBulk{}:
      Bulk{buf.list(body)}
    case BErr{}:
      BulkError{buf.list(body)}
    case BVerb{}:
      verb.split(body)

def bulk.took(kind: BKind, +len: Nat, t: Took, stack: List<&2, Frame>, k: K()) -> Parsed:
  match t:
    case Took{body, BCon{13, BCon{10, after}}}:
      k(MValue{bulk.make(kind, body), after, stack})
    case Took{body, BNil{}}:
      More{MBulk{kind, len, body, stack}, 2n}
    case Took{body, BCon{13, BNil{}}}:
      More{MBulk{kind, len, cat(body, BCon{13, BNil{}}), stack}, 1n}
    case Took{_, _}:
      Bad{"bulk string not ended by CR LF"}
    case Short{read, missing}:
      More{MBulk{kind, len, buf.rev(read, BNil{}), stack}, Nat.add(missing, 2n)}

def bulk.fits(ok: Bool, kind: BKind, +len: Nat, rest: Buf, stack: List<&2, Frame>, k: K()) -> Parsed:
  match ok:
    case True{}:
      k(MBulk{kind, len, rest, stack})
    case False{}:
      TooLarge{}

def bulk.head(kind: BKind, n: Num, rest: Buf, stack: List<&2, Frame>, +max: Nat, k: K()) -> Parsed:
  match n:
    case NOk{True{}, 1n}:
      k(MValue{RNil{}, rest, stack})
    case NOk{False{}, +len}:
      bulk.fits(Nat.is_le(len, max), kind, len, rest, stack, k)
    case _:
      Bad{"bad bulk length"}

def agg.fits(ok: Bool, kind: Agg, +n: Nat, rest: Buf, stack: List<&2, Frame>, k: K()) -> Parsed:
  match ok:
    case True{}:
      k(MItem{rest, Con{Frame{kind, n, []}, stack}})
    case False{}:
      TooLarge{}

def agg.empty(kind: Agg, rest: Buf, stack: List<&2, Frame>, k: K()) -> Parsed:
  k(agg.make(kind, [], rest, stack))

def agg.items(pairs: Bool, +n: Nat) -> Nat:
  match pairs:
    case True{}:
      Nat.add(n, n)
    case False{}:
      n

# an aggregate's header; a map or attribute of n pairs holds 2n items
def agg.head(kind: Agg, +pairs: Bool, n: Num, rest: Buf, stack: List<&2, Frame>, +max: Nat, k: K()) -> Parsed:
  match n:
    case NOk{True{}, 1n}:
      k(MValue{RNil{}, rest, stack})
    case NOk{False{}, 0n}:
      agg.empty(kind, rest, stack, k)
    case NOk{False{}, 1n+(+m)}:
      agg.fits(Nat.is_le(1n+m, max), kind, agg.items(pairs, 1n+m), rest, stack, k)
    case _:
      Bad{"bad aggregate length"}

def integer(big: Bool, n: Num, rest: Buf, stack: List<&2, Frame>, k: K()) -> Parsed:
  match big n:
    case False{} NOk{neg, v}:
      k(MValue{Int{neg, v}, rest, stack})
    case True{} NOk{neg, v}:
      k(MValue{RBig{neg, v}, rest, stack})
    case _ NBad{}:
      Bad{"bad integer"}

def boolean(line: Buf, rest: Buf, stack: List<&2, Frame>, k: K()) -> Parsed:
  match line:
    case BCon{116, BNil{}}:
      k(MValue{RBool{True{}}, rest, stack})
    case BCon{102, BNil{}}:
      k(MValue{RBool{False{}}, rest, stack})
    case _:
      Bad{"bad boolean"}

def null(line: Buf, rest: Buf, stack: List<&2, Frame>, k: K()) -> Parsed:
  match line:
    case BNil{}:
      k(MValue{RNil{}, rest, stack})
    case _:
      Bad{"bad null"}

def typed(t: U32, line: Buf, rest: Buf, stack: List<&2, Frame>, +max: Nat, k: K()) -> Parsed:
  match t:
    case 43:
      k(MValue{Simple{text(line)}, rest, stack})
    case 45:
      k(MValue{Error{text(line)}, rest, stack})
    case 58:
      integer(False{}, num(line), rest, stack, k)
    case 36:
      bulk.head(BBulk{}, num(line), rest, stack, max, k)
    case 42:
      agg.head(KArr{}, False{}, num(line), rest, stack, max, k)
    case 95:
      null(line, rest, stack, k)
    case 35:
      boolean(line, rest, stack, k)
    case 44:
      k(MValue{RDouble{text(line)}, rest, stack})
    case 40:
      integer(True{}, num(line), rest, stack, k)
    case 33:
      bulk.head(BErr{}, num(line), rest, stack, max, k)
    case 61:
      bulk.head(BVerb{}, num(line), rest, stack, max, k)
    case 37:
      agg.head(KMap{}, True{}, num(line), rest, stack, max, k)
    case 126:
      agg.head(KSet{}, False{}, num(line), rest, stack, max, k)
    case 62:
      agg.head(KPush{}, False{}, num(line), rest, stack, max, k)
    case 124:
      agg.head(KAttr{}, True{}, num(line), rest, stack, max, k)
    case _:
      Bad{"unknown reply type"}

def item.line(+t: U32, l: Line, stack: List<&2, Frame>, +max: Nat, k: K()) -> Parsed:
  match l:
    case LOk{line, rest}:
      typed(t, line, rest, stack, max, k)
    case LMore{read}:
      More{MItem{BCon{t, buf.rev(read, BNil{})}, stack}, 1n}
    case LBad{}:
      Bad{"bare CR or LF"}

def item(bs: Buf, stack: List<&2, Frame>, +max: Nat, k: K()) -> Parsed:
  match bs:
    case BCon{+t, rest}:
      item.line(t, line.go(rest, BNil{}), stack, max, k)
    case BNil{}:
      More{MItem{BNil{}, stack}, 1n}

def step(m: Mode, +max: Nat, k: K()) -> Parsed:
  match m:
    case MValue{v, bs, stack}:
      done(stack, v, bs, k)
    case MItem{bs, stack}:
      item(bs, stack, max, k)
    case MBulk{kind, +len, bs, stack}:
      bulk.took(kind, len, take(len, bs, BNil{}), stack, k)

# fuel bounds the steps: one per item and one per value
def parse.go(fuel: Nat, +max: Nat, m: Mode) -> Parsed:
  match fuel:
    case 0n:
      Bad{"reply too long"}
    case 1n+f:
      step(m, max, n => parse.go(f, max, n))

def parse.at(m: Mode, +max: Nat) -> Parsed:
  parse.go(4294967295n, max, m)

# more bytes for a parse that stopped at m
def feed(m: Mode, bs: Buf) -> Mode:
  match m:
    case MItem{a, stack}:
      MItem{cat(a, bs), stack}
    case MBulk{kind, len, a, stack}:
      MBulk{kind, len, cat(a, bs), stack}
    case MValue{v, a, stack}:
      MValue{v, cat(a, bs), stack}

# one reply from bytes, with bulk strings and aggregates of at most max
# bytes or items; nested aggregates use a stack of their own, so no depth
# overflows
def parse.buf(bs: Buf, +max: Nat) -> Parsed:
  parse.at(MItem{bs, []}, max)

def parse(bs: List<&2, U32>) -> Parsed:
  parse.buf(buf.of(bs), 536870912n)

# Writing replies
# ---------------

def push.text(s: String, out: Buf) -> Buf:
  buf.rev(buf.of(U.encode(s)), out)

def push.bytes(bs: List<&2, U32>, out: Buf) -> Buf:
  buf.rev(buf.of(bs), out)

def push.num(neg: Bool, +n: Nat, out: Buf) -> Buf:
  match neg:
    case True{}:
      push.text(Nat.show(n), BCon{45, out})
    case False{}:
      push.text(Nat.show(n), out)

def push.crlf(out: Buf) -> Buf:
  BCon{10, BCon{13, out}}

def push.line(t: U32, s: String, out: Buf) -> Buf:
  push.crlf(push.text(s, BCon{t, out}))

def push.bulk(t: U32, +bs: List<&2, U32>, out: Buf) -> Buf:
  push.crlf(push.bytes(bs, push.crlf(push.text(Nat.show(List.length(&2, U32, bs)), BCon{t, out}))))

def push.agg(t: U32, +n: Nat, out: Buf) -> Buf:
  push.crlf(push.text(Nat.show(n), BCon{t, out}))

def half(n: Nat) -> Nat:
  match n:
    case 1n+1n+m:
      1n+half(m)
    case _:
      0n

def push.verb(f: String, +bs: List<&2, U32>, out: Buf) -> Buf:
  push.bulk(61, List.append(&2, U32, U.encode(f ++ ":"), bs), out)

# the work left: replies to write, the items of an aggregate first
def write.go(fuel: Nat, work: List<&2, Reply>, out: Buf) -> Buf:
  match fuel work:
    case 0n _:
      buf.rev(out, BNil{})
    case 1n+f Nil{}:
      buf.rev(out, BNil{})
    case 1n+f Con{Simple{s}, t}:
      write.go(f, t, push.line(43, s, out))
    case 1n+f Con{Error{s}, t}:
      write.go(f, t, push.line(45, s, out))
    case 1n+f Con{Int{neg, +n}, t}:
      write.go(f, t, push.crlf(push.num(neg, n, BCon{58, out})))
    case 1n+f Con{Bulk{bs}, t}:
      write.go(f, t, push.bulk(36, bs, out))
    case 1n+f Con{RNil{}, t}:
      write.go(f, t, push.line(95, "", out))
    case 1n+f Con{Arr{+xs}, t}:
      write.go(f, List.append(&2, Reply, xs, t), push.agg(42, List.length(&2, Reply, xs), out))
    case 1n+f Con{RBool{True{}}, t}:
      write.go(f, t, push.line(35, "t", out))
    case 1n+f Con{RBool{False{}}, t}:
      write.go(f, t, push.line(35, "f", out))
    case 1n+f Con{RDouble{s}, t}:
      write.go(f, t, push.line(44, s, out))
    case 1n+f Con{RBig{neg, +n}, t}:
      write.go(f, t, push.crlf(push.num(neg, n, BCon{40, out})))
    case 1n+f Con{BulkError{bs}, t}:
      write.go(f, t, push.bulk(33, bs, out))
    case 1n+f Con{Verbatim{fm, bs}, t}:
      write.go(f, t, push.verb(fm, bs, out))
    case 1n+f Con{RMap{+xs}, t}:
      write.go(f, List.append(&2, Reply, xs, t), push.agg(37, half(List.length(&2, Reply, xs)), out))
    case 1n+f Con{RSet{+xs}, t}:
      write.go(f, List.append(&2, Reply, xs, t), push.agg(126, List.length(&2, Reply, xs), out))
    case 1n+f Con{RPush{+xs}, t}:
      write.go(f, List.append(&2, Reply, xs, t), push.agg(62, List.length(&2, Reply, xs), out))

# a reply on the wire, in RESP3 (RNil as _): the fuzz check compares what
# was parsed against what was sent this way
def write(r: Reply) -> List<&2, U32>:
  buf.list(write.go(4294967295n, [r], BNil{}))

# Reading replies
# ---------------

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
    case RBool{True{}}:
      "(true)"
    case RBool{False{}}:
      "(false)"
    case RDouble{t}:
      t
    case RBig{neg, n}:
      "(big) " ++ sign(neg) ++ Nat.show(n)
    case BulkError{bs}:
      "(error) " ++ text.of(U.decode(bs))
    case Verbatim{_, bs}:
      "\"" ++ text.of(U.decode(bs)) ++ "\""
    case _:
      "[...]"

def show.sep(first: Bool) -> String:
  match first:
    case True{}:
      ""
    case False{}:
      ", "

def show.items(xs: List<&2, Reply>, out: String, first: Bool) -> String:
  match xs:
    case Nil{}:
      out ++ "]"
    case Con{x, t}:
      show.items(t, out ++ show.sep(first) ++ show.flat(x), False{})

# a reply as redis-cli would print it; aggregates inside aggregates as [...]
def show(r: Reply) -> String:
  match r:
    case Arr{xs}:
      show.items(xs, "[", True{})
    case RMap{xs}:
      show.items(xs, "[", True{})
    case RSet{xs}:
      show.items(xs, "[", True{})
    case RPush{xs}:
      show.items(xs, "[", True{})
    case other:
      show.flat(other)
