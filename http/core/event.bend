import Base
import ./text.bend as T

# Server-sent events (WHATWG HTML, "Server-sent events", the event stream
# format): the one Message type the server writes and the client reads, the
# writer, and the parser.
#
# The parser reads chars and tests each with Bool predicates only, and it
# joins data lines with the LF it read: a law can then follow any data
# through write and back.

type Message is Data:
  Message{name: String, data: String, id: Maybe<&2, String>}

def name(e: Message) -> String:
  match e:
    case Message{n, _, _}:
      n

def data(e: Message) -> String:
  match e:
    case Message{_, d, _}:
      d

def id(e: Message) -> Maybe<&2, String>:
  match e:
    case Message{_, _, i}:
      i

# Writing
# -------

def data.char(lf: Bool, +x: U32, out: String) -> String:
  match lf:
    case True{}:
      String.reverse.go("data: ", SCon{Chr{x}, out})
    case False{}:
      SCon{Chr{x}, out}

# data's lines as data: lines, reversed onto out: a LF in data ends one,
# and is itself the line's end on the wire
def data.go(s: String, out: String) -> String:
  match s:
    case SNil{}:
      SCon{'\n', out}
    case SCon{Chr{+x}, t}:
      data.go(t, data.char(U32.is_eq(x, 10), x, out))

def id.line(i: Maybe<&2, String>, out: String) -> String:
  match i:
    case Some{s}:
      String.reverse.go("\n", String.reverse.go(s, String.reverse.go("id: ", out)))
    case None{}:
      out

# one event, reversed onto out: its name, its data, its id, and the blank
# line that sends it. A CR in data would end a line, so data should hold LF
# only; a name or id holds neither
def write.go(e: Message, out: String) -> String:
  match e:
    case Message{n, d, i}:
      String.reverse.go("\n", id.line(i, data.go(d, String.reverse.go("data: ", String.reverse.go("\n", String.reverse.go(n, String.reverse.go("event: ", out)))))))

def write(e: Message) -> String:
  String.reverse(write.go(e, ""))

# a retry: line, and a comment line (a heartbeat)
def retry(+ms: U32) -> String:
  "retry: " ++ U32.show(ms) ++ "\n\n"

def ping() -> String:
  ":\n\n"

# Parsing
# -------

# where the parser is: the line so far, reversed; the data so far,
# reversed, each line followed by the LF that ended it; whether a data line
# came; the event's name so far; the last id seen; the last retry; whether
# the char before was a CR; and whether a char has come yet (a BOM at the
# very start is dropped)
type P is Data:
  P{line: String, data: String, any: Bool, name: String, last: Maybe<&2, String>, retry: Maybe<&2, Nat>, cr: Bool, started: Bool}

def start() -> P:
  P{"", "", False{}, "", None{}, None{}, False{}, False{}}

# a line cut at its first colon: the field, and the value after it, one
# space after the colon dropped
type Fld is Data:
  Fld{field: String, value: String, colon: Bool}

def fld.space(sp: Bool, +x: U32, t: String) -> String:
  match sp:
    case True{}:
      t
    case False{}:
      SCon{Chr{x}, t}

def fld.value(s: String) -> String:
  match s:
    case SCon{Chr{+x}, t}:
      fld.space(U32.is_eq(x, 32), x, t)
    case SNil{}:
      ""

# a line's chars so far: the field, reversed; the value, reversed; and
# whether the colon came
type Fs is Data:
  Fs{field: String, value: String, colon: Bool}

def fld.step(s: Fs, hit: Bool, +x: U32) -> Fs:
  match s hit:
    case Fs{f, v, True{}} _:
      Fs{f, SCon{Chr{x}, v}, True{}}
    case Fs{f, v, False{}} True{}:
      Fs{f, v, True{}}
    case Fs{f, v, False{}} False{}:
      Fs{SCon{Chr{x}, f}, v, False{}}

def fld.end(s: Fs) -> Fld:
  match s:
    case Fs{f, v, c}:
      Fld{String.reverse(f), fld.value(String.reverse(v)), c}

def fld.go(s: String, st: Fs) -> Fld:
  match s:
    case SNil{}:
      fld.end(st)
    case SCon{Chr{+x}, t}:
      fld.go(t, fld.step(st, U32.is_eq(x, 58), x))

def digits(s: String, +n: Nat, ok: Bool) -> Maybe<&2, Nat>:
  match s:
    case SNil{}:
      Bool.pick(Maybe<&2, Nat>, ok, Some{n}, None{})
    case SCon{Chr{+x}, t}:
      digits(t, Nat.add(Nat.mul(10n, n), Nat.sub(U32.to_nat(x), 48n)), Bool.and(ok, Bool.and(U32.is_ge(x, 48), U32.is_le(x, 57))))

def has_nul(s: String, found: Bool) -> Bool:
  match s:
    case SNil{}:
      found
    case SCon{Chr{+x}, t}:
      has_nul(t, Bool.or(found, U32.is_eq(x, 0)))

def some.digits(s: String) -> Maybe<&2, Nat>:
  match s:
    case SNil{}:
      None{}
    case other:
      digits(other, 0n, True{})

def keep.retry(m: Maybe<&2, Nat>, old: Maybe<&2, Nat>) -> Maybe<&2, Nat>:
  match m:
    case Some{n}:
      Some{n}
    case None{}:
      old

def keep.id(nul: Bool, v: String, old: Maybe<&2, String>) -> Maybe<&2, String>:
  match nul:
    case True{}:
      old
    case False{}:
      Some{v}

# the parser's event fields, and what one line does to them
type Acc is Data:
  Acc{data: String, any: Bool, name: String, last: Maybe<&2, String>, retry: Maybe<&2, Nat>}

def field.pick(dt: Bool, ev: Bool, i: Bool, rt: Bool, +v: String, +lf: U32, d: String, any: Bool, n: String, last: Maybe<&2, String>, r: Maybe<&2, Nat>) -> Acc:
  match dt ev i rt:
    case True{} _ _ _:
      Acc{SCon{Chr{lf}, String.reverse.go(v, d)}, True{}, n, last, r}
    case False{} True{} _ _:
      Acc{d, any, v, last, r}
    case False{} False{} True{} _:
      Acc{d, any, n, keep.id(has_nul(v, False{}), v, last), r}
    case False{} False{} False{} True{}:
      Acc{d, any, n, last, keep.retry(some.digits(v), r)}
    case False{} False{} False{} False{}:
      Acc{d, any, n, last, r}

def field(k: Fld, +lf: U32, e: Acc) -> Acc:
  match k e:
    case Fld{+f, v, _} Acc{d, any, n, last, r}:
      field.pick(T.same(f, "data", True{}), T.same(f, "event", True{}), T.same(f, "id", True{}), T.same(f, "retry", True{}), v, lf, d, any, n, last, r)

# a blank line: the event, when data came, named message when unnamed; the
# data without the LF after its last line
def drop1(s: String) -> String:
  match s:
    case SCon{_, t}:
      t
    case SNil{}:
      ""

def name.or(n: String) -> String:
  match n:
    case SNil{}:
      "message"
    case other:
      other

type Out is Data:
  Out{ev: Acc, sent: Maybe<&2, Message>}

type M2 is Data:
  M2{a: Maybe<&2, String>, b: Maybe<&2, String>}

def s.dup(s: String, a: String, b: String) -> M2:
  match s:
    case SNil{}:
      M2{Some{String.reverse(a)}, Some{String.reverse(b)}}
    case SCon{Chr{+x}, t}:
      s.dup(t, SCon{Chr{x}, a}, SCon{Chr{x}, b})

def m.dup(m: Maybe<&2, String>) -> M2:
  match m:
    case Some{s}:
      s.dup(s, "", "")
    case None{}:
      M2{None{}, None{}}

def dispatch.go(d: String, n: String, l: M2, r: Maybe<&2, Nat>) -> Out:
  match l:
    case M2{a, b}:
      Out{Acc{"", False{}, "", a, r}, Some{Message{name.or(n), String.reverse(drop1(d)), b}}}

def dispatch(e: Acc) -> Out:
  match e:
    case Acc{d, True{}, n, last, r}:
      dispatch.go(d, n, m.dup(last), r)
    case Acc{_, False{}, _, last, r}:
      Out{Acc{"", False{}, "", last, r}, None{}}

# a line, and what kind it is: blank, a comment, or a field
type Lk is Data:
  Lk{blank: Bool, note: Bool, line: String}

def line.kind(l: String) -> Lk:
  match l:
    case SNil{}:
      Lk{True{}, False{}, SNil{}}
    case SCon{Chr{+x}, t}:
      Lk{False{}, U32.is_eq(x, 58), SCon{Chr{x}, t}}

# a whole line, ended by lf: a blank one sends the event, a comment is
# skipped, another sets a field
def line.do(k: Lk, +lf: U32, e: Acc) -> Out:
  match k:
    case Lk{True{}, _, _}:
      dispatch(e)
    case Lk{False{}, True{}, _}:
      Out{e, None{}}
    case Lk{False{}, False{}, l}:
      Out{field(fld.go(l, Fs{"", "", False{}}), lf, e), None{}}

def line(l: String, +lf: U32, e: Acc) -> Out:
  line.do(line.kind(l), lf, e)

# the state and the events so far, newest first
type Fed is Data:
  Fed{p: P, events: List<&2, Message>}

def fed.out(o: Out, +cr: Bool, events: List<&2, Message>) -> Fed:
  match o:
    case Out{Acc{d, any, n, last, r}, Some{ev}}:
      Fed{P{"", d, any, n, last, r, cr, True{}}, Con{ev, events}}
    case Out{Acc{d, any, n, last, r}, None{}}:
      Fed{P{"", d, any, n, last, r, cr, True{}}, events}

# one char: a LF or a CR ends the line (a LF right after a CR does not
# end another); a BOM at the very start is dropped
def char(lf: Bool, cr: Bool, bom: Bool, +x: U32, p: P, events: List<&2, Message>) -> Fed:
  match lf cr bom p:
    case True{} _ _ P{l, d, any, n, last, r, True{}, _}:
      Fed{P{l, d, any, n, last, r, False{}, True{}}, events}
    case True{} _ _ P{l, d, any, n, last, r, False{}, _}:
      fed.out(line(String.reverse(l), x, Acc{d, any, n, last, r}), False{}, events)
    case False{} True{} _ P{l, d, any, n, last, r, _, _}:
      fed.out(line(String.reverse(l), 10, Acc{d, any, n, last, r}), True{}, events)
    case False{} False{} True{} P{l, d, any, n, last, r, c, False{}}:
      Fed{P{l, d, any, n, last, r, False{}, True{}}, events}
    case False{} False{} _ P{l, d, any, n, last, r, _, _}:
      Fed{P{SCon{Chr{x}, l}, d, any, n, last, r, False{}, True{}}, events}

def feed.go(s: String, f: Fed) -> Fed:
  match s f:
    case SNil{} Fed{p, evs}:
      Fed{p, List.reverse(&2, Message, evs)}
    case SCon{Chr{+x}, t} Fed{p, evs}:
      feed.go(t, char(U32.is_eq(x, 10), U32.is_eq(x, 13), U32.is_eq(x, 65279), x, p, evs))

# the chars of a stream through the parser: its new state, and the events
# they sent, in order
def feed(s: String, p: P) -> Fed:
  feed.go(s, Fed{p, []})

def last(p: P) -> Maybe<&2, String>:
  match p:
    case P{_, _, _, _, l, _, _, _}:
      l

def retry.of(p: P) -> Maybe<&2, Nat>:
  match p:
    case P{_, _, _, _, _, r, _, _}:
      r

# the last id and the last retry, together
type Tail is Data:
  Tail{last: Maybe<&2, String>, retry: Maybe<&2, Nat>}

def tail(p: P) -> Tail:
  match p:
    case P{_, _, _, _, l, r, _, _}:
      Tail{l, r}
