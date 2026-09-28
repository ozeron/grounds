import Base
import ./text.bend as T

# Server-sent events (WHATWG HTML, "Server-sent events", the event stream
# format): the one Message type the server writes and the client reads,
# the writer, and the parser.
#
# The parser reads chars one at a time and tests each with Bool
# predicates only; a data char goes straight to the data, and a data line
# ends with the LF that ended it on the wire. A law can then follow any
# data through write and back.

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

def data.fwd.c(lf: Bool, +x: U32, rest: String) -> String:
  match lf:
    case True{}:
      SCon{Chr{x}, String.append("data: ", rest)}
    case False{}:
      SCon{Chr{x}, rest}

# data's lines after the first data: , each LF in data ending one line and
# starting the next; the last line ends with a LF of its own
def data.fwd(s: String) -> String:
  match s:
    case SNil{}:
      "\n"
    case SCon{Chr{+x}, t}:
      data.fwd.c(U32.is_eq(x, 10), x, data.fwd(t))

def id.fwd(i: Maybe<&2, String>, rest: String) -> String:
  match i:
    case Some{s}:
      String.append("id: ", String.append(s, SCon{'\n', rest}))
    case None{}:
      rest

# one event, then rest: its name, its data, its id, and the blank line
# that sends it. data should hold no CR, which would end a line; a name
# or an id holds neither CR nor LF
def write.to(e: Message, rest: String) -> String:
  match e:
    case Message{n, d, i}:
      String.append("event: ", String.append(n, SCon{'\n', String.append("data: ", String.append(data.fwd(d), id.fwd(i, SCon{'\n', rest})))}))

def write(e: Message) -> String:
  write.to(e, "")

# a retry: line, and a comment line (a heartbeat)
def retry(+ms: U32) -> String:
  "retry: " ++ U32.show(ms) ++ "\n\n"

def ping() -> String:
  ":\n\n"

# Parsing
# -------

# the line so far: 0 in the field's name, 1 just after its colon, 2 in
# its value; the name so far, reversed; the field, once its colon came (1
# data, 2 event, 3 id, 4 retry, 5 a comment, 0 another); and the value of
# an event, id or retry field, reversed
type Ln is Data:
  Ln{mode: U32, fname: String, fk: U32, v: String}

# the event so far: its data, reversed, each line followed by the LF that
# ended it; whether a data line came; its name; the last id; the last
# retry; and the last id a blank line confirmed, which a reconnect sends
type Evs is Data:
  Evs{d: String, any: Bool, name: String, last: Maybe<&2, String>, retry: Maybe<&2, Nat>, sent: Maybe<&2, String>}

# where the parser is: the line, the event, whether the char before was a
# CR, and whether a char has come yet (a BOM at the very start is dropped)
type P is Data:
  P{ln: Ln, ev: Evs, cr: Bool, started: Bool}

def ln0() -> Ln:
  Ln{0, "", 0, ""}

def start() -> P:
  P{ln0(), Evs{"", False{}, "", None{}, None{}, None{}}, False{}, False{}}

# the field a name, reversed, is
def kind.of(+f: String) -> U32:
  Bool.pick(U32, T.same(f, "atad", True{}), 1,
    Bool.pick(U32, T.same(f, "tneve", True{}), 2,
      Bool.pick(U32, T.same(f, "di", True{}), 3,
        Bool.pick(U32, T.same(f, "yrter", True{}), 4,
          Bool.pick(U32, T.same(f, "", True{}), 5, 0)))))

# the line and the event after a char
type Le is Data:
  Le{ln: Ln, ev: Evs}

def push(+fk: U32, +x: U32, v: String, e: Evs) -> Le:
  match fk e:
    case 1 Evs{d, _, n, l, r, i}:
      Le{Ln{2, "", 1, v}, Evs{SCon{Chr{x}, d}, True{}, n, l, r, i}}
    case 2 other:
      Le{Ln{2, "", 2, SCon{Chr{x}, v}}, other}
    case 3 other:
      Le{Ln{2, "", 3, SCon{Chr{x}, v}}, other}
    case 4 other:
      Le{Ln{2, "", 4, SCon{Chr{x}, v}}, other}
    case _ other:
      Le{Ln{2, "", fk, v}, other}

def at.colon(hit: Bool, +x: U32, f: String, e: Evs) -> Le:
  match hit:
    case True{}:
      Le{Ln{1, "", kind.of(f), ""}, e}
    case False{}:
      Le{Ln{0, SCon{Chr{x}, f}, 0, ""}, e}

def at.space(sp: Bool, +x: U32, +fk: U32, v: String, e: Evs) -> Le:
  match sp:
    case True{}:
      Le{Ln{2, "", fk, v}, e}
    case False{}:
      push(fk, x, v, e)

# a char that is not a line end
def plain(+x: U32, l: Ln, e: Evs) -> Le:
  match l:
    case Ln{0, f, _, _}:
      at.colon(U32.is_eq(x, 58), x, f, e)
    case Ln{1, _, +fk, v}:
      at.space(U32.is_eq(x, 32), x, fk, v, e)
    case Ln{_, _, +fk, v}:
      push(fk, x, v, e)

def has_nul(s: String, found: Bool) -> Bool:
  match s:
    case SNil{}:
      found
    case SCon{Chr{+x}, t}:
      has_nul(t, Bool.or(found, U32.is_eq(x, 0)))

# a long retry: stops at 2^32-1 ms, as a Nat past 2^48 would stop the program
def cap(+n: Nat) -> Nat:
  Bool.pick(Nat, Nat.is_le(n, 4294967295n), n, 4294967295n)

def digits(s: String, +n: Nat, ok: Bool) -> Maybe<&2, Nat>:
  match s:
    case SNil{}:
      Bool.pick(Maybe<&2, Nat>, ok, Some{n}, None{})
    case SCon{Chr{+x}, t}:
      digits(t, cap(Nat.add(Nat.mul(10n, n), Nat.sub(U32.to_nat(x), 48n))), Bool.and(ok, Bool.and(U32.is_ge(x, 48), U32.is_le(x, 57))))

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

def keep.id.of(+v: String, old: Maybe<&2, String>) -> Maybe<&2, String>:
  keep.id(has_nul(v, False{}), v, old)

# a field's line ended, with the char j that ended it
def end.field(+fk: U32, v: String, +j: U32, e: Evs) -> Evs:
  match fk e:
    case 1 Evs{d, _, n, l, r, i}:
      Evs{SCon{Chr{j}, d}, True{}, n, l, r, i}
    case 2 Evs{d, a, _, l, r, i}:
      Evs{d, a, String.reverse(v), l, r, i}
    case 3 Evs{d, a, n, l, r, i}:
      Evs{d, a, n, keep.id.of(String.reverse(v), l), r, i}
    case 4 Evs{d, a, n, l, r, i}:
      Evs{d, a, n, l, keep.retry(some.digits(String.reverse(v)), r), i}
    case _ other:
      other

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

# the event so far, and the one a blank line sends, if a data line came
type Out is Data:
  Out{ev: Evs, sent: Maybe<&2, Message>}

def dispatch.to(d: String, n: String, a: Maybe<&2, String>, l: M2, r: Maybe<&2, Nat>) -> Out:
  match l:
    case M2{b, c}:
      Out{Evs{"", False{}, "", a, r, b}, Some{Message{name.or(n), String.reverse(drop1(d)), c}}}

def dispatch.go(d: String, n: String, l: M2, r: Maybe<&2, Nat>) -> Out:
  match l:
    case M2{a, b}:
      dispatch.to(d, n, a, m.dup(b), r)

def dispatch.none(l: M2, r: Maybe<&2, Nat>) -> Out:
  match l:
    case M2{a, b}:
      Out{Evs{"", False{}, "", a, r, b}, None{}}

# a blank line confirms the last id, and sends the event if a data line came
def dispatch(e: Evs) -> Out:
  match e:
    case Evs{d, True{}, n, l, r, _}:
      dispatch.go(d, n, m.dup(l), r)
    case Evs{_, False{}, _, l, r, _}:
      dispatch.none(m.dup(l), r)

# a line ended by j: a blank one sends the event; a field sets its part
def line.end(l: Ln, +j: U32, e: Evs) -> Out:
  match l:
    case Ln{0, SNil{}, _, _}:
      dispatch(e)
    case Ln{0, +f, _, _}:
      Out{end.field(kind.of(f), "", j, e), None{}}
    case Ln{_, _, +fk, v}:
      Out{end.field(fk, v, j, e), None{}}

# the state and the events so far, newest first
type Fed is Data:
  Fed{p: P, events: List<&2, Message>}

def fed.out(o: Out, +cr: Bool, evs: List<&2, Message>) -> Fed:
  match o:
    case Out{e, Some{m}}:
      Fed{P{ln0(), e, cr, True{}}, Con{m, evs}}
    case Out{e, None{}}:
      Fed{P{ln0(), e, cr, True{}}, evs}

def fed.le(le: Le, evs: List<&2, Message>) -> Fed:
  match le:
    case Le{l, e}:
      Fed{P{l, e, False{}, True{}}, evs}

def char.plain(bom: Bool, +x: U32, l: Ln, e: Evs, evs: List<&2, Message>) -> Fed:
  match bom:
    case True{}:
      Fed{P{l, e, False{}, True{}}, evs}
    case False{}:
      fed.le(plain(x, l, e), evs)

# one char: a LF or a CR ends the line (a LF right after a CR does not end
# another); a BOM at the very start is dropped
def char(lf: Bool, cr: Bool, +x: U32, p: P, evs: List<&2, Message>) -> Fed:
  match lf cr p:
    case True{} _ P{l, e, True{}, _}:
      Fed{P{l, e, False{}, True{}}, evs}
    case True{} _ P{l, e, False{}, _}:
      fed.out(line.end(l, x, e), False{}, evs)
    case False{} True{} P{l, e, _, _}:
      fed.out(line.end(l, 10, e), True{}, evs)
    case False{} False{} P{l, e, _, +st}:
      char.plain(Bool.and(Bool.not(st), U32.is_eq(x, 65279)), x, l, e, evs)

# the chars through the parser; events newest first
def feed.go(s: String, f: Fed) -> Fed:
  match s f:
    case SNil{} other:
      other
    case SCon{Chr{+x}, t} Fed{p, evs}:
      feed.go(t, char(U32.is_eq(x, 10), U32.is_eq(x, 13), x, p, evs))

def fed.order(f: Fed) -> Fed:
  match f:
    case Fed{p, evs}:
      Fed{p, List.reverse(&2, Message, evs)}

# the chars of a stream through the parser: its new state, and the events
# they sent, in order
def feed(s: String, p: P) -> Fed:
  fed.order(feed.go(s, Fed{p, []}))

# the last id a blank line confirmed, and the last retry
type Tail is Data:
  Tail{last: Maybe<&2, String>, retry: Maybe<&2, Nat>}

def tail(p: P) -> Tail:
  match p:
    case P{_, Evs{_, _, _, _, r, i}, _, _}:
      Tail{i, r}

def tail.last(t: Tail) -> Maybe<&2, String>:
  match t:
    case Tail{l, _}:
      l

def retry.of(p: P) -> Maybe<&2, Nat>:
  match p:
    case P{_, Evs{_, _, _, _, r, _}, _, _}:
      r
