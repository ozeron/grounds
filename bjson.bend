import Base

# Model
# =====

type Json is Data:
  JNull{}
  JBool{value: Bool}
  JNum{text: String}
  JStr{value: String}
  JArr{items: List<&2, Json>}
  JObj{fields: List<&2, Field>}

type Field is Data:
  Field{key: String, value: Json}

type Reason is Data:
  UnexpectedEnd{}
  UnexpectedChar{char: Char}
  TrailingInput{}
  InvalidNumber{}
  InvalidEscape{}
  InvalidUnicode{}
  LoneSurrogate{}
  ControlChar{}
  Internal{}

# offset counts chars from 0; line and column count from 1
type Error is Data:
  Error{reason: Reason, offset: U32, line: U32, column: U32}

# Lexing
# ======

# a lexed token and the input after it, or why and where lexing stopped
type Lex is Data:
  LOk{text: String, rest: String}
  LBad{reason: Reason, rest: String}

def in_range(+x: U32, lo: U32, hi: U32) -> Bool:
  Bool.and(U32.is_ge(x, lo), U32.is_le(x, hi))

# RFC 8259 §2: only space, tab, LF and CR
def skip_ws(s: String) -> String:
  match s:
    case SCon{' ', t}:
      skip_ws(t)
    case SCon{'\t', t}:
      skip_ws(t)
    case SCon{'\n', t}:
      skip_ws(t)
    case SCon{'\r', t}:
      skip_ws(t)
    case rest:
      rest

# a fixed word at the head of the input
def expect(word: String, s: String) -> Lex:
  match word s:
    case SNil{} rest:
      LOk{"", rest}
    case SCon{_, _} SNil{}:
      LBad{UnexpectedEnd{}, SNil{}}
    case SCon{+w, wt} SCon{+c, +st}:
      Bool.pick(Lex, Char.is_eq(w, c), expect(wt, st), LBad{UnexpectedChar{c}, SCon{c, st}})

# Strings (RFC 8259 §7)
# ---------------------

# chars so far (reversed) and a pending high surrogate (0 if none)
type SSt is Data:
  SGo{acc: String, hi: U32}
  SStop{reason: Reason, rest: String}

type Surr is Data:
  NotSurr{}
  High{}
  Low{}

def surr(+x: U32) -> Surr:
  Bool.pick(Surr, in_range(x, 55296, 56319), High{},
    Bool.pick(Surr, in_range(x, 56320, 57343), Low{}, NotSurr{}))

def hex_digit(c: Char) -> Maybe<&2, U32>:
  match c:
    case Chr{+x}:
      Bool.pick(Maybe<&2, U32>, in_range(x, 48, 57), Some{U32.sub(x, 48)},
        Bool.pick(Maybe<&2, U32>, in_range(x, 97, 102), Some{U32.sub(x, 87)},
          Bool.pick(Maybe<&2, U32>, in_range(x, 65, 70), Some{U32.sub(x, 55)}, None{})))

def hex4(a: Char, b: Char, c: Char, d: Char) -> Maybe<&2, U32>:
  do Maybe<&2, U32>:
    x : U32 <- hex_digit(a)
    y : U32 <- hex_digit(b)
    z : U32 <- hex_digit(c)
    w : U32 <- hex_digit(d)
    return (x * 4096 + y * 256 + z * 16 + w : U32)

def push(acc: String, x: U32) -> SSt:
  SGo{SCon{Chr{x}, acc}, 0}

def pair(+hi: U32, +lo: U32) -> U32:
  (65536 + (hi - 55296) * 1024 + (lo - 56320) : U32)

def on_code(pending: Bool, k: Surr, acc: String, +hi: U32, +x: U32, here: String) -> SSt:
  match pending k:
    case False{} NotSurr{}:
      push(acc, x)
    case False{} High{}:
      SGo{acc, x}
    case False{} Low{}:
      SStop{LoneSurrogate{}, here}
    case True{} Low{}:
      push(acc, pair(hi, x))
    case True{} _:
      SStop{LoneSurrogate{}, here}

def on_u(acc: String, +hi: U32, code: Maybe<&2, U32>, here: String) -> SSt:
  match code:
    case None{}:
      SStop{InvalidUnicode{}, here}
    case Some{+x}:
      on_code(U32.is_ne(hi, 0), surr(x), acc, hi, x, here)

def unescape(e: Char) -> Maybe<&2, U32>:
  match e:
    case '"':
      Some{34}
    case '\\':
      Some{92}
    case '/':
      Some{47}
    case 'b':
      Some{8}
    case 'f':
      Some{12}
    case 'n':
      Some{10}
    case 'r':
      Some{13}
    case 't':
      Some{9}
    case _:
      None{}

def on_esc.go(pending: Bool, code: Maybe<&2, U32>, acc: String, here: String) -> SSt:
  match pending code:
    case True{} _:
      SStop{LoneSurrogate{}, here}
    case False{} None{}:
      SStop{InvalidEscape{}, here}
    case False{} Some{x}:
      push(acc, x)

def on_esc(acc: String, +hi: U32, e: Char, here: String) -> SSt:
  on_esc.go(U32.is_ne(hi, 0), unescape(e), acc, here)

def on_char.go(pending: Bool, ctrl: Bool, acc: String, c: Char, here: String) -> SSt:
  match pending ctrl:
    case True{} _:
      SStop{LoneSurrogate{}, here}
    case False{} True{}:
      SStop{ControlChar{}, here}
    case False{} False{}:
      SGo{SCon{c, acc}, 0}

def on_char(acc: String, +hi: U32, +c: Char, here: String) -> SSt:
  on_char.go(U32.is_ne(hi, 0), U32.is_lt(Char.to_u32(c), 32), acc, c, here)

def str_close.go(done: Bool, acc: String, +rest: String) -> Lex:
  match done:
    case True{}:
      LOk{String.reverse(acc), rest}
    case False{}:
      LBad{LoneSurrogate{}, SCon{'"', rest}}

def str_close(acc: String, +hi: U32, rest: String) -> Lex:
  str_close.go(U32.is_eq(hi, 0), acc, rest)

# the body of a string, after its opening quote
def lex_str(s: String, st: SSt) -> Lex:
  match s st:
    case _ SStop{r, rest}:
      LBad{r, rest}
    case SNil{} SGo{_, _}:
      LBad{UnexpectedEnd{}, SNil{}}
    case SCon{'"', t} SGo{acc, hi}:
      str_close(acc, hi, t)
    case SCon{'\\', SCon{'u', SCon{+a, SCon{+b, SCon{+c, SCon{+d, +t}}}}}} SGo{acc, hi}:
      here : String = SCon{'\\', SCon{'u', SCon{a, SCon{b, SCon{c, SCon{d, t}}}}}}
      lex_str(t, on_u(acc, hi, hex4(a, b, c, d), here))
    case SCon{'\\', SCon{+e, +t}} SGo{acc, hi}:
      lex_str(t, on_esc(acc, hi, e, SCon{'\\', SCon{e, t}}))
    case SCon{'\\', SNil{}} SGo{_, _}:
      LBad{UnexpectedEnd{}, SNil{}}
    case SCon{+c, +t} SGo{acc, hi}:
      lex_str(t, on_char(acc, hi, c, SCon{c, t}))

# Numbers (RFC 8259 §6)
# ---------------------

# states of: [ minus ] int [ frac ] [ exp ]
type NSt is Data:
  NStart{}
  NMinus{}
  NZero{}
  NInt{}
  NDot{}
  NFrac{}
  NE{}
  NESign{}
  NExp{}
  NStop{}
  NHalt{last: NSt, rest: String}

type CClass is Data:
  CZero{}
  CDigit{}
  CMinus{}
  CPlus{}
  CDot{}
  CE{}
  COther{}

def cclass(c: Char) -> CClass:
  match c:
    case '0':
      CZero{}
    case '-':
      CMinus{}
    case '+':
      CPlus{}
    case '.':
      CDot{}
    case 'e':
      CE{}
    case 'E':
      CE{}
    case +d:
      Bool.pick(CClass, Char.is_digit(d), CDigit{}, COther{})

def num_next(st: NSt, k: CClass) -> NSt:
  match st k:
    case NStart{} CMinus{}:
      NMinus{}
    case NStart{} CZero{}:
      NZero{}
    case NStart{} CDigit{}:
      NInt{}
    case NMinus{} CZero{}:
      NZero{}
    case NMinus{} CDigit{}:
      NInt{}
    case NZero{} CDot{}:
      NDot{}
    case NZero{} CE{}:
      NE{}
    case NInt{} CZero{}:
      NInt{}
    case NInt{} CDigit{}:
      NInt{}
    case NInt{} CDot{}:
      NDot{}
    case NInt{} CE{}:
      NE{}
    case NDot{} CZero{}:
      NFrac{}
    case NDot{} CDigit{}:
      NFrac{}
    case NFrac{} CZero{}:
      NFrac{}
    case NFrac{} CDigit{}:
      NFrac{}
    case NFrac{} CE{}:
      NE{}
    case NE{} CPlus{}:
      NESign{}
    case NE{} CMinus{}:
      NESign{}
    case NE{} CZero{}:
      NExp{}
    case NE{} CDigit{}:
      NExp{}
    case NESign{} CZero{}:
      NExp{}
    case NESign{} CDigit{}:
      NExp{}
    case NExp{} CZero{}:
      NExp{}
    case NExp{} CDigit{}:
      NExp{}
    case _ _:
      NStop{}

def is_stop(st: NSt) -> Bool:
  match st:
    case NStop{}:
      True{}
    case _:
      False{}

def accepts(st: NSt) -> Bool:
  match st:
    case NZero{}:
      True{}
    case NInt{}:
      True{}
    case NFrac{}:
      True{}
    case NExp{}:
      True{}
    case _:
      False{}

def num_end.go(ok: Bool, acc: String, rest: String) -> Lex:
  match ok:
    case True{}:
      LOk{acc, rest}
    case False{}:
      LBad{InvalidNumber{}, rest}

# a char that starts no value at all is reported as itself
def num_end(st: NSt, acc: String, rest: String) -> Lex:
  match st rest:
    case NStart{} SNil{}:
      LBad{UnexpectedEnd{}, SNil{}}
    case NStart{} SCon{+c, t}:
      LBad{UnexpectedChar{c}, SCon{c, t}}
    case +other rest:
      num_end.go(accepts(other), acc, rest)

def halt(stop: Bool, last: NSt, next: NSt, +here: String) -> NSt:
  match stop:
    case True{}:
      NHalt{last, here}
    case False{}:
      next

# the chars of a number, reversed, and the input after it
def lex_num(s: String, +st: NSt, +acc: String) -> Lex:
  match s st:
    case _ NHalt{last, rest}:
      num_end(last, acc, rest)
    case SNil{} _:
      num_end(st, acc, SNil{})
    case SCon{+c, +t} _:
      +n = num_next(st, cclass(c))
      +stop = is_stop(n)
      lex_num(t, halt(stop, st, n, SCon{c, t}), Bool.pick(String, stop, acc, SCon{c, acc}))

# Parsing
# =======

# Bend allows no mutual recursion, so nesting lives on an explicit stack
# and one loop steps a token at a time, like Zig's std.json Scanner

# an open container; items and fields are reversed, key is the pending one
type Frame is Data:
  FArr{items: List<&2, Json>}
  FObj{fields: List<&2, Field>, key: String}

# what the next token may be
type Mode is Data:
  MValue{}
  MValueOrClose{}
  MKeyOrClose{}
  MKey{}
  MColon{}
  MCommaOrClose{}

type St is Data:
  Run{s: String, stack: List<&2, Frame>, mode: Mode}
  Fin{value: Json}
  Bad{reason: Reason, rest: String}

def unexpected(s: String) -> St:
  match s:
    case SNil{}:
      Bad{UnexpectedEnd{}, SNil{}}
    case SCon{+c, t}:
      Bad{UnexpectedChar{c}, SCon{c, t}}

def end(value: Json, rest: String) -> St:
  match rest:
    case SNil{}:
      Fin{value}
    case SCon{c, t}:
      Bad{TrailingInput{}, SCon{c, t}}

# a finished value goes into the container above it
def emit(v: Json, s: String, stack: List<&2, Frame>) -> St:
  match stack:
    case Nil{}:
      end(v, skip_ws(s))
    case Con{FArr{items}, up}:
      Run{s, Con{FArr{Con{v, items}}, up}, MCommaOrClose{}}
    case Con{FObj{fields, key}, up}:
      Run{s, Con{FObj{Con{Field{key, v}, fields}, ""}, up}, MCommaOrClose{}}

def token(~mk: String -> Json, l: Lex, stack: List<&2, Frame>) -> St:
  match l:
    case LOk{text, rest}:
      emit(mk(text), rest, stack)
    case LBad{r, rest}:
      Bad{r, rest}

def mk_str(s: String) -> Json:
  JStr{s}

def mk_num(s: String) -> Json:
  JNum{String.reverse(s)}

def mk_true(s: String) -> Json:
  JBool{True{}}

def mk_false(s: String) -> Json:
  JBool{False{}}

def mk_null(s: String) -> Json:
  JNull{}

def value(s: String, stack: List<&2, Frame>) -> St:
  match s:
    case SCon{'[', t}:
      Run{t, Con{FArr{Nil{}}, stack}, MValueOrClose{}}
    case SCon{'{', t}:
      Run{t, Con{FObj{Nil{}, ""}, stack}, MKeyOrClose{}}
    case SCon{'"', t}:
      token(~mk_str, lex_str(t, SGo{"", 0}), stack)
    case SCon{'t', t}:
      token(~mk_true, expect("rue", t), stack)
    case SCon{'f', t}:
      token(~mk_false, expect("alse", t), stack)
    case SCon{'n', t}:
      token(~mk_null, expect("ull", t), stack)
    case other:
      token(~mk_num, lex_num(other, NStart{}, ""), stack)

def key(l: Lex, stack: List<&2, Frame>) -> St:
  match l stack:
    case LOk{k, rest} Con{FObj{fields, _}, up}:
      Run{rest, Con{FObj{fields, k}, up}, MColon{}}
    case LOk{_, rest} _:
      Bad{Internal{}, rest}
    case LBad{r, rest} _:
      Bad{r, rest}

def close_arr(+t: String, stack: List<&2, Frame>) -> St:
  match stack:
    case Con{FArr{items}, up}:
      emit(JArr{List.reverse(&2, Json, items)}, t, up)
    case _:
      Bad{UnexpectedChar{']'}, SCon{']', t}}

def close_obj(+t: String, stack: List<&2, Frame>) -> St:
  match stack:
    case Con{FObj{fields, _}, up}:
      emit(JObj{List.reverse(&2, Field, fields)}, t, up)
    case _:
      Bad{UnexpectedChar{'}'}, SCon{'}', t}}

def comma(+t: String, stack: List<&2, Frame>) -> St:
  match stack:
    case Con{FArr{items}, up}:
      Run{t, Con{FArr{items}, up}, MValue{}}
    case Con{FObj{fields, k}, up}:
      Run{t, Con{FObj{fields, k}, up}, MKey{}}
    case Nil{}:
      Bad{UnexpectedChar{','}, SCon{',', t}}

def dispatch(mode: Mode, s: String, stack: List<&2, Frame>) -> St:
  match mode:
    case MValue{}:
      value(s, stack)
    case MValueOrClose{}:
      match s:
        case SCon{']', t}:
          close_arr(t, stack)
        case other:
          value(other, stack)
    case MKeyOrClose{}:
      match s:
        case SCon{'}', t}:
          close_obj(t, stack)
        case SCon{'"', t}:
          key(lex_str(t, SGo{"", 0}), stack)
        case other:
          unexpected(other)
    case MKey{}:
      match s:
        case SCon{'"', t}:
          key(lex_str(t, SGo{"", 0}), stack)
        case other:
          unexpected(other)
    case MColon{}:
      match s:
        case SCon{':', t}:
          Run{t, stack, MValue{}}
        case other:
          unexpected(other)
    case MCommaOrClose{}:
      match s:
        case SCon{',', t}:
          comma(t, stack)
        case SCon{']', t}:
          close_arr(t, stack)
        case SCon{'}', t}:
          close_obj(t, stack)
        case other:
          unexpected(other)

# every step eats a token, so the input's length bounds the steps
def loop(fuel: Nat, st: St) -> St:
  match fuel st:
    case 0n Run{_, _, _}:
      Bad{Internal{}, SNil{}}
    case 1n+p Run{s, stack, mode}:
      loop(p, dispatch(mode, skip_ws(s), stack))
    case _ done:
      done

type Loc is Data:
  Loc{line: U32, column: U32}

def locate(n: Nat, s: String, +line: U32, +col: U32) -> Loc:
  match n s:
    case 1n+p SCon{'\n', t}:
      locate(p, t, (line + 1 : U32), 1)
    case 1n+p SCon{_, t}:
      locate(p, t, line, (col + 1 : U32))
    case _ _:
      Loc{line, col}

def error.at(r: Reason, +n: Nat, l: Loc) -> Error:
  match l:
    case Loc{line, col}:
      Error{r, U32.from_nat(n), line, col}

def error(+input: String, r: Reason, rest: String) -> Error:
  +n = Nat.sub(String.length(input), String.length(rest))
  error.at(r, n, locate(n, input, 1, 1))

def finish(+input: String, st: St) -> Result<&2, &2, Error, Json>:
  match st:
    case Fin{v}:
      Done{v}
    case Bad{r, rest}:
      Fail{error(input, r, rest)}
    case Run{_, _, _}:
      Fail{error(input, Internal{}, SNil{})}

# RFC 8259 §8.1: a parser MAY skip a leading byte order mark
def skip_bom(s: String) -> String:
  match s:
    case SCon{'\u{FEFF}', t}:
      t
    case rest:
      rest

# RFC 8259 §2: JSON-text = ws value ws
def parse(+s: String) -> Result<&2, &2, Error, Json>:
  finish(s, loop(1n+String.length(s), Run{skip_bom(s), Nil{}, MValue{}}))

# Printing (RFC 8259 §7, §10)
# ===========================

def hex_char(+x: U32) -> Char:
  Chr{Bool.pick(U32, U32.is_lt(x, 10), (x + 48 : U32), (x + 87 : U32))}

# \u00XX for a control char
def u_esc(+x: U32) -> String:
  "\\u00" ++ SCon{hex_char(U32.div(x, 16)), SCon{hex_char(U32.mod(x, 16)), SNil{}}}

# output is built reversed: put pushes a chunk onto it
def put(chunk: String, out: String) -> String:
  String.reverse.go(chunk, out)

def esc_other(+c: Char, +out: String) -> String:
  +x = Char.to_u32(c)
  Bool.pick(String, U32.is_lt(x, 32), put(u_esc(x), out), SCon{c, out})

def escape(s: String, out: String) -> String:
  match s:
    case SNil{}:
      out
    case SCon{'"', t}:
      escape(t, put("\\\"", out))
    case SCon{'\\', t}:
      escape(t, put("\\\\", out))
    case SCon{'\n', t}:
      escape(t, put("\\n", out))
    case SCon{'\r', t}:
      escape(t, put("\\r", out))
    case SCon{'\t', t}:
      escape(t, put("\\t", out))
    case SCon{'\u{8}', t}:
      escape(t, put("\\b", out))
    case SCon{'\u{C}', t}:
      escape(t, put("\\f", out))
    case SCon{c, t}:
      escape(t, esc_other(c, out))

def quote(s: String, out: String) -> String:
  SCon{'"', escape(s, SCon{'"', out})}

def indent(n: Nat, +unit: String, out: String) -> String:
  match n:
    case 0n:
      out
    case 1n+p:
      indent(p, unit, put(unit, out))

# a line break then the indent of depth n; nothing when compact
def br(pretty: Bool, +unit: String, n: Nat, out: String) -> String:
  match pretty:
    case True{}:
      indent(n, unit, SCon{'\n', out})
    case False{}:
      out

def colon(+pretty: Bool) -> String:
  Bool.pick(String, pretty, ": ", ":")

# printing is a flat task loop, so deep nesting needs no stack
type Task is Data:
  TVal{j: Json, depth: Nat}
  TItems{items: List<&2, Json>, depth: Nat}
  TFields{fields: List<&2, Field>, depth: Nat}

type PSt is Data:
  PRun{todo: List<&2, Task>, out: String, pretty: Bool, unit: String}
  PDone{out: String}

def pstep.val(j: Json, +d: Nat, todo: List<&2, Task>, out: String, +pretty: Bool, +unit: String) -> PSt:
  match j:
    case JNull{}:
      PRun{todo, put("null", out), pretty, unit}
    case JBool{True{}}:
      PRun{todo, put("true", out), pretty, unit}
    case JBool{False{}}:
      PRun{todo, put("false", out), pretty, unit}
    case JNum{text}:
      PRun{todo, put(text, out), pretty, unit}
    case JStr{s}:
      PRun{todo, quote(s, out), pretty, unit}
    case JArr{Nil{}}:
      PRun{todo, put("[]", out), pretty, unit}
    case JArr{Con{h, t}}:
      +o = br(pretty, unit, 1n+d, put("[", out))
      PRun{TVal{h, 1n+d} <> TItems{t, d} <> todo, o, pretty, unit}
    case JObj{Nil{}}:
      PRun{todo, put("{}", out), pretty, unit}
    case JObj{Con{Field{k, v}, t}}:
      +o = put(colon(pretty), quote(k, br(pretty, unit, 1n+d, put("{", out))))
      PRun{TVal{v, 1n+d} <> TFields{t, d} <> todo, o, pretty, unit}

def pstep(st: PSt) -> PSt:
  match st:
    case PDone{o}:
      PDone{o}
    case PRun{Nil{}, out, _, _}:
      PDone{out}
    case PRun{Con{TVal{j, d}, todo}, out, +pretty, +unit}:
      pstep.val(j, d, todo, out, pretty, unit)
    case PRun{Con{TItems{Nil{}, +d}, todo}, out, +pretty, +unit}:
      PRun{todo, put("]", br(pretty, unit, d, out)), pretty, unit}
    case PRun{Con{TItems{Con{h, t}, +d}, todo}, out, +pretty, +unit}:
      +o = br(pretty, unit, 1n+d, put(",", out))
      PRun{TVal{h, 1n+d} <> TItems{t, d} <> todo, o, pretty, unit}
    case PRun{Con{TFields{Nil{}, +d}, todo}, out, +pretty, +unit}:
      PRun{todo, put("}", br(pretty, unit, d, out)), pretty, unit}
    case PRun{Con{TFields{Con{Field{k, v}, t}, +d}, todo}, out, +pretty, +unit}:
      +o = put(colon(pretty), quote(k, br(pretty, unit, 1n+d, put(",", out))))
      PRun{TVal{v, 1n+d} <> TFields{t, d} <> todo, o, pretty, unit}

# up to 2^k steps on k frames of stack: each level runs the one below twice
def drive(+k: Nat, st: PSt) -> PSt:
  match k st:
    case _ PDone{o}:
      PDone{o}
    case 0n run:
      pstep(run)
    case 1n+p run:
      drive(p, drive(p, run))

def output(st: PSt) -> String:
  match st:
    case PDone{out}:
      String.reverse(out)
    case PRun{_, out, _, _}:
      String.reverse(out)

def show(j: Json, pretty: Bool, unit: String) -> String:
  output(drive(64n, PRun{[TVal{j, 0n}], "", pretty, unit}))

def stringify(j: Json) -> String:
  show(j, False{}, "")

# unit is the indent of one level, e.g. "  "
def pretty(j: Json, unit: String) -> String:
  show(j, True{}, unit)

# Building
# ========

def num.go(l: Lex) -> Maybe<&2, Json>:
  match l:
    case LOk{text, SNil{}}:
      Some{mk_num(text)}
    case _:
      None{}

# a number from its text, if the text is a JSON number
def num(s: String) -> Maybe<&2, Json>:
  num.go(lex_num(s, NStart{}, ""))

def num_u32(x: U32) -> Json:
  JNum{U32.show(x)}

# None for inf and nan
def num_f32(x: F32) -> Maybe<&2, Json>:
  num(F32.show(x))

# Reading
# =======

def is_null(j: Json) -> Bool:
  match j:
    case JNull{}:
      True{}
    case _:
      False{}

def as_bool(j: Json) -> Maybe<&2, Bool>:
  match j:
    case JBool{b}:
      Some{b}
    case _:
      None{}

def as_str(j: Json) -> Maybe<&2, String>:
  match j:
    case JStr{s}:
      Some{s}
    case _:
      None{}

def as_f32(j: Json) -> Maybe<&2, F32>:
  match j:
    case JNum{text}:
      F32.read(text)
    case _:
      None{}

# None unless the number is a whole number in U32 range
def as_u32(j: Json) -> Maybe<&2, U32>:
  match j:
    case JNum{text}:
      U32.read(text)
    case _:
      None{}

def as_list(j: Json) -> Maybe<&2, List<&2, Json>>:
  match j:
    case JArr{items}:
      Some{items}
    case _:
      None{}

def as_fields(j: Json) -> Maybe<&2, List<&2, Field>>:
  match j:
    case JObj{fields}:
      Some{fields}
    case _:
      None{}

def at.go(xs: List<&2, Json>, n: Nat) -> Maybe<&2, Json>:
  match xs n:
    case Con{h, _} 0n:
      Some{h}
    case Con{_, t} 1n+p:
      at.go(t, p)
    case Nil{} _:
      None{}

# the item at index n of an array
def at(j: Json, n: Nat) -> Maybe<&2, Json>:
  match j:
    case JArr{items}:
      at.go(items, n)
    case _:
      None{}

def get.go(fields: List<&2, Field>, +k: String, found: Maybe<&2, Json>) -> Maybe<&2, Json>:
  match fields:
    case Nil{}:
      found
    case Con{Field{+fk, v}, t}:
      get.go(t, k, Bool.pick(Maybe<&2, Json>, String.eq(fk, k), Some{v}, found))

# the value of key k in an object; the last one wins on duplicates
def get(j: Json, k: String) -> Maybe<&2, Json>:
  match j:
    case JObj{fields}:
      get.go(fields, k, None{})
    case _:
      None{}

# Errors
# ======

def reason(r: Reason) -> String:
  match r:
    case UnexpectedEnd{}:
      "unexpected end of input"
    case UnexpectedChar{c}:
      "unexpected " ++ String.reverse(quote(SCon{c, SNil{}}, ""))
    case TrailingInput{}:
      "unexpected input after the value"
    case InvalidNumber{}:
      "invalid number"
    case InvalidEscape{}:
      "invalid escape"
    case InvalidUnicode{}:
      "invalid \\u escape"
    case LoneSurrogate{}:
      "unpaired UTF-16 surrogate"
    case ControlChar{}:
      "unescaped control character in string"
    case Internal{}:
      "internal parser error"

# e.g. "3:5: unexpected ','"
def message(e: Error) -> String:
  match e:
    case Error{r, _, line, col}:
      U32.show(line) ++ ":" ++ U32.show(col) ++ ": " ++ reason(r)
