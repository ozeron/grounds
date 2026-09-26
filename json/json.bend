import Base
import ../utf8/utf8.bend as U

# Model
# =====

type Json is Data:
  JNull{}
  JBool{value: Bool}
  JNum{value: Number}
  JStr{value: String}
  JArr{items: List<&2, Json>}
  JObj{fields: List<&2, Field>}

type Field is Data:
  Field{key: String, value: Json}

# a JSON number exactly as written (RFC 8259 §6): -12.50e+3 is
# Number{True{}, INon{L1, [D2]}, FSome{D5, [D0]}, ESome{False{}, Plus{}, D3, []}}
# any value of this type prints as a valid number

type Digit is Data:
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

# a leading digit: never 0
type Lead is Data:
  L1{}
  L2{}
  L3{}
  L4{}
  L5{}
  L6{}
  L7{}
  L8{}
  L9{}

type Int is Data:
  IZero{}
  INon{lead: Lead, rest: List<&2, Digit>}

type Frac is Data:
  FNone{}
  FSome{first: Digit, rest: List<&2, Digit>}

type Sign is Data:
  NoSign{}
  Plus{}
  Minus{}

type Exp is Data:
  ENone{}
  ESome{upper: Bool, sign: Sign, first: Digit, rest: List<&2, Digit>}

type Number is Data:
  Number{neg: Bool, int: Int, frac: Frac, exp: Exp}

type Reason is Data:
  UnexpectedEnd{}
  UnexpectedChar{char: Char}
  TrailingInput{}
  InvalidNumber{}
  InvalidEscape{}
  InvalidUnicode{}
  LoneSurrogate{}
  ControlChar{}
  InvalidUtf8{}
  Internal{}

# offset counts chars from 0; line and column count from 1
type Error is Data:
  Error{reason: Reason, offset: U32, line: U32, column: U32}

# Lexing
# ======

# a lexed string and the input after it, or why lexing stopped and how
# many chars were left from where it went wrong. Errors count, not keep
# the input: keeping a String that is still being read shares it, and
# sharing any String counts references on every String in the program
type Lex is Data:
  LOk{text: String, rest: String}
  LBad{reason: Reason, left: U32}

# the length of s, plus n
def size(s: String, +n: U32) -> U32:
  match s:
    case SNil{}:
      n
    case SCon{_, t}:
      size(t, (n + 1 : U32))

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

# whether the next chars of the word and the input agree
def heads_eq(word: String, s: String) -> Bool:
  match word s:
    case SCon{w, _} SCon{c, _}:
      Char.is_eq(w, c)
    case _ _:
      True{}

# a fixed word at the head of the input; same is heads_eq(word, s), tested
# before, since picking between both results would share the input
def expect.go(+word: String, +s: String, same: Bool) -> Lex:
  match word s same:
    case SNil{} rest _:
      LOk{"", rest}
    case SCon{_, _} SNil{} _:
      LBad{UnexpectedEnd{}, 0}
    case SCon{_, wt} SCon{_, st} True{}:
      expect.go(wt, st, heads_eq(wt, st))
    case SCon{_, _} SCon{c, st} False{}:
      LBad{UnexpectedChar{c}, size(st, 1)}

def expect(+word: String, +s: String) -> Lex:
  expect.go(word, s, heads_eq(word, s))

# Strings (RFC 8259 §7)
# ---------------------

# how a char inside a string is treated; the printer and the lexer both
# decide through this one function, which is what lets PROOF.bend show
# that they agree
type Class is Data:
  KCtrl{}
  KQuote{}
  KBack{}
  KPlain{}

def class.go(ctrl: Bool, +x: U32) -> Class:
  match ctrl:
    case True{}:
      KCtrl{}
    case False{}:
      Bool.pick(Class, U32.is_eq(x, 34), KQuote{},
        Bool.pick(Class, U32.is_eq(x, 92), KBack{}, KPlain{}))

# U+0000 to U+001F are control chars
def class(+c: Char) -> Class:
  +x = Char.to_u32(c)
  class.go(U32.is_lt(x, 32), x)

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

# inside a string: chars so far (reversed) and a pending high surrogate
# (0 if none). back counts the chars of an escape read before this one;
# SStop's back counts from where it went wrong through this char, and the
# lexer reads the input left once it has taken this char
type SSt is Data:
  SGo{acc: String, hi: U32}
  SEsc{acc: String, hi: U32}
  SHex{acc: String, hi: U32, left: Nat, code: U32, back: U32}
  SStop{reason: Reason, back: U32}
  SDone{value: String}

def pair(+hi: U32, +lo: U32) -> U32:
  (65536 + (hi - 55296) * 1024 + (lo - 56320) : U32)

def push(acc: String, x: U32) -> SSt:
  SGo{SCon{Chr{x}, acc}, 0}

def on_code(pending: Bool, k: Surr, acc: String, +hi: U32, +x: U32, back: U32) -> SSt:
  match pending k:
    case False{} NotSurr{}:
      push(acc, x)
    case False{} High{}:
      SGo{acc, x}
    case False{} Low{}:
      SStop{LoneSurrogate{}, back}
    case True{} Low{}:
      push(acc, pair(hi, x))
    case True{} _:
      SStop{LoneSurrogate{}, back}

def code(acc: String, +hi: U32, +x: U32, back: U32) -> SSt:
  on_code(U32.is_ne(hi, 0), surr(x), acc, hi, x, back)

# a char taken as is after a backslash
def keep.go(pending: Bool, acc: String, c: Char) -> SSt:
  match pending:
    case True{}:
      SStop{LoneSurrogate{}, 2}
    case False{}:
      SGo{SCon{c, acc}, 0}

def keep(acc: String, +hi: U32, c: Char) -> SSt:
  keep.go(U32.is_ne(hi, 0), acc, c)

def close.go(pending: Bool, acc: String) -> SSt:
  match pending:
    case True{}:
      SStop{LoneSurrogate{}, 1}
    case False{}:
      SDone{String.reverse(acc)}

def close(acc: String, +hi: U32) -> SSt:
  close.go(U32.is_ne(hi, 0), acc)

def unescape(e: Char) -> Maybe<&2, U32>:
  match e:
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

def letter.go(m: Maybe<&2, U32>, acc: String, +hi: U32) -> SSt:
  match m:
    case Some{x}:
      code(acc, hi, x, 2)
    case None{}:
      SStop{InvalidEscape{}, 2}

# the letter after a backslash
def letter(+c: Char, acc: String, +hi: U32) -> SSt:
  match c:
    case 'u':
      SHex{acc, hi, 4n, 0, 2}
    case other:
      letter.go(unescape(other), acc, hi)

def plain.go(pending: Bool, acc: String, +c: Char) -> SSt:
  match pending:
    case True{}:
      SStop{LoneSurrogate{}, 1}
    case False{}:
      SGo{SCon{c, acc}, 0}

def s_go(k: Class, +c: Char, acc: String, +hi: U32) -> SSt:
  match k:
    case KQuote{}:
      close(acc, hi)
    case KBack{}:
      SEsc{acc, hi}
    case KCtrl{}:
      SStop{ControlChar{}, 1}
    case KPlain{}:
      plain.go(U32.is_ne(hi, 0), acc, c)

def s_esc(k: Class, +c: Char, acc: String, +hi: U32) -> SSt:
  match k:
    case KQuote{}:
      keep(acc, hi, c)
    case KBack{}:
      keep(acc, hi, c)
    case KCtrl{}:
      SStop{InvalidEscape{}, 2}
    case KPlain{}:
      letter(c, acc, hi)

def s_hex.go(left: Nat, d: Maybe<&2, U32>, acc: String, +hi: U32, +x: U32, back: U32) -> SSt:
  match left d:
    case _ None{}:
      SStop{InvalidUnicode{}, (back + 1 : U32)}
    case 0n Some{_}:
      SStop{Internal{}, 1}
    case 1n Some{v}:
      code(acc, hi, (x * 16 + v : U32), (back + 1 : U32))
    case 2n+p Some{v}:
      SHex{acc, hi, 1n+p, (x * 16 + v : U32), (back + 1 : U32)}

# one char of a string body
def s_step(st: SSt, +c: Char) -> SSt:
  match st:
    case SGo{acc, hi}:
      s_go(class(c), c, acc, hi)
    case SEsc{acc, hi}:
      s_esc(class(c), c, acc, hi)
    case SHex{acc, hi, left, x, back}:
      s_hex.go(left, hex_digit(c), acc, hi, x, back)
    case done:
      done

# the body of a string, after its opening quote. A step never sees the
# input after its char: the closing quote and errors take effect one call
# later, where that input is the one being read
def lex_str(s: String, st: SSt) -> Lex:
  match s st:
    case _ SStop{r, back}:
      LBad{r, size(s, back)}
    case _ SDone{v}:
      LOk{v, s}
    case SNil{} _:
      LBad{UnexpectedEnd{}, 0}
    case SCon{+c, t} going:
      lex_str(t, s_step(going, c))

# Numbers (RFC 8259 §6)
# ---------------------

# what a char can be inside a number
type NC is Data:
  CDig{d: Digit}
  CMinus{}
  CPlus{}
  CDot{}
  CExpE{upper: Bool}
  COther{}

def nclass(c: Char) -> NC:
  match c:
    case '0':
      CDig{D0{}}
    case '1':
      CDig{D1{}}
    case '2':
      CDig{D2{}}
    case '3':
      CDig{D3{}}
    case '4':
      CDig{D4{}}
    case '5':
      CDig{D5{}}
    case '6':
      CDig{D6{}}
    case '7':
      CDig{D7{}}
    case '8':
      CDig{D8{}}
    case '9':
      CDig{D9{}}
    case '-':
      CMinus{}
    case '+':
      CPlus{}
    case '.':
      CDot{}
    case 'e':
      CExpE{False{}}
    case 'E':
      CExpE{True{}}
    case _:
      COther{}

# states of [ minus ] int [ frac ] [ exp ]; digit lists are reversed
type NSt is Data:
  NStart{}
  NMin{}
  NZero{neg: Bool}
  NInt{neg: Bool, lead: Lead, ds: List<&2, Digit>}
  NDot{neg: Bool, int: Int}
  NFrac{neg: Bool, int: Int, first: Digit, ds: List<&2, Digit>}
  NE{neg: Bool, int: Int, frac: Frac, upper: Bool}
  NESign{neg: Bool, int: Int, frac: Frac, upper: Bool, sign: Sign}
  NExp{neg: Bool, int: Int, frac: Frac, upper: Bool, sign: Sign, first: Digit, ds: List<&2, Digit>}
  NHalt{last: NSt, next: Char}

def rev(ds: List<&2, Digit>) -> List<&2, Digit>:
  List.reverse(&2, Digit, ds)

def first_digit(neg: Bool, d: Digit) -> NSt:
  match d:
    case D0{}:
      NZero{neg}
    case D1{}:
      NInt{neg, L1{}, []}
    case D2{}:
      NInt{neg, L2{}, []}
    case D3{}:
      NInt{neg, L3{}, []}
    case D4{}:
      NInt{neg, L4{}, []}
    case D5{}:
      NInt{neg, L5{}, []}
    case D6{}:
      NInt{neg, L6{}, []}
    case D7{}:
      NInt{neg, L7{}, []}
    case D8{}:
      NInt{neg, L8{}, []}
    case D9{}:
      NInt{neg, L9{}, []}

# one char of a number; a char the number cannot take ends it, and the
# lexer resumes from it
def num_step(st: NSt, k: NC, c: Char) -> NSt:
  match st k:
    case NStart{} CMinus{}:
      NMin{}
    case NStart{} CDig{d}:
      first_digit(False{}, d)
    case NMin{} CDig{d}:
      first_digit(True{}, d)
    case NZero{neg} CDot{}:
      NDot{neg, IZero{}}
    case NZero{neg} CExpE{u}:
      NE{neg, IZero{}, FNone{}, u}
    case NInt{neg, l, ds} CDig{d}:
      NInt{neg, l, Con{d, ds}}
    case NInt{neg, l, ds} CDot{}:
      NDot{neg, INon{l, rev(ds)}}
    case NInt{neg, l, ds} CExpE{u}:
      NE{neg, INon{l, rev(ds)}, FNone{}, u}
    case NDot{neg, i} CDig{d}:
      NFrac{neg, i, d, []}
    case NFrac{neg, i, f, ds} CDig{d}:
      NFrac{neg, i, f, Con{d, ds}}
    case NFrac{neg, i, f, ds} CExpE{u}:
      NE{neg, i, FSome{f, rev(ds)}, u}
    case NE{neg, i, fr, u} CPlus{}:
      NESign{neg, i, fr, u, Plus{}}
    case NE{neg, i, fr, u} CMinus{}:
      NESign{neg, i, fr, u, Minus{}}
    case NE{neg, i, fr, u} CDig{d}:
      NExp{neg, i, fr, u, NoSign{}, d, []}
    case NESign{neg, i, fr, u, sg} CDig{d}:
      NExp{neg, i, fr, u, sg, d, []}
    case NExp{neg, i, fr, u, sg, f, ds} CDig{d}:
      NExp{neg, i, fr, u, sg, f, Con{d, ds}}
    case last _:
      NHalt{last, c}

# a lexed number and the input after it
type NLex is Data:
  NOk{value: Number, rest: String}
  NBad{reason: Reason, left: U32}

# a char that starts no value at all is reported as itself
def num_end(st: NSt, rest: String) -> NLex:
  match st rest:
    case NZero{neg} _:
      NOk{Number{neg, IZero{}, FNone{}, ENone{}}, rest}
    case NInt{neg, l, ds} _:
      NOk{Number{neg, INon{l, rev(ds)}, FNone{}, ENone{}}, rest}
    case NFrac{neg, i, f, ds} _:
      NOk{Number{neg, i, FSome{f, rev(ds)}, ENone{}}, rest}
    case NExp{neg, i, fr, u, sg, f, ds} _:
      NOk{Number{neg, i, fr, ESome{u, sg, f, rev(ds)}}, rest}
    case NStart{} SNil{}:
      NBad{UnexpectedEnd{}, 0}
    case NStart{} SCon{c, t}:
      NBad{UnexpectedChar{c}, size(t, 1)}
    case _ _:
      NBad{InvalidNumber{}, size(rest, 0)}

# a step never sees the input after its char, so where the number ends
# takes effect one call later
def lex_num(s: String, st: NSt) -> NLex:
  match s st:
    case _ NHalt{last, c}:
      num_end(last, SCon{c, s})
    case SNil{} last:
      num_end(last, SNil{})
    case SCon{+c, t} going:
      lex_num(t, num_step(going, nclass(c), c))

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
  Bad{reason: Reason, left: U32}

def unexpected(s: String) -> St:
  match s:
    case SNil{}:
      Bad{UnexpectedEnd{}, 0}
    case SCon{c, t}:
      Bad{UnexpectedChar{c}, size(t, 1)}

def end(value: Json, rest: String) -> St:
  match rest:
    case SNil{}:
      Fin{value}
    case SCon{c, t}:
      Bad{TrailingInput{}, size(t, 1)}

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
    case LBad{r, left}:
      Bad{r, left}

def num_token(l: NLex, stack: List<&2, Frame>) -> St:
  match l:
    case NOk{n, rest}:
      emit(JNum{n}, rest, stack)
    case NBad{r, left}:
      Bad{r, left}

def mk_str(s: String) -> Json:
  JStr{s}

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
      num_token(lex_num(other, NStart{}), stack)

def key(l: Lex, stack: List<&2, Frame>) -> St:
  match l stack:
    case LOk{k, rest} Con{FObj{fields, _}, up}:
      Run{rest, Con{FObj{fields, k}, up}, MColon{}}
    case LOk{_, rest} _:
      Bad{Internal{}, size(rest, 0)}
    case LBad{r, left} _:
      Bad{r, left}

def close_arr(t: String, stack: List<&2, Frame>) -> St:
  match stack:
    case Con{FArr{items}, up}:
      emit(JArr{List.reverse(&2, Json, items)}, t, up)
    case _:
      Bad{UnexpectedChar{']'}, size(t, 1)}

def close_obj(t: String, stack: List<&2, Frame>) -> St:
  match stack:
    case Con{FObj{fields, _}, up}:
      emit(JObj{List.reverse(&2, Field, fields)}, t, up)
    case _:
      Bad{UnexpectedChar{'}'}, size(t, 1)}

def comma(t: String, stack: List<&2, Frame>) -> St:
  match stack:
    case Con{FArr{items}, up}:
      Run{t, Con{FArr{items}, up}, MValue{}}
    case Con{FObj{fields, k}, up}:
      Run{t, Con{FObj{fields, k}, up}, MKey{}}
    case Nil{}:
      Bad{UnexpectedChar{','}, size(t, 1)}

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
    case 1n+p Run{s, stack, mode}:
      loop(p, dispatch(mode, skip_ws(s), stack))
    case _ other:
      other

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

def position.go(r: Reason, +offset: U32, l: Loc) -> Error:
  match l:
    case Loc{line, col}:
      Error{r, offset, line, col}

# what an error needs to know of the input, which is gone by then: its
# size, and where its line breaks are (last first)
type Lines is Data:
  Lines{size: U32, breaks: List<&2, U32>}

def lines(s: String, +at: U32, bs: List<&2, U32>) -> Lines:
  match s:
    case SNil{}:
      Lines{at, bs}
    case SCon{'\n', t}:
      lines(t, (at + 1 : U32), Con{at, bs})
    case SCon{_, t}:
      lines(t, (at + 1 : U32), bs)

# the line and column of offset at: one line per break before it, and the
# column counts from the last of them (m is one past it, 0 if none)
def line_col(bs: List<&2, U32>, +at: U32, +line: U32, +m: U32) -> Loc:
  match bs:
    case Nil{}:
      Loc{line, (at + 1 - m : U32)}
    case Con{+b, t}:
      +hit = Bool.to_u32(U32.is_lt(b, at))
      line_col(t, at, (line + hit : U32), U32.max(m, (hit * (b + 1) : U32)))

def error(ls: Lines, r: Reason, left: U32) -> Error:
  match ls:
    case Lines{+n, bs}:
      +at = (n - left : U32)
      position.go(r, at, line_col(bs, at, 1, 0))

def finish(ls: Lines, st: St) -> Result<&2, &2, Error, Json>:
  match st:
    case Fin{v}:
      Done{v}
    case Bad{r, left}:
      Fail{error(ls, r, left)}
    case Run{_, _, _}:
      Fail{error(ls, Internal{}, 0)}

# RFC 8259 §8.1: a parser MAY skip a leading byte order mark
def skip_bom(s: String) -> String:
  match s:
    case SCon{'\u{FEFF}', t}:
      t
    case rest:
      rest

# RFC 8259 §2: JSON-text = ws value ws
def parse(+s: String) -> Result<&2, &2, Error, Json>:
  finish(lines(s, 0, []), loop(1n+String.length(s), Run{skip_bom(s), Nil{}, MValue{}}))

# Bytes (RFC 8259 §8.1)
# =====================

def bad_utf8(+at: U32, +before: String) -> Error:
  Error{InvalidUtf8{}, at, U.back_line(before, 1), U.back_col(before, 1)}

def parse_text(t: U.Text) -> Result<&2, &2, Error, Json>:
  match t:
    case U.TOk{text}:
      parse(text)
    case U.TBad{at, before}:
      Fail{bad_utf8(at, before)}

# provisional: parse raw bytes (0..255), which must be UTF-8
def parse_bytes(bs: List<&2, U32>) -> Result<&2, &2, Error, Json>:
  parse_text(U.decode(bs))

# Printing (RFC 8259 §7, §10)
# ===========================

# forward text: each function writes its part in front of k

def digit_char(d: Digit) -> Char:
  match d:
    case D0{}:
      '0'
    case D1{}:
      '1'
    case D2{}:
      '2'
    case D3{}:
      '3'
    case D4{}:
      '4'
    case D5{}:
      '5'
    case D6{}:
      '6'
    case D7{}:
      '7'
    case D8{}:
      '8'
    case D9{}:
      '9'

def lead_char(l: Lead) -> Char:
  match l:
    case L1{}:
      '1'
    case L2{}:
      '2'
    case L3{}:
      '3'
    case L4{}:
      '4'
    case L5{}:
      '5'
    case L6{}:
      '6'
    case L7{}:
      '7'
    case L8{}:
      '8'
    case L9{}:
      '9'

def digits_k(ds: List<&2, Digit>, k: String) -> String:
  match ds:
    case Nil{}:
      k
    case Con{d, t}:
      SCon{digit_char(d), digits_k(t, k)}

def int_k(i: Int, k: String) -> String:
  match i:
    case IZero{}:
      SCon{'0', k}
    case INon{l, ds}:
      SCon{lead_char(l), digits_k(ds, k)}

def frac_k(f: Frac, k: String) -> String:
  match f:
    case FNone{}:
      k
    case FSome{d, ds}:
      SCon{'.', SCon{digit_char(d), digits_k(ds, k)}}

def sign_k(s: Sign, k: String) -> String:
  match s:
    case NoSign{}:
      k
    case Plus{}:
      SCon{'+', k}
    case Minus{}:
      SCon{'-', k}

def exp_k(e: Exp, k: String) -> String:
  match e:
    case ENone{}:
      k
    case ESome{u, s, d, ds}:
      SCon{Bool.pick(Char, u, 'E', 'e'), sign_k(s, SCon{digit_char(d), digits_k(ds, k)})}

def neg_k(neg: Bool, k: String) -> String:
  match neg:
    case True{}:
      SCon{'-', k}
    case False{}:
      k

def num_k(n: Number, k: String) -> String:
  match n:
    case Number{neg, i, f, e}:
      neg_k(neg, int_k(i, frac_k(f, exp_k(e, k))))

# the same text, pushed onto a reversed output: a tail call per digit
def digits_out(ds: List<&2, Digit>, out: String) -> String:
  match ds:
    case Nil{}:
      out
    case Con{d, t}:
      digits_out(t, SCon{digit_char(d), out})

def int_out(i: Int, out: String) -> String:
  match i:
    case IZero{}:
      SCon{'0', out}
    case INon{l, ds}:
      digits_out(ds, SCon{lead_char(l), out})

def frac_out(f: Frac, out: String) -> String:
  match f:
    case FNone{}:
      out
    case FSome{d, ds}:
      digits_out(ds, SCon{digit_char(d), SCon{'.', out}})

def sign_out(s: Sign, out: String) -> String:
  match s:
    case NoSign{}:
      out
    case Plus{}:
      SCon{'+', out}
    case Minus{}:
      SCon{'-', out}

def exp_out(e: Exp, out: String) -> String:
  match e:
    case ENone{}:
      out
    case ESome{u, s, d, ds}:
      digits_out(ds, SCon{digit_char(d), sign_out(s, SCon{Bool.pick(Char, u, 'E', 'e'), out})})

def neg_out(neg: Bool, out: String) -> String:
  match neg:
    case True{}:
      SCon{'-', out}
    case False{}:
      out

def num_out(n: Number, out: String) -> String:
  match n:
    case Number{neg, i, f, e}:
      exp_out(e, frac_out(f, int_out(i, neg_out(neg, out))))

def num_text(n: Number) -> String:
  String.reverse(num_out(n, ""))

def hex_char(+x: U32) -> Char:
  Chr{Bool.pick(U32, U32.is_lt(x, 10), (x + 48 : U32), (x + 87 : U32))}

# the escape of a control char
def ctrl_text(+c: Char) -> String:
  match c:
    case '\u{8}':
      "\\b"
    case '\u{C}':
      "\\f"
    case '\n':
      "\\n"
    case '\r':
      "\\r"
    case '\t':
      "\\t"
    case other:
      +x = Char.to_u32(other)
      "\\u00" ++ SCon{hex_char(U32.div(x, 16)), SCon{hex_char(U32.mod(x, 16)), SNil{}}}

# output is built reversed: put pushes a chunk onto it
def put(chunk: String, out: String) -> String:
  String.reverse.go(chunk, out)

def esc_char(k: Class, +c: Char, out: String) -> String:
  match k:
    case KQuote{}:
      SCon{c, SCon{'\\', out}}
    case KBack{}:
      SCon{c, SCon{'\\', out}}
    case KCtrl{}:
      put(ctrl_text(c), out)
    case KPlain{}:
      SCon{c, out}

def escape(s: String, out: String) -> String:
  match s:
    case SNil{}:
      out
    case SCon{+c, t}:
      escape(t, esc_char(class(c), c, out))

def quote(s: String, out: String) -> String:
  SCon{'"', escape(s, SCon{'"', out})}

# put, for a chunk used again: it pushes new chars, so the chunk is only
# read and never shared (sharing any String counts references on all)
def put_copy(chunk: String, out: String) -> String:
  match chunk:
    case SNil{}:
      out
    case SCon{Chr{x}, t}:
      put_copy(t, SCon{Chr{x}, out})

def indent(n: Nat, +unit: String, out: String) -> String:
  match n:
    case 0n:
      out
    case 1n+p:
      indent(p, unit, put_copy(unit, out))

# a line break then the indent of depth n; nothing when compact
def br(pretty: Bool, +unit: String, n: Nat, out: String) -> String:
  match pretty:
    case True{}:
      indent(n, unit, SCon{'\n', out})
    case False{}:
      out

def colon(pretty: Bool, out: String) -> String:
  match pretty:
    case True{}:
      SCon{' ', SCon{':', out}}
    case False{}:
      SCon{':', out}

def opener(more: Bool, c: Char, out: String) -> String:
  match more:
    case True{}:
      SCon{',', out}
    case False{}:
      SCon{c, out}

# more: j is the tail of a container that already printed its first item;
# items are tail calls, so only nesting grows the stack
def show(j: Json, +more: Bool, +pretty: Bool, +unit: String, +d: Nat, out: String) -> String:
  match j:
    case JNull{}:
      put("null", out)
    case JBool{True{}}:
      put("true", out)
    case JBool{False{}}:
      put("false", out)
    case JNum{n}:
      num_out(n, out)
    case JStr{s}:
      quote(s, out)
    case JArr{Nil{}}:
      match more:
        case True{}:
          SCon{']', br(pretty, unit, d, out)}
        case False{}:
          SCon{']', SCon{'[', out}}
    case JArr{Con{h, t}}:
      show(JArr{t}, True{}, pretty, unit, d,
        show(h, False{}, pretty, unit, 1n+d, br(pretty, unit, 1n+d, opener(more, '[', out))))
    case JObj{Nil{}}:
      match more:
        case True{}:
          SCon{'}', br(pretty, unit, d, out)}
        case False{}:
          SCon{'}', SCon{'{', out}}
    case JObj{Con{Field{k, v}, t}}:
      show(JObj{t}, True{}, pretty, unit, d,
        show(v, False{}, pretty, unit, 1n+d,
          colon(pretty, quote(k, br(pretty, unit, 1n+d, opener(more, '{', out))))))

# show, one value at a time off an explicit stack, so nesting costs no
# machine stack. Each item is a value still to print, with show's more and
# depth. fuel only satisfies the termination check: it allows 2^32 - 1
# values, and should it run out, show finishes the job, so the loop always
# writes what show writes (proof/print.bend)
type Item is Data:
  Item{value: Json, more: Bool, depth: Nat}

def show_all(items: List<&2, Item>, +pretty: Bool, +unit: String, out: String) -> String:
  match items:
    case Nil{}:
      out
    case Con{Item{j, more, d}, up}:
      show_all(up, pretty, unit, show(j, more, pretty, unit, d, out))

def print_loop(fuel: Nat, items: List<&2, Item>, +pretty: Bool, +unit: String, out: String) -> String:
  match fuel items:
    case _ Nil{}:
      out
    case 0n rest:
      show_all(rest, pretty, unit, out)
    case 1n+p Con{Item{JNull{}, _, _}, up}:
      print_loop(p, up, pretty, unit, put("null", out))
    case 1n+p Con{Item{JBool{True{}}, _, _}, up}:
      print_loop(p, up, pretty, unit, put("true", out))
    case 1n+p Con{Item{JBool{False{}}, _, _}, up}:
      print_loop(p, up, pretty, unit, put("false", out))
    case 1n+p Con{Item{JNum{n}, _, _}, up}:
      print_loop(p, up, pretty, unit, num_out(n, out))
    case 1n+p Con{Item{JStr{x}, _, _}, up}:
      print_loop(p, up, pretty, unit, quote(x, out))
    case 1n+p Con{Item{JArr{Nil{}}, True{}, +d}, up}:
      print_loop(p, up, pretty, unit, SCon{']', br(pretty, unit, d, out)})
    case 1n+p Con{Item{JArr{Nil{}}, False{}, _}, up}:
      print_loop(p, up, pretty, unit, SCon{']', SCon{'[', out}})
    case 1n+p Con{Item{JArr{Con{h, t}}, more, +d}, up}:
      print_loop(p, Con{Item{h, False{}, 1n+d}, Con{Item{JArr{t}, True{}, d}, up}}, pretty, unit,
        br(pretty, unit, 1n+d, opener(more, '[', out)))
    case 1n+p Con{Item{JObj{Nil{}}, True{}, +d}, up}:
      print_loop(p, up, pretty, unit, SCon{'}', br(pretty, unit, d, out)})
    case 1n+p Con{Item{JObj{Nil{}}, False{}, _}, up}:
      print_loop(p, up, pretty, unit, SCon{'}', SCon{'{', out}})
    case 1n+p Con{Item{JObj{Con{Field{k, v}, t}}, more, +d}, up}:
      print_loop(p, Con{Item{v, False{}, 1n+d}, Con{Item{JObj{t}, True{}, d}, up}}, pretty, unit,
        colon(pretty, quote(k, br(pretty, unit, 1n+d, opener(more, '{', out)))))

def print_fuel() -> Nat:
  4294967295n

def encode(j: Json) -> String:
  String.reverse(print_loop(print_fuel(), [Item{j, False{}, 0n}], False{}, "", ""))

# unit is the indent of one level, e.g. "  "
def pretty(j: Json, unit: String) -> String:
  String.reverse(print_loop(print_fuel(), [Item{j, False{}, 0n}], True{}, unit, ""))

# Building
# ========

def num.go(l: NLex) -> Maybe<&2, Json>:
  match l:
    case NOk{n, SNil{}}:
      Some{JNum{n}}
    case _:
      None{}

# a number from its text, if the text is a JSON number
def num(s: String) -> Maybe<&2, Json>:
  num.go(lex_num(s, NStart{}))

def num_u32.go(m: Maybe<&2, Json>) -> Json:
  match m:
    case Some{j}:
      j
    case None{}:
      JNull{}

def num_u32(x: U32) -> Json:
  num_u32.go(num(U32.show(x)))

# None for inf and nan
def num_f32(x: F32) -> Maybe<&2, Json>:
  num(F32.show(x))

# Reading
# =======

def is_ok(r: Result<&2, &2, Error, Json>) -> Bool:
  match r:
    case Done{_}:
      True{}
    case Fail{_}:
      False{}

def is_null(j: Json) -> Bool:
  match j:
    case JNull{}:
      True{}
    case _:
      False{}

# Access (level A of docs/API.md)
# ------

type JKind is Data:
  KNull{}
  KBool{}
  KNumber{}
  KString{}
  KArray{}
  KObject{}

# a step into a value: an object's key or an array's index
type Step is Data:
  Name{key: String}
  Index{i: U32}

# why a read failed, and where: the path from the root, first step first
type Access is Data:
  Missing{path: List<&2, Step>}
  Expected{path: List<&2, Step>, want: JKind, got: JKind}
  OutOfRange{path: List<&2, Step>}

def kind(j: Json) -> JKind:
  match j:
    case JNull{}:
      KNull{}
    case JBool{_}:
      KBool{}
    case JNum{_}:
      KNumber{}
    case JStr{_}:
      KString{}
    case JArr{_}:
      KArray{}
    case JObj{_}:
      KObject{}

def expected(want: JKind, j: Json) -> Access:
  Expected{[], want, kind(j)}

def string(j: Json) -> Result<&2, &2, Access, String>:
  match j:
    case JStr{s}:
      Done{s}
    case other:
      Fail{expected(KString{}, other)}

def bool(j: Json) -> Result<&2, &2, Access, Bool>:
  match j:
    case JBool{b}:
      Done{b}
    case other:
      Fail{expected(KBool{}, other)}

# the number exactly as written, for what u32 and f32 cannot hold
def number(j: Json) -> Result<&2, &2, Access, Number>:
  match j:
    case JNum{n}:
      Done{n}
    case other:
      Fail{expected(KNumber{}, other)}

# the items, in order
def array(j: Json) -> Result<&2, &2, Access, List<&2, Json>>:
  match j:
    case JArr{xs}:
      Done{xs}
    case other:
      Fail{expected(KArray{}, other)}

# the fields, in order, duplicates kept
def object(j: Json) -> Result<&2, &2, Access, List<&2, Field>>:
  match j:
    case JObj{fs}:
      Done{fs}
    case other:
      Fail{expected(KObject{}, other)}

# u32 reads the value, not the text: 1e2, 100.0 and 0.5e2 are all 50 or
# 100 as written. The digits d1..dk, with leading and trailing zeros gone,
# are the whole number d1..dk followed by q - k zeros, where q is where
# the point falls: the integer digits, less the leading zeros, plus the
# exponent. The number is whole when q >= k, and fits when q <= 10.

def lead_digit(l: Lead) -> Digit:
  match l:
    case L1{}:
      D1{}
    case L2{}:
      D2{}
    case L3{}:
      D3{}
    case L4{}:
      D4{}
    case L5{}:
      D5{}
    case L6{}:
      D6{}
    case L7{}:
      D7{}
    case L8{}:
      D8{}
    case L9{}:
      D9{}

def digit_nat(d: Digit) -> Nat:
  match d:
    case D0{}:
      0n
    case D1{}:
      1n
    case D2{}:
      2n
    case D3{}:
      3n
    case D4{}:
      4n
    case D5{}:
      5n
    case D6{}:
      6n
    case D7{}:
      7n
    case D8{}:
      8n
    case D9{}:
      9n

def dlen(ds: List<&2, Digit>, +n: Nat) -> Nat:
  match ds:
    case Nil{}:
      n
    case Con{_, t}:
      dlen(t, 1n+n)

def frac_digits(f: Frac) -> List<&2, Digit>:
  match f:
    case FNone{}:
      []
    case FSome{d, ds}:
      Con{d, ds}

# all the digits, and how many come before the point
type Digits is Data:
  Digits{ds: List<&2, Digit>, point: Nat}

def with_point(i: Int, f: Frac) -> Digits:
  match i:
    case IZero{}:
      Digits{frac_digits(f), 0n}
    case INon{l, +ds}:
      Digits{Con{lead_digit(l), List.append(&2, Digit, ds, frac_digits(f))}, 1n+dlen(ds, 0n)}

# the smaller of two Nats; Base's Nat.min counts down one by one, which
# overflows the stack on large values, where Nat.is_le runs natively
def nat_min.go(le: Bool, +a: Nat, +b: Nat) -> Nat:
  match le:
    case True{}:
      a
    case False{}:
      b

def nat_min(+a: Nat, +b: Nat) -> Nat:
  nat_min.go(Nat.is_le(a, b), a, b)

# an exponent's value, held at 2^32 - 1 once past it: past any input's
# length, so a larger one decides nothing differently
def exp_val(ds: List<&2, Digit>, +acc: Nat) -> Nat:
  match ds:
    case Nil{}:
      acc
    case Con{d, t}:
      exp_val(t, nat_min(4294967295n, Nat.add(Nat.mul(10n, acc), digit_nat(d))))

def exp_up(e: Exp) -> Nat:
  match e:
    case ESome{_, Minus{}, _, _}:
      0n
    case ESome{_, _, d, ds}:
      exp_val(ds, digit_nat(d))
    case ENone{}:
      0n

def exp_down(e: Exp) -> Nat:
  match e:
    case ESome{_, Minus{}, d, ds}:
      exp_val(ds, digit_nat(d))
    case _:
      0n

# leading zeros dropped, and how many
type Lead0 is Data:
  Lead0{ds: List<&2, Digit>, zeros: Nat}

def drop_lead(ds: List<&2, Digit>, +z: Nat) -> Lead0:
  match ds:
    case Con{D0{}, t}:
      drop_lead(t, 1n+z)
    case rest:
      Lead0{rest, z}

def drop_zeros(ds: List<&2, Digit>) -> List<&2, Digit>:
  match ds:
    case Con{D0{}, t}:
      drop_zeros(t)
    case rest:
      rest

def rev_digits(ds: List<&2, Digit>, acc: List<&2, Digit>) -> List<&2, Digit>:
  match ds:
    case Nil{}:
      acc
    case Con{d, t}:
      rev_digits(t, Con{d, acc})

# trailing zeros do not change the value
def strip_trailing(ds: List<&2, Digit>) -> List<&2, Digit>:
  rev_digits(drop_zeros(rev_digits(ds, [])), [])

def dvalue(ds: List<&2, Digit>, +acc: Nat) -> Nat:
  match ds:
    case Nil{}:
      acc
    case Con{d, t}:
      dvalue(t, Nat.add(Nat.mul(10n, acc), digit_nat(d)))

def times10(n: Nat, +acc: Nat) -> Nat:
  match n:
    case 0n:
      acc
    case 1n+p:
      times10(p, Nat.mul(10n, acc))

def u32.fits.go(ok: Bool, +v: Nat) -> Result<&2, &2, Access, U32>:
  match ok:
    case True{}:
      Done{U32.from_nat(v)}
    case False{}:
      Fail{OutOfRange{[]}}

def u32.fits(+v: Nat) -> Result<&2, &2, Access, U32>:
  u32.fits.go(Nat.is_le(v, 4294967295n), v)

def u32.whole(ok: Bool, sig: List<&2, Digit>, +shift: Nat) -> Result<&2, &2, Access, U32>:
  match ok:
    case True{}:
      u32.fits(times10(shift, dvalue(sig, 0n)))
    case False{}:
      Fail{OutOfRange{[]}}

# hi is where the point falls plus the leading zeros and the negative
# exponent moved across; lo is the digits' count plus the same
def u32.sig(neg: Bool, sig: List<&2, Digit>, +k: Nat, +hi: Nat, +low: Nat) -> Result<&2, &2, Access, U32>:
  match neg sig:
    case _ Nil{}:
      Done{0}
    case True{} Con{_, _}:
      Fail{OutOfRange{[]}}
    case False{} Con{d, t}:
      u32.whole(Bool.and(Nat.is_ge(hi, Nat.add(k, low)), Nat.is_le(hi, Nat.add(10n, low))), Con{d, t}, Nat.sub(hi, Nat.add(k, low)))

def u32.trail(neg: Bool, +sig: List<&2, Digit>, +hi: Nat, +low: Nat) -> Result<&2, &2, Access, U32>:
  u32.sig(neg, sig, dlen(sig, 0n), hi, low)

def u32.lead(neg: Bool, l: Lead0, +point: Nat, +up: Nat, +down: Nat) -> Result<&2, &2, Access, U32>:
  match l:
    case Lead0{ds, z}:
      u32.trail(neg, strip_trailing(ds), Nat.add(point, up), Nat.add(z, down))

def u32.digits(neg: Bool, d: Digits, +e: Exp) -> Result<&2, &2, Access, U32>:
  match d:
    case Digits{ds, point}:
      u32.lead(neg, drop_lead(ds, 0n), point, exp_up(e), exp_down(e))

def u32.num(n: Number) -> Result<&2, &2, Access, U32>:
  match n:
    case Number{neg, i, f, e}:
      u32.digits(neg, with_point(i, f), e)

# a whole number from 0 to 2^32 - 1, however it is written: 1e2, 100.0
def u32(j: Json) -> Result<&2, &2, Access, U32>:
  match j:
    case JNum{n}:
      u32.num(n)
    case other:
      Fail{expected(KNumber{}, other)}

# not infinite or NaN: an F32's exponent bits are all ones only for those
def finite(+x: F32) -> Bool:
  Bool.not(U32.is_eq(((F32.bits(x) >> 23n) .&. 255 : U32), 255))

def f32.fin(ok: Bool, +x: F32) -> Result<&2, &2, Access, F32>:
  match ok:
    case True{}:
      Done{x}
    case False{}:
      Fail{OutOfRange{[]}}

def f32.go(m: Maybe<&2, F32>) -> Result<&2, &2, Access, F32>:
  match m:
    case Some{+x}:
      f32.fin(finite(x), x)
    case None{}:
      Fail{OutOfRange{[]}}

# the nearest F32: past 2^24 not every whole number has one, and a number
# past the largest F32 (about 3.4e38) is OutOfRange, not infinity
def f32(j: Json) -> Result<&2, &2, Access, F32>:
  match j:
    case JNum{n}:
      f32.go(F32.read(num_text(n)))
    case other:
      Fail{expected(KNumber{}, other)}

def index.go(xs: List<&2, Json>, n: Nat, +i: U32) -> Result<&2, &2, Access, Json>:
  match xs n:
    case Con{h, _} 0n:
      Done{h}
    case Con{_, t} 1n+p:
      index.go(t, p, i)
    case Nil{} _:
      Fail{Missing{[Index{i}]}}

# the item at index i of an array
def index(j: Json, +i: U32) -> Result<&2, &2, Access, Json>:
  match j:
    case JArr{xs}:
      index.go(xs, U32.to_nat(i), i)
    case other:
      Fail{expected(KArray{}, other)}

# whether two strings are equal, by reading them only: String.eq hands its
# strings back, which would share them
def same(a: String, b: String, ok: Bool) -> Bool:
  match a b:
    case SNil{} SNil{}:
      ok
    case SCon{x, at} SCon{y, bt}:
      same(at, bt, Bool.and(ok, Char.is_eq(x, y)))
    case _ _:
      False{}

def get.keep(hit: Bool, v: Json, found: Maybe<&2, Json>) -> Maybe<&2, Json>:
  match hit:
    case True{}:
      Some{v}
    case False{}:
      found

# the last field named k: a later duplicate overrides, so every field is read
def get.go(fs: List<&2, Field>, +k: String, found: Maybe<&2, Json>) -> Maybe<&2, Json>:
  match fs:
    case Nil{}:
      found
    case Con{Field{fk, v}, t}:
      get.go(t, k, get.keep(same(fk, k, True{}), v, found))

def get.fin(m: Maybe<&2, Json>, k: String) -> Result<&2, &2, Access, Json>:
  match m:
    case Some{v}:
      Done{v}
    case None{}:
      Fail{Missing{[Name{k}]}}

# the value of key k in an object; the last one wins on duplicates
def get(j: Json, +k: String) -> Result<&2, &2, Access, Json>:
  match j:
    case JObj{fs}:
      get.fin(get.go(fs, k, None{}), k)
    case other:
      Fail{expected(KObject{}, other)}

def kind_name(k: JKind) -> String:
  match k:
    case KNull{}:
      "null"
    case KBool{}:
      "bool"
    case KNumber{}:
      "number"
    case KString{}:
      "string"
    case KArray{}:
      "array"
    case KObject{}:
      "object"

# a key that reads unambiguously after a dot: a letter or _, then
# letters, digits or _
def ident_char(+x: U32, first: Bool) -> Bool:
  Bool.or(Bool.or(in_range(x, 97, 122), in_range(x, 65, 90)),
    Bool.or(U32.is_eq(x, 95), Bool.and(Bool.not(first), in_range(x, 48, 57))))

def ident.go(s: String, first: Bool, ok: Bool) -> Bool:
  match s:
    case SNil{}:
      Bool.and(ok, Bool.not(first))
    case SCon{Chr{+x}, t}:
      ident.go(t, False{}, Bool.and(ok, ident_char(x, first)))

def ident(k: String) -> Bool:
  ident.go(k, True{}, True{})

# a key as a path writes it, pushed onto a reversed output: .key when
# plain, else ["key"] as JSON writes the string, so a dot or bracket in a
# key reads as part of it
def key_text(plain: Bool, k: String, out: String) -> String:
  match plain:
    case True{}:
      String.reverse.go(k, SCon{'.', out})
    case False{}:
      SCon{']', String.reverse.go(encode(JStr{k}), SCon{'[', out})}

def path_text(p: List<&2, Step>, out: String) -> String:
  match p:
    case Nil{}:
      String.reverse(out)
    case Con{Name{+k}, t}:
      path_text(t, key_text(ident(k), k, out))
    case Con{Index{i}, t}:
      path_text(t, SCon{']', String.reverse.go(U32.show(i), SCon{'[', out})})

# e.g. "$.user.tags[0]: expected string, found number"
def message_access(a: Access) -> String:
  match a:
    case Missing{p}:
      path_text(p, "$") ++ ": missing"
    case Expected{p, want, got}:
      path_text(p, "$") ++ ": expected " ++ kind_name(want) ++ ", found " ++ kind_name(got)
    case OutOfRange{p}:
      path_text(p, "$") ++ ": number out of range"

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
    case InvalidUtf8{}:
      "invalid UTF-8"
    case Internal{}:
      "internal parser error"

# the error at an offset of s, with its line and column
def position(r: Reason, +offset: U32, s: String) -> Error:
  position.go(r, offset, locate(U32.to_nat(offset), s, 1, 1))

# e.g. "3:5: unexpected ','"
def message(e: Error) -> String:
  match e:
    case Error{r, _, line, col}:
      U32.show(line) ++ ":" ++ U32.show(col) ++ ": " ++ reason(r)
