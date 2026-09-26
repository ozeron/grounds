import Base

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
  Internal{}

# offset counts chars from 0; line and column count from 1
type Error is Data:
  Error{reason: Reason, offset: U32, line: U32, column: U32}

# Lexing
# ======

# a lexed string and the input after it, or why and where lexing stopped
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

# inside a string: chars so far (reversed), a pending high surrogate (0 if
# none), and for an escape the input at its backslash
type SSt is Data:
  SGo{acc: String, hi: U32}
  SEsc{acc: String, hi: U32, at: String}
  SHex{acc: String, hi: U32, left: Nat, code: U32, at: String}
  SStop{reason: Reason, rest: String}
  SDone{value: String, rest: String}

def pair(+hi: U32, +lo: U32) -> U32:
  (65536 + (hi - 55296) * 1024 + (lo - 56320) : U32)

def push(acc: String, x: U32) -> SSt:
  SGo{SCon{Chr{x}, acc}, 0}

def on_code(pending: Bool, k: Surr, acc: String, +hi: U32, +x: U32, at: String) -> SSt:
  match pending k:
    case False{} NotSurr{}:
      push(acc, x)
    case False{} High{}:
      SGo{acc, x}
    case False{} Low{}:
      SStop{LoneSurrogate{}, at}
    case True{} Low{}:
      push(acc, pair(hi, x))
    case True{} _:
      SStop{LoneSurrogate{}, at}

def code(acc: String, +hi: U32, +x: U32, at: String) -> SSt:
  on_code(U32.is_ne(hi, 0), surr(x), acc, hi, x, at)

# a char taken as is, raw or after a backslash
def keep.go(pending: Bool, acc: String, c: Char, at: String) -> SSt:
  match pending:
    case True{}:
      SStop{LoneSurrogate{}, at}
    case False{}:
      SGo{SCon{c, acc}, 0}

def keep(acc: String, +hi: U32, c: Char, at: String) -> SSt:
  keep.go(U32.is_ne(hi, 0), acc, c, at)

def close.go(pending: Bool, acc: String, +rest: String) -> SSt:
  match pending:
    case True{}:
      SStop{LoneSurrogate{}, SCon{'"', rest}}
    case False{}:
      SDone{String.reverse(acc), rest}

def close(acc: String, +hi: U32, rest: String) -> SSt:
  close.go(U32.is_ne(hi, 0), acc, rest)

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

def letter.go(m: Maybe<&2, U32>, acc: String, +hi: U32, at: String) -> SSt:
  match m:
    case Some{x}:
      code(acc, hi, x, at)
    case None{}:
      SStop{InvalidEscape{}, at}

# the letter after a backslash
def letter(+c: Char, acc: String, +hi: U32, at: String) -> SSt:
  match c:
    case 'u':
      SHex{acc, hi, 4n, 0, at}
    case other:
      letter.go(unescape(other), acc, hi, at)

# a raw char: the input at it is built only for the error
def plain.go(pending: Bool, acc: String, +c: Char, t: String) -> SSt:
  match pending:
    case True{}:
      SStop{LoneSurrogate{}, SCon{c, t}}
    case False{}:
      SGo{SCon{c, acc}, 0}

def s_go(k: Class, +c: Char, acc: String, +hi: U32, +t: String) -> SSt:
  match k:
    case KQuote{}:
      close(acc, hi, t)
    case KBack{}:
      SEsc{acc, hi, SCon{c, t}}
    case KCtrl{}:
      SStop{ControlChar{}, SCon{c, t}}
    case KPlain{}:
      plain.go(U32.is_ne(hi, 0), acc, c, t)

def s_esc(k: Class, +c: Char, acc: String, +hi: U32, at: String) -> SSt:
  match k:
    case KQuote{}:
      keep(acc, hi, c, at)
    case KBack{}:
      keep(acc, hi, c, at)
    case KCtrl{}:
      SStop{InvalidEscape{}, at}
    case KPlain{}:
      letter(c, acc, hi, at)

def s_hex.go(left: Nat, d: Maybe<&2, U32>, acc: String, +hi: U32, +x: U32, at: String) -> SSt:
  match left d:
    case _ None{}:
      SStop{InvalidUnicode{}, at}
    case 0n Some{_}:
      SStop{Internal{}, at}
    case 1n Some{v}:
      code(acc, hi, (x * 16 + v : U32), at)
    case 2n+p Some{v}:
      SHex{acc, hi, 1n+p, (x * 16 + v : U32), at}

# one char of a string body
def s_step(st: SSt, +c: Char, +t: String) -> SSt:
  match st:
    case SGo{acc, hi}:
      s_go(class(c), c, acc, hi, t)
    case SEsc{acc, hi, at}:
      s_esc(class(c), c, acc, hi, at)
    case SHex{acc, hi, left, x, at}:
      s_hex.go(left, hex_digit(c), acc, hi, x, at)
    case done:
      done

# the body of a string, after its opening quote
def lex_str(s: String, st: SSt) -> Lex:
  match s st:
    case _ SStop{r, rest}:
      LBad{r, rest}
    case _ SDone{v, rest}:
      LOk{v, rest}
    case SNil{} _:
      LBad{UnexpectedEnd{}, SNil{}}
    case SCon{+c, +t} going:
      lex_str(t, s_step(going, c, t))

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
  NHalt{last: NSt, rest: String}

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
# lexer resumes from here
def num_step(st: NSt, k: NC, c: Char, t: String) -> NSt:
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
      NHalt{last, SCon{c, t}}

# a lexed number and the input after it
type NLex is Data:
  NOk{value: Number, rest: String}
  NBad{reason: Reason, rest: String}

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
      NBad{UnexpectedEnd{}, SNil{}}
    case NStart{} SCon{+c, t}:
      NBad{UnexpectedChar{c}, SCon{c, t}}
    case _ _:
      NBad{InvalidNumber{}, rest}

def lex_num(s: String, st: NSt) -> NLex:
  match s st:
    case _ NHalt{last, rest}:
      num_end(last, rest)
    case SNil{} last:
      num_end(last, SNil{})
    case SCon{+c, +t} going:
      lex_num(t, num_step(going, nclass(c), c, t))

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

def number(l: NLex, stack: List<&2, Frame>) -> St:
  match l:
    case NOk{n, rest}:
      emit(JNum{n}, rest, stack)
    case NBad{r, rest}:
      Bad{r, rest}

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
      number(lex_num(other, NStart{}), stack)

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

def stringify(j: Json) -> String:
  String.reverse(show(j, False{}, False{}, "", 0n, ""))

# unit is the indent of one level, e.g. "  "
def pretty(j: Json, unit: String) -> String:
  String.reverse(show(j, False{}, True{}, unit, 0n, ""))

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
    case JNum{n}:
      F32.read(num_text(n))
    case _:
      None{}

# None unless the number is a whole number in U32 range
def as_u32(j: Json) -> Maybe<&2, U32>:
  match j:
    case JNum{n}:
      U32.read(num_text(n))
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
