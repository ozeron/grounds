import Base
import ./bjson.bend as J

# reformat(s) is stringify(parse(s)) in one pass: it checks the input and
# writes the compact text as it reads, without building the Json value.
# Ok{text} when s is JSON; Err{reason, offset} when not, the same reason
# and offset J.parse reports. suite.bend and scripts/integration.py check
# both against J.parse and J.stringify, which PROOF.bend proves.
#
# Only J's types and message text are used here: calling J.parse would
# link code that shares Strings, which makes every String in the program
# reference counted (scripts/cold.py checks this stays so).

# output is built reversed and turned around once at the end

type Box is Data:
  BArr{}
  BObj{}

# what may come next; strings and numbers are read a char at a time.
# Every mode is a plain tag: a case that looks two chars ahead makes the
# compiler test the next char for every char, which halves the speed
type Mode is Data:
  VStart{}
  VTop{}
  VFirst{}
  VItem{}
  VObjFirst{}
  VKey{}
  VColon{}
  VObjVal{}
  VAfter{}
  SStr{}
  SEsc{}
  SU4{}
  SU3{}
  SU2{}
  SU1{}
  SHi{}
  SHiU{}
  NMin{}
  NZero{}
  NInt{}
  NDot{}
  NFrac{}
  NE{}
  NESign{}
  NExp{}
  T1{}
  T2{}
  T3{}
  F1{}
  F2{}
  F3{}
  F4{}
  U1{}
  U2{}
  U3{}
  BCtrl{}
  BUni{}
  BLone{}
  BEsc{}

# Strings
# -------

# copies of bjson.bend's helpers: importing that file would link the
# proven parser, whose shared Strings make every String here counted

def in_range(+x: U32, lo: U32, hi: U32) -> Bool:
  Bool.and(U32.is_ge(x, lo), U32.is_le(x, hi))

def hex_digit(c: Char) -> Maybe<&2, U32>:
  match c:
    case Chr{+x}:
      Bool.pick(Maybe<&2, U32>, in_range(x, 48, 57), Some{U32.sub(x, 48)},
        Bool.pick(Maybe<&2, U32>, in_range(x, 97, 102), Some{U32.sub(x, 87)},
          Bool.pick(Maybe<&2, U32>, in_range(x, 65, 70), Some{U32.sub(x, 55)}, None{})))

type Surr is Data:
  NotSurr{}
  High{}
  Low{}

def surr(+x: U32) -> Surr:
  Bool.pick(Surr, in_range(x, 55296, 56319), High{},
    Bool.pick(Surr, in_range(x, 56320, 57343), Low{}, NotSurr{}))

def pair(+hi: U32, +lo: U32) -> U32:
  (65536 + (hi - 55296) * 1024 + (lo - 56320) : U32)

def pending(+hi: U32) -> Bool:
  U32.is_ne(hi, 0)

def ctrl(c: Char) -> Bool:
  U32.is_lt(Char.to_u32(c), 32)

def hex4(a: Char, b: Char, c: Char, d: Char) -> Maybe<&2, U32>:
  do Maybe<&2, U32>:
    w : U32 <- hex_digit(a)
    x : U32 <- hex_digit(b)
    y : U32 <- hex_digit(c)
    z : U32 <- hex_digit(d)
    return (w * 4096 + x * 256 + y * 16 + z : U32)

# how the printer writes a decoded char (J.esc_char on J.class), spelled
# with plain conses and arithmetic: a call into the printer here would
# make the loop below a slow segment instead of a tight C loop
def hex_char(+x: U32) -> Char:
  Chr{Bool.pick(U32, U32.is_lt(x, 10), (x + 48 : U32), (x + 87 : U32))}

# the escape text, reversed; out is not shared, which keeps String flat
def ctrl_chunk(+x: U32) -> String:
  Bool.pick(String, U32.is_eq(x, 8), "b\\",
    Bool.pick(String, U32.is_eq(x, 12), "f\\",
      Bool.pick(String, U32.is_eq(x, 10), "n\\",
        Bool.pick(String, U32.is_eq(x, 13), "r\\",
          Bool.pick(String, U32.is_eq(x, 9), "t\\",
            SCon{hex_char(U32.mod(x, 16)), SCon{hex_char(U32.div(x, 16)), "00u\\"}})))))

def chunk(+x: U32) -> String:
  Bool.pick(String, U32.is_lt(x, 32), ctrl_chunk(x),
    Bool.pick(String, U32.is_eq(x, 34), "\"\\",
      Bool.pick(String, U32.is_eq(x, 92), "\\\\", SCon{Chr{x}, ""})))

def onto(chunk: String, out: String) -> String:
  match chunk:
    case SNil{}:
      out
    case SCon{c, t}:
      onto(t, SCon{c, out})

def emit_code(+x: U32, out: String) -> String:
  onto(String.reverse(chunk(x)), out)

# where a string ends: a value, or a key before its colon
def close_mode(key: Bool) -> Mode:
  match key:
    case True{}:
      VColon{}
    case False{}:
      VAfter{}

# A char in a string, and the char after a backslash, go by J.class, as the
# proven lexer's do: a proof can then take each class as one case, where a
# case per char literal would leave it stuck on a char it does not know
def str_mode(k: J.Class, key: Bool) -> Mode:
  match k:
    case J.KQuote{}:
      close_mode(key)
    case J.KBack{}:
      SEsc{}
    case J.KCtrl{}:
      BCtrl{}
    case J.KPlain{}:
      SStr{}

def str_out(k: J.Class, c: Char, out: String) -> String:
  match k:
    case J.KQuote{}:
      SCon{'"', out}
    case J.KBack{}:
      out
    case J.KCtrl{}:
      out
    case J.KPlain{}:
      SCon{c, out}

def str_ea(k: J.Class, +at: U32, +ea: U32) -> U32:
  match k:
    case J.KBack{}:
      at
    case J.KCtrl{}:
      at
    case _:
      ea

def letter_mode(c: Char) -> Mode:
  match c:
    case '/':
      SStr{}
    case 'b':
      SStr{}
    case 'f':
      SStr{}
    case 'n':
      SStr{}
    case 'r':
      SStr{}
    case 't':
      SStr{}
    case 'u':
      SU4{}
    case _:
      BEsc{}

def letter_out(c: Char, out: String) -> String:
  match c:
    case '/':
      SCon{'/', out}
    case 'b':
      SCon{'b', SCon{'\\', out}}
    case 'f':
      SCon{'f', SCon{'\\', out}}
    case 'n':
      SCon{'n', SCon{'\\', out}}
    case 'r':
      SCon{'r', SCon{'\\', out}}
    case 't':
      SCon{'t', SCon{'\\', out}}
    case _:
      out

def esc_mode(k: J.Class, c: Char) -> Mode:
  match k:
    case J.KQuote{}:
      SStr{}
    case J.KBack{}:
      SStr{}
    case J.KCtrl{}:
      BEsc{}
    case J.KPlain{}:
      letter_mode(c)

def esc_out(k: J.Class, +c: Char, out: String) -> String:
  match k:
    case J.KQuote{}:
      SCon{c, SCon{'\\', out}}
    case J.KBack{}:
      SCon{c, SCon{'\\', out}}
    case J.KCtrl{}:
      out
    case J.KPlain{}:
      letter_out(c, out)

# a \\u escape's last hex digit completes the code. With hi (a pending
# high surrogate, or 0) the code decides the mode, the output and the new
# hi; a wrong one goes to BUni (bad hex) or BLone (unpaired surrogate)
def code_of.go(d: Maybe<&2, U32>, +code: U32) -> Maybe<&2, U32>:
  match d:
    case Some{v}:
      Some{(code * 16 + v : U32)}
    case None{}:
      None{}

def code_of(c: Char, +code: U32) -> Maybe<&2, U32>:
  code_of.go(hex_digit(c), code)

def u_mode.k(k: Surr, pend: Bool) -> Mode:
  match k pend:
    case NotSurr{} False{}:
      SStr{}
    case High{} False{}:
      SHi{}
    case Low{} True{}:
      SStr{}
    case _ _:
      BLone{}

def u_mode(m: Maybe<&2, U32>, +hi: U32) -> Mode:
  match m:
    case None{}:
      BUni{}
    case Some{+x}:
      u_mode.k(surr(x), pending(hi))

# only the two good cases build a char: the pair of nothing is not one
def u_out.k(k: Surr, pend: Bool, +hi: U32, +x: U32, out: String) -> String:
  match k pend:
    case NotSurr{} False{}:
      emit_code(x, out)
    case Low{} True{}:
      emit_code(pair(hi, x), out)
    case _ _:
      out

def u_out(m: Maybe<&2, U32>, +hi: U32, out: String) -> String:
  match m:
    case None{}:
      out
    case Some{+x}:
      u_out.k(surr(x), pending(hi), hi, x, out)

def u_hi.k(k: Surr, pend: Bool, +x: U32) -> U32:
  match k pend:
    case High{} False{}:
      x
    case _ _:
      0

def u_hi(m: Maybe<&2, U32>, +hi: U32) -> U32:
  match m:
    case None{}:
      0
    case Some{+x}:
      u_hi.k(surr(x), pending(hi), x)

# a hex digit before the last: the next mode, or BUni
def hex_mode(d: Maybe<&2, U32>, next: Mode) -> Mode:
  match d:
    case Some{_}:
      next
    case None{}:
      BUni{}

def hex_add(d: Maybe<&2, U32>, +code: U32) -> U32:
  match d:
    case Some{v}:
      (code * 16 + v : U32)
    case None{}:
      0

# Pretty output (the same text as J.pretty(j, "  ")): a line break and
# two spaces per level. Tail calls only, so the loop stays a C loop
def spaces(n: Nat, out: String) -> String:
  match n:
    case 0n:
      out
    case 1n+p:
      spaces(p, SCon{' ', SCon{' ', out}})

def nl(d: Nat, out: String) -> String:
  spaces(d, SCon{'\n', out})

def dec(d: Nat) -> Nat:
  match d:
    case 0n:
      0n
    case 1n+p:
      p

# what reformat answers
type Out is Data:
  Ok{text: String}
  Err{reason: J.Reason, at: U32}

# the end of the input
def finish(mode: Mode, stack: List<&2, Box>, out: String, +at: U32) -> Out:
  match mode stack:
    case VAfter{} Nil{}:
      Ok{String.reverse(out)}
    case NZero{} Nil{}:
      Ok{String.reverse(out)}
    case NInt{} Nil{}:
      Ok{String.reverse(out)}
    case NFrac{} Nil{}:
      Ok{String.reverse(out)}
    case NExp{} Nil{}:
      Ok{String.reverse(out)}
    case NMin{} _:
      Err{J.InvalidNumber{}, at}
    case NDot{} _:
      Err{J.InvalidNumber{}, at}
    case NE{} _:
      Err{J.InvalidNumber{}, at}
    case NESign{} _:
      Err{J.InvalidNumber{}, at}
    case _ _:
      Err{J.UnexpectedEnd{}, at}

# generated by scripts/gen_fast.py; do not edit

# one char per call; fuel is the input itself, so it never runs out first.
# at is the offset of the char read now; ea the offset of the backslash of
# the current escape, or of an error found inside a string (the B modes
# report it at the next step). hi is a pending high surrogate, code the
# \\u digits so far, key whether the string is an object key. gc writes
# compact text; gp the same loop indenting, with d the depth

def gc(fuel: String, mode: Mode, s: String, stack: List<&2, Box>, out: String, +hi: U32, +code: U32, +key: Bool, +at: U32, +ea: U32) -> Out:
  match fuel mode s stack:
    case _ BCtrl{} _ _:
      Err{J.ControlChar{}, ea}
    case _ BUni{} _ _:
      Err{J.InvalidUnicode{}, ea}
    case _ BLone{} _ _:
      Err{J.LoneSurrogate{}, ea}
    case _ BEsc{} _ _:
      Err{J.InvalidEscape{}, ea}
    case _ m SNil{} stk:
      finish(m, stk, out, at)
    case SNil{} _ _ _:
      Err{J.Internal{}, at}
    case SCon{_, f} SStr{} SCon{+c, t} stk:
      +k = J.class(c)
      gc(f, str_mode(k, key), t, stk, str_out(k, c, out), 0, 0, key, (at + 1 : U32), str_ea(k, at, ea))
    case SCon{_, f} SEsc{} SCon{+c, t} stk:
      +k = J.class(c)
      gc(f, esc_mode(k, c), t, stk, esc_out(k, c, out), hi, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} SU4{} SCon{+c, t} stk:
      gc(f, hex_mode(hex_digit(c), SU3{}), t, stk, out, hi, hex_add(hex_digit(c), code), key, (at + 1 : U32), ea)
    case SCon{_, f} SU3{} SCon{+c, t} stk:
      gc(f, hex_mode(hex_digit(c), SU2{}), t, stk, out, hi, hex_add(hex_digit(c), code), key, (at + 1 : U32), ea)
    case SCon{_, f} SU2{} SCon{+c, t} stk:
      gc(f, hex_mode(hex_digit(c), SU1{}), t, stk, out, hi, hex_add(hex_digit(c), code), key, (at + 1 : U32), ea)
    case SCon{_, f} SU1{} SCon{+c, t} stk:
      gc(f, u_mode(code_of(c, code), hi), t, stk, u_out(code_of(c, code), hi, out), u_hi(code_of(c, code), hi), 0, key, (at + 1 : U32), ea)
    case SCon{_, f} SHi{} SCon{'\\', t} stk:
      gc(f, SHiU{}, t, stk, out, hi, 0, key, (at + 1 : U32), at)
    case SCon{_, f} SHi{} SCon{+c, _} _:
      Bool.pick(Out, ctrl(c), Err{J.ControlChar{}, at}, Err{J.LoneSurrogate{}, at})
    case SCon{_, f} SHiU{} SCon{'u', t} stk:
      gc(f, SU4{}, t, stk, out, hi, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} SHiU{} SCon{'"', t} _:
      Err{J.LoneSurrogate{}, ea}
    case SCon{_, f} SHiU{} SCon{'\\', t} _:
      Err{J.LoneSurrogate{}, ea}
    case SCon{_, f} SHiU{} SCon{'/', t} _:
      Err{J.LoneSurrogate{}, ea}
    case SCon{_, f} SHiU{} SCon{'b', t} _:
      Err{J.LoneSurrogate{}, ea}
    case SCon{_, f} SHiU{} SCon{'f', t} _:
      Err{J.LoneSurrogate{}, ea}
    case SCon{_, f} SHiU{} SCon{'n', t} _:
      Err{J.LoneSurrogate{}, ea}
    case SCon{_, f} SHiU{} SCon{'r', t} _:
      Err{J.LoneSurrogate{}, ea}
    case SCon{_, f} SHiU{} SCon{'t', t} _:
      Err{J.LoneSurrogate{}, ea}
    case SCon{_, f} SHiU{} _ _:
      Err{J.InvalidEscape{}, ea}
    case SCon{_, f} NInt{} SCon{'0', t} stk:
      gc(f, NInt{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NInt{} SCon{'1', t} stk:
      gc(f, NInt{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NInt{} SCon{'2', t} stk:
      gc(f, NInt{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NInt{} SCon{'3', t} stk:
      gc(f, NInt{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NInt{} SCon{'4', t} stk:
      gc(f, NInt{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NInt{} SCon{'5', t} stk:
      gc(f, NInt{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NInt{} SCon{'6', t} stk:
      gc(f, NInt{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NInt{} SCon{'7', t} stk:
      gc(f, NInt{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NInt{} SCon{'8', t} stk:
      gc(f, NInt{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NInt{} SCon{'9', t} stk:
      gc(f, NInt{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NFrac{} SCon{'0', t} stk:
      gc(f, NFrac{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NFrac{} SCon{'1', t} stk:
      gc(f, NFrac{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NFrac{} SCon{'2', t} stk:
      gc(f, NFrac{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NFrac{} SCon{'3', t} stk:
      gc(f, NFrac{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NFrac{} SCon{'4', t} stk:
      gc(f, NFrac{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NFrac{} SCon{'5', t} stk:
      gc(f, NFrac{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NFrac{} SCon{'6', t} stk:
      gc(f, NFrac{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NFrac{} SCon{'7', t} stk:
      gc(f, NFrac{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NFrac{} SCon{'8', t} stk:
      gc(f, NFrac{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NFrac{} SCon{'9', t} stk:
      gc(f, NFrac{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NExp{} SCon{'0', t} stk:
      gc(f, NExp{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NExp{} SCon{'1', t} stk:
      gc(f, NExp{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NExp{} SCon{'2', t} stk:
      gc(f, NExp{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NExp{} SCon{'3', t} stk:
      gc(f, NExp{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NExp{} SCon{'4', t} stk:
      gc(f, NExp{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NExp{} SCon{'5', t} stk:
      gc(f, NExp{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NExp{} SCon{'6', t} stk:
      gc(f, NExp{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NExp{} SCon{'7', t} stk:
      gc(f, NExp{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NExp{} SCon{'8', t} stk:
      gc(f, NExp{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NExp{} SCon{'9', t} stk:
      gc(f, NExp{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NMin{} SCon{'0', t} stk:
      gc(f, NZero{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NMin{} SCon{'1', t} stk:
      gc(f, NInt{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NMin{} SCon{'2', t} stk:
      gc(f, NInt{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NMin{} SCon{'3', t} stk:
      gc(f, NInt{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NMin{} SCon{'4', t} stk:
      gc(f, NInt{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NMin{} SCon{'5', t} stk:
      gc(f, NInt{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NMin{} SCon{'6', t} stk:
      gc(f, NInt{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NMin{} SCon{'7', t} stk:
      gc(f, NInt{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NMin{} SCon{'8', t} stk:
      gc(f, NInt{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NMin{} SCon{'9', t} stk:
      gc(f, NInt{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NZero{} SCon{'.', t} stk:
      gc(f, NDot{}, t, stk, SCon{'.', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NZero{} SCon{'e', t} stk:
      gc(f, NE{}, t, stk, SCon{'e', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NZero{} SCon{'E', t} stk:
      gc(f, NE{}, t, stk, SCon{'E', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NInt{} SCon{'.', t} stk:
      gc(f, NDot{}, t, stk, SCon{'.', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NInt{} SCon{'e', t} stk:
      gc(f, NE{}, t, stk, SCon{'e', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NInt{} SCon{'E', t} stk:
      gc(f, NE{}, t, stk, SCon{'E', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NFrac{} SCon{'e', t} stk:
      gc(f, NE{}, t, stk, SCon{'e', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NFrac{} SCon{'E', t} stk:
      gc(f, NE{}, t, stk, SCon{'E', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NDot{} SCon{'0', t} stk:
      gc(f, NFrac{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NDot{} SCon{'1', t} stk:
      gc(f, NFrac{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NDot{} SCon{'2', t} stk:
      gc(f, NFrac{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NDot{} SCon{'3', t} stk:
      gc(f, NFrac{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NDot{} SCon{'4', t} stk:
      gc(f, NFrac{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NDot{} SCon{'5', t} stk:
      gc(f, NFrac{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NDot{} SCon{'6', t} stk:
      gc(f, NFrac{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NDot{} SCon{'7', t} stk:
      gc(f, NFrac{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NDot{} SCon{'8', t} stk:
      gc(f, NFrac{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NDot{} SCon{'9', t} stk:
      gc(f, NFrac{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NE{} SCon{'+', t} stk:
      gc(f, NESign{}, t, stk, SCon{'+', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NE{} SCon{'-', t} stk:
      gc(f, NESign{}, t, stk, SCon{'-', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NE{} SCon{'0', t} stk:
      gc(f, NExp{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NESign{} SCon{'0', t} stk:
      gc(f, NExp{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NE{} SCon{'1', t} stk:
      gc(f, NExp{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NESign{} SCon{'1', t} stk:
      gc(f, NExp{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NE{} SCon{'2', t} stk:
      gc(f, NExp{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NESign{} SCon{'2', t} stk:
      gc(f, NExp{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NE{} SCon{'3', t} stk:
      gc(f, NExp{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NESign{} SCon{'3', t} stk:
      gc(f, NExp{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NE{} SCon{'4', t} stk:
      gc(f, NExp{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NESign{} SCon{'4', t} stk:
      gc(f, NExp{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NE{} SCon{'5', t} stk:
      gc(f, NExp{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NESign{} SCon{'5', t} stk:
      gc(f, NExp{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NE{} SCon{'6', t} stk:
      gc(f, NExp{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NESign{} SCon{'6', t} stk:
      gc(f, NExp{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NE{} SCon{'7', t} stk:
      gc(f, NExp{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NESign{} SCon{'7', t} stk:
      gc(f, NExp{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NE{} SCon{'8', t} stk:
      gc(f, NExp{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NESign{} SCon{'8', t} stk:
      gc(f, NExp{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NE{} SCon{'9', t} stk:
      gc(f, NExp{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NESign{} SCon{'9', t} stk:
      gc(f, NExp{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NMin{} _ _:
      Err{J.InvalidNumber{}, at}
    case SCon{_, f} NDot{} _ _:
      Err{J.InvalidNumber{}, at}
    case SCon{_, f} NE{} _ _:
      Err{J.InvalidNumber{}, at}
    case SCon{_, f} NESign{} _ _:
      Err{J.InvalidNumber{}, at}
    case SCon{_, f} VAfter{} SCon{' ', t} stk:
      gc(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VAfter{} SCon{'\t', t} stk:
      gc(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VAfter{} SCon{'\n', t} stk:
      gc(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VAfter{} SCon{'\r', t} stk:
      gc(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VAfter{} SCon{',', t} Con{BArr{}, up}:
      gc(f, VItem{}, t, Con{BArr{}, up}, SCon{',', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VAfter{} SCon{',', t} Con{BObj{}, up}:
      gc(f, VKey{}, t, Con{BObj{}, up}, SCon{',', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VAfter{} SCon{']', t} Con{BArr{}, up}:
      gc(f, VAfter{}, t, up, SCon{']', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VAfter{} SCon{'}', t} Con{BObj{}, up}:
      gc(f, VAfter{}, t, up, SCon{'}', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VAfter{} _ Nil{}:
      Err{J.TrailingInput{}, at}
    case SCon{_, f} VAfter{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} NZero{} SCon{' ', t} stk:
      gc(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NZero{} SCon{'\t', t} stk:
      gc(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NZero{} SCon{'\n', t} stk:
      gc(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NZero{} SCon{'\r', t} stk:
      gc(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NZero{} SCon{',', t} Con{BArr{}, up}:
      gc(f, VItem{}, t, Con{BArr{}, up}, SCon{',', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NZero{} SCon{',', t} Con{BObj{}, up}:
      gc(f, VKey{}, t, Con{BObj{}, up}, SCon{',', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NZero{} SCon{']', t} Con{BArr{}, up}:
      gc(f, VAfter{}, t, up, SCon{']', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NZero{} SCon{'}', t} Con{BObj{}, up}:
      gc(f, VAfter{}, t, up, SCon{'}', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NZero{} _ Nil{}:
      Err{J.TrailingInput{}, at}
    case SCon{_, f} NZero{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} NInt{} SCon{' ', t} stk:
      gc(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NInt{} SCon{'\t', t} stk:
      gc(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NInt{} SCon{'\n', t} stk:
      gc(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NInt{} SCon{'\r', t} stk:
      gc(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NInt{} SCon{',', t} Con{BArr{}, up}:
      gc(f, VItem{}, t, Con{BArr{}, up}, SCon{',', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NInt{} SCon{',', t} Con{BObj{}, up}:
      gc(f, VKey{}, t, Con{BObj{}, up}, SCon{',', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NInt{} SCon{']', t} Con{BArr{}, up}:
      gc(f, VAfter{}, t, up, SCon{']', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NInt{} SCon{'}', t} Con{BObj{}, up}:
      gc(f, VAfter{}, t, up, SCon{'}', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NInt{} _ Nil{}:
      Err{J.TrailingInput{}, at}
    case SCon{_, f} NInt{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} NFrac{} SCon{' ', t} stk:
      gc(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NFrac{} SCon{'\t', t} stk:
      gc(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NFrac{} SCon{'\n', t} stk:
      gc(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NFrac{} SCon{'\r', t} stk:
      gc(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NFrac{} SCon{',', t} Con{BArr{}, up}:
      gc(f, VItem{}, t, Con{BArr{}, up}, SCon{',', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NFrac{} SCon{',', t} Con{BObj{}, up}:
      gc(f, VKey{}, t, Con{BObj{}, up}, SCon{',', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NFrac{} SCon{']', t} Con{BArr{}, up}:
      gc(f, VAfter{}, t, up, SCon{']', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NFrac{} SCon{'}', t} Con{BObj{}, up}:
      gc(f, VAfter{}, t, up, SCon{'}', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NFrac{} _ Nil{}:
      Err{J.TrailingInput{}, at}
    case SCon{_, f} NFrac{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} NExp{} SCon{' ', t} stk:
      gc(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NExp{} SCon{'\t', t} stk:
      gc(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NExp{} SCon{'\n', t} stk:
      gc(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NExp{} SCon{'\r', t} stk:
      gc(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NExp{} SCon{',', t} Con{BArr{}, up}:
      gc(f, VItem{}, t, Con{BArr{}, up}, SCon{',', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NExp{} SCon{',', t} Con{BObj{}, up}:
      gc(f, VKey{}, t, Con{BObj{}, up}, SCon{',', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NExp{} SCon{']', t} Con{BArr{}, up}:
      gc(f, VAfter{}, t, up, SCon{']', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NExp{} SCon{'}', t} Con{BObj{}, up}:
      gc(f, VAfter{}, t, up, SCon{'}', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} NExp{} _ Nil{}:
      Err{J.TrailingInput{}, at}
    case SCon{_, f} NExp{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} T1{} SCon{'r', t} stk:
      gc(f, T2{}, t, stk, SCon{'r', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} T1{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} T2{} SCon{'u', t} stk:
      gc(f, T3{}, t, stk, SCon{'u', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} T2{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} T3{} SCon{'e', t} stk:
      gc(f, VAfter{}, t, stk, SCon{'e', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} T3{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} F1{} SCon{'a', t} stk:
      gc(f, F2{}, t, stk, SCon{'a', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} F1{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} F2{} SCon{'l', t} stk:
      gc(f, F3{}, t, stk, SCon{'l', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} F2{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} F3{} SCon{'s', t} stk:
      gc(f, F4{}, t, stk, SCon{'s', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} F3{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} F4{} SCon{'e', t} stk:
      gc(f, VAfter{}, t, stk, SCon{'e', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} F4{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} U1{} SCon{'u', t} stk:
      gc(f, U2{}, t, stk, SCon{'u', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} U1{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} U2{} SCon{'l', t} stk:
      gc(f, U3{}, t, stk, SCon{'l', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} U2{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} U3{} SCon{'l', t} stk:
      gc(f, VAfter{}, t, stk, SCon{'l', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} U3{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} VTop{} SCon{' ', t} stk:
      gc(f, VTop{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{'\t', t} stk:
      gc(f, VTop{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{'\n', t} stk:
      gc(f, VTop{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{'\r', t} stk:
      gc(f, VTop{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{'[', t} stk:
      gc(f, VFirst{}, t, Con{BArr{}, stk}, SCon{'[', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{'{', t} stk:
      gc(f, VObjFirst{}, t, Con{BObj{}, stk}, SCon{'{', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{'"', t} stk:
      gc(f, SStr{}, t, stk, SCon{'"', out}, 0, 0, False{}, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{'-', t} stk:
      gc(f, NMin{}, t, stk, SCon{'-', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{'0', t} stk:
      gc(f, NZero{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{'1', t} stk:
      gc(f, NInt{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{'2', t} stk:
      gc(f, NInt{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{'3', t} stk:
      gc(f, NInt{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{'4', t} stk:
      gc(f, NInt{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{'5', t} stk:
      gc(f, NInt{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{'6', t} stk:
      gc(f, NInt{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{'7', t} stk:
      gc(f, NInt{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{'8', t} stk:
      gc(f, NInt{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{'9', t} stk:
      gc(f, NInt{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{'t', t} stk:
      gc(f, T1{}, t, stk, SCon{'t', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{'f', t} stk:
      gc(f, F1{}, t, stk, SCon{'f', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{'n', t} stk:
      gc(f, U1{}, t, stk, SCon{'n', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VTop{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} VFirst{} SCon{' ', t} stk:
      gc(f, VFirst{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{'\t', t} stk:
      gc(f, VFirst{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{'\n', t} stk:
      gc(f, VFirst{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{'\r', t} stk:
      gc(f, VFirst{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{'[', t} stk:
      gc(f, VFirst{}, t, Con{BArr{}, stk}, SCon{'[', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{'{', t} stk:
      gc(f, VObjFirst{}, t, Con{BObj{}, stk}, SCon{'{', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{'"', t} stk:
      gc(f, SStr{}, t, stk, SCon{'"', out}, 0, 0, False{}, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{'-', t} stk:
      gc(f, NMin{}, t, stk, SCon{'-', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{'0', t} stk:
      gc(f, NZero{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{'1', t} stk:
      gc(f, NInt{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{'2', t} stk:
      gc(f, NInt{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{'3', t} stk:
      gc(f, NInt{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{'4', t} stk:
      gc(f, NInt{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{'5', t} stk:
      gc(f, NInt{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{'6', t} stk:
      gc(f, NInt{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{'7', t} stk:
      gc(f, NInt{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{'8', t} stk:
      gc(f, NInt{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{'9', t} stk:
      gc(f, NInt{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{'t', t} stk:
      gc(f, T1{}, t, stk, SCon{'t', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{'f', t} stk:
      gc(f, F1{}, t, stk, SCon{'f', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{'n', t} stk:
      gc(f, U1{}, t, stk, SCon{'n', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{']', t} Con{_, up}:
      gc(f, VAfter{}, t, up, SCon{']', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VFirst{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} VItem{} SCon{' ', t} stk:
      gc(f, VItem{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{'\t', t} stk:
      gc(f, VItem{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{'\n', t} stk:
      gc(f, VItem{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{'\r', t} stk:
      gc(f, VItem{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{'[', t} stk:
      gc(f, VFirst{}, t, Con{BArr{}, stk}, SCon{'[', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{'{', t} stk:
      gc(f, VObjFirst{}, t, Con{BObj{}, stk}, SCon{'{', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{'"', t} stk:
      gc(f, SStr{}, t, stk, SCon{'"', out}, 0, 0, False{}, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{'-', t} stk:
      gc(f, NMin{}, t, stk, SCon{'-', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{'0', t} stk:
      gc(f, NZero{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{'1', t} stk:
      gc(f, NInt{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{'2', t} stk:
      gc(f, NInt{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{'3', t} stk:
      gc(f, NInt{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{'4', t} stk:
      gc(f, NInt{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{'5', t} stk:
      gc(f, NInt{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{'6', t} stk:
      gc(f, NInt{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{'7', t} stk:
      gc(f, NInt{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{'8', t} stk:
      gc(f, NInt{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{'9', t} stk:
      gc(f, NInt{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{'t', t} stk:
      gc(f, T1{}, t, stk, SCon{'t', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{'f', t} stk:
      gc(f, F1{}, t, stk, SCon{'f', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{'n', t} stk:
      gc(f, U1{}, t, stk, SCon{'n', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VItem{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} VObjVal{} SCon{' ', t} stk:
      gc(f, VObjVal{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{'\t', t} stk:
      gc(f, VObjVal{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{'\n', t} stk:
      gc(f, VObjVal{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{'\r', t} stk:
      gc(f, VObjVal{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{'[', t} stk:
      gc(f, VFirst{}, t, Con{BArr{}, stk}, SCon{'[', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{'{', t} stk:
      gc(f, VObjFirst{}, t, Con{BObj{}, stk}, SCon{'{', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{'"', t} stk:
      gc(f, SStr{}, t, stk, SCon{'"', out}, 0, 0, False{}, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{'-', t} stk:
      gc(f, NMin{}, t, stk, SCon{'-', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{'0', t} stk:
      gc(f, NZero{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{'1', t} stk:
      gc(f, NInt{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{'2', t} stk:
      gc(f, NInt{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{'3', t} stk:
      gc(f, NInt{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{'4', t} stk:
      gc(f, NInt{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{'5', t} stk:
      gc(f, NInt{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{'6', t} stk:
      gc(f, NInt{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{'7', t} stk:
      gc(f, NInt{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{'8', t} stk:
      gc(f, NInt{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{'9', t} stk:
      gc(f, NInt{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{'t', t} stk:
      gc(f, T1{}, t, stk, SCon{'t', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{'f', t} stk:
      gc(f, F1{}, t, stk, SCon{'f', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{'n', t} stk:
      gc(f, U1{}, t, stk, SCon{'n', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjVal{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} VStart{} SCon{' ', t} stk:
      gc(f, VTop{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'\t', t} stk:
      gc(f, VTop{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'\n', t} stk:
      gc(f, VTop{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'\r', t} stk:
      gc(f, VTop{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'[', t} stk:
      gc(f, VFirst{}, t, Con{BArr{}, stk}, SCon{'[', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'{', t} stk:
      gc(f, VObjFirst{}, t, Con{BObj{}, stk}, SCon{'{', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'"', t} stk:
      gc(f, SStr{}, t, stk, SCon{'"', out}, 0, 0, False{}, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'-', t} stk:
      gc(f, NMin{}, t, stk, SCon{'-', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'0', t} stk:
      gc(f, NZero{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'1', t} stk:
      gc(f, NInt{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'2', t} stk:
      gc(f, NInt{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'3', t} stk:
      gc(f, NInt{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'4', t} stk:
      gc(f, NInt{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'5', t} stk:
      gc(f, NInt{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'6', t} stk:
      gc(f, NInt{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'7', t} stk:
      gc(f, NInt{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'8', t} stk:
      gc(f, NInt{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'9', t} stk:
      gc(f, NInt{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'t', t} stk:
      gc(f, T1{}, t, stk, SCon{'t', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'f', t} stk:
      gc(f, F1{}, t, stk, SCon{'f', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'n', t} stk:
      gc(f, U1{}, t, stk, SCon{'n', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{'\u{FEFF}', t} stk:
      gc(f, VTop{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VStart{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} VObjFirst{} SCon{' ', t} stk:
      gc(f, VObjFirst{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjFirst{} SCon{'\t', t} stk:
      gc(f, VObjFirst{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjFirst{} SCon{'\n', t} stk:
      gc(f, VObjFirst{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjFirst{} SCon{'\r', t} stk:
      gc(f, VObjFirst{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VKey{} SCon{' ', t} stk:
      gc(f, VKey{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VKey{} SCon{'\t', t} stk:
      gc(f, VKey{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VKey{} SCon{'\n', t} stk:
      gc(f, VKey{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VKey{} SCon{'\r', t} stk:
      gc(f, VKey{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VColon{} SCon{' ', t} stk:
      gc(f, VColon{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VColon{} SCon{'\t', t} stk:
      gc(f, VColon{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VColon{} SCon{'\n', t} stk:
      gc(f, VColon{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VColon{} SCon{'\r', t} stk:
      gc(f, VColon{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjFirst{} SCon{'"', t} stk:
      gc(f, SStr{}, t, stk, SCon{'"', out}, 0, 0, True{}, (at + 1 : U32), ea)
    case SCon{_, f} VKey{} SCon{'"', t} stk:
      gc(f, SStr{}, t, stk, SCon{'"', out}, 0, 0, True{}, (at + 1 : U32), ea)
    case SCon{_, f} VObjFirst{} SCon{'}', t} Con{_, up}:
      gc(f, VAfter{}, t, up, SCon{'}', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VColon{} SCon{':', t} stk:
      gc(f, VObjVal{}, t, stk, SCon{':', out}, 0, 0, key, (at + 1 : U32), ea)
    case SCon{_, f} VObjFirst{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} VKey{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} VColon{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}

def gp(fuel: String, mode: Mode, s: String, stack: List<&2, Box>, out: String, +hi: U32, +code: U32, +key: Bool, +at: U32, +ea: U32, +d: Nat) -> Out:
  match fuel mode s stack:
    case _ BCtrl{} _ _:
      Err{J.ControlChar{}, ea}
    case _ BUni{} _ _:
      Err{J.InvalidUnicode{}, ea}
    case _ BLone{} _ _:
      Err{J.LoneSurrogate{}, ea}
    case _ BEsc{} _ _:
      Err{J.InvalidEscape{}, ea}
    case _ m SNil{} stk:
      finish(m, stk, out, at)
    case SNil{} _ _ _:
      Err{J.Internal{}, at}
    case SCon{_, f} SStr{} SCon{+c, t} stk:
      +k = J.class(c)
      gp(f, str_mode(k, key), t, stk, str_out(k, c, out), 0, 0, key, (at + 1 : U32), str_ea(k, at, ea), d)
    case SCon{_, f} SEsc{} SCon{+c, t} stk:
      +k = J.class(c)
      gp(f, esc_mode(k, c), t, stk, esc_out(k, c, out), hi, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} SU4{} SCon{+c, t} stk:
      gp(f, hex_mode(hex_digit(c), SU3{}), t, stk, out, hi, hex_add(hex_digit(c), code), key, (at + 1 : U32), ea, d)
    case SCon{_, f} SU3{} SCon{+c, t} stk:
      gp(f, hex_mode(hex_digit(c), SU2{}), t, stk, out, hi, hex_add(hex_digit(c), code), key, (at + 1 : U32), ea, d)
    case SCon{_, f} SU2{} SCon{+c, t} stk:
      gp(f, hex_mode(hex_digit(c), SU1{}), t, stk, out, hi, hex_add(hex_digit(c), code), key, (at + 1 : U32), ea, d)
    case SCon{_, f} SU1{} SCon{+c, t} stk:
      gp(f, u_mode(code_of(c, code), hi), t, stk, u_out(code_of(c, code), hi, out), u_hi(code_of(c, code), hi), 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} SHi{} SCon{'\\', t} stk:
      gp(f, SHiU{}, t, stk, out, hi, 0, key, (at + 1 : U32), at, d)
    case SCon{_, f} SHi{} SCon{+c, _} _:
      Bool.pick(Out, ctrl(c), Err{J.ControlChar{}, at}, Err{J.LoneSurrogate{}, at})
    case SCon{_, f} SHiU{} SCon{'u', t} stk:
      gp(f, SU4{}, t, stk, out, hi, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} SHiU{} SCon{'"', t} _:
      Err{J.LoneSurrogate{}, ea}
    case SCon{_, f} SHiU{} SCon{'\\', t} _:
      Err{J.LoneSurrogate{}, ea}
    case SCon{_, f} SHiU{} SCon{'/', t} _:
      Err{J.LoneSurrogate{}, ea}
    case SCon{_, f} SHiU{} SCon{'b', t} _:
      Err{J.LoneSurrogate{}, ea}
    case SCon{_, f} SHiU{} SCon{'f', t} _:
      Err{J.LoneSurrogate{}, ea}
    case SCon{_, f} SHiU{} SCon{'n', t} _:
      Err{J.LoneSurrogate{}, ea}
    case SCon{_, f} SHiU{} SCon{'r', t} _:
      Err{J.LoneSurrogate{}, ea}
    case SCon{_, f} SHiU{} SCon{'t', t} _:
      Err{J.LoneSurrogate{}, ea}
    case SCon{_, f} SHiU{} _ _:
      Err{J.InvalidEscape{}, ea}
    case SCon{_, f} NInt{} SCon{'0', t} stk:
      gp(f, NInt{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NInt{} SCon{'1', t} stk:
      gp(f, NInt{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NInt{} SCon{'2', t} stk:
      gp(f, NInt{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NInt{} SCon{'3', t} stk:
      gp(f, NInt{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NInt{} SCon{'4', t} stk:
      gp(f, NInt{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NInt{} SCon{'5', t} stk:
      gp(f, NInt{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NInt{} SCon{'6', t} stk:
      gp(f, NInt{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NInt{} SCon{'7', t} stk:
      gp(f, NInt{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NInt{} SCon{'8', t} stk:
      gp(f, NInt{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NInt{} SCon{'9', t} stk:
      gp(f, NInt{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NFrac{} SCon{'0', t} stk:
      gp(f, NFrac{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NFrac{} SCon{'1', t} stk:
      gp(f, NFrac{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NFrac{} SCon{'2', t} stk:
      gp(f, NFrac{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NFrac{} SCon{'3', t} stk:
      gp(f, NFrac{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NFrac{} SCon{'4', t} stk:
      gp(f, NFrac{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NFrac{} SCon{'5', t} stk:
      gp(f, NFrac{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NFrac{} SCon{'6', t} stk:
      gp(f, NFrac{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NFrac{} SCon{'7', t} stk:
      gp(f, NFrac{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NFrac{} SCon{'8', t} stk:
      gp(f, NFrac{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NFrac{} SCon{'9', t} stk:
      gp(f, NFrac{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NExp{} SCon{'0', t} stk:
      gp(f, NExp{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NExp{} SCon{'1', t} stk:
      gp(f, NExp{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NExp{} SCon{'2', t} stk:
      gp(f, NExp{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NExp{} SCon{'3', t} stk:
      gp(f, NExp{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NExp{} SCon{'4', t} stk:
      gp(f, NExp{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NExp{} SCon{'5', t} stk:
      gp(f, NExp{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NExp{} SCon{'6', t} stk:
      gp(f, NExp{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NExp{} SCon{'7', t} stk:
      gp(f, NExp{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NExp{} SCon{'8', t} stk:
      gp(f, NExp{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NExp{} SCon{'9', t} stk:
      gp(f, NExp{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NMin{} SCon{'0', t} stk:
      gp(f, NZero{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NMin{} SCon{'1', t} stk:
      gp(f, NInt{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NMin{} SCon{'2', t} stk:
      gp(f, NInt{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NMin{} SCon{'3', t} stk:
      gp(f, NInt{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NMin{} SCon{'4', t} stk:
      gp(f, NInt{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NMin{} SCon{'5', t} stk:
      gp(f, NInt{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NMin{} SCon{'6', t} stk:
      gp(f, NInt{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NMin{} SCon{'7', t} stk:
      gp(f, NInt{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NMin{} SCon{'8', t} stk:
      gp(f, NInt{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NMin{} SCon{'9', t} stk:
      gp(f, NInt{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NZero{} SCon{'.', t} stk:
      gp(f, NDot{}, t, stk, SCon{'.', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NZero{} SCon{'e', t} stk:
      gp(f, NE{}, t, stk, SCon{'e', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NZero{} SCon{'E', t} stk:
      gp(f, NE{}, t, stk, SCon{'E', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NInt{} SCon{'.', t} stk:
      gp(f, NDot{}, t, stk, SCon{'.', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NInt{} SCon{'e', t} stk:
      gp(f, NE{}, t, stk, SCon{'e', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NInt{} SCon{'E', t} stk:
      gp(f, NE{}, t, stk, SCon{'E', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NFrac{} SCon{'e', t} stk:
      gp(f, NE{}, t, stk, SCon{'e', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NFrac{} SCon{'E', t} stk:
      gp(f, NE{}, t, stk, SCon{'E', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NDot{} SCon{'0', t} stk:
      gp(f, NFrac{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NDot{} SCon{'1', t} stk:
      gp(f, NFrac{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NDot{} SCon{'2', t} stk:
      gp(f, NFrac{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NDot{} SCon{'3', t} stk:
      gp(f, NFrac{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NDot{} SCon{'4', t} stk:
      gp(f, NFrac{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NDot{} SCon{'5', t} stk:
      gp(f, NFrac{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NDot{} SCon{'6', t} stk:
      gp(f, NFrac{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NDot{} SCon{'7', t} stk:
      gp(f, NFrac{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NDot{} SCon{'8', t} stk:
      gp(f, NFrac{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NDot{} SCon{'9', t} stk:
      gp(f, NFrac{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NE{} SCon{'+', t} stk:
      gp(f, NESign{}, t, stk, SCon{'+', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NE{} SCon{'-', t} stk:
      gp(f, NESign{}, t, stk, SCon{'-', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NE{} SCon{'0', t} stk:
      gp(f, NExp{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NESign{} SCon{'0', t} stk:
      gp(f, NExp{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NE{} SCon{'1', t} stk:
      gp(f, NExp{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NESign{} SCon{'1', t} stk:
      gp(f, NExp{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NE{} SCon{'2', t} stk:
      gp(f, NExp{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NESign{} SCon{'2', t} stk:
      gp(f, NExp{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NE{} SCon{'3', t} stk:
      gp(f, NExp{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NESign{} SCon{'3', t} stk:
      gp(f, NExp{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NE{} SCon{'4', t} stk:
      gp(f, NExp{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NESign{} SCon{'4', t} stk:
      gp(f, NExp{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NE{} SCon{'5', t} stk:
      gp(f, NExp{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NESign{} SCon{'5', t} stk:
      gp(f, NExp{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NE{} SCon{'6', t} stk:
      gp(f, NExp{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NESign{} SCon{'6', t} stk:
      gp(f, NExp{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NE{} SCon{'7', t} stk:
      gp(f, NExp{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NESign{} SCon{'7', t} stk:
      gp(f, NExp{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NE{} SCon{'8', t} stk:
      gp(f, NExp{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NESign{} SCon{'8', t} stk:
      gp(f, NExp{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NE{} SCon{'9', t} stk:
      gp(f, NExp{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NESign{} SCon{'9', t} stk:
      gp(f, NExp{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NMin{} _ _:
      Err{J.InvalidNumber{}, at}
    case SCon{_, f} NDot{} _ _:
      Err{J.InvalidNumber{}, at}
    case SCon{_, f} NE{} _ _:
      Err{J.InvalidNumber{}, at}
    case SCon{_, f} NESign{} _ _:
      Err{J.InvalidNumber{}, at}
    case SCon{_, f} VAfter{} SCon{' ', t} stk:
      gp(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VAfter{} SCon{'\t', t} stk:
      gp(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VAfter{} SCon{'\n', t} stk:
      gp(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VAfter{} SCon{'\r', t} stk:
      gp(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VAfter{} SCon{',', t} Con{BArr{}, up}:
      gp(f, VItem{}, t, Con{BArr{}, up}, nl(d, SCon{',', out}), 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VAfter{} SCon{',', t} Con{BObj{}, up}:
      gp(f, VKey{}, t, Con{BObj{}, up}, nl(d, SCon{',', out}), 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VAfter{} SCon{']', t} Con{BArr{}, up}:
      gp(f, VAfter{}, t, up, SCon{']', nl(dec(d), out)}, 0, 0, key, (at + 1 : U32), ea, dec(d))
    case SCon{_, f} VAfter{} SCon{'}', t} Con{BObj{}, up}:
      gp(f, VAfter{}, t, up, SCon{'}', nl(dec(d), out)}, 0, 0, key, (at + 1 : U32), ea, dec(d))
    case SCon{_, f} VAfter{} _ Nil{}:
      Err{J.TrailingInput{}, at}
    case SCon{_, f} VAfter{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} NZero{} SCon{' ', t} stk:
      gp(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NZero{} SCon{'\t', t} stk:
      gp(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NZero{} SCon{'\n', t} stk:
      gp(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NZero{} SCon{'\r', t} stk:
      gp(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NZero{} SCon{',', t} Con{BArr{}, up}:
      gp(f, VItem{}, t, Con{BArr{}, up}, nl(d, SCon{',', out}), 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NZero{} SCon{',', t} Con{BObj{}, up}:
      gp(f, VKey{}, t, Con{BObj{}, up}, nl(d, SCon{',', out}), 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NZero{} SCon{']', t} Con{BArr{}, up}:
      gp(f, VAfter{}, t, up, SCon{']', nl(dec(d), out)}, 0, 0, key, (at + 1 : U32), ea, dec(d))
    case SCon{_, f} NZero{} SCon{'}', t} Con{BObj{}, up}:
      gp(f, VAfter{}, t, up, SCon{'}', nl(dec(d), out)}, 0, 0, key, (at + 1 : U32), ea, dec(d))
    case SCon{_, f} NZero{} _ Nil{}:
      Err{J.TrailingInput{}, at}
    case SCon{_, f} NZero{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} NInt{} SCon{' ', t} stk:
      gp(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NInt{} SCon{'\t', t} stk:
      gp(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NInt{} SCon{'\n', t} stk:
      gp(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NInt{} SCon{'\r', t} stk:
      gp(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NInt{} SCon{',', t} Con{BArr{}, up}:
      gp(f, VItem{}, t, Con{BArr{}, up}, nl(d, SCon{',', out}), 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NInt{} SCon{',', t} Con{BObj{}, up}:
      gp(f, VKey{}, t, Con{BObj{}, up}, nl(d, SCon{',', out}), 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NInt{} SCon{']', t} Con{BArr{}, up}:
      gp(f, VAfter{}, t, up, SCon{']', nl(dec(d), out)}, 0, 0, key, (at + 1 : U32), ea, dec(d))
    case SCon{_, f} NInt{} SCon{'}', t} Con{BObj{}, up}:
      gp(f, VAfter{}, t, up, SCon{'}', nl(dec(d), out)}, 0, 0, key, (at + 1 : U32), ea, dec(d))
    case SCon{_, f} NInt{} _ Nil{}:
      Err{J.TrailingInput{}, at}
    case SCon{_, f} NInt{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} NFrac{} SCon{' ', t} stk:
      gp(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NFrac{} SCon{'\t', t} stk:
      gp(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NFrac{} SCon{'\n', t} stk:
      gp(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NFrac{} SCon{'\r', t} stk:
      gp(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NFrac{} SCon{',', t} Con{BArr{}, up}:
      gp(f, VItem{}, t, Con{BArr{}, up}, nl(d, SCon{',', out}), 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NFrac{} SCon{',', t} Con{BObj{}, up}:
      gp(f, VKey{}, t, Con{BObj{}, up}, nl(d, SCon{',', out}), 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NFrac{} SCon{']', t} Con{BArr{}, up}:
      gp(f, VAfter{}, t, up, SCon{']', nl(dec(d), out)}, 0, 0, key, (at + 1 : U32), ea, dec(d))
    case SCon{_, f} NFrac{} SCon{'}', t} Con{BObj{}, up}:
      gp(f, VAfter{}, t, up, SCon{'}', nl(dec(d), out)}, 0, 0, key, (at + 1 : U32), ea, dec(d))
    case SCon{_, f} NFrac{} _ Nil{}:
      Err{J.TrailingInput{}, at}
    case SCon{_, f} NFrac{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} NExp{} SCon{' ', t} stk:
      gp(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NExp{} SCon{'\t', t} stk:
      gp(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NExp{} SCon{'\n', t} stk:
      gp(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NExp{} SCon{'\r', t} stk:
      gp(f, VAfter{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NExp{} SCon{',', t} Con{BArr{}, up}:
      gp(f, VItem{}, t, Con{BArr{}, up}, nl(d, SCon{',', out}), 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NExp{} SCon{',', t} Con{BObj{}, up}:
      gp(f, VKey{}, t, Con{BObj{}, up}, nl(d, SCon{',', out}), 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} NExp{} SCon{']', t} Con{BArr{}, up}:
      gp(f, VAfter{}, t, up, SCon{']', nl(dec(d), out)}, 0, 0, key, (at + 1 : U32), ea, dec(d))
    case SCon{_, f} NExp{} SCon{'}', t} Con{BObj{}, up}:
      gp(f, VAfter{}, t, up, SCon{'}', nl(dec(d), out)}, 0, 0, key, (at + 1 : U32), ea, dec(d))
    case SCon{_, f} NExp{} _ Nil{}:
      Err{J.TrailingInput{}, at}
    case SCon{_, f} NExp{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} T1{} SCon{'r', t} stk:
      gp(f, T2{}, t, stk, SCon{'r', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} T1{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} T2{} SCon{'u', t} stk:
      gp(f, T3{}, t, stk, SCon{'u', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} T2{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} T3{} SCon{'e', t} stk:
      gp(f, VAfter{}, t, stk, SCon{'e', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} T3{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} F1{} SCon{'a', t} stk:
      gp(f, F2{}, t, stk, SCon{'a', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} F1{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} F2{} SCon{'l', t} stk:
      gp(f, F3{}, t, stk, SCon{'l', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} F2{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} F3{} SCon{'s', t} stk:
      gp(f, F4{}, t, stk, SCon{'s', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} F3{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} F4{} SCon{'e', t} stk:
      gp(f, VAfter{}, t, stk, SCon{'e', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} F4{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} U1{} SCon{'u', t} stk:
      gp(f, U2{}, t, stk, SCon{'u', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} U1{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} U2{} SCon{'l', t} stk:
      gp(f, U3{}, t, stk, SCon{'l', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} U2{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} U3{} SCon{'l', t} stk:
      gp(f, VAfter{}, t, stk, SCon{'l', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} U3{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} VTop{} SCon{' ', t} stk:
      gp(f, VTop{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VTop{} SCon{'\t', t} stk:
      gp(f, VTop{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VTop{} SCon{'\n', t} stk:
      gp(f, VTop{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VTop{} SCon{'\r', t} stk:
      gp(f, VTop{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VTop{} SCon{'[', t} stk:
      gp(f, VFirst{}, t, Con{BArr{}, stk}, SCon{'[', out}, 0, 0, key, (at + 1 : U32), ea, 1n+d)
    case SCon{_, f} VTop{} SCon{'{', t} stk:
      gp(f, VObjFirst{}, t, Con{BObj{}, stk}, SCon{'{', out}, 0, 0, key, (at + 1 : U32), ea, 1n+d)
    case SCon{_, f} VTop{} SCon{'"', t} stk:
      gp(f, SStr{}, t, stk, SCon{'"', out}, 0, 0, False{}, (at + 1 : U32), ea, d)
    case SCon{_, f} VTop{} SCon{'-', t} stk:
      gp(f, NMin{}, t, stk, SCon{'-', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VTop{} SCon{'0', t} stk:
      gp(f, NZero{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VTop{} SCon{'1', t} stk:
      gp(f, NInt{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VTop{} SCon{'2', t} stk:
      gp(f, NInt{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VTop{} SCon{'3', t} stk:
      gp(f, NInt{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VTop{} SCon{'4', t} stk:
      gp(f, NInt{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VTop{} SCon{'5', t} stk:
      gp(f, NInt{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VTop{} SCon{'6', t} stk:
      gp(f, NInt{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VTop{} SCon{'7', t} stk:
      gp(f, NInt{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VTop{} SCon{'8', t} stk:
      gp(f, NInt{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VTop{} SCon{'9', t} stk:
      gp(f, NInt{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VTop{} SCon{'t', t} stk:
      gp(f, T1{}, t, stk, SCon{'t', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VTop{} SCon{'f', t} stk:
      gp(f, F1{}, t, stk, SCon{'f', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VTop{} SCon{'n', t} stk:
      gp(f, U1{}, t, stk, SCon{'n', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VTop{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} VFirst{} SCon{' ', t} stk:
      gp(f, VFirst{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VFirst{} SCon{'\t', t} stk:
      gp(f, VFirst{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VFirst{} SCon{'\n', t} stk:
      gp(f, VFirst{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VFirst{} SCon{'\r', t} stk:
      gp(f, VFirst{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VFirst{} SCon{'[', t} stk:
      gp(f, VFirst{}, t, Con{BArr{}, stk}, SCon{'[', nl(d, out)}, 0, 0, key, (at + 1 : U32), ea, 1n+d)
    case SCon{_, f} VFirst{} SCon{'{', t} stk:
      gp(f, VObjFirst{}, t, Con{BObj{}, stk}, SCon{'{', nl(d, out)}, 0, 0, key, (at + 1 : U32), ea, 1n+d)
    case SCon{_, f} VFirst{} SCon{'"', t} stk:
      gp(f, SStr{}, t, stk, SCon{'"', nl(d, out)}, 0, 0, False{}, (at + 1 : U32), ea, d)
    case SCon{_, f} VFirst{} SCon{'-', t} stk:
      gp(f, NMin{}, t, stk, SCon{'-', nl(d, out)}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VFirst{} SCon{'0', t} stk:
      gp(f, NZero{}, t, stk, SCon{'0', nl(d, out)}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VFirst{} SCon{'1', t} stk:
      gp(f, NInt{}, t, stk, SCon{'1', nl(d, out)}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VFirst{} SCon{'2', t} stk:
      gp(f, NInt{}, t, stk, SCon{'2', nl(d, out)}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VFirst{} SCon{'3', t} stk:
      gp(f, NInt{}, t, stk, SCon{'3', nl(d, out)}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VFirst{} SCon{'4', t} stk:
      gp(f, NInt{}, t, stk, SCon{'4', nl(d, out)}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VFirst{} SCon{'5', t} stk:
      gp(f, NInt{}, t, stk, SCon{'5', nl(d, out)}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VFirst{} SCon{'6', t} stk:
      gp(f, NInt{}, t, stk, SCon{'6', nl(d, out)}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VFirst{} SCon{'7', t} stk:
      gp(f, NInt{}, t, stk, SCon{'7', nl(d, out)}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VFirst{} SCon{'8', t} stk:
      gp(f, NInt{}, t, stk, SCon{'8', nl(d, out)}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VFirst{} SCon{'9', t} stk:
      gp(f, NInt{}, t, stk, SCon{'9', nl(d, out)}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VFirst{} SCon{'t', t} stk:
      gp(f, T1{}, t, stk, SCon{'t', nl(d, out)}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VFirst{} SCon{'f', t} stk:
      gp(f, F1{}, t, stk, SCon{'f', nl(d, out)}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VFirst{} SCon{'n', t} stk:
      gp(f, U1{}, t, stk, SCon{'n', nl(d, out)}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VFirst{} SCon{']', t} Con{_, up}:
      gp(f, VAfter{}, t, up, SCon{']', out}, 0, 0, key, (at + 1 : U32), ea, dec(d))
    case SCon{_, f} VFirst{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} VItem{} SCon{' ', t} stk:
      gp(f, VItem{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VItem{} SCon{'\t', t} stk:
      gp(f, VItem{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VItem{} SCon{'\n', t} stk:
      gp(f, VItem{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VItem{} SCon{'\r', t} stk:
      gp(f, VItem{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VItem{} SCon{'[', t} stk:
      gp(f, VFirst{}, t, Con{BArr{}, stk}, SCon{'[', out}, 0, 0, key, (at + 1 : U32), ea, 1n+d)
    case SCon{_, f} VItem{} SCon{'{', t} stk:
      gp(f, VObjFirst{}, t, Con{BObj{}, stk}, SCon{'{', out}, 0, 0, key, (at + 1 : U32), ea, 1n+d)
    case SCon{_, f} VItem{} SCon{'"', t} stk:
      gp(f, SStr{}, t, stk, SCon{'"', out}, 0, 0, False{}, (at + 1 : U32), ea, d)
    case SCon{_, f} VItem{} SCon{'-', t} stk:
      gp(f, NMin{}, t, stk, SCon{'-', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VItem{} SCon{'0', t} stk:
      gp(f, NZero{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VItem{} SCon{'1', t} stk:
      gp(f, NInt{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VItem{} SCon{'2', t} stk:
      gp(f, NInt{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VItem{} SCon{'3', t} stk:
      gp(f, NInt{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VItem{} SCon{'4', t} stk:
      gp(f, NInt{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VItem{} SCon{'5', t} stk:
      gp(f, NInt{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VItem{} SCon{'6', t} stk:
      gp(f, NInt{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VItem{} SCon{'7', t} stk:
      gp(f, NInt{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VItem{} SCon{'8', t} stk:
      gp(f, NInt{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VItem{} SCon{'9', t} stk:
      gp(f, NInt{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VItem{} SCon{'t', t} stk:
      gp(f, T1{}, t, stk, SCon{'t', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VItem{} SCon{'f', t} stk:
      gp(f, F1{}, t, stk, SCon{'f', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VItem{} SCon{'n', t} stk:
      gp(f, U1{}, t, stk, SCon{'n', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VItem{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} VObjVal{} SCon{' ', t} stk:
      gp(f, VObjVal{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjVal{} SCon{'\t', t} stk:
      gp(f, VObjVal{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjVal{} SCon{'\n', t} stk:
      gp(f, VObjVal{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjVal{} SCon{'\r', t} stk:
      gp(f, VObjVal{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjVal{} SCon{'[', t} stk:
      gp(f, VFirst{}, t, Con{BArr{}, stk}, SCon{'[', out}, 0, 0, key, (at + 1 : U32), ea, 1n+d)
    case SCon{_, f} VObjVal{} SCon{'{', t} stk:
      gp(f, VObjFirst{}, t, Con{BObj{}, stk}, SCon{'{', out}, 0, 0, key, (at + 1 : U32), ea, 1n+d)
    case SCon{_, f} VObjVal{} SCon{'"', t} stk:
      gp(f, SStr{}, t, stk, SCon{'"', out}, 0, 0, False{}, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjVal{} SCon{'-', t} stk:
      gp(f, NMin{}, t, stk, SCon{'-', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjVal{} SCon{'0', t} stk:
      gp(f, NZero{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjVal{} SCon{'1', t} stk:
      gp(f, NInt{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjVal{} SCon{'2', t} stk:
      gp(f, NInt{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjVal{} SCon{'3', t} stk:
      gp(f, NInt{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjVal{} SCon{'4', t} stk:
      gp(f, NInt{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjVal{} SCon{'5', t} stk:
      gp(f, NInt{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjVal{} SCon{'6', t} stk:
      gp(f, NInt{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjVal{} SCon{'7', t} stk:
      gp(f, NInt{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjVal{} SCon{'8', t} stk:
      gp(f, NInt{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjVal{} SCon{'9', t} stk:
      gp(f, NInt{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjVal{} SCon{'t', t} stk:
      gp(f, T1{}, t, stk, SCon{'t', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjVal{} SCon{'f', t} stk:
      gp(f, F1{}, t, stk, SCon{'f', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjVal{} SCon{'n', t} stk:
      gp(f, U1{}, t, stk, SCon{'n', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjVal{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} VStart{} SCon{' ', t} stk:
      gp(f, VTop{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VStart{} SCon{'\t', t} stk:
      gp(f, VTop{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VStart{} SCon{'\n', t} stk:
      gp(f, VTop{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VStart{} SCon{'\r', t} stk:
      gp(f, VTop{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VStart{} SCon{'[', t} stk:
      gp(f, VFirst{}, t, Con{BArr{}, stk}, SCon{'[', out}, 0, 0, key, (at + 1 : U32), ea, 1n+d)
    case SCon{_, f} VStart{} SCon{'{', t} stk:
      gp(f, VObjFirst{}, t, Con{BObj{}, stk}, SCon{'{', out}, 0, 0, key, (at + 1 : U32), ea, 1n+d)
    case SCon{_, f} VStart{} SCon{'"', t} stk:
      gp(f, SStr{}, t, stk, SCon{'"', out}, 0, 0, False{}, (at + 1 : U32), ea, d)
    case SCon{_, f} VStart{} SCon{'-', t} stk:
      gp(f, NMin{}, t, stk, SCon{'-', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VStart{} SCon{'0', t} stk:
      gp(f, NZero{}, t, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VStart{} SCon{'1', t} stk:
      gp(f, NInt{}, t, stk, SCon{'1', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VStart{} SCon{'2', t} stk:
      gp(f, NInt{}, t, stk, SCon{'2', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VStart{} SCon{'3', t} stk:
      gp(f, NInt{}, t, stk, SCon{'3', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VStart{} SCon{'4', t} stk:
      gp(f, NInt{}, t, stk, SCon{'4', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VStart{} SCon{'5', t} stk:
      gp(f, NInt{}, t, stk, SCon{'5', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VStart{} SCon{'6', t} stk:
      gp(f, NInt{}, t, stk, SCon{'6', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VStart{} SCon{'7', t} stk:
      gp(f, NInt{}, t, stk, SCon{'7', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VStart{} SCon{'8', t} stk:
      gp(f, NInt{}, t, stk, SCon{'8', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VStart{} SCon{'9', t} stk:
      gp(f, NInt{}, t, stk, SCon{'9', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VStart{} SCon{'t', t} stk:
      gp(f, T1{}, t, stk, SCon{'t', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VStart{} SCon{'f', t} stk:
      gp(f, F1{}, t, stk, SCon{'f', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VStart{} SCon{'n', t} stk:
      gp(f, U1{}, t, stk, SCon{'n', out}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VStart{} SCon{'\u{FEFF}', t} stk:
      gp(f, VTop{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VStart{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} VObjFirst{} SCon{' ', t} stk:
      gp(f, VObjFirst{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjFirst{} SCon{'\t', t} stk:
      gp(f, VObjFirst{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjFirst{} SCon{'\n', t} stk:
      gp(f, VObjFirst{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjFirst{} SCon{'\r', t} stk:
      gp(f, VObjFirst{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VKey{} SCon{' ', t} stk:
      gp(f, VKey{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VKey{} SCon{'\t', t} stk:
      gp(f, VKey{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VKey{} SCon{'\n', t} stk:
      gp(f, VKey{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VKey{} SCon{'\r', t} stk:
      gp(f, VKey{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VColon{} SCon{' ', t} stk:
      gp(f, VColon{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VColon{} SCon{'\t', t} stk:
      gp(f, VColon{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VColon{} SCon{'\n', t} stk:
      gp(f, VColon{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VColon{} SCon{'\r', t} stk:
      gp(f, VColon{}, t, stk, out, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjFirst{} SCon{'"', t} stk:
      gp(f, SStr{}, t, stk, SCon{'"', nl(d, out)}, 0, 0, True{}, (at + 1 : U32), ea, d)
    case SCon{_, f} VKey{} SCon{'"', t} stk:
      gp(f, SStr{}, t, stk, SCon{'"', out}, 0, 0, True{}, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjFirst{} SCon{'}', t} Con{_, up}:
      gp(f, VAfter{}, t, up, SCon{'}', out}, 0, 0, key, (at + 1 : U32), ea, dec(d))
    case SCon{_, f} VColon{} SCon{':', t} stk:
      gp(f, VObjVal{}, t, stk, SCon{' ', SCon{':', out}}, 0, 0, key, (at + 1 : U32), ea, d)
    case SCon{_, f} VObjFirst{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} VKey{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}
    case SCon{_, f} VColon{} SCon{c, _} _:
      Err{J.UnexpectedChar{c}, at}

# the fuel must be the very list the loop reads: a second list over the
# same chars makes every node shared, which doubles the time
def start.c(+t: String) -> Out:
  gc(t, VStart{}, t, [], "", 0, 0, False{}, 0, 0)

def start.p(+t: String) -> Out:
  gp(t, VStart{}, t, [], "", 0, 0, False{}, 0, 0, 0n)

# compact text, as J.stringify writes it
def reformat(s: String) -> Out:
  start.c(s)

# indented text, as J.pretty(j, "  ") writes it
def pretty(s: String) -> Out:
  start.p(s)
