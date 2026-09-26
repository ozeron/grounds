import Base

# reformat(s) is stringify(parse(s)) in one pass: it checks the input and
# writes the compact text as it reads, without building the Json value.
# Some{text} when s is JSON, None when it is not (J.parse then says why).
# The suite and scripts/integration.py check it against J.parse and
# J.stringify, which PROOF.bend proves round-trip.

# output is built reversed and turned around once at the end

type Box is Data:
  BArr{}
  BObj{}

# what may come next; strings and numbers are read a char at a time.
# Every mode is a plain tag: a case that looks two chars ahead makes the
# compiler test the next char for every char, which halves the speed
type Mode is Data:
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
  Bad{}

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

# after a \u escape: its output, the pending high surrogate, and whether
# it was wrong
type U is Data:
  U{out: String, hi: U32, bad: Bool}

def u_out(u: U) -> String:
  match u:
    case U{o, _, _}:
      o

def u_hi(u: U) -> U32:
  match u:
    case U{_, h, _}:
      h

def u_bad(u: U) -> Bool:
  match u:
    case U{_, _, b}:
      b

# a low surrogate: with its high half it makes one char; alone it is an
# error, and nothing is built (the pair of nothing is not a char)
def low(pend: Bool, +hi: U32, +x: U32, out: String) -> U:
  match pend:
    case True{}:
      U{emit_code(pair(hi, x), out), 0, False{}}
    case False{}:
      U{out, 0, True{}}

def u_code.go(k: Surr, +hi: U32, +x: U32, out: String) -> U:
  match k:
    case NotSurr{}:
      U{emit_code(x, out), 0, pending(hi)}
    case High{}:
      U{out, x, pending(hi)}
    case Low{}:
      low(pending(hi), hi, x, out)

def u_code(m: Maybe<&2, U32>, +hi: U32, out: String) -> U:
  match m:
    case None{}:
      U{out, 0, True{}}
    case Some{+x}:
      u_code.go(surr(x), hi, x, out)

# where a string ends: a value, or a key before its colon
def close_mode(key: Bool) -> Mode:
  match key:
    case True{}:
      VColon{}
    case False{}:
      VAfter{}

# the mode after a \u escape: back in the string, or waiting for the low
# half of a surrogate pair
def u_mode.go(none: Bool) -> Mode:
  match none:
    case True{}:
      SStr{}
    case False{}:
      SHi{}

def u_mode(+hi: U32) -> Mode:
  u_mode.go(U32.is_eq(hi, 0))

# a hex digit of a \u escape: the next mode, or Bad
def hex_mode(d: Maybe<&2, U32>, next: Mode) -> Mode:
  match d:
    case Some{_}:
      next
    case None{}:
      Bad{}

def hex_add(d: Maybe<&2, U32>, +code: U32) -> U32:
  match d:
    case Some{v}:
      (code * 16 + v : U32)
    case None{}:
      0

# the fourth hex digit: the code is complete
def u_last.go(d: Maybe<&2, U32>, +code: U32, +hi: U32, out: String) -> U:
  match d:
    case Some{v}:
      u_code(Some{(code * 16 + v : U32)}, hi, out)
    case None{}:
      U{out, 0, True{}}

def finish(mode: Mode, stack: List<&2, Box>, out: String, bad: Bool) -> Maybe<&2, String>:
  match mode stack bad:
    case _ _ True{}:
      None{}
    case VAfter{} Nil{} False{}:
      Some{String.reverse(out)}
    case NZero{} Nil{} False{}:
      Some{String.reverse(out)}
    case NInt{} Nil{} False{}:
      Some{String.reverse(out)}
    case NFrac{} Nil{} False{}:
      Some{String.reverse(out)}
    case NExp{} Nil{} False{}:
      Some{String.reverse(out)}
    case _ _ _:
      None{}

# generated by scripts/gen_fast.py; do not edit

# one char, or one escape or literal, per call; fuel is the input itself,
# so it never runs out first. bad records a control char seen in a string,
# hi a pending high surrogate, code the \u digits so far, key whether the
# string is an object key
def go(fuel: String, mode: Mode, s: String, stack: List<&2, Box>, out: String, +bad: Bool, +hi: U32, +code: U32, +key: Bool) -> Maybe<&2, String>:
  match fuel mode s stack:
    case _ Bad{} _ _:
      None{}
    case _ m SNil{} stk:
      finish(m, stk, out, bad)
    case SNil{} _ _ _:
      None{}
    case SCon{_, f} SStr{} SCon{'"', t} stk:
      go(f, close_mode(key), t, stk, SCon{'"', out}, bad, 0, 0, key)
    case SCon{_, f} SStr{} SCon{'\\', t} stk:
      go(f, SEsc{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} SStr{} SCon{+c, t} stk:
      go(f, SStr{}, t, stk, SCon{c, out}, Bool.or(bad, ctrl(c)), 0, 0, key)
    case SCon{_, f} SEsc{} SCon{'"', t} stk:
      go(f, SStr{}, t, stk, SCon{'"', SCon{'\\', out}}, bad, 0, 0, key)
    case SCon{_, f} SEsc{} SCon{'\\', t} stk:
      go(f, SStr{}, t, stk, SCon{'\\', SCon{'\\', out}}, bad, 0, 0, key)
    case SCon{_, f} SEsc{} SCon{'/', t} stk:
      go(f, SStr{}, t, stk, SCon{'/', out}, bad, 0, 0, key)
    case SCon{_, f} SEsc{} SCon{'b', t} stk:
      go(f, SStr{}, t, stk, SCon{'b', SCon{'\\', out}}, bad, 0, 0, key)
    case SCon{_, f} SEsc{} SCon{'f', t} stk:
      go(f, SStr{}, t, stk, SCon{'f', SCon{'\\', out}}, bad, 0, 0, key)
    case SCon{_, f} SEsc{} SCon{'n', t} stk:
      go(f, SStr{}, t, stk, SCon{'n', SCon{'\\', out}}, bad, 0, 0, key)
    case SCon{_, f} SEsc{} SCon{'r', t} stk:
      go(f, SStr{}, t, stk, SCon{'r', SCon{'\\', out}}, bad, 0, 0, key)
    case SCon{_, f} SEsc{} SCon{'t', t} stk:
      go(f, SStr{}, t, stk, SCon{'t', SCon{'\\', out}}, bad, 0, 0, key)
    case SCon{_, f} SEsc{} SCon{'u', t} stk:
      go(f, SU4{}, t, stk, out, bad, hi, 0, key)
    case SCon{_, f} SEsc{} _ _:
      None{}
    case SCon{_, f} SU4{} SCon{+c, t} stk:
      go(f, hex_mode(hex_digit(c), SU3{}), t, stk, out, bad, hi, hex_add(hex_digit(c), code), key)
    case SCon{_, f} SU3{} SCon{+c, t} stk:
      go(f, hex_mode(hex_digit(c), SU2{}), t, stk, out, bad, hi, hex_add(hex_digit(c), code), key)
    case SCon{_, f} SU2{} SCon{+c, t} stk:
      go(f, hex_mode(hex_digit(c), SU1{}), t, stk, out, bad, hi, hex_add(hex_digit(c), code), key)
    case SCon{_, f} SU1{} SCon{+c, t} stk:
      go(f, u_mode(u_hi(u_last.go(hex_digit(c), code, hi, ""))), t, stk, u_out(u_last.go(hex_digit(c), code, hi, out)), Bool.or(bad, u_bad(u_last.go(hex_digit(c), code, hi, ""))), u_hi(u_last.go(hex_digit(c), code, hi, "")), 0, key)
    case SCon{_, f} SHi{} SCon{'\\', t} stk:
      go(f, SHiU{}, t, stk, out, bad, hi, 0, key)
    case SCon{_, f} SHi{} _ _:
      None{}
    case SCon{_, f} SHiU{} SCon{'u', t} stk:
      go(f, SU4{}, t, stk, out, bad, hi, 0, key)
    case SCon{_, f} SHiU{} _ _:
      None{}
    case SCon{_, f} NInt{} SCon{'0', t} stk:
      go(f, NInt{}, t, stk, SCon{'0', out}, bad, 0, 0, key)
    case SCon{_, f} NInt{} SCon{'1', t} stk:
      go(f, NInt{}, t, stk, SCon{'1', out}, bad, 0, 0, key)
    case SCon{_, f} NInt{} SCon{'2', t} stk:
      go(f, NInt{}, t, stk, SCon{'2', out}, bad, 0, 0, key)
    case SCon{_, f} NInt{} SCon{'3', t} stk:
      go(f, NInt{}, t, stk, SCon{'3', out}, bad, 0, 0, key)
    case SCon{_, f} NInt{} SCon{'4', t} stk:
      go(f, NInt{}, t, stk, SCon{'4', out}, bad, 0, 0, key)
    case SCon{_, f} NInt{} SCon{'5', t} stk:
      go(f, NInt{}, t, stk, SCon{'5', out}, bad, 0, 0, key)
    case SCon{_, f} NInt{} SCon{'6', t} stk:
      go(f, NInt{}, t, stk, SCon{'6', out}, bad, 0, 0, key)
    case SCon{_, f} NInt{} SCon{'7', t} stk:
      go(f, NInt{}, t, stk, SCon{'7', out}, bad, 0, 0, key)
    case SCon{_, f} NInt{} SCon{'8', t} stk:
      go(f, NInt{}, t, stk, SCon{'8', out}, bad, 0, 0, key)
    case SCon{_, f} NInt{} SCon{'9', t} stk:
      go(f, NInt{}, t, stk, SCon{'9', out}, bad, 0, 0, key)
    case SCon{_, f} NFrac{} SCon{'0', t} stk:
      go(f, NFrac{}, t, stk, SCon{'0', out}, bad, 0, 0, key)
    case SCon{_, f} NFrac{} SCon{'1', t} stk:
      go(f, NFrac{}, t, stk, SCon{'1', out}, bad, 0, 0, key)
    case SCon{_, f} NFrac{} SCon{'2', t} stk:
      go(f, NFrac{}, t, stk, SCon{'2', out}, bad, 0, 0, key)
    case SCon{_, f} NFrac{} SCon{'3', t} stk:
      go(f, NFrac{}, t, stk, SCon{'3', out}, bad, 0, 0, key)
    case SCon{_, f} NFrac{} SCon{'4', t} stk:
      go(f, NFrac{}, t, stk, SCon{'4', out}, bad, 0, 0, key)
    case SCon{_, f} NFrac{} SCon{'5', t} stk:
      go(f, NFrac{}, t, stk, SCon{'5', out}, bad, 0, 0, key)
    case SCon{_, f} NFrac{} SCon{'6', t} stk:
      go(f, NFrac{}, t, stk, SCon{'6', out}, bad, 0, 0, key)
    case SCon{_, f} NFrac{} SCon{'7', t} stk:
      go(f, NFrac{}, t, stk, SCon{'7', out}, bad, 0, 0, key)
    case SCon{_, f} NFrac{} SCon{'8', t} stk:
      go(f, NFrac{}, t, stk, SCon{'8', out}, bad, 0, 0, key)
    case SCon{_, f} NFrac{} SCon{'9', t} stk:
      go(f, NFrac{}, t, stk, SCon{'9', out}, bad, 0, 0, key)
    case SCon{_, f} NExp{} SCon{'0', t} stk:
      go(f, NExp{}, t, stk, SCon{'0', out}, bad, 0, 0, key)
    case SCon{_, f} NExp{} SCon{'1', t} stk:
      go(f, NExp{}, t, stk, SCon{'1', out}, bad, 0, 0, key)
    case SCon{_, f} NExp{} SCon{'2', t} stk:
      go(f, NExp{}, t, stk, SCon{'2', out}, bad, 0, 0, key)
    case SCon{_, f} NExp{} SCon{'3', t} stk:
      go(f, NExp{}, t, stk, SCon{'3', out}, bad, 0, 0, key)
    case SCon{_, f} NExp{} SCon{'4', t} stk:
      go(f, NExp{}, t, stk, SCon{'4', out}, bad, 0, 0, key)
    case SCon{_, f} NExp{} SCon{'5', t} stk:
      go(f, NExp{}, t, stk, SCon{'5', out}, bad, 0, 0, key)
    case SCon{_, f} NExp{} SCon{'6', t} stk:
      go(f, NExp{}, t, stk, SCon{'6', out}, bad, 0, 0, key)
    case SCon{_, f} NExp{} SCon{'7', t} stk:
      go(f, NExp{}, t, stk, SCon{'7', out}, bad, 0, 0, key)
    case SCon{_, f} NExp{} SCon{'8', t} stk:
      go(f, NExp{}, t, stk, SCon{'8', out}, bad, 0, 0, key)
    case SCon{_, f} NExp{} SCon{'9', t} stk:
      go(f, NExp{}, t, stk, SCon{'9', out}, bad, 0, 0, key)
    case SCon{_, f} NMin{} SCon{'0', t} stk:
      go(f, NZero{}, t, stk, SCon{'0', out}, bad, 0, 0, key)
    case SCon{_, f} NMin{} SCon{'1', t} stk:
      go(f, NInt{}, t, stk, SCon{'1', out}, bad, 0, 0, key)
    case SCon{_, f} NMin{} SCon{'2', t} stk:
      go(f, NInt{}, t, stk, SCon{'2', out}, bad, 0, 0, key)
    case SCon{_, f} NMin{} SCon{'3', t} stk:
      go(f, NInt{}, t, stk, SCon{'3', out}, bad, 0, 0, key)
    case SCon{_, f} NMin{} SCon{'4', t} stk:
      go(f, NInt{}, t, stk, SCon{'4', out}, bad, 0, 0, key)
    case SCon{_, f} NMin{} SCon{'5', t} stk:
      go(f, NInt{}, t, stk, SCon{'5', out}, bad, 0, 0, key)
    case SCon{_, f} NMin{} SCon{'6', t} stk:
      go(f, NInt{}, t, stk, SCon{'6', out}, bad, 0, 0, key)
    case SCon{_, f} NMin{} SCon{'7', t} stk:
      go(f, NInt{}, t, stk, SCon{'7', out}, bad, 0, 0, key)
    case SCon{_, f} NMin{} SCon{'8', t} stk:
      go(f, NInt{}, t, stk, SCon{'8', out}, bad, 0, 0, key)
    case SCon{_, f} NMin{} SCon{'9', t} stk:
      go(f, NInt{}, t, stk, SCon{'9', out}, bad, 0, 0, key)
    case SCon{_, f} NMin{} _ _:
      None{}
    case SCon{_, f} NZero{} SCon{'.', t} stk:
      go(f, NDot{}, t, stk, SCon{'.', out}, bad, 0, 0, key)
    case SCon{_, f} NZero{} SCon{'e', t} stk:
      go(f, NE{}, t, stk, SCon{'e', out}, bad, 0, 0, key)
    case SCon{_, f} NZero{} SCon{'E', t} stk:
      go(f, NE{}, t, stk, SCon{'E', out}, bad, 0, 0, key)
    case SCon{_, f} NInt{} SCon{'.', t} stk:
      go(f, NDot{}, t, stk, SCon{'.', out}, bad, 0, 0, key)
    case SCon{_, f} NInt{} SCon{'e', t} stk:
      go(f, NE{}, t, stk, SCon{'e', out}, bad, 0, 0, key)
    case SCon{_, f} NInt{} SCon{'E', t} stk:
      go(f, NE{}, t, stk, SCon{'E', out}, bad, 0, 0, key)
    case SCon{_, f} NFrac{} SCon{'e', t} stk:
      go(f, NE{}, t, stk, SCon{'e', out}, bad, 0, 0, key)
    case SCon{_, f} NFrac{} SCon{'E', t} stk:
      go(f, NE{}, t, stk, SCon{'E', out}, bad, 0, 0, key)
    case SCon{_, f} NDot{} SCon{'0', t} stk:
      go(f, NFrac{}, t, stk, SCon{'0', out}, bad, 0, 0, key)
    case SCon{_, f} NDot{} SCon{'1', t} stk:
      go(f, NFrac{}, t, stk, SCon{'1', out}, bad, 0, 0, key)
    case SCon{_, f} NDot{} SCon{'2', t} stk:
      go(f, NFrac{}, t, stk, SCon{'2', out}, bad, 0, 0, key)
    case SCon{_, f} NDot{} SCon{'3', t} stk:
      go(f, NFrac{}, t, stk, SCon{'3', out}, bad, 0, 0, key)
    case SCon{_, f} NDot{} SCon{'4', t} stk:
      go(f, NFrac{}, t, stk, SCon{'4', out}, bad, 0, 0, key)
    case SCon{_, f} NDot{} SCon{'5', t} stk:
      go(f, NFrac{}, t, stk, SCon{'5', out}, bad, 0, 0, key)
    case SCon{_, f} NDot{} SCon{'6', t} stk:
      go(f, NFrac{}, t, stk, SCon{'6', out}, bad, 0, 0, key)
    case SCon{_, f} NDot{} SCon{'7', t} stk:
      go(f, NFrac{}, t, stk, SCon{'7', out}, bad, 0, 0, key)
    case SCon{_, f} NDot{} SCon{'8', t} stk:
      go(f, NFrac{}, t, stk, SCon{'8', out}, bad, 0, 0, key)
    case SCon{_, f} NDot{} SCon{'9', t} stk:
      go(f, NFrac{}, t, stk, SCon{'9', out}, bad, 0, 0, key)
    case SCon{_, f} NDot{} _ _:
      None{}
    case SCon{_, f} NE{} SCon{'+', t} stk:
      go(f, NESign{}, t, stk, SCon{'+', out}, bad, 0, 0, key)
    case SCon{_, f} NE{} SCon{'-', t} stk:
      go(f, NESign{}, t, stk, SCon{'-', out}, bad, 0, 0, key)
    case SCon{_, f} NE{} SCon{'0', t} stk:
      go(f, NExp{}, t, stk, SCon{'0', out}, bad, 0, 0, key)
    case SCon{_, f} NE{} SCon{'1', t} stk:
      go(f, NExp{}, t, stk, SCon{'1', out}, bad, 0, 0, key)
    case SCon{_, f} NE{} SCon{'2', t} stk:
      go(f, NExp{}, t, stk, SCon{'2', out}, bad, 0, 0, key)
    case SCon{_, f} NE{} SCon{'3', t} stk:
      go(f, NExp{}, t, stk, SCon{'3', out}, bad, 0, 0, key)
    case SCon{_, f} NE{} SCon{'4', t} stk:
      go(f, NExp{}, t, stk, SCon{'4', out}, bad, 0, 0, key)
    case SCon{_, f} NE{} SCon{'5', t} stk:
      go(f, NExp{}, t, stk, SCon{'5', out}, bad, 0, 0, key)
    case SCon{_, f} NE{} SCon{'6', t} stk:
      go(f, NExp{}, t, stk, SCon{'6', out}, bad, 0, 0, key)
    case SCon{_, f} NE{} SCon{'7', t} stk:
      go(f, NExp{}, t, stk, SCon{'7', out}, bad, 0, 0, key)
    case SCon{_, f} NE{} SCon{'8', t} stk:
      go(f, NExp{}, t, stk, SCon{'8', out}, bad, 0, 0, key)
    case SCon{_, f} NE{} SCon{'9', t} stk:
      go(f, NExp{}, t, stk, SCon{'9', out}, bad, 0, 0, key)
    case SCon{_, f} NE{} _ _:
      None{}
    case SCon{_, f} NESign{} SCon{'0', t} stk:
      go(f, NExp{}, t, stk, SCon{'0', out}, bad, 0, 0, key)
    case SCon{_, f} NESign{} SCon{'1', t} stk:
      go(f, NExp{}, t, stk, SCon{'1', out}, bad, 0, 0, key)
    case SCon{_, f} NESign{} SCon{'2', t} stk:
      go(f, NExp{}, t, stk, SCon{'2', out}, bad, 0, 0, key)
    case SCon{_, f} NESign{} SCon{'3', t} stk:
      go(f, NExp{}, t, stk, SCon{'3', out}, bad, 0, 0, key)
    case SCon{_, f} NESign{} SCon{'4', t} stk:
      go(f, NExp{}, t, stk, SCon{'4', out}, bad, 0, 0, key)
    case SCon{_, f} NESign{} SCon{'5', t} stk:
      go(f, NExp{}, t, stk, SCon{'5', out}, bad, 0, 0, key)
    case SCon{_, f} NESign{} SCon{'6', t} stk:
      go(f, NExp{}, t, stk, SCon{'6', out}, bad, 0, 0, key)
    case SCon{_, f} NESign{} SCon{'7', t} stk:
      go(f, NExp{}, t, stk, SCon{'7', out}, bad, 0, 0, key)
    case SCon{_, f} NESign{} SCon{'8', t} stk:
      go(f, NExp{}, t, stk, SCon{'8', out}, bad, 0, 0, key)
    case SCon{_, f} NESign{} SCon{'9', t} stk:
      go(f, NExp{}, t, stk, SCon{'9', out}, bad, 0, 0, key)
    case SCon{_, f} NESign{} _ _:
      None{}
    case SCon{_, f} VAfter{} SCon{' ', t} stk:
      go(f, VAfter{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VAfter{} SCon{'\t', t} stk:
      go(f, VAfter{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VAfter{} SCon{'\n', t} stk:
      go(f, VAfter{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VAfter{} SCon{'\r', t} stk:
      go(f, VAfter{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VAfter{} SCon{',', t} Con{BArr{}, up}:
      go(f, VItem{}, t, Con{BArr{}, up}, SCon{',', out}, bad, 0, 0, key)
    case SCon{_, f} VAfter{} SCon{',', t} Con{BObj{}, up}:
      go(f, VKey{}, t, Con{BObj{}, up}, SCon{',', out}, bad, 0, 0, key)
    case SCon{_, f} VAfter{} SCon{']', t} Con{BArr{}, up}:
      go(f, VAfter{}, t, up, SCon{']', out}, bad, 0, 0, key)
    case SCon{_, f} VAfter{} SCon{'}', t} Con{BObj{}, up}:
      go(f, VAfter{}, t, up, SCon{'}', out}, bad, 0, 0, key)
    case SCon{_, f} VAfter{} _ _:
      None{}
    case SCon{_, f} NZero{} SCon{' ', t} stk:
      go(f, VAfter{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} NZero{} SCon{'\t', t} stk:
      go(f, VAfter{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} NZero{} SCon{'\n', t} stk:
      go(f, VAfter{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} NZero{} SCon{'\r', t} stk:
      go(f, VAfter{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} NZero{} SCon{',', t} Con{BArr{}, up}:
      go(f, VItem{}, t, Con{BArr{}, up}, SCon{',', out}, bad, 0, 0, key)
    case SCon{_, f} NZero{} SCon{',', t} Con{BObj{}, up}:
      go(f, VKey{}, t, Con{BObj{}, up}, SCon{',', out}, bad, 0, 0, key)
    case SCon{_, f} NZero{} SCon{']', t} Con{BArr{}, up}:
      go(f, VAfter{}, t, up, SCon{']', out}, bad, 0, 0, key)
    case SCon{_, f} NZero{} SCon{'}', t} Con{BObj{}, up}:
      go(f, VAfter{}, t, up, SCon{'}', out}, bad, 0, 0, key)
    case SCon{_, f} NZero{} _ _:
      None{}
    case SCon{_, f} NInt{} SCon{' ', t} stk:
      go(f, VAfter{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} NInt{} SCon{'\t', t} stk:
      go(f, VAfter{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} NInt{} SCon{'\n', t} stk:
      go(f, VAfter{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} NInt{} SCon{'\r', t} stk:
      go(f, VAfter{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} NInt{} SCon{',', t} Con{BArr{}, up}:
      go(f, VItem{}, t, Con{BArr{}, up}, SCon{',', out}, bad, 0, 0, key)
    case SCon{_, f} NInt{} SCon{',', t} Con{BObj{}, up}:
      go(f, VKey{}, t, Con{BObj{}, up}, SCon{',', out}, bad, 0, 0, key)
    case SCon{_, f} NInt{} SCon{']', t} Con{BArr{}, up}:
      go(f, VAfter{}, t, up, SCon{']', out}, bad, 0, 0, key)
    case SCon{_, f} NInt{} SCon{'}', t} Con{BObj{}, up}:
      go(f, VAfter{}, t, up, SCon{'}', out}, bad, 0, 0, key)
    case SCon{_, f} NInt{} _ _:
      None{}
    case SCon{_, f} NFrac{} SCon{' ', t} stk:
      go(f, VAfter{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} NFrac{} SCon{'\t', t} stk:
      go(f, VAfter{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} NFrac{} SCon{'\n', t} stk:
      go(f, VAfter{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} NFrac{} SCon{'\r', t} stk:
      go(f, VAfter{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} NFrac{} SCon{',', t} Con{BArr{}, up}:
      go(f, VItem{}, t, Con{BArr{}, up}, SCon{',', out}, bad, 0, 0, key)
    case SCon{_, f} NFrac{} SCon{',', t} Con{BObj{}, up}:
      go(f, VKey{}, t, Con{BObj{}, up}, SCon{',', out}, bad, 0, 0, key)
    case SCon{_, f} NFrac{} SCon{']', t} Con{BArr{}, up}:
      go(f, VAfter{}, t, up, SCon{']', out}, bad, 0, 0, key)
    case SCon{_, f} NFrac{} SCon{'}', t} Con{BObj{}, up}:
      go(f, VAfter{}, t, up, SCon{'}', out}, bad, 0, 0, key)
    case SCon{_, f} NFrac{} _ _:
      None{}
    case SCon{_, f} NExp{} SCon{' ', t} stk:
      go(f, VAfter{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} NExp{} SCon{'\t', t} stk:
      go(f, VAfter{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} NExp{} SCon{'\n', t} stk:
      go(f, VAfter{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} NExp{} SCon{'\r', t} stk:
      go(f, VAfter{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} NExp{} SCon{',', t} Con{BArr{}, up}:
      go(f, VItem{}, t, Con{BArr{}, up}, SCon{',', out}, bad, 0, 0, key)
    case SCon{_, f} NExp{} SCon{',', t} Con{BObj{}, up}:
      go(f, VKey{}, t, Con{BObj{}, up}, SCon{',', out}, bad, 0, 0, key)
    case SCon{_, f} NExp{} SCon{']', t} Con{BArr{}, up}:
      go(f, VAfter{}, t, up, SCon{']', out}, bad, 0, 0, key)
    case SCon{_, f} NExp{} SCon{'}', t} Con{BObj{}, up}:
      go(f, VAfter{}, t, up, SCon{'}', out}, bad, 0, 0, key)
    case SCon{_, f} NExp{} _ _:
      None{}
    case SCon{_, f} T1{} SCon{'r', t} stk:
      go(f, T2{}, t, stk, SCon{'r', out}, bad, 0, 0, key)
    case SCon{_, f} T1{} _ _:
      None{}
    case SCon{_, f} T2{} SCon{'u', t} stk:
      go(f, T3{}, t, stk, SCon{'u', out}, bad, 0, 0, key)
    case SCon{_, f} T2{} _ _:
      None{}
    case SCon{_, f} T3{} SCon{'e', t} stk:
      go(f, VAfter{}, t, stk, SCon{'e', out}, bad, 0, 0, key)
    case SCon{_, f} T3{} _ _:
      None{}
    case SCon{_, f} F1{} SCon{'a', t} stk:
      go(f, F2{}, t, stk, SCon{'a', out}, bad, 0, 0, key)
    case SCon{_, f} F1{} _ _:
      None{}
    case SCon{_, f} F2{} SCon{'l', t} stk:
      go(f, F3{}, t, stk, SCon{'l', out}, bad, 0, 0, key)
    case SCon{_, f} F2{} _ _:
      None{}
    case SCon{_, f} F3{} SCon{'s', t} stk:
      go(f, F4{}, t, stk, SCon{'s', out}, bad, 0, 0, key)
    case SCon{_, f} F3{} _ _:
      None{}
    case SCon{_, f} F4{} SCon{'e', t} stk:
      go(f, VAfter{}, t, stk, SCon{'e', out}, bad, 0, 0, key)
    case SCon{_, f} F4{} _ _:
      None{}
    case SCon{_, f} U1{} SCon{'u', t} stk:
      go(f, U2{}, t, stk, SCon{'u', out}, bad, 0, 0, key)
    case SCon{_, f} U1{} _ _:
      None{}
    case SCon{_, f} U2{} SCon{'l', t} stk:
      go(f, U3{}, t, stk, SCon{'l', out}, bad, 0, 0, key)
    case SCon{_, f} U2{} _ _:
      None{}
    case SCon{_, f} U3{} SCon{'l', t} stk:
      go(f, VAfter{}, t, stk, SCon{'l', out}, bad, 0, 0, key)
    case SCon{_, f} U3{} _ _:
      None{}
    case SCon{_, f} VTop{} SCon{' ', t} stk:
      go(f, VTop{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VTop{} SCon{'\t', t} stk:
      go(f, VTop{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VTop{} SCon{'\n', t} stk:
      go(f, VTop{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VTop{} SCon{'\r', t} stk:
      go(f, VTop{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VTop{} SCon{'[', t} stk:
      go(f, VFirst{}, t, Con{BArr{}, stk}, SCon{'[', out}, bad, 0, 0, key)
    case SCon{_, f} VTop{} SCon{'{', t} stk:
      go(f, VObjFirst{}, t, Con{BObj{}, stk}, SCon{'{', out}, bad, 0, 0, key)
    case SCon{_, f} VTop{} SCon{'"', t} stk:
      go(f, SStr{}, t, stk, SCon{'"', out}, bad, 0, 0, False{})
    case SCon{_, f} VTop{} SCon{'-', t} stk:
      go(f, NMin{}, t, stk, SCon{'-', out}, bad, 0, 0, key)
    case SCon{_, f} VTop{} SCon{'0', t} stk:
      go(f, NZero{}, t, stk, SCon{'0', out}, bad, 0, 0, key)
    case SCon{_, f} VTop{} SCon{'1', t} stk:
      go(f, NInt{}, t, stk, SCon{'1', out}, bad, 0, 0, key)
    case SCon{_, f} VTop{} SCon{'2', t} stk:
      go(f, NInt{}, t, stk, SCon{'2', out}, bad, 0, 0, key)
    case SCon{_, f} VTop{} SCon{'3', t} stk:
      go(f, NInt{}, t, stk, SCon{'3', out}, bad, 0, 0, key)
    case SCon{_, f} VTop{} SCon{'4', t} stk:
      go(f, NInt{}, t, stk, SCon{'4', out}, bad, 0, 0, key)
    case SCon{_, f} VTop{} SCon{'5', t} stk:
      go(f, NInt{}, t, stk, SCon{'5', out}, bad, 0, 0, key)
    case SCon{_, f} VTop{} SCon{'6', t} stk:
      go(f, NInt{}, t, stk, SCon{'6', out}, bad, 0, 0, key)
    case SCon{_, f} VTop{} SCon{'7', t} stk:
      go(f, NInt{}, t, stk, SCon{'7', out}, bad, 0, 0, key)
    case SCon{_, f} VTop{} SCon{'8', t} stk:
      go(f, NInt{}, t, stk, SCon{'8', out}, bad, 0, 0, key)
    case SCon{_, f} VTop{} SCon{'9', t} stk:
      go(f, NInt{}, t, stk, SCon{'9', out}, bad, 0, 0, key)
    case SCon{_, f} VTop{} SCon{'t', t} stk:
      go(f, T1{}, t, stk, SCon{'t', out}, bad, 0, 0, key)
    case SCon{_, f} VTop{} SCon{'f', t} stk:
      go(f, F1{}, t, stk, SCon{'f', out}, bad, 0, 0, key)
    case SCon{_, f} VTop{} SCon{'n', t} stk:
      go(f, U1{}, t, stk, SCon{'n', out}, bad, 0, 0, key)
    case SCon{_, f} VTop{} _ _:
      None{}
    case SCon{_, f} VFirst{} SCon{' ', t} stk:
      go(f, VFirst{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VFirst{} SCon{'\t', t} stk:
      go(f, VFirst{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VFirst{} SCon{'\n', t} stk:
      go(f, VFirst{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VFirst{} SCon{'\r', t} stk:
      go(f, VFirst{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VFirst{} SCon{'[', t} stk:
      go(f, VFirst{}, t, Con{BArr{}, stk}, SCon{'[', out}, bad, 0, 0, key)
    case SCon{_, f} VFirst{} SCon{'{', t} stk:
      go(f, VObjFirst{}, t, Con{BObj{}, stk}, SCon{'{', out}, bad, 0, 0, key)
    case SCon{_, f} VFirst{} SCon{'"', t} stk:
      go(f, SStr{}, t, stk, SCon{'"', out}, bad, 0, 0, False{})
    case SCon{_, f} VFirst{} SCon{'-', t} stk:
      go(f, NMin{}, t, stk, SCon{'-', out}, bad, 0, 0, key)
    case SCon{_, f} VFirst{} SCon{'0', t} stk:
      go(f, NZero{}, t, stk, SCon{'0', out}, bad, 0, 0, key)
    case SCon{_, f} VFirst{} SCon{'1', t} stk:
      go(f, NInt{}, t, stk, SCon{'1', out}, bad, 0, 0, key)
    case SCon{_, f} VFirst{} SCon{'2', t} stk:
      go(f, NInt{}, t, stk, SCon{'2', out}, bad, 0, 0, key)
    case SCon{_, f} VFirst{} SCon{'3', t} stk:
      go(f, NInt{}, t, stk, SCon{'3', out}, bad, 0, 0, key)
    case SCon{_, f} VFirst{} SCon{'4', t} stk:
      go(f, NInt{}, t, stk, SCon{'4', out}, bad, 0, 0, key)
    case SCon{_, f} VFirst{} SCon{'5', t} stk:
      go(f, NInt{}, t, stk, SCon{'5', out}, bad, 0, 0, key)
    case SCon{_, f} VFirst{} SCon{'6', t} stk:
      go(f, NInt{}, t, stk, SCon{'6', out}, bad, 0, 0, key)
    case SCon{_, f} VFirst{} SCon{'7', t} stk:
      go(f, NInt{}, t, stk, SCon{'7', out}, bad, 0, 0, key)
    case SCon{_, f} VFirst{} SCon{'8', t} stk:
      go(f, NInt{}, t, stk, SCon{'8', out}, bad, 0, 0, key)
    case SCon{_, f} VFirst{} SCon{'9', t} stk:
      go(f, NInt{}, t, stk, SCon{'9', out}, bad, 0, 0, key)
    case SCon{_, f} VFirst{} SCon{'t', t} stk:
      go(f, T1{}, t, stk, SCon{'t', out}, bad, 0, 0, key)
    case SCon{_, f} VFirst{} SCon{'f', t} stk:
      go(f, F1{}, t, stk, SCon{'f', out}, bad, 0, 0, key)
    case SCon{_, f} VFirst{} SCon{'n', t} stk:
      go(f, U1{}, t, stk, SCon{'n', out}, bad, 0, 0, key)
    case SCon{_, f} VFirst{} SCon{']', t} Con{_, up}:
      go(f, VAfter{}, t, up, SCon{']', out}, bad, 0, 0, key)
    case SCon{_, f} VFirst{} _ _:
      None{}
    case SCon{_, f} VItem{} SCon{' ', t} stk:
      go(f, VItem{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VItem{} SCon{'\t', t} stk:
      go(f, VItem{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VItem{} SCon{'\n', t} stk:
      go(f, VItem{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VItem{} SCon{'\r', t} stk:
      go(f, VItem{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VItem{} SCon{'[', t} stk:
      go(f, VFirst{}, t, Con{BArr{}, stk}, SCon{'[', out}, bad, 0, 0, key)
    case SCon{_, f} VItem{} SCon{'{', t} stk:
      go(f, VObjFirst{}, t, Con{BObj{}, stk}, SCon{'{', out}, bad, 0, 0, key)
    case SCon{_, f} VItem{} SCon{'"', t} stk:
      go(f, SStr{}, t, stk, SCon{'"', out}, bad, 0, 0, False{})
    case SCon{_, f} VItem{} SCon{'-', t} stk:
      go(f, NMin{}, t, stk, SCon{'-', out}, bad, 0, 0, key)
    case SCon{_, f} VItem{} SCon{'0', t} stk:
      go(f, NZero{}, t, stk, SCon{'0', out}, bad, 0, 0, key)
    case SCon{_, f} VItem{} SCon{'1', t} stk:
      go(f, NInt{}, t, stk, SCon{'1', out}, bad, 0, 0, key)
    case SCon{_, f} VItem{} SCon{'2', t} stk:
      go(f, NInt{}, t, stk, SCon{'2', out}, bad, 0, 0, key)
    case SCon{_, f} VItem{} SCon{'3', t} stk:
      go(f, NInt{}, t, stk, SCon{'3', out}, bad, 0, 0, key)
    case SCon{_, f} VItem{} SCon{'4', t} stk:
      go(f, NInt{}, t, stk, SCon{'4', out}, bad, 0, 0, key)
    case SCon{_, f} VItem{} SCon{'5', t} stk:
      go(f, NInt{}, t, stk, SCon{'5', out}, bad, 0, 0, key)
    case SCon{_, f} VItem{} SCon{'6', t} stk:
      go(f, NInt{}, t, stk, SCon{'6', out}, bad, 0, 0, key)
    case SCon{_, f} VItem{} SCon{'7', t} stk:
      go(f, NInt{}, t, stk, SCon{'7', out}, bad, 0, 0, key)
    case SCon{_, f} VItem{} SCon{'8', t} stk:
      go(f, NInt{}, t, stk, SCon{'8', out}, bad, 0, 0, key)
    case SCon{_, f} VItem{} SCon{'9', t} stk:
      go(f, NInt{}, t, stk, SCon{'9', out}, bad, 0, 0, key)
    case SCon{_, f} VItem{} SCon{'t', t} stk:
      go(f, T1{}, t, stk, SCon{'t', out}, bad, 0, 0, key)
    case SCon{_, f} VItem{} SCon{'f', t} stk:
      go(f, F1{}, t, stk, SCon{'f', out}, bad, 0, 0, key)
    case SCon{_, f} VItem{} SCon{'n', t} stk:
      go(f, U1{}, t, stk, SCon{'n', out}, bad, 0, 0, key)
    case SCon{_, f} VItem{} _ _:
      None{}
    case SCon{_, f} VObjVal{} SCon{' ', t} stk:
      go(f, VObjVal{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VObjVal{} SCon{'\t', t} stk:
      go(f, VObjVal{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VObjVal{} SCon{'\n', t} stk:
      go(f, VObjVal{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VObjVal{} SCon{'\r', t} stk:
      go(f, VObjVal{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VObjVal{} SCon{'[', t} stk:
      go(f, VFirst{}, t, Con{BArr{}, stk}, SCon{'[', out}, bad, 0, 0, key)
    case SCon{_, f} VObjVal{} SCon{'{', t} stk:
      go(f, VObjFirst{}, t, Con{BObj{}, stk}, SCon{'{', out}, bad, 0, 0, key)
    case SCon{_, f} VObjVal{} SCon{'"', t} stk:
      go(f, SStr{}, t, stk, SCon{'"', out}, bad, 0, 0, False{})
    case SCon{_, f} VObjVal{} SCon{'-', t} stk:
      go(f, NMin{}, t, stk, SCon{'-', out}, bad, 0, 0, key)
    case SCon{_, f} VObjVal{} SCon{'0', t} stk:
      go(f, NZero{}, t, stk, SCon{'0', out}, bad, 0, 0, key)
    case SCon{_, f} VObjVal{} SCon{'1', t} stk:
      go(f, NInt{}, t, stk, SCon{'1', out}, bad, 0, 0, key)
    case SCon{_, f} VObjVal{} SCon{'2', t} stk:
      go(f, NInt{}, t, stk, SCon{'2', out}, bad, 0, 0, key)
    case SCon{_, f} VObjVal{} SCon{'3', t} stk:
      go(f, NInt{}, t, stk, SCon{'3', out}, bad, 0, 0, key)
    case SCon{_, f} VObjVal{} SCon{'4', t} stk:
      go(f, NInt{}, t, stk, SCon{'4', out}, bad, 0, 0, key)
    case SCon{_, f} VObjVal{} SCon{'5', t} stk:
      go(f, NInt{}, t, stk, SCon{'5', out}, bad, 0, 0, key)
    case SCon{_, f} VObjVal{} SCon{'6', t} stk:
      go(f, NInt{}, t, stk, SCon{'6', out}, bad, 0, 0, key)
    case SCon{_, f} VObjVal{} SCon{'7', t} stk:
      go(f, NInt{}, t, stk, SCon{'7', out}, bad, 0, 0, key)
    case SCon{_, f} VObjVal{} SCon{'8', t} stk:
      go(f, NInt{}, t, stk, SCon{'8', out}, bad, 0, 0, key)
    case SCon{_, f} VObjVal{} SCon{'9', t} stk:
      go(f, NInt{}, t, stk, SCon{'9', out}, bad, 0, 0, key)
    case SCon{_, f} VObjVal{} SCon{'t', t} stk:
      go(f, T1{}, t, stk, SCon{'t', out}, bad, 0, 0, key)
    case SCon{_, f} VObjVal{} SCon{'f', t} stk:
      go(f, F1{}, t, stk, SCon{'f', out}, bad, 0, 0, key)
    case SCon{_, f} VObjVal{} SCon{'n', t} stk:
      go(f, U1{}, t, stk, SCon{'n', out}, bad, 0, 0, key)
    case SCon{_, f} VObjVal{} _ _:
      None{}
    case SCon{_, f} VObjFirst{} SCon{' ', t} stk:
      go(f, VObjFirst{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VObjFirst{} SCon{'\t', t} stk:
      go(f, VObjFirst{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VObjFirst{} SCon{'\n', t} stk:
      go(f, VObjFirst{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VObjFirst{} SCon{'\r', t} stk:
      go(f, VObjFirst{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VKey{} SCon{' ', t} stk:
      go(f, VKey{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VKey{} SCon{'\t', t} stk:
      go(f, VKey{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VKey{} SCon{'\n', t} stk:
      go(f, VKey{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VKey{} SCon{'\r', t} stk:
      go(f, VKey{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VColon{} SCon{' ', t} stk:
      go(f, VColon{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VColon{} SCon{'\t', t} stk:
      go(f, VColon{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VColon{} SCon{'\n', t} stk:
      go(f, VColon{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VColon{} SCon{'\r', t} stk:
      go(f, VColon{}, t, stk, out, bad, 0, 0, key)
    case SCon{_, f} VObjFirst{} SCon{'"', t} stk:
      go(f, SStr{}, t, stk, SCon{'"', out}, bad, 0, 0, True{})
    case SCon{_, f} VKey{} SCon{'"', t} stk:
      go(f, SStr{}, t, stk, SCon{'"', out}, bad, 0, 0, True{})
    case SCon{_, f} VObjFirst{} SCon{'}', t} Con{_, up}:
      go(f, VAfter{}, t, up, SCon{'}', out}, bad, 0, 0, key)
    case SCon{_, f} VColon{} SCon{':', t} stk:
      go(f, VObjVal{}, t, stk, SCon{':', out}, bad, 0, 0, key)
    case SCon{_, f} VObjFirst{} _ _:
      None{}
    case SCon{_, f} VKey{} _ _:
      None{}
    case SCon{_, f} VColon{} _ _:
      None{}

# the fuel must be the very list the loop reads: a second list over the
# same chars makes every node shared, which doubles the time
def start(+t: String) -> Maybe<&2, String>:
  go(t, VTop{}, t, [], "", False{}, 0, 0, False{})

def bom(s: String) -> String:
  match s:
    case SCon{'\u{FEFF}', t}:
      t
    case rest:
      rest

def reformat(s: String) -> Maybe<&2, String>:
  start(bom(s))
