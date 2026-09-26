import Base

# grounds-utf8: strict UTF-8 decoding of raw bytes (RFC 3629).
#
#   import ../utf8/utf8.bend as U
#   U.decode(bytes)   # TOk{text}, or TBad{at, before}: where the first bad
#                     # sequence starts (in chars) and the chars before it

def in_range(+x: U32, lo: U32, hi: U32) -> Bool:
  Bool.and(U32.is_ge(x, lo), U32.is_le(x, hi))

# a UTF-8 decoder that rejects what the runtime's text reader would turn
# into U+FFFD: overlong forms, surrogates, code points past U+10FFFF, and
# cut-off sequences. need is how many continuation bytes are still to
# come, and lo and hi bound the next one; at counts the chars so far
type U8 is Data:
  U8{need: U32, code: U32, lo: U32, hi: U32, at: U32, out: String}
  U8Bad{at: U32, out: String}

def u8.char(+c: U32, +at: U32, out: String) -> U8:
  U8{0, 0, 128, 191, (at + 1 : U32), SCon{Chr{c}, out}}

def u8.lead(ok: Bool, +b: U32, +at: U32, out: String) -> U8:
  match ok:
    case True{}:
      +two = U32.is_lt(b, 224)
      +three = U32.is_lt(b, 240)
      +need = Bool.pick(U32, two, 1, Bool.pick(U32, three, 2, 3))
      +base = Bool.pick(U32, two, 192, Bool.pick(U32, three, 224, 240))
      +lo = Bool.pick(U32, U32.is_eq(b, 224), 160, Bool.pick(U32, U32.is_eq(b, 240), 144, 128))
      +hi = Bool.pick(U32, U32.is_eq(b, 237), 159, Bool.pick(U32, U32.is_eq(b, 244), 143, 191))
      U8{need, (b - base : U32), lo, hi, at, out}
    case False{}:
      U8Bad{at, out}

def u8.start(ascii: Bool, +b: U32, +at: U32, out: String) -> U8:
  match ascii:
    case True{}:
      u8.char(b, at, out)
    case False{}:
      u8.lead(in_range(b, 194, 244), b, at, out)

def u8.more(last: Bool, +c: U32, +need: U32, +at: U32, out: String) -> U8:
  match last:
    case True{}:
      u8.char(c, at, out)
    case False{}:
      U8{(need - 1 : U32), c, 128, 191, at, out}

def u8.cont(ok: Bool, +b: U32, +need: U32, +c: U32, +at: U32, out: String) -> U8:
  match ok:
    case True{}:
      u8.more(U32.is_eq(need, 1), (c * 64 + b - 128 : U32), need, at, out)
    case False{}:
      U8Bad{at, out}

def u8.go(start: Bool, +b: U32, +need: U32, +c: U32, +lo: U32, +hi: U32, +at: U32, out: String) -> U8:
  match start:
    case True{}:
      u8.start(U32.is_lt(b, 128), b, at, out)
    case False{}:
      u8.cont(in_range(b, lo, hi), b, need, c, at, out)

def u8.step(u: U8, +b: U32) -> U8:
  match u:
    case U8{+need, c, lo, hi, at, out}:
      u8.go(U32.is_eq(need, 0), b, need, c, lo, hi, at, out)
    case bad:
      bad

# the decoded text, or where the first bad sequence starts and the chars
# before it (reversed)
type Text is Data:
  TOk{text: String}
  TBad{at: U32, before: String}

def u8.end(done: Bool, +at: U32, out: String) -> Text:
  match done:
    case True{}:
      TOk{String.reverse(out)}
    case False{}:
      TBad{at, out}

def decode.go(bs: List<&2, U32>, u: U8) -> Text:
  match bs u:
    case _ U8Bad{at, out}:
      TBad{at, out}
    case Nil{} U8{+need, _, _, _, at, out}:
      u8.end(U32.is_eq(need, 0), at, out)
    case Con{+b, t} going:
      decode.go(t, u8.step(going, b))

def decode(bs: List<&2, U32>) -> Text:
  decode.go(bs, U8{0, 0, 128, 191, 0, ""})

# the column of the char after before (reversed), counting from col
def back_col(before: String, +col: U32) -> U32:
  match before:
    case SCon{'\n', _}:
      col
    case SCon{_, t}:
      back_col(t, (col + 1 : U32))
    case SNil{}:
      col

def back_line(before: String, +line: U32) -> U32:
  match before:
    case SCon{'\n', t}:
      back_line(t, (line + 1 : U32))
    case SCon{_, t}:
      back_line(t, line)
    case SNil{}:
      line

