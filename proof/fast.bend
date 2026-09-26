import Base
import ../bjson.bend as J
import ../fast.bend as F
import ./spec.bend as S
import ./strings.bend as Str
import ./fast_text.bend as T

# The fast loop reads S.text(j) back to the same text. This file: the
# chars of a string. proof/fast_run.bend: numbers, values, the theorem.

def push(a: String, out: String) -> String:
  String.reverse.go(a, out)

# the offset and escape position after a stretch of input
type P2 is Data:
  P2{at: U32, ea: U32}

def p_at(p: P2) -> U32:
  match p:
    case P2{a, _}:
      a

def p_ea(p: P2) -> U32:
  match p:
    case P2{_, e}:
      e

# A control char is one of 32: five free bits, then zeros
type B5 is Data:
  B5{b0: Bool, b1: Bool, b2: Bool, b3: Bool, b4: Bool}

def ofb(b: B5) -> Char:
  match b:
    case B5{b0, b1, b2, b3, b4}:
      Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, Word.zero(27n)}}}}}}}

def Shape(c: Char) -> Type:
  &b: B5 -> {c == ofb(b) : Char}

law shape.b:
  for +b0: Bool
  for +b1: Bool
  for +b2: Bool
  for +b3: Bool
  for +b4: Bool
  for +b5: Bool
  for +rest: Word(26n)
  for +s: Cmp
  for es: {s == Word.cmp(26n, rest, Word.zero(26n)) : Cmp}
  for ez: {True{} == Cmp.is_lt(Word.cmp.fin(b0, False{}, Word.cmp.fin(b1, False{}, Word.cmp.fin(b2, False{}, Word.cmp.fin(b3, False{}, Word.cmp.fin(b4, False{}, Word.cmp.fin(b5, True{}, Word.cmp(26n, rest, Word.zero(26n))))))))) : Bool}
  Shape(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}})

def shape.b(b0, b1, b2, b3, b4, b5, rest, s, es, ez):
  match b5 s:
    case _ LT{}:
      Str.efq(Shape(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}), Str.lt_absurd(26n, rest, es))
    case _ GT{}:
      Str.efq(Shape(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}), Str.ctrl.b.gt(b0, b1, b2, b3, b4, b5, rest, es, ez))
    case True{} EQ{}:
      Str.efq(Shape(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{True{}, rest}}}}}}}}), Str.ctrl.b.hi(b0, b1, b2, b3, b4, rest, es, ez))
    case False{} EQ{}:
      %Equal.sym(Word(26n), rest, Word.zero(26n), Str.eq_zero(26n, rest, es)) : Shape(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{False{}, _}}}}}}}})
      (B5{b0, b1, b2, b3, b4}, {==})

law shape.a:
  for +b0: Bool
  for +b1: Bool
  for +b2: Bool
  for +b3: Bool
  for +b4: Bool
  for +b5: Bool
  for +rest: Word(26n)
  for +z: Bool
  for ez: {z == U32.is_lt(Char.to_u32(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}), 32) : Bool}
  for e: {J.KCtrl{} == J.class(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}) : J.Class}
  Shape(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}})

def shape.a(b0, b1, b2, b3, b4, b5, rest, z, ez, e):
  match z:
    case True{}:
      shape.b(b0, b1, b2, b3, b4, b5, rest, Word.cmp(26n, rest, Word.zero(26n)), {==}, ez)
    case False{}:
      Str.efq(Shape(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}), Str.ctrl.bad(Char.to_u32(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}), U32.is_lt(Char.to_u32(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}), 32), ez, e))

law shape:
  for +c: Char
  for e: {J.KCtrl{} == J.class(c) : J.Class}
  Shape(c)

def shape(c, e):
  match c:
    case Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}:
      shape.a(b0, b1, b2, b3, b4, b5, rest, U32.is_lt(Char.to_u32(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}), 32), {==}, e)

# One char of a string body, printed by S.esc_char and read by the loop:
# it pushes the same text and leaves the loop in the string again
def CS(k: J.Class, c: Char, x: String, stk: List<&2, F.Box>, out: String, key: Bool, at: U32, ea: U32) -> Type:
  &p: P2 -> {F.gc(S.esc_char(k, c, x), F.SStr{}, S.esc_char(k, c, x), stk, out, 0, 0, key, at, ea) == F.gc(x, F.SStr{}, x, stk, push(S.esc_char(k, c, ""), out), 0, 0, key, p_at(p), p_ea(p)) : F.Out}

# the 32 control chars, one case each
law cs.ctrl:
  for +b: B5
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  CS(J.KCtrl{}, ofb(b), x, stk, out, key, at, ea)

def cs.ctrl(b, x, stk, out, key, at, ea):
  match b:
    case B5{False{}, False{}, False{}, False{}, False{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{False{}, False{}, False{}, False{}, True{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{False{}, False{}, False{}, True{}, False{}}:
      (P2{((at + 1 : U32) + 1 : U32), at}, {==})
    case B5{False{}, False{}, False{}, True{}, True{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{False{}, False{}, True{}, False{}, False{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{False{}, False{}, True{}, False{}, True{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{False{}, False{}, True{}, True{}, False{}}:
      (P2{((at + 1 : U32) + 1 : U32), at}, {==})
    case B5{False{}, False{}, True{}, True{}, True{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{False{}, True{}, False{}, False{}, False{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{False{}, True{}, False{}, False{}, True{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{False{}, True{}, False{}, True{}, False{}}:
      (P2{((at + 1 : U32) + 1 : U32), at}, {==})
    case B5{False{}, True{}, False{}, True{}, True{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{False{}, True{}, True{}, False{}, False{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{False{}, True{}, True{}, False{}, True{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{False{}, True{}, True{}, True{}, False{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{False{}, True{}, True{}, True{}, True{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{True{}, False{}, False{}, False{}, False{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{True{}, False{}, False{}, False{}, True{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{True{}, False{}, False{}, True{}, False{}}:
      (P2{((at + 1 : U32) + 1 : U32), at}, {==})
    case B5{True{}, False{}, False{}, True{}, True{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{True{}, False{}, True{}, False{}, False{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{True{}, False{}, True{}, False{}, True{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{True{}, False{}, True{}, True{}, False{}}:
      (P2{((at + 1 : U32) + 1 : U32), at}, {==})
    case B5{True{}, False{}, True{}, True{}, True{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{True{}, True{}, False{}, False{}, False{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{True{}, True{}, False{}, False{}, True{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{True{}, True{}, False{}, True{}, False{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{True{}, True{}, False{}, True{}, True{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{True{}, True{}, True{}, False{}, False{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{True{}, True{}, True{}, False{}, True{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{True{}, True{}, True{}, True{}, False{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})
    case B5{True{}, True{}, True{}, True{}, True{}}:
      (P2{((((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), at}, {==})

law cs.ctrl.shape:
  for +c: Char
  for sh: Shape(c)
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  CS(J.KCtrl{}, c, x, stk, out, key, at, ea)

def cs.ctrl.shape(c, sh, x, stk, out, key, at, ea):
  (+b, eq) = sh
  %Equal.sym(Char, c, ofb(b), eq) : CS(J.KCtrl{}, _, x, stk, out, key, at, ea)
  cs.ctrl(b, x, stk, out, key, at, ea)

law cs.plain:
  for +c: Char
  for e: {J.KPlain{} == J.class(c) : J.Class}
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{c, x}, F.SStr{}, SCon{c, x}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.SStr{}, x, stk, SCon{c, out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def cs.plain(c, e, x, stk, out, key, at, ea):
  %e : {F.gc(x, F.str_mode(_, key), x, stk, F.str_out(_, c, out), 0, 0, key, (at + 1 : U32), F.str_ea(_, at, ea)) == F.gc(x, F.SStr{}, x, stk, SCon{c, out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}
  {==}

# a quote or backslash: printed after a backslash, read back after it
law cs.esc:
  for +c: Char
  for +k: J.Class
  for e: {k == J.class(c) : J.Class}
  for ok: {F.esc_mode(k, c) == F.SStr{} : F.Mode}
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  {F.gc(SCon{c, x}, F.SEsc{}, SCon{c, x}, stk, out, 0, 0, key, (at + 1 : U32), at) == F.gc(x, F.SStr{}, x, stk, F.esc_out(k, c, out), 0, 0, key, ((at + 1 : U32) + 1 : U32), at) : F.Out}

def cs.esc(c, k, e, ok, x, stk, out, key, at):
  %e : {F.gc(x, F.esc_mode(_, c), x, stk, F.esc_out(_, c, out), 0, 0, key, ((at + 1 : U32) + 1 : U32), at) == F.gc(x, F.SStr{}, x, stk, F.esc_out(k, c, out), 0, 0, key, ((at + 1 : U32) + 1 : U32), at) : F.Out}
  %Equal.sym(F.Mode, F.esc_mode(k, c), F.SStr{}, ok) : {F.gc(x, _, x, stk, F.esc_out(k, c, out), 0, 0, key, ((at + 1 : U32) + 1 : U32), at) == F.gc(x, F.SStr{}, x, stk, F.esc_out(k, c, out), 0, 0, key, ((at + 1 : U32) + 1 : U32), at) : F.Out}
  {==}

law cs.go:
  for +c: Char
  for +k: J.Class
  for e: {k == J.class(c) : J.Class}
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  CS(k, c, x, stk, out, key, at, ea)

def cs.go(c, k, e, x, stk, out, key, at, ea):
  match k:
    case J.KPlain{}:
      (P2{(at + 1 : U32), ea}, cs.plain(c, e, x, stk, out, key, at, ea))
    case J.KQuote{}:
      (P2{((at + 1 : U32) + 1 : U32), at}, cs.esc(c, J.KQuote{}, e, {==}, x, stk, out, key, at))
    case J.KBack{}:
      (P2{((at + 1 : U32) + 1 : U32), at}, cs.esc(c, J.KBack{}, e, {==}, x, stk, out, key, at))
    case J.KCtrl{}:
      cs.ctrl.shape(c, shape(c, e), x, stk, out, key, at, ea)

law cs:
  for +c: Char
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  CS(J.class(c), c, x, stk, out, key, at, ea)

def cs(c, x, stk, out, key, at, ea):
  cs.go(c, J.class(c), {==}, x, stk, out, key, at, ea)

# a whole string body and its closing quote
def SB(s: String, r: String, stk: List<&2, F.Box>, out: String, key: Bool, at: U32, ea: U32) -> Type:
  &p: P2 -> {F.gc(S.esc(s, SCon{'"', r}), F.SStr{}, S.esc(s, SCon{'"', r}), stk, out, 0, 0, key, at, ea) == F.gc(r, F.close_mode(key), r, stk, push(S.esc(s, "\""), out), 0, 0, key, p_at(p), p_ea(p)) : F.Out}

# pushing a char's escape, then the rest, is pushing the whole
law sb.out:
  for +c: Char
  for +t: String
  for +out: String
  {push(S.esc(t, "\""), push(S.esc_char(J.class(c), c, ""), out)) == push(S.esc(SCon{c, t}, "\""), out) : String}

def sb.out(c, t, out):
  +k : J.Class = J.class(c)
  +y : String = S.esc_char(k, c, "")
  Equal.trans(String, push(S.esc(t, "\""), push(y, out)), push(y ++ S.esc(t, "\""), out), push(S.esc_char(k, c, S.esc(t, "\"")), out),
    Equal.sym(String, push(y ++ S.esc(t, "\""), out), push(S.esc(t, "\""), push(y, out)), T.push_app(y, S.esc(t, "\""), out)),
    Equal.cong(String, String, z => push(z, out), y ++ S.esc(t, "\""), S.esc_char(k, c, S.esc(t, "\"")),
      Equal.sym(String, S.esc_char(k, c, S.esc(t, "\"")), y ++ S.esc(t, "\""), T.esc_char(k, c, "", S.esc(t, "\"")))))

law sb.2:
  for +c: Char
  for +t: String
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for +p1: P2
  for e1: {F.gc(S.esc_char(J.class(c), c, S.esc(t, SCon{'"', r})), F.SStr{}, S.esc_char(J.class(c), c, S.esc(t, SCon{'"', r})), stk, out, 0, 0, key, at, ea) == F.gc(S.esc(t, SCon{'"', r}), F.SStr{}, S.esc(t, SCon{'"', r}), stk, push(S.esc_char(J.class(c), c, ""), out), 0, 0, key, p_at(p1), p_ea(p1)) : F.Out}
  for g2: SB(t, r, stk, push(S.esc_char(J.class(c), c, ""), out), key, p_at(p1), p_ea(p1))
  SB(SCon{c, t}, r, stk, out, key, at, ea)

def sb.2(c, t, r, stk, out, key, at, ea, p1, e1, g2):
  (+p2, e2) = g2
  +o1 : String = push(S.esc_char(J.class(c), c, ""), out)
  (p2, Equal.trans(F.Out,
    F.gc(S.esc(SCon{c, t}, SCon{'"', r}), F.SStr{}, S.esc(SCon{c, t}, SCon{'"', r}), stk, out, 0, 0, key, at, ea),
    F.gc(S.esc(t, SCon{'"', r}), F.SStr{}, S.esc(t, SCon{'"', r}), stk, o1, 0, 0, key, p_at(p1), p_ea(p1)),
    F.gc(r, F.close_mode(key), r, stk, push(S.esc(SCon{c, t}, "\""), out), 0, 0, key, p_at(p2), p_ea(p2)),
    e1,
    Equal.trans(F.Out,
      F.gc(S.esc(t, SCon{'"', r}), F.SStr{}, S.esc(t, SCon{'"', r}), stk, o1, 0, 0, key, p_at(p1), p_ea(p1)),
      F.gc(r, F.close_mode(key), r, stk, push(S.esc(t, "\""), o1), 0, 0, key, p_at(p2), p_ea(p2)),
      F.gc(r, F.close_mode(key), r, stk, push(S.esc(SCon{c, t}, "\""), out), 0, 0, key, p_at(p2), p_ea(p2)),
      e2,
      Equal.cong(String, F.Out, z => F.gc(r, F.close_mode(key), r, stk, z, 0, 0, key, p_at(p2), p_ea(p2)),
        push(S.esc(t, "\""), o1), push(S.esc(SCon{c, t}, "\""), out), sb.out(c, t, out)))))

law sb.1:
  for +c: Char
  for +t: String
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for g1: CS(J.class(c), c, S.esc(t, SCon{'"', r}), stk, out, key, at, ea)
  for ih: @p: P2 -> SB(t, r, stk, push(S.esc_char(J.class(c), c, ""), out), key, p_at(p), p_ea(p))
  SB(SCon{c, t}, r, stk, out, key, at, ea)

def sb.1(c, t, r, stk, out, key, at, ea, g1, ih):
  (+p1, e1) = g1
  sb.2(c, t, r, stk, out, key, at, ea, p1, e1, ih(p1))

law sb:
  for +s: String
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  SB(s, r, stk, out, key, at, ea)

def sb(s, r, stk, out, key, at, ea):
  match s:
    case SNil{}:
      (P2{(at + 1 : U32), ea}, {==})
    case SCon{c, t}:
      sb.1(c, t, r, stk, out, key, at, ea, cs(c, S.esc(t, SCon{'"', r}), stk, out, key, at, ea),
        +p => sb(t, r, stk, push(S.esc_char(J.class(c), c, ""), out), key, p_at(p), p_ea(p)))
