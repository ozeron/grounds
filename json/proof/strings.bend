import Base
import ../json.bend as J
import ./spec.bend as S

# Lexing S.esc(s) gives back s: the printer and the lexer both decide
# what to do with a char through J.class, so each class is one case.

def Pick(b: Bool, X: Type, Y: Type) -> Type:
  match b:
    case True{}:
      X
    case False{}:
      Y

law absurd:
  for -A: Type
  for e: {False{} == True{} : Bool}
  A

def absurd(A, e):
  %e : Pick(_, A, Unit)
  Unit{}

law efq:
  for -A: Type
  for x: Empty
  A

def efq(A, x):
  match x:

def NotCtrl(k: J.Class) -> Type:
  match k:
    case J.KCtrl{}:
      Empty
    case _:
      Unit

law not_ctrl:
  for +q: Bool
  for +b: Bool
  NotCtrl(Bool.pick(J.Class, q, J.KQuote{}, Bool.pick(J.Class, b, J.KBack{}, J.KPlain{})))

def not_ctrl(q, b):
  match q b:
    case True{} _:
      Unit{}
    case False{} True{}:
      Unit{}
    case False{} False{}:
      Unit{}

# each of the 32 control chars: its escape lexes back to it
law ctrl_bits:
  for +b0: Bool
  for +b1: Bool
  for +b2: Bool
  for +b3: Bool
  for +b4: Bool
  for +acc: String
  for +r: String
  {J.lex_str(J.ctrl_text(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, Word.zero(27n)}}}}}}}) ++ r, J.SGo{acc, 0}) == J.lex_str(r, J.SGo{SCon{Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, Word.zero(27n)}}}}}}}, acc}, 0}) : J.Lex}

def ctrl_bits(b0, b1, b2, b3, b4, acc, r):
  match b0 b1 b2 b3 b4:
    case False{} False{} False{} False{} False{}:
      {==}
    case False{} False{} False{} False{} True{}:
      {==}
    case False{} False{} False{} True{} False{}:
      {==}
    case False{} False{} False{} True{} True{}:
      {==}
    case False{} False{} True{} False{} False{}:
      {==}
    case False{} False{} True{} False{} True{}:
      {==}
    case False{} False{} True{} True{} False{}:
      {==}
    case False{} False{} True{} True{} True{}:
      {==}
    case False{} True{} False{} False{} False{}:
      {==}
    case False{} True{} False{} False{} True{}:
      {==}
    case False{} True{} False{} True{} False{}:
      {==}
    case False{} True{} False{} True{} True{}:
      {==}
    case False{} True{} True{} False{} False{}:
      {==}
    case False{} True{} True{} False{} True{}:
      {==}
    case False{} True{} True{} True{} False{}:
      {==}
    case False{} True{} True{} True{} True{}:
      {==}
    case True{} False{} False{} False{} False{}:
      {==}
    case True{} False{} False{} False{} True{}:
      {==}
    case True{} False{} False{} True{} False{}:
      {==}
    case True{} False{} False{} True{} True{}:
      {==}
    case True{} False{} True{} False{} False{}:
      {==}
    case True{} False{} True{} False{} True{}:
      {==}
    case True{} False{} True{} True{} False{}:
      {==}
    case True{} False{} True{} True{} True{}:
      {==}
    case True{} True{} False{} False{} False{}:
      {==}
    case True{} True{} False{} False{} True{}:
      {==}
    case True{} True{} False{} True{} False{}:
      {==}
    case True{} True{} False{} True{} True{}:
      {==}
    case True{} True{} True{} False{} False{}:
      {==}
    case True{} True{} True{} False{} True{}:
      {==}
    case True{} True{} True{} True{} False{}:
      {==}
    case True{} True{} True{} True{} True{}:
      {==}

# Word.cmp against zero is never LT, and is EQ only for zero

def NotLT(t: Cmp) -> Type:
  match t:
    case LT{}:
      Empty
    case _:
      Unit

def NotEq(t: Cmp) -> Type:
  match t:
    case EQ{}:
      Empty
    case _:
      Unit

def TrueE(b: Bool) -> Type:
  match b:
    case True{}:
      Empty
    case False{}:
      Unit

law nlt_fin:
  for +b: Bool
  for +t: Cmp
  for h: NotLT(t)
  NotLT(Word.cmp.fin(b, False{}, t))

def nlt_fin(b, t, h):
  match b t:
    case _ LT{}:
      match h:
    case True{} EQ{}:
      Unit{}
    case False{} EQ{}:
      Unit{}
    case _ GT{}:
      Unit{}

law nlt_zero:
  for +n: Nat
  for +w: Word(n)
  NotLT(Word.cmp(n, w, Word.zero(n)))

def nlt_zero(n, w):
  match n:
    case 0n:
      Unit{}
    case 1n+p:
      match w:
        case WCon{b, t}:
          nlt_fin(b, Word.cmp(p, t, Word.zero(p)), nlt_zero(p, t))

law nlt_is_lt:
  for +t: Cmp
  for h: NotLT(t)
  {Cmp.is_lt(t) == False{} : Bool}

def nlt_is_lt(t, h):
  match t:
    case LT{}:
      match h:
    case EQ{}:
      {==}
    case GT{}:
      {==}

law lt_absurd:
  for +n: Nat
  for +w: Word(n)
  for es: {LT{} == Word.cmp(n, w, Word.zero(n)) : Cmp}
  Empty

def lt_absurd(n, w, es):
  %Equal.sym(Cmp, LT{}, Word.cmp(n, w, Word.zero(n)), es) : NotLT(_)
  nlt_zero(n, w)

law eq_zero.ne:
  for +p: Nat
  for +b: Bool
  for +t: Word(p)
  for +s: Cmp
  for es: {s == Word.cmp(p, t, Word.zero(p)) : Cmp}
  for e: {EQ{} == Word.cmp.fin(b, False{}, Word.cmp(p, t, Word.zero(p))) : Cmp}
  for h: NotEq(Word.cmp.fin(b, False{}, s))
  Empty

def eq_zero.ne(p, b, t, s, es, e, h):
  %Equal.sym(Cmp, EQ{}, Word.cmp.fin(b, False{}, Word.cmp(p, t, Word.zero(p))), e) : NotEq(_)
  %es : NotEq(Word.cmp.fin(b, False{}, _))
  h

law eq_zero.go:
  for +p: Nat
  for +b: Bool
  for +t: Word(p)
  for +s: Cmp
  for es: {s == Word.cmp(p, t, Word.zero(p)) : Cmp}
  for e: {EQ{} == Word.cmp.fin(b, False{}, Word.cmp(p, t, Word.zero(p))) : Cmp}
  for ih: @x: {EQ{} == Word.cmp(p, t, Word.zero(p)) : Cmp} -> {t == Word.zero(p) : Word(p)}
  {WCon{b, t} == WCon{False{}, Word.zero(p)} : Word(1n+p)}

def eq_zero.go(p, b, t, s, es, e, ih):
  match b s:
    case _ LT{}:
      efq({WCon{b, t} == WCon{False{}, Word.zero(p)} : Word(1n+p)}, lt_absurd(p, t, es))
    case _ GT{}:
      efq({WCon{b, t} == WCon{False{}, Word.zero(p)} : Word(1n+p)}, eq_zero.ne(p, b, t, GT{}, es, e, Unit{}))
    case True{} EQ{}:
      efq({WCon{True{}, t} == WCon{False{}, Word.zero(p)} : Word(1n+p)}, eq_zero.ne(p, True{}, t, EQ{}, es, e, Unit{}))
    case False{} EQ{}:
      %ih(es) : {WCon{False{}, t} == WCon{False{}, _} : Word(1n+p)}
      {==}

law eq_zero:
  for +n: Nat
  for +w: Word(n)
  for e: {EQ{} == Word.cmp(n, w, Word.zero(n)) : Cmp}
  {w == Word.zero(n) : Word(n)}

def eq_zero(n, w, e):
  match n:
    case 0n:
      match w:
        case WNil{}:
          {==}
    case 1n+p:
      match w:
        case WCon{b, t}:
          eq_zero.go(p, b, t, Word.cmp(p, t, Word.zero(p)), {==}, e, x => eq_zero(p, t, x))

# a control char's code is below 32: bit 5 and up are clear
law ctrl.bad:
  for +x: U32
  for +z: Bool
  for ez: {False{} == z : Bool}
  for e: {J.KCtrl{} == J.class.go(z, x) : J.Class}
  Empty

def ctrl.bad(x, z, ez, e):
  %Equal.sym(J.Class, J.KCtrl{}, J.class.go(z, x), e) : NotCtrl(_)
  %ez : NotCtrl(J.class.go(_, x))
  not_ctrl(U32.is_eq(x, 34), U32.is_eq(x, 92))


law ctrl.b.gt:
  for +b0: Bool
  for +b1: Bool
  for +b2: Bool
  for +b3: Bool
  for +b4: Bool
  for +b5: Bool
  for +rest: Word(26n)
  for es: {GT{} == Word.cmp(26n, rest, Word.zero(26n)) : Cmp}
  for ez: {True{} == Cmp.is_lt(Word.cmp.fin(b0, False{}, Word.cmp.fin(b1, False{}, Word.cmp.fin(b2, False{}, Word.cmp.fin(b3, False{}, Word.cmp.fin(b4, False{}, Word.cmp.fin(b5, True{}, Word.cmp(26n, rest, Word.zero(26n))))))))) : Bool}
  Empty

def ctrl.b.gt(b0, b1, b2, b3, b4, b5, rest, es, ez):
  %Equal.sym(Bool, True{}, Cmp.is_lt(Word.cmp.fin(b0, False{}, Word.cmp.fin(b1, False{}, Word.cmp.fin(b2, False{}, Word.cmp.fin(b3, False{}, Word.cmp.fin(b4, False{}, Word.cmp.fin(b5, True{}, Word.cmp(26n, rest, Word.zero(26n))))))))), ez) : TrueE(_)
  %es : TrueE(Cmp.is_lt(Word.cmp.fin(b0, False{}, Word.cmp.fin(b1, False{}, Word.cmp.fin(b2, False{}, Word.cmp.fin(b3, False{}, Word.cmp.fin(b4, False{}, Word.cmp.fin(b5, True{}, _))))))))
  Unit{}

law ctrl.b.hi:
  for +b0: Bool
  for +b1: Bool
  for +b2: Bool
  for +b3: Bool
  for +b4: Bool
  for +rest: Word(26n)
  for es: {EQ{} == Word.cmp(26n, rest, Word.zero(26n)) : Cmp}
  for ez: {True{} == Cmp.is_lt(Word.cmp.fin(b0, False{}, Word.cmp.fin(b1, False{}, Word.cmp.fin(b2, False{}, Word.cmp.fin(b3, False{}, Word.cmp.fin(b4, False{}, Word.cmp.fin(True{}, True{}, Word.cmp(26n, rest, Word.zero(26n))))))))) : Bool}
  Empty

def ctrl.b.hi(b0, b1, b2, b3, b4, rest, es, ez):
  +t4 : Cmp = Word.cmp.fin(True{}, True{}, EQ{})
  +t3 : Cmp = Word.cmp.fin(b4, False{}, t4)
  +t2 : Cmp = Word.cmp.fin(b3, False{}, t3)
  +t1 : Cmp = Word.cmp.fin(b2, False{}, t2)
  +t0 : Cmp = Word.cmp.fin(b1, False{}, t1)
  +t : Cmp = Word.cmp.fin(b0, False{}, t0)
  h : NotLT(t) = nlt_fin(b0, t0, nlt_fin(b1, t1, nlt_fin(b2, t2, nlt_fin(b3, t3, nlt_fin(b4, t4, Unit{})))))
  %Equal.sym(Bool, True{}, Cmp.is_lt(Word.cmp.fin(b0, False{}, Word.cmp.fin(b1, False{}, Word.cmp.fin(b2, False{}, Word.cmp.fin(b3, False{}, Word.cmp.fin(b4, False{}, Word.cmp.fin(True{}, True{}, Word.cmp(26n, rest, Word.zero(26n))))))))), ez) : TrueE(_)
  %es : TrueE(Cmp.is_lt(Word.cmp.fin(b0, False{}, Word.cmp.fin(b1, False{}, Word.cmp.fin(b2, False{}, Word.cmp.fin(b3, False{}, Word.cmp.fin(b4, False{}, Word.cmp.fin(True{}, True{}, _))))))))
  %Equal.sym(Bool, Cmp.is_lt(t), False{}, nlt_is_lt(t, h)) : TrueE(_)
  Unit{}

law ctrl.b:
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
  for +acc: String
  for +r: String
  {J.lex_str(J.ctrl_text(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}) ++ r, J.SGo{acc, 0}) == J.lex_str(r, J.SGo{SCon{Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}, acc}, 0}) : J.Lex}

def ctrl.b(b0, b1, b2, b3, b4, b5, rest, s, es, ez, acc, r):
  match b5 s:
    case _ LT{}:
      efq({J.lex_str(J.ctrl_text(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}) ++ r, J.SGo{acc, 0}) == J.lex_str(r, J.SGo{SCon{Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}, acc}, 0}) : J.Lex}, lt_absurd(26n, rest, es))
    case _ GT{}:
      bad : Empty = ctrl.b.gt(b0, b1, b2, b3, b4, b5, rest, es, ez)
      efq({J.lex_str(J.ctrl_text(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}) ++ r, J.SGo{acc, 0}) == J.lex_str(r, J.SGo{SCon{Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}, acc}, 0}) : J.Lex}, bad)
    case True{} EQ{}:
      bad : Empty = ctrl.b.hi(b0, b1, b2, b3, b4, rest, es, ez)
      efq({J.lex_str(J.ctrl_text(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{True{}, rest}}}}}}}}) ++ r, J.SGo{acc, 0}) == J.lex_str(r, J.SGo{SCon{Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{True{}, rest}}}}}}}}, acc}, 0}) : J.Lex}, bad)
    case False{} EQ{}:
      %Equal.sym(Word(26n), rest, Word.zero(26n), eq_zero(26n, rest, es)) : {J.lex_str(J.ctrl_text(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{False{}, _}}}}}}}}) ++ r, J.SGo{acc, 0}) == J.lex_str(r, J.SGo{SCon{Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{False{}, _}}}}}}}}, acc}, 0}) : J.Lex}
      ctrl_bits(b0, b1, b2, b3, b4, acc, r)

law ctrl.a:
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
  for +acc: String
  for +r: String
  {J.lex_str(J.ctrl_text(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}) ++ r, J.SGo{acc, 0}) == J.lex_str(r, J.SGo{SCon{Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}, acc}, 0}) : J.Lex}

def ctrl.a(b0, b1, b2, b3, b4, b5, rest, z, ez, e, acc, r):
  match z:
    case True{}:
      ctrl.b(b0, b1, b2, b3, b4, b5, rest, Word.cmp(26n, rest, Word.zero(26n)), {==}, ez, acc, r)
    case False{}:
      efq({J.lex_str(J.ctrl_text(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}) ++ r, J.SGo{acc, 0}) == J.lex_str(r, J.SGo{SCon{Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}, acc}, 0}) : J.Lex}, ctrl.bad(Char.to_u32(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}), U32.is_lt(Char.to_u32(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}), 32), ez, e))

law ctrl:
  for +c: Char
  for e: {J.KCtrl{} == J.class(c) : J.Class}
  for +acc: String
  for +r: String
  {J.lex_str(J.ctrl_text(c) ++ r, J.SGo{acc, 0}) == J.lex_str(r, J.SGo{SCon{c, acc}, 0}) : J.Lex}

def ctrl(c, e, acc, r):
  match c:
    case Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}:
      ctrl.a(b0, b1, b2, b3, b4, b5, rest, U32.is_lt(Char.to_u32(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, WCon{b5, rest}}}}}}}}), 32), {==}, e, acc, r)

# one printed char lexes back to itself, whatever its class
law char.go:
  for +c: Char
  for +cl: J.Class
  for e: {cl == J.class(c) : J.Class}
  for +acc: String
  for +r: String
  {J.lex_str(S.esc_char(cl, c, r), J.SGo{acc, 0}) == J.lex_str(r, J.SGo{SCon{c, acc}, 0}) : J.Lex}

def char.go(c, cl, e, acc, r):
  match cl:
    case J.KPlain{}:
      %e : {J.lex_str(r, J.s_go(_, c, acc, 0)) == J.lex_str(r, J.SGo{SCon{c, acc}, 0}) : J.Lex}
      {==}
    case J.KQuote{}:
      %e : {J.lex_str(r, J.s_esc(_, c, acc, 0)) == J.lex_str(r, J.SGo{SCon{c, acc}, 0}) : J.Lex}
      {==}
    case J.KBack{}:
      %e : {J.lex_str(r, J.s_esc(_, c, acc, 0)) == J.lex_str(r, J.SGo{SCon{c, acc}, 0}) : J.Lex}
      {==}
    case J.KCtrl{}:
      ctrl(c, e, acc, r)

law char:
  for +c: Char
  for +acc: String
  for +r: String
  {J.lex_str(S.esc_char(J.class(c), c, r), J.SGo{acc, 0}) == J.lex_str(r, J.SGo{SCon{c, acc}, 0}) : J.Lex}

def char(c, acc, r):
  char.go(c, J.class(c), {==}, acc, r)

# the closing quote: the lexer stops and hands back what follows
law close:
  for +acc: String
  for +k: String
  {J.lex_str(SCon{'"', k}, J.SGo{acc, 0}) == J.LOk{String.reverse(acc), k} : J.Lex}

def close(acc, k):
  match k:
    case SNil{}:
      {==}
    case SCon{_, _}:
      {==}

# a printed string body lexes back to the string
law body:
  for +s: String
  for +acc: String
  for +k: String
  {J.lex_str(S.esc(s, SCon{'"', k}), J.SGo{acc, 0}) == J.LOk{String.reverse.go(acc, s), k} : J.Lex}

def body(s, acc, k):
  match s:
    case SNil{}:
      close(acc, k)
    case SCon{c, t}:
      Equal.trans(J.Lex,
        J.lex_str(S.esc_char(J.class(c), c, S.esc(t, SCon{'"', k})), J.SGo{acc, 0}),
        J.lex_str(S.esc(t, SCon{'"', k}), J.SGo{SCon{c, acc}, 0}),
        J.LOk{String.reverse.go(acc, SCon{c, t}), k},
        char(c, acc, S.esc(t, SCon{'"', k})),
        body(t, SCon{c, acc}, k))
