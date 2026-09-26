import Base
import ../bjson.bend as J
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

# only zero words pass J.zeros
law zeros_eq:
  for +n: Nat
  for +w: Word(n)
  for e: {J.zeros(n, w) == True{} : Bool}
  {w == Word.zero(n) : Word(n)}

def zeros_eq(n, w, e):
  match n:
    case 0n:
      match w:
        case WNil{}:
          {==}
    case 1n+p:
      match w:
        case WCon{True{}, t}:
          absurd({WCon{True{}, t} == Word.zero(1n+p) : Word(1n+p)}, e)
        case WCon{False{}, t}:
          %zeros_eq(p, t, e) : {WCon{False{}, t} == WCon{False{}, _} : Word(1n+p)}
          {==}

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

law ctrl.z.bad:
  for +high: Word(27n)
  for +x: U32
  for ez: {False{} == J.zeros(27n, high) : Bool}
  for e: {J.KCtrl{} == J.class.go(J.zeros(27n, high), x) : J.Class}
  Empty

def ctrl.z.bad(high, x, ez, e):
  %Equal.sym(J.Class, J.KCtrl{}, J.class.go(J.zeros(27n, high), x), e) : NotCtrl(_)
  %ez : NotCtrl(J.class.go(_, x))
  not_ctrl(U32.is_eq(x, 34), U32.is_eq(x, 92))

law ctrl.z:
  for +b0: Bool
  for +b1: Bool
  for +b2: Bool
  for +b3: Bool
  for +b4: Bool
  for +high: Word(27n)
  for +z: Bool
  for ez: {z == J.zeros(27n, high) : Bool}
  for e: {J.KCtrl{} == J.class(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, high}}}}}}}) : J.Class}
  for +acc: String
  for +r: String
  {J.lex_str(J.ctrl_text(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, high}}}}}}}) ++ r, J.SGo{acc, 0}) == J.lex_str(r, J.SGo{SCon{Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, high}}}}}}}, acc}, 0}) : J.Lex}

def ctrl.z(b0, b1, b2, b3, b4, high, z, ez, e, acc, r):
  match z:
    case True{}:
      +hz : {high == Word.zero(27n) : Word(27n)} = zeros_eq(27n, high, Equal.sym(Bool, True{}, J.zeros(27n, high), ez))
      %Equal.sym(Word(27n), high, Word.zero(27n), hz) : {J.lex_str(J.ctrl_text(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, _}}}}}}}) ++ r, J.SGo{acc, 0}) == J.lex_str(r, J.SGo{SCon{Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, _}}}}}}}, acc}, 0}) : J.Lex}
      ctrl_bits(b0, b1, b2, b3, b4, acc, r)
    case False{}:
      efq({J.lex_str(J.ctrl_text(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, high}}}}}}}) ++ r, J.SGo{acc, 0}) == J.lex_str(r, J.SGo{SCon{Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, high}}}}}}}, acc}, 0}) : J.Lex},
        ctrl.z.bad(high, Char.to_u32(Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, high}}}}}}}), ez, e))


law ctrl:
  for +c: Char
  for e: {J.KCtrl{} == J.class(c) : J.Class}
  for +acc: String
  for +r: String
  {J.lex_str(J.ctrl_text(c) ++ r, J.SGo{acc, 0}) == J.lex_str(r, J.SGo{SCon{c, acc}, 0}) : J.Lex}

def ctrl(c, e, acc, r):
  match c:
    case Chr{U32{WCon{b0, WCon{b1, WCon{b2, WCon{b3, WCon{b4, high}}}}}}}:
      ctrl.z(b0, b1, b2, b3, b4, high, J.zeros(27n, high), {==}, e, acc, r)

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
      %e : {J.lex_str(r, J.s_go(_, c, acc, 0, r)) == J.lex_str(r, J.SGo{SCon{c, acc}, 0}) : J.Lex}
      {==}
    case J.KQuote{}:
      %e : {J.lex_str(r, J.s_esc(_, c, acc, 0, SCon{'\\', SCon{c, r}})) == J.lex_str(r, J.SGo{SCon{c, acc}, 0}) : J.Lex}
      {==}
    case J.KBack{}:
      %e : {J.lex_str(r, J.s_esc(_, c, acc, 0, SCon{'\\', SCon{c, r}})) == J.lex_str(r, J.SGo{SCon{c, acc}, 0}) : J.Lex}
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
