import Base
import ../json.bend as J
import ./spec.bend as S

# S.text(j, more, k) is S.text(j, more, "") with k after it, and pushing
# a ++ b onto a reversed output pushes a, then b. Used by proof/fast.bend.

def push(a: String, out: String) -> String:
  String.reverse.go(a, out)

law app_nil:
  for +a: String
  {a ++ "" == a : String}

def app_nil(a):
  match a:
    case SNil{}:
      {==}
    case SCon{c, t}:
      Equal.cong(String, String, x => SCon{c, x}, t ++ "", t, app_nil(t))

law app_assoc:
  for +a: String
  for +b: String
  for +c: String
  {(a ++ b) ++ c == a ++ (b ++ c) : String}

def app_assoc(a, b, c):
  match a:
    case SNil{}:
      {==}
    case SCon{h, t}:
      Equal.cong(String, String, x => SCon{h, x}, (t ++ b) ++ c, t ++ (b ++ c), app_assoc(t, b, c))

law push_app:
  for +a: String
  for +b: String
  for +out: String
  {push(a ++ b, out) == push(b, push(a, out)) : String}

def push_app(a, b, out):
  match a:
    case SNil{}:
      {==}
    case SCon{h, t}:
      push_app(t, b, SCon{h, out})

# a continuation k after y moves out of any spec writer
def Ta(y: String, k: String, fy: String, fyk: String) -> Type:
  {fyk == fy ++ k : String}

law esc_char:
  for +cl: J.Class
  for +c: Char
  for +y: String
  for +k: String
  {S.esc_char(cl, c, y ++ k) == S.esc_char(cl, c, y) ++ k : String}

def esc_char(cl, c, y, k):
  match cl:
    case J.KQuote{}:
      {==}
    case J.KBack{}:
      {==}
    case J.KCtrl{}:
      Equal.sym(String, (J.ctrl_text(c) ++ y) ++ k, J.ctrl_text(c) ++ (y ++ k), app_assoc(J.ctrl_text(c), y, k))
    case J.KPlain{}:
      {==}

law esc:
  for +s: String
  for +y: String
  for +k: String
  {S.esc(s, y ++ k) == S.esc(s, y) ++ k : String}

def esc(s, y, k):
  match s:
    case SNil{}:
      {==}
    case SCon{c, t}:
      Equal.trans(String,
        S.esc_char(J.class(c), c, S.esc(t, y ++ k)),
        S.esc_char(J.class(c), c, S.esc(t, y) ++ k),
        S.esc_char(J.class(c), c, S.esc(t, y)) ++ k,
        Equal.cong(String, String, x => S.esc_char(J.class(c), c, x), S.esc(t, y ++ k), S.esc(t, y) ++ k, esc(t, y, k)),
        esc_char(J.class(c), c, S.esc(t, y), k))

law digits:
  for +ds: List<&2, J.Digit>
  for +y: String
  for +k: String
  {J.digits_k(ds, y ++ k) == J.digits_k(ds, y) ++ k : String}

def digits(ds, y, k):
  match ds:
    case Nil{}:
      {==}
    case Con{d, t}:
      Equal.cong(String, String, x => SCon{J.digit_char(d), x}, J.digits_k(t, y ++ k), J.digits_k(t, y) ++ k, digits(t, y, k))

law int:
  for +i: J.Int
  for +y: String
  for +k: String
  {J.int_k(i, y ++ k) == J.int_k(i, y) ++ k : String}

def int(i, y, k):
  match i:
    case J.IZero{}:
      {==}
    case J.INon{l, ds}:
      Equal.cong(String, String, x => SCon{J.lead_char(l), x}, J.digits_k(ds, y ++ k), J.digits_k(ds, y) ++ k, digits(ds, y, k))

law frac:
  for +f: J.Frac
  for +y: String
  for +k: String
  {J.frac_k(f, y ++ k) == J.frac_k(f, y) ++ k : String}

def frac(f, y, k):
  match f:
    case J.FNone{}:
      {==}
    case J.FSome{d, ds}:
      Equal.cong(String, String, x => SCon{'.', SCon{J.digit_char(d), x}}, J.digits_k(ds, y ++ k), J.digits_k(ds, y) ++ k, digits(ds, y, k))

law sign:
  for +s: J.Sign
  for +y: String
  for +k: String
  {J.sign_k(s, y ++ k) == J.sign_k(s, y) ++ k : String}

def sign(s, y, k):
  match s:
    case J.NoSign{}:
      {==}
    case J.Plus{}:
      {==}
    case J.Minus{}:
      {==}

law exp:
  for +e: J.Exp
  for +y: String
  for +k: String
  {J.exp_k(e, y ++ k) == J.exp_k(e, y) ++ k : String}

def exp(e, y, k):
  match e:
    case J.ENone{}:
      {==}
    case J.ESome{u, s, d, ds}:
      Equal.trans(String,
        SCon{Bool.pick(Char, u, 'E', 'e'), J.sign_k(s, SCon{J.digit_char(d), J.digits_k(ds, y ++ k)})},
        SCon{Bool.pick(Char, u, 'E', 'e'), J.sign_k(s, SCon{J.digit_char(d), J.digits_k(ds, y)} ++ k)},
        J.exp_k(J.ESome{u, s, d, ds}, y) ++ k,
        Equal.cong(String, String, x => SCon{Bool.pick(Char, u, 'E', 'e'), J.sign_k(s, SCon{J.digit_char(d), x})},
          J.digits_k(ds, y ++ k), J.digits_k(ds, y) ++ k, digits(ds, y, k)),
        Equal.cong(String, String, x => SCon{Bool.pick(Char, u, 'E', 'e'), x},
          J.sign_k(s, SCon{J.digit_char(d), J.digits_k(ds, y)} ++ k), J.sign_k(s, SCon{J.digit_char(d), J.digits_k(ds, y)}) ++ k,
          sign(s, SCon{J.digit_char(d), J.digits_k(ds, y)}, k)))

law neg:
  for +b: Bool
  for +y: String
  for +k: String
  {J.neg_k(b, y ++ k) == J.neg_k(b, y) ++ k : String}

def neg(b, y, k):
  match b:
    case True{}:
      {==}
    case False{}:
      {==}

law num:
  for +n: J.Number
  for +y: String
  for +k: String
  {J.num_k(n, y ++ k) == J.num_k(n, y) ++ k : String}

def num(n, y, k):
  match n:
    case J.Number{b, i, f, e}:
      +e1 : String = J.exp_k(e, y)
      +f1 : String = J.frac_k(f, e1)
      +i1 : String = J.int_k(i, f1)
      Equal.trans(String, J.neg_k(b, J.int_k(i, J.frac_k(f, J.exp_k(e, y ++ k)))), J.neg_k(b, J.int_k(i, J.frac_k(f, e1 ++ k))),
        J.neg_k(b, i1) ++ k,
        Equal.cong(String, String, x => J.neg_k(b, J.int_k(i, J.frac_k(f, x))), J.exp_k(e, y ++ k), e1 ++ k, exp(e, y, k)),
        Equal.trans(String, J.neg_k(b, J.int_k(i, J.frac_k(f, e1 ++ k))), J.neg_k(b, J.int_k(i, f1 ++ k)), J.neg_k(b, i1) ++ k,
          Equal.cong(String, String, x => J.neg_k(b, J.int_k(i, x)), J.frac_k(f, e1 ++ k), f1 ++ k, frac(f, e1, k)),
          Equal.trans(String, J.neg_k(b, J.int_k(i, f1 ++ k)), J.neg_k(b, i1 ++ k), J.neg_k(b, i1) ++ k,
            Equal.cong(String, String, x => J.neg_k(b, x), J.int_k(i, f1 ++ k), i1 ++ k, int(i, f1, k)),
            neg(b, i1, k))))

law str:
  for +s: String
  for +y: String
  for +k: String
  {S.str(s, y ++ k) == S.str(s, y) ++ k : String}

def str(s, y, k):
  Equal.cong(String, String, x => SCon{'"', x}, S.esc(s, SCon{'"', y ++ k}), S.esc(s, SCon{'"', y}) ++ k, esc(s, SCon{'"', y}, k))

# the continuation of any value's text moves out
law text:
  for +j: J.Json
  for +more: Bool
  for +y: String
  for +k: String
  {S.text(j, more, y ++ k) == S.text(j, more, y) ++ k : String}

def text(j, more, y, k):
  match j:
    case J.JNull{}:
      Equal.sym(String, ("null" ++ y) ++ k, "null" ++ (y ++ k), app_assoc("null", y, k))
    case J.JBool{True{}}:
      Equal.sym(String, ("true" ++ y) ++ k, "true" ++ (y ++ k), app_assoc("true", y, k))
    case J.JBool{False{}}:
      Equal.sym(String, ("false" ++ y) ++ k, "false" ++ (y ++ k), app_assoc("false", y, k))
    case J.JNum{n}:
      num(n, y, k)
    case J.JStr{s}:
      str(s, y, k)
    case J.JArr{Nil{}}:
      match more:
        case True{}:
          {==}
        case False{}:
          {==}
    case J.JArr{Con{h, t}}:
      +r1 : String = S.text(J.JArr{t}, True{}, y)
      Equal.trans(String,
        SCon{S.op(more, '['), S.text(h, False{}, S.text(J.JArr{t}, True{}, y ++ k))},
        SCon{S.op(more, '['), S.text(h, False{}, r1 ++ k)},
        SCon{S.op(more, '['), S.text(h, False{}, r1)} ++ k,
        Equal.cong(String, String, x => SCon{S.op(more, '['), S.text(h, False{}, x)}, S.text(J.JArr{t}, True{}, y ++ k), r1 ++ k, text(J.JArr{t}, True{}, y, k)),
        Equal.cong(String, String, x => SCon{S.op(more, '['), x}, S.text(h, False{}, r1 ++ k), S.text(h, False{}, r1) ++ k, text(h, False{}, r1, k)))
    case J.JObj{Nil{}}:
      match more:
        case True{}:
          {==}
        case False{}:
          {==}
    case J.JObj{Con{J.Field{key, v}, t}}:
      +r1 : String = S.text(J.JObj{t}, True{}, y)
      +r2 : String = SCon{':', S.text(v, False{}, r1)}
      Equal.trans(String,
        SCon{S.op(more, '{'), S.str(key, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, y ++ k))})},
        SCon{S.op(more, '{'), S.str(key, SCon{':', S.text(v, False{}, r1 ++ k)})},
        SCon{S.op(more, '{'), S.str(key, r2)} ++ k,
        Equal.cong(String, String, x => SCon{S.op(more, '{'), S.str(key, SCon{':', S.text(v, False{}, x)})}, S.text(J.JObj{t}, True{}, y ++ k), r1 ++ k, text(J.JObj{t}, True{}, y, k)),
        Equal.trans(String,
          SCon{S.op(more, '{'), S.str(key, SCon{':', S.text(v, False{}, r1 ++ k)})},
          SCon{S.op(more, '{'), S.str(key, r2 ++ k)},
          SCon{S.op(more, '{'), S.str(key, r2)} ++ k,
          Equal.cong(String, String, x => SCon{S.op(more, '{'), S.str(key, SCon{':', x})}, S.text(v, False{}, r1 ++ k), S.text(v, False{}, r1) ++ k, text(v, False{}, r1, k)),
          Equal.cong(String, String, x => SCon{S.op(more, '{'), x}, S.str(key, r2 ++ k), S.str(key, r2) ++ k, str(key, r2, k))))
