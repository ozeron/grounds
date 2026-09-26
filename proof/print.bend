import Base
import ../bjson.bend as J
import ./spec.bend as S

# The printer builds its output reversed, one tail call at a time. These
# lemmas show that reversing it gives S.text: the plain forward text.

def rev(a: String, k: String) -> String:
  String.reverse.go(a, k)

# pushing a onto a reversed output, then unreversing, puts a in front
law rr:
  for +a: String
  for +out: String
  for +k: String
  {rev(rev(a, out), k) == rev(out, a ++ k) : String}

def rr(a, out, k):
  match a:
    case SNil{}:
      {==}
    case SCon{c, t}:
      rr(t, SCon{c, out}, k)

law esc_char:
  for +cl: J.Class
  for +c: Char
  for +out: String
  for +k: String
  {rev(J.esc_char(cl, c, out), k) == rev(out, S.esc_char(cl, c, k)) : String}

def esc_char(cl, c, out, k):
  match cl:
    case J.KQuote{}:
      {==}
    case J.KBack{}:
      {==}
    case J.KCtrl{}:
      rr(J.ctrl_text(c), out, k)
    case J.KPlain{}:
      {==}

law escape:
  for +s: String
  for +out: String
  for +k: String
  {rev(J.escape(s, out), k) == rev(out, S.esc(s, k)) : String}

def escape(s, out, k):
  match s:
    case SNil{}:
      {==}
    case SCon{c, t}:
      Equal.trans(String,
        rev(J.escape(t, J.esc_char(J.class(c), c, out)), k),
        rev(J.esc_char(J.class(c), c, out), S.esc(t, k)),
        rev(out, S.esc_char(J.class(c), c, S.esc(t, k))),
        escape(t, J.esc_char(J.class(c), c, out), k),
        esc_char(J.class(c), c, out, S.esc(t, k)))

law digits:
  for +ds: List<&2, J.Digit>
  for +out: String
  for +k: String
  {rev(J.digits_out(ds, out), k) == rev(out, J.digits_k(ds, k)) : String}

def digits(ds, out, k):
  match ds:
    case Nil{}:
      {==}
    case Con{d, t}:
      digits(t, SCon{J.digit_char(d), out}, k)

law int:
  for +i: J.Int
  for +out: String
  for +k: String
  {rev(J.int_out(i, out), k) == rev(out, J.int_k(i, k)) : String}

def int(i, out, k):
  match i:
    case J.IZero{}:
      {==}
    case J.INon{l, ds}:
      digits(ds, SCon{J.lead_char(l), out}, k)

law frac:
  for +f: J.Frac
  for +out: String
  for +k: String
  {rev(J.frac_out(f, out), k) == rev(out, J.frac_k(f, k)) : String}

def frac(f, out, k):
  match f:
    case J.FNone{}:
      {==}
    case J.FSome{d, ds}:
      digits(ds, SCon{J.digit_char(d), SCon{'.', out}}, k)

law sign:
  for +s: J.Sign
  for +out: String
  for +k: String
  {rev(J.sign_out(s, out), k) == rev(out, J.sign_k(s, k)) : String}

def sign(s, out, k):
  match s:
    case J.NoSign{}:
      {==}
    case J.Plus{}:
      {==}
    case J.Minus{}:
      {==}

law exp:
  for +e: J.Exp
  for +out: String
  for +k: String
  {rev(J.exp_out(e, out), k) == rev(out, J.exp_k(e, k)) : String}

def exp(e, out, k):
  match e:
    case J.ENone{}:
      {==}
    case J.ESome{u, s, d, ds}:
      Equal.trans(String,
        rev(J.digits_out(ds, SCon{J.digit_char(d), J.sign_out(s, SCon{Bool.pick(Char, u, 'E', 'e'), out})}), k),
        rev(J.sign_out(s, SCon{Bool.pick(Char, u, 'E', 'e'), out}), SCon{J.digit_char(d), J.digits_k(ds, k)}),
        rev(out, J.exp_k(J.ESome{u, s, d, ds}, k)),
        digits(ds, SCon{J.digit_char(d), J.sign_out(s, SCon{Bool.pick(Char, u, 'E', 'e'), out})}, k),
        sign(s, SCon{Bool.pick(Char, u, 'E', 'e'), out}, SCon{J.digit_char(d), J.digits_k(ds, k)}))

law neg:
  for +b: Bool
  for +out: String
  for +k: String
  {rev(J.neg_out(b, out), k) == rev(out, J.neg_k(b, k)) : String}

def neg(b, out, k):
  match b:
    case True{}:
      {==}
    case False{}:
      {==}

law num:
  for +n: J.Number
  for +out: String
  for +k: String
  {rev(J.num_out(n, out), k) == rev(out, J.num_k(n, k)) : String}

def num(n, out, k):
  match n:
    case J.Number{b, i, f, e}:
      +o1 : String = J.neg_out(b, out)
      +o2 : String = J.int_out(i, o1)
      +o3 : String = J.frac_out(f, o2)
      +k3 : String = J.exp_k(e, k)
      +k2 : String = J.frac_k(f, k3)
      +k1 : String = J.int_k(i, k2)
      Equal.trans(String, rev(J.exp_out(e, o3), k), rev(o3, k3), rev(out, J.neg_k(b, k1)),
        exp(e, o3, k),
        Equal.trans(String, rev(o3, k3), rev(o2, k2), rev(out, J.neg_k(b, k1)),
          frac(f, o2, k3),
          Equal.trans(String, rev(o2, k2), rev(o1, k1), rev(out, J.neg_k(b, k1)),
            int(i, o1, k2),
            neg(b, out, k1))))

# the opening char of a container, or the comma before an item
law show.open:
  for +more: Bool
  for +c: Char
  for +out: String
  for +k: String
  {rev(J.opener(more, c, out), k) == rev(out, SCon{S.op(more, c), k}) : String}

def show.open(more, c, out, k):
  match more:
    case True{}:
      {==}
    case False{}:
      {==}

law show:
  for +j: J.Json
  for +more: Bool
  for +d: Nat
  for +out: String
  for +k: String
  {rev(J.show(j, more, False{}, "", d, out), k) == rev(out, S.text(j, more, k)) : String}

def show(j, more, d, out, k):
  match j:
    case J.JNull{}:
      rr("null", out, k)
    case J.JBool{True{}}:
      rr("true", out, k)
    case J.JBool{False{}}:
      rr("false", out, k)
    case J.JNum{n}:
      num(n, out, k)
    case J.JStr{s}:
      escape(s, SCon{'"', out}, SCon{'"', k})
    case J.JArr{Nil{}}:
      match more:
        case True{}:
          {==}
        case False{}:
          {==}
    case J.JArr{Con{h, t}}:
      +o2 : String = J.opener(more, '[', out)
      +o1 : String = J.show(h, False{}, False{}, "", 1n+d, o2)
      +k1 : String = S.text(J.JArr{t}, True{}, k)
      Equal.trans(String,
        rev(J.show(J.JArr{t}, True{}, False{}, "", d, o1), k),
        rev(o1, k1),
        rev(out, S.text(J.JArr{Con{h, t}}, more, k)),
        show(J.JArr{t}, True{}, d, o1, k),
        Equal.trans(String, rev(o1, k1), rev(o2, S.text(h, False{}, k1)), rev(out, S.text(J.JArr{Con{h, t}}, more, k)),
          show(h, False{}, 1n+d, o2, k1),
          show.open(more, '[', out, S.text(h, False{}, k1))))
    case J.JObj{Nil{}}:
      match more:
        case True{}:
          {==}
        case False{}:
          {==}
    case J.JObj{Con{J.Field{key, v}, t}}:
      +o3 : String = J.opener(more, '{', out)
      +o2 : String = SCon{':', J.quote(key, o3)}
      +o1 : String = J.show(v, False{}, False{}, "", 1n+d, o2)
      +k1 : String = S.text(J.JObj{t}, True{}, k)
      +k2 : String = S.text(v, False{}, k1)
      Equal.trans(String,
        rev(J.show(J.JObj{t}, True{}, False{}, "", d, o1), k),
        rev(o1, k1),
        rev(out, S.text(J.JObj{Con{J.Field{key, v}, t}}, more, k)),
        show(J.JObj{t}, True{}, d, o1, k),
        Equal.trans(String, rev(o1, k1), rev(o2, k2), rev(out, S.text(J.JObj{Con{J.Field{key, v}, t}}, more, k)),
          show(v, False{}, 1n+d, o2, k1),
          Equal.trans(String, rev(o2, k2), rev(SCon{'"', o3}, S.esc(key, SCon{'"', SCon{':', k2}})),
            rev(out, S.text(J.JObj{Con{J.Field{key, v}, t}}, more, k)),
            escape(key, SCon{'"', o3}, SCon{'"', SCon{':', k2}}),
            show.open(more, '{', out, S.str(key, SCon{':', k2})))))

# the printer writes S.text
law print:
  for +j: J.Json
  {J.stringify(j) == S.text(j, False{}, "") : String}

def print(j):
  show(j, False{}, 0n, "", "")
