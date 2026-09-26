import Base
import ../json.bend as J
import ./spec.bend as S
import ./fast_text.bend as T

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

# the printing loop writes what show writes, whatever its fuel
law loop:
  for +f: Nat
  for +items: List<&2, J.Item>
  for +pretty: Bool
  for +unit: String
  for +out: String
  {J.print_loop(f, items, pretty, unit, out) == J.show_all(items, pretty, unit, out) : String}

def loop(f, items, pretty, unit, out):
  match f:
    case 0n:
      match items:
        case Nil{}:
          {==}
        case Con{_, _}:
          {==}
    case 1n+p:
      match items:
        case Nil{}:
          {==}
        case Con{J.Item{j, more, d}, up}:
          match j:
            case J.JNull{}:
              loop(p, up, pretty, unit, J.put("null", out))
            case J.JBool{True{}}:
              loop(p, up, pretty, unit, J.put("true", out))
            case J.JBool{False{}}:
              loop(p, up, pretty, unit, J.put("false", out))
            case J.JNum{n}:
              loop(p, up, pretty, unit, J.num_out(n, out))
            case J.JStr{x}:
              loop(p, up, pretty, unit, J.quote(x, out))
            case J.JArr{Nil{}}:
              match more:
                case True{}:
                  loop(p, up, pretty, unit, SCon{']', J.br(pretty, unit, d, out)})
                case False{}:
                  loop(p, up, pretty, unit, SCon{']', SCon{'[', out}})
            case J.JArr{Con{h, t}}:
              loop(p, Con{J.Item{h, False{}, 1n+d}, Con{J.Item{J.JArr{t}, True{}, d}, up}}, pretty, unit,
                J.br(pretty, unit, 1n+d, J.opener(more, '[', out)))
            case J.JObj{Nil{}}:
              match more:
                case True{}:
                  loop(p, up, pretty, unit, SCon{'}', J.br(pretty, unit, d, out)})
                case False{}:
                  loop(p, up, pretty, unit, SCon{'}', SCon{'{', out}})
            case J.JObj{Con{J.Field{k, v}, t}}:
              loop(p, Con{J.Item{v, False{}, 1n+d}, Con{J.Item{J.JObj{t}, True{}, d}, up}}, pretty, unit,
                J.colon(pretty, J.quote(k, J.br(pretty, unit, 1n+d, J.opener(more, '{', out)))))

# the printer writes S.text
law print:
  for +j: J.Json
  {J.stringify(j) == S.text(j, False{}, "") : String}

def print(j):
  +items : List<&2, J.Item> = [J.Item{j, False{}, 0n}]
  %Equal.sym(String, J.print_loop(J.print_fuel(), items, False{}, "", ""), J.show_all(items, False{}, "", ""),
    loop(J.print_fuel(), items, False{}, "", "")) : {String.reverse(_) == S.text(j, False{}, "") : String}
  show(j, False{}, 0n, "", "")

# Laid out
# --------

# a chunk pushed as copies lands in front, like rr
law copy:
  for +u: String
  for +out: String
  for +k: String
  {rev(J.put_copy(u, out), k) == rev(out, u ++ k) : String}

def copy(u, out, k):
  match u:
    case SNil{}:
      {==}
    case SCon{c, t}:
      match c:
        case Chr{x}:
          copy(t, SCon{Chr{x}, out}, k)

law indent:
  for +n: Nat
  for +u: String
  for +out: String
  for +k: String
  {rev(J.indent(n, u, out), k) == rev(out, S.ind(n, u) ++ k) : String}

def indent(n, u, out, k):
  match n:
    case 0n:
      {==}
    case 1n+p:
      Equal.trans(String, rev(J.indent(p, u, J.put_copy(u, out)), k), rev(J.put_copy(u, out), S.ind(p, u) ++ k),
        rev(out, S.ind(1n+p, u) ++ k),
        indent(p, u, J.put_copy(u, out), k),
        Equal.trans(String, rev(J.put_copy(u, out), S.ind(p, u) ++ k), rev(out, u ++ (S.ind(p, u) ++ k)),
          rev(out, (u ++ S.ind(p, u)) ++ k),
          copy(u, out, S.ind(p, u) ++ k),
          Equal.cong(String, String, x => rev(out, x), u ++ (S.ind(p, u) ++ k), (u ++ S.ind(p, u)) ++ k,
            Equal.sym(String, (u ++ S.ind(p, u)) ++ k, u ++ (S.ind(p, u) ++ k), T.app_assoc(u, S.ind(p, u), k)))))

law br:
  for +p: Bool
  for +u: String
  for +n: Nat
  for +out: String
  for +k: String
  {rev(J.br(p, u, n, out), k) == rev(out, S.bw(p, u, n) ++ k) : String}

def br(p, u, n, out, k):
  match p:
    case True{}:
      indent(n, u, SCon{'\n', out}, k)
    case False{}:
      {==}

law colon:
  for +p: Bool
  for +out: String
  for +k: String
  {rev(J.colon(p, out), k) == rev(out, SCon{':', S.sp(p) ++ k}) : String}

def colon(p, out, k):
  match p:
    case True{}:
      {==}
    case False{}:
      {==}

law show_lay:
  for +j: J.Json
  for +more: Bool
  for +p: Bool
  for +u: String
  for +d: Nat
  for +out: String
  for +k: String
  {rev(J.show(j, more, p, u, d, out), k) == rev(out, S.lay(j, more, p, u, d, k)) : String}

def show_lay(j, more, p, u, d, out, k):
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
          br(p, u, d, out, SCon{']', k})
        case False{}:
          {==}
    case J.JArr{Con{h, t}}:
      +o3 : String = J.opener(more, '[', out)
      +o2 : String = J.br(p, u, 1n+d, o3)
      +o1 : String = J.show(h, False{}, p, u, 1n+d, o2)
      +k1 : String = S.lay(J.JArr{t}, True{}, p, u, d, k)
      +k2 : String = S.lay(h, False{}, p, u, 1n+d, k1)
      Equal.trans(String, rev(J.show(J.JArr{t}, True{}, p, u, d, o1), k), rev(o1, k1),
        rev(out, S.lay(J.JArr{Con{h, t}}, more, p, u, d, k)),
        show_lay(J.JArr{t}, True{}, p, u, d, o1, k),
        Equal.trans(String, rev(o1, k1), rev(o2, k2), rev(out, S.lay(J.JArr{Con{h, t}}, more, p, u, d, k)),
          show_lay(h, False{}, p, u, 1n+d, o2, k1),
          Equal.trans(String, rev(o2, k2), rev(o3, S.bw(p, u, 1n+d) ++ k2), rev(out, S.lay(J.JArr{Con{h, t}}, more, p, u, d, k)),
            br(p, u, 1n+d, o3, k2),
            show.open(more, '[', out, S.bw(p, u, 1n+d) ++ k2))))
    case J.JObj{Nil{}}:
      match more:
        case True{}:
          br(p, u, d, out, SCon{'}', k})
        case False{}:
          {==}
    case J.JObj{Con{J.Field{key, v}, t}}:
      +o4 : String = J.opener(more, '{', out)
      +o3 : String = J.br(p, u, 1n+d, o4)
      +o2 : String = J.colon(p, J.quote(key, o3))
      +o1 : String = J.show(v, False{}, p, u, 1n+d, o2)
      +k1 : String = S.lay(J.JObj{t}, True{}, p, u, d, k)
      +k2 : String = S.lay(v, False{}, p, u, 1n+d, k1)
      +y : String = SCon{':', S.sp(p) ++ k2}
      Equal.trans(String, rev(J.show(J.JObj{t}, True{}, p, u, d, o1), k), rev(o1, k1),
        rev(out, S.lay(J.JObj{Con{J.Field{key, v}, t}}, more, p, u, d, k)),
        show_lay(J.JObj{t}, True{}, p, u, d, o1, k),
        Equal.trans(String, rev(o1, k1), rev(o2, k2), rev(out, S.lay(J.JObj{Con{J.Field{key, v}, t}}, more, p, u, d, k)),
          show_lay(v, False{}, p, u, 1n+d, o2, k1),
          Equal.trans(String, rev(o2, k2), rev(J.quote(key, o3), y), rev(out, S.lay(J.JObj{Con{J.Field{key, v}, t}}, more, p, u, d, k)),
            colon(p, J.quote(key, o3), k2),
            Equal.trans(String, rev(J.quote(key, o3), y), rev(SCon{'"', o3}, S.esc(key, SCon{'"', y})),
              rev(out, S.lay(J.JObj{Con{J.Field{key, v}, t}}, more, p, u, d, k)),
              escape(key, SCon{'"', o3}, SCon{'"', y}),
              Equal.trans(String, rev(o3, S.str(key, y)), rev(o4, S.bw(p, u, 1n+d) ++ S.str(key, y)),
                rev(out, S.lay(J.JObj{Con{J.Field{key, v}, t}}, more, p, u, d, k)),
                br(p, u, 1n+d, o4, S.str(key, y)),
                show.open(more, '{', out, S.bw(p, u, 1n+d) ++ S.str(key, y)))))))

# the pretty printer writes S.lay
law pretty:
  for +j: J.Json
  for +u: String
  {J.pretty(j, u) == S.lay(j, False{}, True{}, u, 0n, "") : String}

def pretty(j, u):
  +items : List<&2, J.Item> = [J.Item{j, False{}, 0n}]
  %Equal.sym(String, J.print_loop(J.print_fuel(), items, True{}, u, ""), J.show_all(items, True{}, u, ""),
    loop(J.print_fuel(), items, True{}, u, "")) : {String.reverse(_) == S.lay(j, False{}, True{}, u, 0n, "") : String}
  show_lay(j, False{}, True{}, u, 0n, "", "")
