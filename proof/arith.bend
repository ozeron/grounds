import Base
import ../bjson.bend as J
import ./spec.bend as S

# Nat and length facts for the parser's fuel.

def add(a: Nat, b: Nat) -> Nat:
  Nat.add(a, b)

def len(s: String) -> Nat:
  String.length(s)

law add_succ:
  for +a: Nat
  for +b: Nat
  {add(a, 1n+b) == 1n+add(a, b) : Nat}

def add_succ(a, b):
  match a:
    case 0n:
      {==}
    case 1n+p:
      Equal.cong(Nat, Nat, x => 1n+x, add(p, 1n+b), 1n+add(p, b), add_succ(p, b))

law add_assoc:
  for +a: Nat
  for +b: Nat
  for +c: Nat
  {add(add(a, b), c) == add(a, add(b, c)) : Nat}

def add_assoc(a, b, c):
  match a:
    case 0n:
      {==}
    case 1n+p:
      Equal.cong(Nat, Nat, x => 1n+x, add(add(p, b), c), add(p, add(b, c)), add_assoc(p, b, c))

law len_app:
  for +a: String
  for +b: String
  {len(a ++ b) == add(len(a), len(b)) : Nat}

def len_app(a, b):
  match a:
    case SNil{}:
      {==}
    case SCon{_, t}:
      Equal.cong(Nat, Nat, x => 1n+x, len(t ++ b), add(len(t), len(b)), len_app(t, b))

# a prefix adds its own length: len(p ++ k) == x + len(k)
def Pre(s: String, k: String) -> Type:
  &x: Nat -> {len(s) == add(x, len(k)) : Nat}

law pre_cons:
  for +c: Char
  for +s: String
  for +k: String
  for w: Pre(s, k)
  Pre(SCon{c, s}, k)

def pre_cons(c, s, k, w):
  (+x, e) = w
  (1n+x, Equal.cong(Nat, Nat, y => 1n+y, len(s), add(x, len(k)), e))

law pre_app:
  for +a: String
  for +s: String
  for +k: String
  for w: Pre(s, k)
  Pre(a ++ s, k)

def pre_app(a, s, k, w):
  (+x, e) = w
  (add(len(a), x),
    Equal.trans(Nat, len(a ++ s), add(len(a), len(s)), add(add(len(a), x), len(k)),
      len_app(a, s),
      Equal.trans(Nat, add(len(a), len(s)), add(len(a), add(x, len(k))), add(add(len(a), x), len(k)),
        Equal.cong(Nat, Nat, y => add(len(a), y), len(s), add(x, len(k)), e),
        Equal.sym(Nat, add(add(len(a), x), len(k)), add(len(a), add(x, len(k))), add_assoc(len(a), x, len(k))))))

# prefixes chain: if s ends in x and x ends in k, s ends in k
law pre_trans:
  for +s: String
  for +x: String
  for +k: String
  for a: Pre(s, x)
  for b: Pre(x, k)
  Pre(s, k)

def pre_trans(s, x, k, a, b):
  (+p, ea) = a
  (+q, eb) = b
  (add(p, q),
    Equal.trans(Nat, len(s), add(p, len(x)), add(add(p, q), len(k)),
      ea,
      Equal.trans(Nat, add(p, len(x)), add(p, add(q, len(k))), add(add(p, q), len(k)),
        Equal.cong(Nat, Nat, y => add(p, y), len(x), add(q, len(k)), eb),
        Equal.sym(Nat, add(add(p, q), len(k)), add(p, add(q, len(k))), add_assoc(p, q, len(k))))))

law pre_nil:
  for +k: String
  Pre(k, k)

def pre_nil(k):
  (0n, {==})

law pre_esc_char:
  for +cl: J.Class
  for +c: Char
  for +s: String
  for +k: String
  for w: Pre(s, k)
  Pre(S.esc_char(cl, c, s), k)

def pre_esc_char(cl, c, s, k, w):
  match cl:
    case J.KQuote{}:
      pre_cons('\\', SCon{c, s}, k, pre_cons(c, s, k, w))
    case J.KBack{}:
      pre_cons('\\', SCon{c, s}, k, pre_cons(c, s, k, w))
    case J.KCtrl{}:
      pre_app(J.ctrl_text(c), s, k, w)
    case J.KPlain{}:
      pre_cons(c, s, k, w)

law pre_esc:
  for +s: String
  for +k: String
  Pre(S.esc(s, k), k)

def pre_esc(s, k):
  match s:
    case SNil{}:
      pre_nil(k)
    case SCon{c, t}:
      pre_esc_char(J.class(c), c, S.esc(t, k), k, pre_esc(t, k))

law pre_digits:
  for +ds: List<&2, J.Digit>
  for +k: String
  Pre(J.digits_k(ds, k), k)

def pre_digits(ds, k):
  match ds:
    case Nil{}:
      pre_nil(k)
    case Con{d, t}:
      pre_cons(J.digit_char(d), J.digits_k(t, k), k, pre_digits(t, k))

law pre_sign:
  for +s: J.Sign
  for +x: String
  for +k: String
  for w: Pre(x, k)
  Pre(J.sign_k(s, x), k)

def pre_sign(s, x, k, w):
  match s:
    case J.NoSign{}:
      w
    case J.Plus{}:
      pre_cons('+', x, k, w)
    case J.Minus{}:
      pre_cons('-', x, k, w)

law pre_exp:
  for +e: J.Exp
  for +k: String
  Pre(J.exp_k(e, k), k)

def pre_exp(e, k):
  match e:
    case J.ENone{}:
      pre_nil(k)
    case J.ESome{u, s, d, ds}:
      +x : String = SCon{J.digit_char(d), J.digits_k(ds, k)}
      pre_cons(Bool.pick(Char, u, 'E', 'e'), J.sign_k(s, x), k,
        pre_sign(s, x, k, pre_cons(J.digit_char(d), J.digits_k(ds, k), k, pre_digits(ds, k))))

law pre_frac:
  for +f: J.Frac
  for +x: String
  for +k: String
  for w: Pre(x, k)
  Pre(J.frac_k(f, x), k)

def pre_frac(f, x, k, w):
  match f:
    case J.FNone{}:
      w
    case J.FSome{d, ds}:
      pre_cons('.', SCon{J.digit_char(d), J.digits_k(ds, x)}, k,
        pre_cons(J.digit_char(d), J.digits_k(ds, x), k,
          pre_trans(J.digits_k(ds, x), x, k, pre_digits(ds, x), w)))


law pre_int:
  for +i: J.Int
  for +x: String
  for +k: String
  for w: Pre(x, k)
  Pre(J.int_k(i, x), k)

def pre_int(i, x, k, w):
  match i:
    case J.IZero{}:
      pre_cons('0', x, k, w)
    case J.INon{l, ds}:
      pre_cons(J.lead_char(l), J.digits_k(ds, x), k, pre_trans(J.digits_k(ds, x), x, k, pre_digits(ds, x), w))

# at least one char, then a prefix of k
def Pre1(s: String, k: String) -> Type:
  &x: Nat -> {len(s) == 1n+add(x, len(k)) : Nat}

law num_len.cons:
  for +c: Char
  for +s: String
  for +k: String
  for w: Pre(s, k)
  Pre1(SCon{c, s}, k)

def num_len.cons(c, s, k, w):
  (+x, e) = w
  (x, Equal.cong(Nat, Nat, y => 1n+y, len(s), add(x, len(k)), e))

law num_len.go:
  for +neg: Bool
  for +i: J.Int
  for +f: J.Frac
  for +e: J.Exp
  for +k: String
  Pre1(J.num_k(J.Number{neg, i, f, e}, k), k)

def num_len.go(neg, i, f, e, k):
  match neg:
    case True{}:
      +fx : String = J.frac_k(f, J.exp_k(e, k))
      num_len.cons('-', J.int_k(i, fx), k, pre_int(i, fx, k, pre_frac(f, J.exp_k(e, k), k, pre_exp(e, k))))
    case False{}:
      match i:
        case J.IZero{}:
          +fx : String = J.frac_k(f, J.exp_k(e, k))
          num_len.cons('0', fx, k, pre_frac(f, J.exp_k(e, k), k, pre_exp(e, k)))
        case J.INon{l, ds}:
          +fx : String = J.frac_k(f, J.exp_k(e, k))
          num_len.cons(J.lead_char(l), J.digits_k(ds, fx), k,
            pre_trans(J.digits_k(ds, fx), fx, k, pre_digits(ds, fx), pre_frac(f, J.exp_k(e, k), k, pre_exp(e, k))))

# a number is at least one char, then the rest of its text
law num_len:
  for +n: J.Number
  for +k: String
  Pre1(J.num_k(n, k), k)

def num_len(n, k):
  match n:
    case J.Number{neg, i, f, e}:
      num_len.go(neg, i, f, e, k)

