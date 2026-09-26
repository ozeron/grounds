import Base
import ../bjson.bend as J

# Lexing J.num_k(n, r) gives back n, when r starts with a char no number
# continues with (as the printer's ',', ']', '}' or the end all do).

def Delim(r: String) -> Type:
  match r:
    case SNil{}:
      Unit
    case SCon{c, _}:
      {J.nclass(c) == J.COther{} : J.NC}

def rl(xs: List<&2, J.Digit>, acc: List<&2, J.Digit>) -> List<&2, J.Digit>:
  List.reverse.go(&2, J.Digit, xs, acc)

# reversing twice gives the list back
law rrl:
  for +a: List<&2, J.Digit>
  for +b: List<&2, J.Digit>
  {rl(rl(a, b), []) == rl(b, a) : List<&2, J.Digit>}

def rrl(a, b):
  match a:
    case Nil{}:
      {==}
    case Con{x, t}:
      rrl(t, Con{x, b})

law rev_rev:
  for +a: List<&2, J.Digit>
  {J.rev(rl(a, [])) == a : List<&2, J.Digit>}

def rev_rev(a):
  rrl(a, [])

# after a halt, the lexer reports what it had
law halt_end:
  for +st: J.NSt
  for +here: String
  for +t: String
  {J.lex_num(t, J.NHalt{st, here}) == J.num_end(st, here) : J.NLex}

def halt_end(st, here, t):
  match t:
    case SNil{}:
      {==}
    case SCon{_, _}:
      {==}

# a number ends at a delimiter
law fin_zero:
  for +neg: Bool
  for +r: String
  for dl: Delim(r)
  {J.lex_num(r, J.NZero{neg}) == J.num_end(J.NZero{neg}, r) : J.NLex}

def fin_zero(neg, r, dl):
  match r:
    case SNil{}:
      {==}
    case SCon{c, t}:
      %Equal.sym(J.NC, J.nclass(c), J.COther{}, dl) : {J.lex_num(t, J.halt(J.is_stop(J.num_next(J.NZero{neg}, _)), J.NZero{neg}, J.num_next(J.NZero{neg}, _), SCon{c, t})) == J.num_end(J.NZero{neg}, SCon{c, t}) : J.NLex}
      halt_end(J.NZero{neg}, SCon{c, t}, t)

# a number ends at a delimiter
law fin_int:
  for +neg: Bool
  for +l: J.Lead
  for +acc: List<&2, J.Digit>
  for +r: String
  for dl: Delim(r)
  {J.lex_num(r, J.NInt{neg, l, acc}) == J.num_end(J.NInt{neg, l, acc}, r) : J.NLex}

def fin_int(neg, l, acc, r, dl):
  match r:
    case SNil{}:
      {==}
    case SCon{c, t}:
      %Equal.sym(J.NC, J.nclass(c), J.COther{}, dl) : {J.lex_num(t, J.halt(J.is_stop(J.num_next(J.NInt{neg, l, acc}, _)), J.NInt{neg, l, acc}, J.num_next(J.NInt{neg, l, acc}, _), SCon{c, t})) == J.num_end(J.NInt{neg, l, acc}, SCon{c, t}) : J.NLex}
      halt_end(J.NInt{neg, l, acc}, SCon{c, t}, t)

# a number ends at a delimiter
law fin_frac:
  for +neg: Bool
  for +i: J.Int
  for +f: J.Digit
  for +acc: List<&2, J.Digit>
  for +r: String
  for dl: Delim(r)
  {J.lex_num(r, J.NFrac{neg, i, f, acc}) == J.num_end(J.NFrac{neg, i, f, acc}, r) : J.NLex}

def fin_frac(neg, i, f, acc, r, dl):
  match r:
    case SNil{}:
      {==}
    case SCon{c, t}:
      %Equal.sym(J.NC, J.nclass(c), J.COther{}, dl) : {J.lex_num(t, J.halt(J.is_stop(J.num_next(J.NFrac{neg, i, f, acc}, _)), J.NFrac{neg, i, f, acc}, J.num_next(J.NFrac{neg, i, f, acc}, _), SCon{c, t})) == J.num_end(J.NFrac{neg, i, f, acc}, SCon{c, t}) : J.NLex}
      halt_end(J.NFrac{neg, i, f, acc}, SCon{c, t}, t)

# a number ends at a delimiter
law fin_exp:
  for +neg: Bool
  for +i: J.Int
  for +fr: J.Frac
  for +u: Bool
  for +sg: J.Sign
  for +f: J.Digit
  for +acc: List<&2, J.Digit>
  for +r: String
  for dl: Delim(r)
  {J.lex_num(r, J.NExp{neg, i, fr, u, sg, f, acc}) == J.num_end(J.NExp{neg, i, fr, u, sg, f, acc}, r) : J.NLex}

def fin_exp(neg, i, fr, u, sg, f, acc, r, dl):
  match r:
    case SNil{}:
      {==}
    case SCon{c, t}:
      %Equal.sym(J.NC, J.nclass(c), J.COther{}, dl) : {J.lex_num(t, J.halt(J.is_stop(J.num_next(J.NExp{neg, i, fr, u, sg, f, acc}, _)), J.NExp{neg, i, fr, u, sg, f, acc}, J.num_next(J.NExp{neg, i, fr, u, sg, f, acc}, _), SCon{c, t})) == J.num_end(J.NExp{neg, i, fr, u, sg, f, acc}, SCon{c, t}) : J.NLex}
      halt_end(J.NExp{neg, i, fr, u, sg, f, acc}, SCon{c, t}, t)

# a run of digits is pushed, reversed, onto the state's list
law run_int:
  for +neg: Bool
  for +l: J.Lead
  for +ds: List<&2, J.Digit>
  for +acc: List<&2, J.Digit>
  for +k: String
  {J.lex_num(J.digits_k(ds, k), J.NInt{neg, l, acc}) == J.lex_num(k, J.NInt{neg, l, rl(ds, acc)}) : J.NLex}

def run_int(neg, l, ds, acc, k):
  match ds:
    case Nil{}:
      {==}
    case Con{d, t}:
      match d:
        case J.D0{}:
          run_int(neg, l, t, Con{J.D0{}, acc}, k)
        case J.D1{}:
          run_int(neg, l, t, Con{J.D1{}, acc}, k)
        case J.D2{}:
          run_int(neg, l, t, Con{J.D2{}, acc}, k)
        case J.D3{}:
          run_int(neg, l, t, Con{J.D3{}, acc}, k)
        case J.D4{}:
          run_int(neg, l, t, Con{J.D4{}, acc}, k)
        case J.D5{}:
          run_int(neg, l, t, Con{J.D5{}, acc}, k)
        case J.D6{}:
          run_int(neg, l, t, Con{J.D6{}, acc}, k)
        case J.D7{}:
          run_int(neg, l, t, Con{J.D7{}, acc}, k)
        case J.D8{}:
          run_int(neg, l, t, Con{J.D8{}, acc}, k)
        case J.D9{}:
          run_int(neg, l, t, Con{J.D9{}, acc}, k)

# a run of digits is pushed, reversed, onto the state's list
law run_frac:
  for +neg: Bool
  for +i: J.Int
  for +f: J.Digit
  for +ds: List<&2, J.Digit>
  for +acc: List<&2, J.Digit>
  for +k: String
  {J.lex_num(J.digits_k(ds, k), J.NFrac{neg, i, f, acc}) == J.lex_num(k, J.NFrac{neg, i, f, rl(ds, acc)}) : J.NLex}

def run_frac(neg, i, f, ds, acc, k):
  match ds:
    case Nil{}:
      {==}
    case Con{d, t}:
      match d:
        case J.D0{}:
          run_frac(neg, i, f, t, Con{J.D0{}, acc}, k)
        case J.D1{}:
          run_frac(neg, i, f, t, Con{J.D1{}, acc}, k)
        case J.D2{}:
          run_frac(neg, i, f, t, Con{J.D2{}, acc}, k)
        case J.D3{}:
          run_frac(neg, i, f, t, Con{J.D3{}, acc}, k)
        case J.D4{}:
          run_frac(neg, i, f, t, Con{J.D4{}, acc}, k)
        case J.D5{}:
          run_frac(neg, i, f, t, Con{J.D5{}, acc}, k)
        case J.D6{}:
          run_frac(neg, i, f, t, Con{J.D6{}, acc}, k)
        case J.D7{}:
          run_frac(neg, i, f, t, Con{J.D7{}, acc}, k)
        case J.D8{}:
          run_frac(neg, i, f, t, Con{J.D8{}, acc}, k)
        case J.D9{}:
          run_frac(neg, i, f, t, Con{J.D9{}, acc}, k)

# a run of digits is pushed, reversed, onto the state's list
law run_exp:
  for +neg: Bool
  for +i: J.Int
  for +fr: J.Frac
  for +u: Bool
  for +sg: J.Sign
  for +f: J.Digit
  for +ds: List<&2, J.Digit>
  for +acc: List<&2, J.Digit>
  for +k: String
  {J.lex_num(J.digits_k(ds, k), J.NExp{neg, i, fr, u, sg, f, acc}) == J.lex_num(k, J.NExp{neg, i, fr, u, sg, f, rl(ds, acc)}) : J.NLex}

def run_exp(neg, i, fr, u, sg, f, ds, acc, k):
  match ds:
    case Nil{}:
      {==}
    case Con{d, t}:
      match d:
        case J.D0{}:
          run_exp(neg, i, fr, u, sg, f, t, Con{J.D0{}, acc}, k)
        case J.D1{}:
          run_exp(neg, i, fr, u, sg, f, t, Con{J.D1{}, acc}, k)
        case J.D2{}:
          run_exp(neg, i, fr, u, sg, f, t, Con{J.D2{}, acc}, k)
        case J.D3{}:
          run_exp(neg, i, fr, u, sg, f, t, Con{J.D3{}, acc}, k)
        case J.D4{}:
          run_exp(neg, i, fr, u, sg, f, t, Con{J.D4{}, acc}, k)
        case J.D5{}:
          run_exp(neg, i, fr, u, sg, f, t, Con{J.D5{}, acc}, k)
        case J.D6{}:
          run_exp(neg, i, fr, u, sg, f, t, Con{J.D6{}, acc}, k)
        case J.D7{}:
          run_exp(neg, i, fr, u, sg, f, t, Con{J.D7{}, acc}, k)
        case J.D8{}:
          run_exp(neg, i, fr, u, sg, f, t, Con{J.D8{}, acc}, k)
        case J.D9{}:
          run_exp(neg, i, fr, u, sg, f, t, Con{J.D9{}, acc}, k)

law step_dot:
  for +neg: Bool
  for +i: J.Int
  for +d: J.Digit
  for +k: String
  {J.lex_num(SCon{J.digit_char(d), k}, J.NDot{neg, i}) == J.lex_num(k, J.NFrac{neg, i, d, []}) : J.NLex}

def step_dot(neg, i, d, k):
  match d:
    case J.D0{}:
      {==}
    case J.D1{}:
      {==}
    case J.D2{}:
      {==}
    case J.D3{}:
      {==}
    case J.D4{}:
      {==}
    case J.D5{}:
      {==}
    case J.D6{}:
      {==}
    case J.D7{}:
      {==}
    case J.D8{}:
      {==}
    case J.D9{}:
      {==}

law step_e:
  for +neg: Bool
  for +i: J.Int
  for +fr: J.Frac
  for +u: Bool
  for +d: J.Digit
  for +k: String
  {J.lex_num(SCon{J.digit_char(d), k}, J.NE{neg, i, fr, u}) == J.lex_num(k, J.NExp{neg, i, fr, u, J.NoSign{}, d, []}) : J.NLex}

def step_e(neg, i, fr, u, d, k):
  match d:
    case J.D0{}:
      {==}
    case J.D1{}:
      {==}
    case J.D2{}:
      {==}
    case J.D3{}:
      {==}
    case J.D4{}:
      {==}
    case J.D5{}:
      {==}
    case J.D6{}:
      {==}
    case J.D7{}:
      {==}
    case J.D8{}:
      {==}
    case J.D9{}:
      {==}

law step_esign:
  for +neg: Bool
  for +i: J.Int
  for +fr: J.Frac
  for +u: Bool
  for +sg: J.Sign
  for +d: J.Digit
  for +k: String
  {J.lex_num(SCon{J.digit_char(d), k}, J.NESign{neg, i, fr, u, sg}) == J.lex_num(k, J.NExp{neg, i, fr, u, sg, d, []}) : J.NLex}

def step_esign(neg, i, fr, u, sg, d, k):
  match d:
    case J.D0{}:
      {==}
    case J.D1{}:
      {==}
    case J.D2{}:
      {==}
    case J.D3{}:
      {==}
    case J.D4{}:
      {==}
    case J.D5{}:
      {==}
    case J.D6{}:
      {==}
    case J.D7{}:
      {==}
    case J.D8{}:
      {==}
    case J.D9{}:
      {==}

def start(neg: Bool) -> J.NSt:
  match neg:
    case True{}:
      J.NMin{}
    case False{}:
      J.NStart{}

law step_lead:
  for +neg: Bool
  for +l: J.Lead
  for +k: String
  {J.lex_num(SCon{J.lead_char(l), k}, start(neg)) == J.lex_num(k, J.NInt{neg, l, []}) : J.NLex}

def step_lead(neg, l, k):
  match neg:
    case True{}:
      match l:
        case J.L1{}:
          {==}
        case J.L2{}:
          {==}
        case J.L3{}:
          {==}
        case J.L4{}:
          {==}
        case J.L5{}:
          {==}
        case J.L6{}:
          {==}
        case J.L7{}:
          {==}
        case J.L8{}:
          {==}
        case J.L9{}:
          {==}
    case False{}:
      match l:
        case J.L1{}:
          {==}
        case J.L2{}:
          {==}
        case J.L3{}:
          {==}
        case J.L4{}:
          {==}
        case J.L5{}:
          {==}
        case J.L6{}:
          {==}
        case J.L7{}:
          {==}
        case J.L8{}:
          {==}
        case J.L9{}:
          {==}

law step_zero:
  for +neg: Bool
  for +k: String
  {J.lex_num(SCon{'0', k}, start(neg)) == J.lex_num(k, J.NZero{neg}) : J.NLex}

def step_zero(neg, k):
  match neg:
    case True{}:
      {==}
    case False{}:
      {==}

def ok(n: J.Number, r: String) -> J.NLex:
  J.NOk{n, r}

# exponent digits, then the end
law exp_digits:
  for +neg: Bool
  for +i: J.Int
  for +fr: J.Frac
  for +u: Bool
  for +sg: J.Sign
  for +d: J.Digit
  for +ds: List<&2, J.Digit>
  for +r: String
  for dl: Delim(r)
  {J.lex_num(J.digits_k(ds, r), J.NExp{neg, i, fr, u, sg, d, []}) == ok(J.Number{neg, i, fr, J.ESome{u, sg, d, ds}}, r) : J.NLex}

def exp_digits(neg, i, fr, u, sg, d, ds, r, dl):
  +st : J.NSt = J.NExp{neg, i, fr, u, sg, d, rl(ds, [])}
  Equal.trans(J.NLex, J.lex_num(J.digits_k(ds, r), J.NExp{neg, i, fr, u, sg, d, []}), J.lex_num(r, st),
    ok(J.Number{neg, i, fr, J.ESome{u, sg, d, ds}}, r),
    run_exp(neg, i, fr, u, sg, d, ds, [], r),
    Equal.trans(J.NLex, J.lex_num(r, st), J.num_end(st, r), ok(J.Number{neg, i, fr, J.ESome{u, sg, d, ds}}, r),
      fin_exp(neg, i, fr, u, sg, d, rl(ds, []), r, dl),
      Equal.cong(List<&2, J.Digit>, J.NLex, x => ok(J.Number{neg, i, fr, J.ESome{u, sg, d, x}}, r), J.rev(rl(ds, [])), ds, rev_rev(ds))))

# after e or E: an optional sign, then digits
law exp_rest:
  for +neg: Bool
  for +i: J.Int
  for +fr: J.Frac
  for +u: Bool
  for +sg: J.Sign
  for +d: J.Digit
  for +ds: List<&2, J.Digit>
  for +r: String
  for dl: Delim(r)
  {J.lex_num(J.sign_k(sg, SCon{J.digit_char(d), J.digits_k(ds, r)}), J.NE{neg, i, fr, u}) == ok(J.Number{neg, i, fr, J.ESome{u, sg, d, ds}}, r) : J.NLex}

def exp_rest(neg, i, fr, u, sg, d, ds, r, dl):
  match sg:
    case J.NoSign{}:
      Equal.trans(J.NLex, J.lex_num(SCon{J.digit_char(d), J.digits_k(ds, r)}, J.NE{neg, i, fr, u}),
        J.lex_num(J.digits_k(ds, r), J.NExp{neg, i, fr, u, J.NoSign{}, d, []}),
        ok(J.Number{neg, i, fr, J.ESome{u, J.NoSign{}, d, ds}}, r),
        step_e(neg, i, fr, u, d, J.digits_k(ds, r)),
        exp_digits(neg, i, fr, u, J.NoSign{}, d, ds, r, dl))
    case J.Plus{}:
      Equal.trans(J.NLex, J.lex_num(SCon{J.digit_char(d), J.digits_k(ds, r)}, J.NESign{neg, i, fr, u, J.Plus{}}),
        J.lex_num(J.digits_k(ds, r), J.NExp{neg, i, fr, u, J.Plus{}, d, []}),
        ok(J.Number{neg, i, fr, J.ESome{u, J.Plus{}, d, ds}}, r),
        step_esign(neg, i, fr, u, J.Plus{}, d, J.digits_k(ds, r)),
        exp_digits(neg, i, fr, u, J.Plus{}, d, ds, r, dl))
    case J.Minus{}:
      Equal.trans(J.NLex, J.lex_num(SCon{J.digit_char(d), J.digits_k(ds, r)}, J.NESign{neg, i, fr, u, J.Minus{}}),
        J.lex_num(J.digits_k(ds, r), J.NExp{neg, i, fr, u, J.Minus{}, d, []}),
        ok(J.Number{neg, i, fr, J.ESome{u, J.Minus{}, d, ds}}, r),
        step_esign(neg, i, fr, u, J.Minus{}, d, J.digits_k(ds, r)),
        exp_digits(neg, i, fr, u, J.Minus{}, d, ds, r, dl))

law exp_zero:
  for +neg: Bool
  for +e: J.Exp
  for +r: String
  for dl: Delim(r)
  {J.lex_num(J.exp_k(e, r), J.NZero{neg}) == ok(J.Number{neg, J.IZero{}, J.FNone{}, e}, r) : J.NLex}

def exp_zero(neg, e, r, dl):
  match e:
    case J.ENone{}:
      fin_zero(neg, r, dl)
    case J.ESome{u, sg, d, ds}:
      match u:
        case True{}:
          exp_rest(neg, J.IZero{}, J.FNone{}, True{}, sg, d, ds, r, dl)
        case False{}:
          exp_rest(neg, J.IZero{}, J.FNone{}, False{}, sg, d, ds, r, dl)

law exp_int:
  for +neg: Bool
  for +l: J.Lead
  for +acc: List<&2, J.Digit>
  for +e: J.Exp
  for +r: String
  for dl: Delim(r)
  {J.lex_num(J.exp_k(e, r), J.NInt{neg, l, acc}) == ok(J.Number{neg, J.INon{l, J.rev(acc)}, J.FNone{}, e}, r) : J.NLex}

def exp_int(neg, l, acc, e, r, dl):
  match e:
    case J.ENone{}:
      fin_int(neg, l, acc, r, dl)
    case J.ESome{u, sg, d, ds}:
      match u:
        case True{}:
          exp_rest(neg, J.INon{l, J.rev(acc)}, J.FNone{}, True{}, sg, d, ds, r, dl)
        case False{}:
          exp_rest(neg, J.INon{l, J.rev(acc)}, J.FNone{}, False{}, sg, d, ds, r, dl)

law exp_frac:
  for +neg: Bool
  for +i: J.Int
  for +f: J.Digit
  for +acc: List<&2, J.Digit>
  for +e: J.Exp
  for +r: String
  for dl: Delim(r)
  {J.lex_num(J.exp_k(e, r), J.NFrac{neg, i, f, acc}) == ok(J.Number{neg, i, J.FSome{f, J.rev(acc)}, e}, r) : J.NLex}

def exp_frac(neg, i, f, acc, e, r, dl):
  match e:
    case J.ENone{}:
      fin_frac(neg, i, f, acc, r, dl)
    case J.ESome{u, sg, d, ds}:
      match u:
        case True{}:
          exp_rest(neg, i, J.FSome{f, J.rev(acc)}, True{}, sg, d, ds, r, dl)
        case False{}:
          exp_rest(neg, i, J.FSome{f, J.rev(acc)}, False{}, sg, d, ds, r, dl)

law frac_zero:
  for +neg: Bool
  for +fr: J.Frac
  for +e: J.Exp
  for +r: String
  for dl: Delim(r)
  {J.lex_num(J.frac_k(fr, J.exp_k(e, r)), J.NZero{neg}) == ok(J.Number{neg, J.IZero{}, fr, e}, r) : J.NLex}

def frac_zero(neg, fr, e, r, dl):
  match fr:
    case J.FNone{}:
      exp_zero(neg, e, r, dl)
    case J.FSome{d, ds}:
      +k : String = J.exp_k(e, r)
      +st : J.NSt = J.NFrac{neg, J.IZero{}, d, rl(ds, [])}
      +want : J.NLex = ok(J.Number{neg, J.IZero{}, J.FSome{d, ds}, e}, r)
      Equal.trans(J.NLex, J.lex_num(SCon{J.digit_char(d), J.digits_k(ds, k)}, J.NDot{neg, J.IZero{}}),
        J.lex_num(J.digits_k(ds, k), J.NFrac{neg, J.IZero{}, d, []}), want,
        step_dot(neg, J.IZero{}, d, J.digits_k(ds, k)),
        Equal.trans(J.NLex, J.lex_num(J.digits_k(ds, k), J.NFrac{neg, J.IZero{}, d, []}), J.lex_num(k, st), want,
          run_frac(neg, J.IZero{}, d, ds, [], k),
          Equal.trans(J.NLex, J.lex_num(k, st), ok(J.Number{neg, J.IZero{}, J.FSome{d, J.rev(rl(ds, []))}, e}, r), want,
            exp_frac(neg, J.IZero{}, d, rl(ds, []), e, r, dl),
            Equal.cong(List<&2, J.Digit>, J.NLex, x => ok(J.Number{neg, J.IZero{}, J.FSome{d, x}, e}, r), J.rev(rl(ds, [])), ds, rev_rev(ds)))))

law frac_int:
  for +neg: Bool
  for +l: J.Lead
  for +acc: List<&2, J.Digit>
  for +fr: J.Frac
  for +e: J.Exp
  for +r: String
  for dl: Delim(r)
  {J.lex_num(J.frac_k(fr, J.exp_k(e, r)), J.NInt{neg, l, acc}) == ok(J.Number{neg, J.INon{l, J.rev(acc)}, fr, e}, r) : J.NLex}

def frac_int(neg, l, acc, fr, e, r, dl):
  match fr:
    case J.FNone{}:
      exp_int(neg, l, acc, e, r, dl)
    case J.FSome{d, ds}:
      +k : String = J.exp_k(e, r)
      +st : J.NSt = J.NFrac{neg, J.INon{l, J.rev(acc)}, d, rl(ds, [])}
      +want : J.NLex = ok(J.Number{neg, J.INon{l, J.rev(acc)}, J.FSome{d, ds}, e}, r)
      Equal.trans(J.NLex, J.lex_num(SCon{J.digit_char(d), J.digits_k(ds, k)}, J.NDot{neg, J.INon{l, J.rev(acc)}}),
        J.lex_num(J.digits_k(ds, k), J.NFrac{neg, J.INon{l, J.rev(acc)}, d, []}), want,
        step_dot(neg, J.INon{l, J.rev(acc)}, d, J.digits_k(ds, k)),
        Equal.trans(J.NLex, J.lex_num(J.digits_k(ds, k), J.NFrac{neg, J.INon{l, J.rev(acc)}, d, []}), J.lex_num(k, st), want,
          run_frac(neg, J.INon{l, J.rev(acc)}, d, ds, [], k),
          Equal.trans(J.NLex, J.lex_num(k, st), ok(J.Number{neg, J.INon{l, J.rev(acc)}, J.FSome{d, J.rev(rl(ds, []))}, e}, r), want,
            exp_frac(neg, J.INon{l, J.rev(acc)}, d, rl(ds, []), e, r, dl),
            Equal.cong(List<&2, J.Digit>, J.NLex, x => ok(J.Number{neg, J.INon{l, J.rev(acc)}, J.FSome{d, x}, e}, r), J.rev(rl(ds, [])), ds, rev_rev(ds)))))

law int:
  for +neg: Bool
  for +i: J.Int
  for +fr: J.Frac
  for +e: J.Exp
  for +r: String
  for dl: Delim(r)
  {J.lex_num(J.int_k(i, J.frac_k(fr, J.exp_k(e, r))), start(neg)) == ok(J.Number{neg, i, fr, e}, r) : J.NLex}

def int(neg, i, fr, e, r, dl):
  match i:
    case J.IZero{}:
      +k : String = J.frac_k(fr, J.exp_k(e, r))
      Equal.trans(J.NLex, J.lex_num(SCon{'0', k}, start(neg)), J.lex_num(k, J.NZero{neg}), ok(J.Number{neg, J.IZero{}, fr, e}, r),
        step_zero(neg, k),
        frac_zero(neg, fr, e, r, dl))
    case J.INon{l, ds}:
      +k : String = J.frac_k(fr, J.exp_k(e, r))
      +want : J.NLex = ok(J.Number{neg, J.INon{l, ds}, fr, e}, r)
      Equal.trans(J.NLex, J.lex_num(SCon{J.lead_char(l), J.digits_k(ds, k)}, start(neg)),
        J.lex_num(J.digits_k(ds, k), J.NInt{neg, l, []}), want,
        step_lead(neg, l, J.digits_k(ds, k)),
        Equal.trans(J.NLex, J.lex_num(J.digits_k(ds, k), J.NInt{neg, l, []}), J.lex_num(k, J.NInt{neg, l, rl(ds, [])}), want,
          run_int(neg, l, ds, [], k),
          Equal.trans(J.NLex, J.lex_num(k, J.NInt{neg, l, rl(ds, [])}), ok(J.Number{neg, J.INon{l, J.rev(rl(ds, []))}, fr, e}, r), want,
            frac_int(neg, l, rl(ds, []), fr, e, r, dl),
            Equal.cong(List<&2, J.Digit>, J.NLex, x => ok(J.Number{neg, J.INon{l, x}, fr, e}, r), J.rev(rl(ds, [])), ds, rev_rev(ds)))))

# a printed number lexes back to itself
law number:
  for +n: J.Number
  for +r: String
  for dl: Delim(r)
  {J.lex_num(J.num_k(n, r), J.NStart{}) == J.NOk{n, r} : J.NLex}

def number(n, r, dl):
  match n:
    case J.Number{neg, i, fr, e}:
      match neg:
        case True{}:
          int(True{}, i, fr, e, r, dl)
        case False{}:
          int(False{}, i, fr, e, r, dl)
