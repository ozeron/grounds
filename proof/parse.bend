import Base
import ../bjson.bend as J
import ./spec.bend as S
import ./arith.bend as A
import ./strings.bend as Str
import ./numbers.bend as Num
import ./print.bend as P

# The parser loop reads S.text(j) back to j.

def ValMode(m: J.Mode) -> Type:
  match m:
    case J.MValue{}:
      Unit
    case J.MValueOrClose{}:
      Unit
    case _:
      Empty

# where the loop may be when the text of j starts: a value is expected,
# or (more) the rest of a container whose frame is on top of the stack
def Ctx(more: Bool, j: J.Json, m: J.Mode, stk: List<&2, J.Frame>) -> Type:
  match more:
    case False{}:
      ValMode(m)
    case True{}:
      match j m stk:
        case J.JArr{_} J.MCommaOrClose{} Con{J.FArr{_}, _}:
          Unit
        case J.JObj{_} J.MCommaOrClose{} Con{J.FObj{_, _}, _}:
          Unit
        case _ _ _:
          Empty

def rlj(acc: List<&2, J.Json>, t: List<&2, J.Json>) -> List<&2, J.Json>:
  List.reverse.go(&2, J.Json, acc, t)

def rlf(acc: List<&2, J.Field>, t: List<&2, J.Field>) -> List<&2, J.Field>:
  List.reverse.go(&2, J.Field, acc, t)

# where the loop is once the text of j is read
def result(more: Bool, j: J.Json, stk: List<&2, J.Frame>, r: String) -> J.St:
  match more:
    case False{}:
      J.emit(j, r, stk)
    case True{}:
      match j stk:
        case J.JArr{t} Con{J.FArr{acc}, up}:
          J.emit(J.JArr{rlj(acc, t)}, r, up)
        case J.JObj{t} Con{J.FObj{acc, _}, up}:
          J.emit(J.JObj{rlf(acc, t)}, r, up)
        case _ _:
          J.Bad{J.Internal{}, r}

def Goal(j: J.Json, more: Bool, m: J.Mode, stk: List<&2, J.Frame>, r: String, slack: Nat) -> Type:
  &w: Nat -> {J.loop(A.add(slack, A.len(S.text(j, more, r))), J.Run{S.text(j, more, r), stk, m}) == J.loop(A.add(w, A.len(r)), result(more, j, stk, r)) : J.St}

law efq:
  for -X: Type
  for x: Empty
  X

def efq(X, x):
  match x:

# one step of the loop, when the input has at least one char
law step:
  for +slack: Nat
  for +s: String
  for +q: Nat
  for +stk: List<&2, J.Frame>
  for +m: J.Mode
  for e: {A.len(s) == 1n+q : Nat}
  {J.loop(A.add(slack, A.len(s)), J.Run{s, stk, m}) == J.loop(A.add(slack, q), J.dispatch(m, J.skip_ws(s), stk)) : J.St}

def step(slack, s, q, stk, m, e):
  %Equal.sym(Nat, A.len(s), 1n+q, e) : {J.loop(A.add(slack, _), J.Run{s, stk, m}) == J.loop(A.add(slack, q), J.dispatch(m, J.skip_ws(s), stk)) : J.St}
  %Equal.sym(Nat, A.add(slack, 1n+q), 1n+A.add(slack, q), A.add_succ(slack, q)) : {J.loop(_, J.Run{s, stk, m}) == J.loop(A.add(slack, q), J.dispatch(m, J.skip_ws(s), stk)) : J.St}
  {==}

# spare fuel regrouped: slack + (x + L) is (slack + x) + L
law regroup:
  for +slack: Nat
  for +x: Nat
  for +l: Nat
  for +st: J.St
  {J.loop(A.add(slack, A.add(x, l)), st) == J.loop(A.add(A.add(slack, x), l), st) : J.St}

def regroup(slack, x, l, st):
  Equal.cong(Nat, J.St, f => J.loop(f, st), A.add(slack, A.add(x, l)), A.add(A.add(slack, x), l),
    Equal.sym(Nat, A.add(A.add(slack, x), l), A.add(slack, A.add(x, l)), A.add_assoc(slack, x, l)))

law regroup2:
  for +slack: Nat
  for +x: Nat
  for +y: Nat
  for +l: Nat
  for +st: J.St
  {J.loop(A.add(slack, A.add(x, A.add(y, l))), st) == J.loop(A.add(A.add(A.add(slack, x), y), l), st) : J.St}

def regroup2(slack, x, y, l, st):
  Equal.trans(J.St, J.loop(A.add(slack, A.add(x, A.add(y, l))), st), J.loop(A.add(A.add(slack, x), A.add(y, l)), st),
    J.loop(A.add(A.add(A.add(slack, x), y), l), st),
    regroup(slack, x, A.add(y, l), st),
    regroup(A.add(slack, x), y, l, st))

# a finished parse stays finished
law loop_fin:
  for +f: Nat
  for +v: J.Json
  {J.loop(f, J.Fin{v}) == J.Fin{v} : J.St}

def loop_fin(f, v):
  match f:
    case 0n:
      {==}
    case 1n+_:
      {==}

law num_dispatch.go:
  for +neg: Bool
  for +i: J.Int
  for +f: J.Frac
  for +e: J.Exp
  for +r: String
  for +stk: List<&2, J.Frame>
  for +m: J.Mode
  for vm: ValMode(m)
  {J.dispatch(m, J.skip_ws(J.num_k(J.Number{neg, i, f, e}, r)), stk) == J.number(J.lex_num(J.num_k(J.Number{neg, i, f, e}, r), J.NStart{}), stk) : J.St}

def num_dispatch.go(neg, i, f, e, r, stk, m, vm):
  match neg i m:
    case True{} _ J.MValue{}:
      {==}
    case True{} _ J.MValueOrClose{}:
      {==}
    case False{} J.IZero{} J.MValue{}:
      {==}
    case False{} J.IZero{} J.MValueOrClose{}:
      {==}
    case False{} J.INon{J.L1{}, _} J.MValue{}:
      {==}
    case False{} J.INon{J.L2{}, _} J.MValue{}:
      {==}
    case False{} J.INon{J.L3{}, _} J.MValue{}:
      {==}
    case False{} J.INon{J.L4{}, _} J.MValue{}:
      {==}
    case False{} J.INon{J.L5{}, _} J.MValue{}:
      {==}
    case False{} J.INon{J.L6{}, _} J.MValue{}:
      {==}
    case False{} J.INon{J.L7{}, _} J.MValue{}:
      {==}
    case False{} J.INon{J.L8{}, _} J.MValue{}:
      {==}
    case False{} J.INon{J.L9{}, _} J.MValue{}:
      {==}
    case False{} J.INon{J.L1{}, _} J.MValueOrClose{}:
      {==}
    case False{} J.INon{J.L2{}, _} J.MValueOrClose{}:
      {==}
    case False{} J.INon{J.L3{}, _} J.MValueOrClose{}:
      {==}
    case False{} J.INon{J.L4{}, _} J.MValueOrClose{}:
      {==}
    case False{} J.INon{J.L5{}, _} J.MValueOrClose{}:
      {==}
    case False{} J.INon{J.L6{}, _} J.MValueOrClose{}:
      {==}
    case False{} J.INon{J.L7{}, _} J.MValueOrClose{}:
      {==}
    case False{} J.INon{J.L8{}, _} J.MValueOrClose{}:
      {==}
    case False{} J.INon{J.L9{}, _} J.MValueOrClose{}:
      {==}
    case _ _ J.MKeyOrClose{}:
      match vm:
    case _ _ J.MKey{}:
      match vm:
    case _ _ J.MColon{}:
      match vm:
    case _ _ J.MCommaOrClose{}:
      match vm:

# a number starts with a char that neither mode mistakes for anything else
law num_dispatch:
  for +n: J.Number
  for +r: String
  for +stk: List<&2, J.Frame>
  for +m: J.Mode
  for vm: ValMode(m)
  {J.dispatch(m, J.skip_ws(J.num_k(n, r)), stk) == J.number(J.lex_num(J.num_k(n, r), J.NStart{}), stk) : J.St}

def num_dispatch(n, r, stk, m, vm):
  match n:
    case J.Number{neg, i, f, e}:
      num_dispatch.go(neg, i, f, e, r, stk, m, vm)


law g_null:
  for +slack: Nat
  for +m: J.Mode
  for vm: ValMode(m)
  for +stk: List<&2, J.Frame>
  for +r: String
  Goal(J.JNull{}, False{}, m, stk, r, slack)

def g_null(slack, m, vm, stk, r):
  match m:
    case J.MValue{}:
      (A.add(slack, 3n), Equal.trans(J.St,
        J.loop(A.add(slack, A.len("null" ++ r)), J.Run{"null" ++ r, stk, J.MValue{}}),
        J.loop(A.add(slack, A.add(3n, A.len(r))), J.emit(J.JNull{}, r, stk)),
        J.loop(A.add(A.add(slack, 3n), A.len(r)), J.emit(J.JNull{}, r, stk)),
        step(slack, "null" ++ r, A.add(3n, A.len(r)), stk, J.MValue{}, {==}),
        regroup(slack, 3n, A.len(r), J.emit(J.JNull{}, r, stk))))
    case J.MValueOrClose{}:
      (A.add(slack, 3n), Equal.trans(J.St,
        J.loop(A.add(slack, A.len("null" ++ r)), J.Run{"null" ++ r, stk, J.MValueOrClose{}}),
        J.loop(A.add(slack, A.add(3n, A.len(r))), J.emit(J.JNull{}, r, stk)),
        J.loop(A.add(A.add(slack, 3n), A.len(r)), J.emit(J.JNull{}, r, stk)),
        step(slack, "null" ++ r, A.add(3n, A.len(r)), stk, J.MValueOrClose{}, {==}),
        regroup(slack, 3n, A.len(r), J.emit(J.JNull{}, r, stk))))
    case J.MKeyOrClose{}:
      match vm:
    case J.MKey{}:
      match vm:
    case J.MColon{}:
      match vm:
    case J.MCommaOrClose{}:
      match vm:

law g_true:
  for +slack: Nat
  for +m: J.Mode
  for vm: ValMode(m)
  for +stk: List<&2, J.Frame>
  for +r: String
  Goal(J.JBool{True{}}, False{}, m, stk, r, slack)

def g_true(slack, m, vm, stk, r):
  match m:
    case J.MValue{}:
      (A.add(slack, 3n), Equal.trans(J.St,
        J.loop(A.add(slack, A.len("true" ++ r)), J.Run{"true" ++ r, stk, J.MValue{}}),
        J.loop(A.add(slack, A.add(3n, A.len(r))), J.emit(J.JBool{True{}}, r, stk)),
        J.loop(A.add(A.add(slack, 3n), A.len(r)), J.emit(J.JBool{True{}}, r, stk)),
        step(slack, "true" ++ r, A.add(3n, A.len(r)), stk, J.MValue{}, {==}),
        regroup(slack, 3n, A.len(r), J.emit(J.JBool{True{}}, r, stk))))
    case J.MValueOrClose{}:
      (A.add(slack, 3n), Equal.trans(J.St,
        J.loop(A.add(slack, A.len("true" ++ r)), J.Run{"true" ++ r, stk, J.MValueOrClose{}}),
        J.loop(A.add(slack, A.add(3n, A.len(r))), J.emit(J.JBool{True{}}, r, stk)),
        J.loop(A.add(A.add(slack, 3n), A.len(r)), J.emit(J.JBool{True{}}, r, stk)),
        step(slack, "true" ++ r, A.add(3n, A.len(r)), stk, J.MValueOrClose{}, {==}),
        regroup(slack, 3n, A.len(r), J.emit(J.JBool{True{}}, r, stk))))
    case J.MKeyOrClose{}:
      match vm:
    case J.MKey{}:
      match vm:
    case J.MColon{}:
      match vm:
    case J.MCommaOrClose{}:
      match vm:

law g_false:
  for +slack: Nat
  for +m: J.Mode
  for vm: ValMode(m)
  for +stk: List<&2, J.Frame>
  for +r: String
  Goal(J.JBool{False{}}, False{}, m, stk, r, slack)

def g_false(slack, m, vm, stk, r):
  match m:
    case J.MValue{}:
      (A.add(slack, 4n), Equal.trans(J.St,
        J.loop(A.add(slack, A.len("false" ++ r)), J.Run{"false" ++ r, stk, J.MValue{}}),
        J.loop(A.add(slack, A.add(4n, A.len(r))), J.emit(J.JBool{False{}}, r, stk)),
        J.loop(A.add(A.add(slack, 4n), A.len(r)), J.emit(J.JBool{False{}}, r, stk)),
        step(slack, "false" ++ r, A.add(4n, A.len(r)), stk, J.MValue{}, {==}),
        regroup(slack, 4n, A.len(r), J.emit(J.JBool{False{}}, r, stk))))
    case J.MValueOrClose{}:
      (A.add(slack, 4n), Equal.trans(J.St,
        J.loop(A.add(slack, A.len("false" ++ r)), J.Run{"false" ++ r, stk, J.MValueOrClose{}}),
        J.loop(A.add(slack, A.add(4n, A.len(r))), J.emit(J.JBool{False{}}, r, stk)),
        J.loop(A.add(A.add(slack, 4n), A.len(r)), J.emit(J.JBool{False{}}, r, stk)),
        step(slack, "false" ++ r, A.add(4n, A.len(r)), stk, J.MValueOrClose{}, {==}),
        regroup(slack, 4n, A.len(r), J.emit(J.JBool{False{}}, r, stk))))
    case J.MKeyOrClose{}:
      match vm:
    case J.MKey{}:
      match vm:
    case J.MColon{}:
      match vm:
    case J.MCommaOrClose{}:
      match vm:

law g_str.x:
  for +s: String
  for +slack: Nat
  for +m: J.Mode
  for vm: ValMode(m)
  for +stk: List<&2, J.Frame>
  for +r: String
  for +x: Nat
  for ex: {A.len(S.esc(s, SCon{'"', r})) == A.add(x, A.len(SCon{'"', r})) : Nat}
  Goal(J.JStr{s}, False{}, m, stk, r, slack)

def g_str.x(s, slack, m, vm, stk, r, x, ex):
  match m:
    case J.MValue{}:
      (A.add(A.add(slack, x), 1n), Equal.trans(J.St,
        J.loop(A.add(slack, A.len(S.str(s, r))), J.Run{S.str(s, r), stk, J.MValue{}}),
        J.loop(A.add(slack, A.len(S.esc(s, SCon{'"', r}))), J.token(~J.mk_str, J.lex_str(S.esc(s, SCon{'"', r}), J.SGo{"", 0}), stk)),
        J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(r)), J.emit(J.JStr{s}, r, stk)),
        step(slack, S.str(s, r), A.len(S.esc(s, SCon{'"', r})), stk, J.MValue{}, {==}),
        Equal.trans(J.St,
          J.loop(A.add(slack, A.len(S.esc(s, SCon{'"', r}))), J.token(~J.mk_str, J.lex_str(S.esc(s, SCon{'"', r}), J.SGo{"", 0}), stk)),
          J.loop(A.add(slack, A.len(S.esc(s, SCon{'"', r}))), J.emit(J.JStr{s}, r, stk)),
          J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(r)), J.emit(J.JStr{s}, r, stk)),
          Equal.cong(J.Lex, J.St, y => J.loop(A.add(slack, A.len(S.esc(s, SCon{'"', r}))), J.token(~J.mk_str, y, stk)), J.lex_str(S.esc(s, SCon{'"', r}), J.SGo{"", 0}), J.LOk{s, r}, Str.body(s, "", r)),
          Equal.trans(J.St,
            J.loop(A.add(slack, A.len(S.esc(s, SCon{'"', r}))), J.emit(J.JStr{s}, r, stk)),
            J.loop(A.add(slack, A.add(x, A.add(1n, A.len(r)))), J.emit(J.JStr{s}, r, stk)),
            J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(r)), J.emit(J.JStr{s}, r, stk)),
            Equal.cong(Nat, J.St, f => J.loop(A.add(slack, f), J.emit(J.JStr{s}, r, stk)), A.len(S.esc(s, SCon{'"', r})), A.add(x, A.add(1n, A.len(r))), ex),
            regroup2(slack, x, 1n, A.len(r), J.emit(J.JStr{s}, r, stk))))))
    case J.MValueOrClose{}:
      (A.add(A.add(slack, x), 1n), Equal.trans(J.St,
        J.loop(A.add(slack, A.len(S.str(s, r))), J.Run{S.str(s, r), stk, J.MValueOrClose{}}),
        J.loop(A.add(slack, A.len(S.esc(s, SCon{'"', r}))), J.token(~J.mk_str, J.lex_str(S.esc(s, SCon{'"', r}), J.SGo{"", 0}), stk)),
        J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(r)), J.emit(J.JStr{s}, r, stk)),
        step(slack, S.str(s, r), A.len(S.esc(s, SCon{'"', r})), stk, J.MValueOrClose{}, {==}),
        Equal.trans(J.St,
          J.loop(A.add(slack, A.len(S.esc(s, SCon{'"', r}))), J.token(~J.mk_str, J.lex_str(S.esc(s, SCon{'"', r}), J.SGo{"", 0}), stk)),
          J.loop(A.add(slack, A.len(S.esc(s, SCon{'"', r}))), J.emit(J.JStr{s}, r, stk)),
          J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(r)), J.emit(J.JStr{s}, r, stk)),
          Equal.cong(J.Lex, J.St, y => J.loop(A.add(slack, A.len(S.esc(s, SCon{'"', r}))), J.token(~J.mk_str, y, stk)), J.lex_str(S.esc(s, SCon{'"', r}), J.SGo{"", 0}), J.LOk{s, r}, Str.body(s, "", r)),
          Equal.trans(J.St,
            J.loop(A.add(slack, A.len(S.esc(s, SCon{'"', r}))), J.emit(J.JStr{s}, r, stk)),
            J.loop(A.add(slack, A.add(x, A.add(1n, A.len(r)))), J.emit(J.JStr{s}, r, stk)),
            J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(r)), J.emit(J.JStr{s}, r, stk)),
            Equal.cong(Nat, J.St, f => J.loop(A.add(slack, f), J.emit(J.JStr{s}, r, stk)), A.len(S.esc(s, SCon{'"', r})), A.add(x, A.add(1n, A.len(r))), ex),
            regroup2(slack, x, 1n, A.len(r), J.emit(J.JStr{s}, r, stk))))))
    case J.MKeyOrClose{}:
      match vm:
    case J.MKey{}:
      match vm:
    case J.MColon{}:
      match vm:
    case J.MCommaOrClose{}:
      match vm:

law g_str.w:
  for +s: String
  for +slack: Nat
  for +m: J.Mode
  for vm: ValMode(m)
  for +stk: List<&2, J.Frame>
  for +r: String
  for w: A.Pre(S.esc(s, SCon{'"', r}), SCon{'"', r})
  Goal(J.JStr{s}, False{}, m, stk, r, slack)

def g_str.w(s, slack, m, vm, stk, r, w):
  (+x, ex) = w
  g_str.x(s, slack, m, vm, stk, r, x, ex)

law g_str:
  for +s: String
  for +slack: Nat
  for +m: J.Mode
  for vm: ValMode(m)
  for +stk: List<&2, J.Frame>
  for +r: String
  Goal(J.JStr{s}, False{}, m, stk, r, slack)

def g_str(s, slack, m, vm, stk, r):
  g_str.w(s, slack, m, vm, stk, r, A.pre_esc(s, SCon{'"', r}))

law g_num.w:
  for +n: J.Number
  for +slack: Nat
  for +m: J.Mode
  for vm: ValMode(m)
  for +stk: List<&2, J.Frame>
  for +r: String
  for dl: Num.Delim(r)
  for w: A.Pre1(J.num_k(n, r), r)
  Goal(J.JNum{n}, False{}, m, stk, r, slack)

def g_num.w(n, slack, m, vm, stk, r, dl, w):
  (+x, ex) = w
  (A.add(slack, x), Equal.trans(J.St,
    J.loop(A.add(slack, A.len(J.num_k(n, r))), J.Run{J.num_k(n, r), stk, m}),
    J.loop(A.add(slack, A.add(x, A.len(r))), J.dispatch(m, J.skip_ws(J.num_k(n, r)), stk)),
    J.loop(A.add(A.add(slack, x), A.len(r)), J.emit(J.JNum{n}, r, stk)),
    step(slack, J.num_k(n, r), A.add(x, A.len(r)), stk, m, ex),
    Equal.trans(J.St,
      J.loop(A.add(slack, A.add(x, A.len(r))), J.dispatch(m, J.skip_ws(J.num_k(n, r)), stk)),
      J.loop(A.add(slack, A.add(x, A.len(r))), J.number(J.lex_num(J.num_k(n, r), J.NStart{}), stk)),
      J.loop(A.add(A.add(slack, x), A.len(r)), J.emit(J.JNum{n}, r, stk)),
      Equal.cong(J.St, J.St, y => J.loop(A.add(slack, A.add(x, A.len(r))), y), J.dispatch(m, J.skip_ws(J.num_k(n, r)), stk), J.number(J.lex_num(J.num_k(n, r), J.NStart{}), stk), num_dispatch(n, r, stk, m, vm)),
      Equal.trans(J.St,
        J.loop(A.add(slack, A.add(x, A.len(r))), J.number(J.lex_num(J.num_k(n, r), J.NStart{}), stk)),
        J.loop(A.add(slack, A.add(x, A.len(r))), J.emit(J.JNum{n}, r, stk)),
        J.loop(A.add(A.add(slack, x), A.len(r)), J.emit(J.JNum{n}, r, stk)),
        Equal.cong(J.NLex, J.St, y => J.loop(A.add(slack, A.add(x, A.len(r))), J.number(y, stk)), J.lex_num(J.num_k(n, r), J.NStart{}), J.NOk{n, r}, Num.number(n, r, dl)),
        regroup(slack, x, A.len(r), J.emit(J.JNum{n}, r, stk))))))

law g_num:
  for +n: J.Number
  for +slack: Nat
  for +m: J.Mode
  for vm: ValMode(m)
  for +stk: List<&2, J.Frame>
  for +r: String
  for dl: Num.Delim(r)
  Goal(J.JNum{n}, False{}, m, stk, r, slack)

def g_num(n, slack, m, vm, stk, r, dl):
  g_num.w(n, slack, m, vm, stk, r, dl, A.num_len(n, r))

law delim_arr:
  for +t: List<&2, J.Json>
  for +r: String
  Num.Delim(S.text(J.JArr{t}, True{}, r))

def delim_arr(t, r):
  match t:
    case Nil{}:
      {==}
    case Con{_, _}:
      {==}

law delim_obj:
  for +t: List<&2, J.Field>
  for +r: String
  Num.Delim(S.text(J.JObj{t}, True{}, r))

def delim_obj(t, r):
  match t:
    case Nil{}:
      {==}
    case Con{J.Field{_, _}, _}:
      {==}

law g_arr_nil:
  for +slack: Nat
  for +m: J.Mode
  for vm: ValMode(m)
  for +stk: List<&2, J.Frame>
  for +r: String
  Goal(J.JArr{[]}, False{}, m, stk, r, slack)

def g_arr_nil(slack, m, vm, stk, r):
  match m:
    case J.MValue{}:
      (slack, Equal.trans(J.St,
        J.loop(A.add(slack, A.len(SCon{'[', SCon{']', r}})), J.Run{SCon{'[', SCon{']', r}}, stk, J.MValue{}}),
        J.loop(A.add(slack, A.len(SCon{']', r})), J.Run{SCon{']', r}, Con{J.FArr{[]}, stk}, J.MValueOrClose{}}),
        J.loop(A.add(slack, A.len(r)), J.emit(J.JArr{[]}, r, stk)),
        step(slack, SCon{'[', SCon{']', r}}, A.len(SCon{']', r}), stk, J.MValue{}, {==}),
        step(slack, SCon{']', r}, A.len(r), Con{J.FArr{[]}, stk}, J.MValueOrClose{}, {==})))
    case J.MValueOrClose{}:
      (slack, Equal.trans(J.St,
        J.loop(A.add(slack, A.len(SCon{'[', SCon{']', r}})), J.Run{SCon{'[', SCon{']', r}}, stk, J.MValueOrClose{}}),
        J.loop(A.add(slack, A.len(SCon{']', r})), J.Run{SCon{']', r}, Con{J.FArr{[]}, stk}, J.MValueOrClose{}}),
        J.loop(A.add(slack, A.len(r)), J.emit(J.JArr{[]}, r, stk)),
        step(slack, SCon{'[', SCon{']', r}}, A.len(SCon{']', r}), stk, J.MValueOrClose{}, {==}),
        step(slack, SCon{']', r}, A.len(r), Con{J.FArr{[]}, stk}, J.MValueOrClose{}, {==})))
    case J.MKeyOrClose{}:
      match vm:
    case J.MKey{}:
      match vm:
    case J.MColon{}:
      match vm:
    case J.MCommaOrClose{}:
      match vm:

law g_arr_nil_t:
  for +acc: List<&2, J.Json>
  for +up: List<&2, J.Frame>
  for +r: String
  for +slack: Nat
  Goal(J.JArr{[]}, True{}, J.MCommaOrClose{}, Con{J.FArr{acc}, up}, r, slack)

def g_arr_nil_t(acc, up, r, slack):
  (slack, step(slack, SCon{']', r}, A.len(r), Con{J.FArr{acc}, up}, J.MCommaOrClose{}, {==}))

law g_obj_nil:
  for +slack: Nat
  for +m: J.Mode
  for vm: ValMode(m)
  for +stk: List<&2, J.Frame>
  for +r: String
  Goal(J.JObj{[]}, False{}, m, stk, r, slack)

def g_obj_nil(slack, m, vm, stk, r):
  match m:
    case J.MValue{}:
      (slack, Equal.trans(J.St,
        J.loop(A.add(slack, A.len(SCon{'{', SCon{'}', r}})), J.Run{SCon{'{', SCon{'}', r}}, stk, J.MValue{}}),
        J.loop(A.add(slack, A.len(SCon{'}', r})), J.Run{SCon{'}', r}, Con{J.FObj{[], ""}, stk}, J.MKeyOrClose{}}),
        J.loop(A.add(slack, A.len(r)), J.emit(J.JObj{[]}, r, stk)),
        step(slack, SCon{'{', SCon{'}', r}}, A.len(SCon{'}', r}), stk, J.MValue{}, {==}),
        step(slack, SCon{'}', r}, A.len(r), Con{J.FObj{[], ""}, stk}, J.MKeyOrClose{}, {==})))
    case J.MValueOrClose{}:
      (slack, Equal.trans(J.St,
        J.loop(A.add(slack, A.len(SCon{'{', SCon{'}', r}})), J.Run{SCon{'{', SCon{'}', r}}, stk, J.MValueOrClose{}}),
        J.loop(A.add(slack, A.len(SCon{'}', r})), J.Run{SCon{'}', r}, Con{J.FObj{[], ""}, stk}, J.MKeyOrClose{}}),
        J.loop(A.add(slack, A.len(r)), J.emit(J.JObj{[]}, r, stk)),
        step(slack, SCon{'{', SCon{'}', r}}, A.len(SCon{'}', r}), stk, J.MValueOrClose{}, {==}),
        step(slack, SCon{'}', r}, A.len(r), Con{J.FObj{[], ""}, stk}, J.MKeyOrClose{}, {==})))
    case J.MKeyOrClose{}:
      match vm:
    case J.MKey{}:
      match vm:
    case J.MColon{}:
      match vm:
    case J.MCommaOrClose{}:
      match vm:

law g_obj_nil_t:
  for +acc: List<&2, J.Field>
  for +k0: String
  for +up: List<&2, J.Frame>
  for +r: String
  for +slack: Nat
  Goal(J.JObj{[]}, True{}, J.MCommaOrClose{}, Con{J.FObj{acc, k0}, up}, r, slack)

def g_obj_nil_t(acc, k0, up, r, slack):
  (slack, step(slack, SCon{'}', r}, A.len(r), Con{J.FObj{acc, k0}, up}, J.MCommaOrClose{}, {==}))

law arr_f.3:
  for +h: J.Json
  for +t: List<&2, J.Json>
  for +stk: List<&2, J.Frame>
  for +r: String
  for +slack: Nat
  for +m: J.Mode
  for vm: ValMode(m)
  for +w1: Nat
  for p1: {J.loop(A.add(slack, A.len(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)))), J.Run{S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{J.FArr{[]}, stk}, J.MValueOrClose{}}) == J.loop(A.add(w1, A.len(S.text(J.JArr{t}, True{}, r))), result(False{}, h, Con{J.FArr{[]}, stk}, S.text(J.JArr{t}, True{}, r))) : J.St}
  for +w2: Nat
  for p2: {J.loop(A.add(w1, A.len(S.text(J.JArr{t}, True{}, r))), J.Run{S.text(J.JArr{t}, True{}, r), Con{J.FArr{[h]}, stk}, J.MCommaOrClose{}}) == J.loop(A.add(w2, A.len(r)), result(True{}, J.JArr{t}, Con{J.FArr{[h]}, stk}, r)) : J.St}
  Goal(J.JArr{Con{h, t}}, False{}, m, stk, r, slack)

def arr_f.3(h, t, stk, r, slack, m, vm, w1, p1, w2, p2):
  match m:
    case J.MValue{}:
      (w2, Equal.trans(J.St,
        J.loop(A.add(slack, A.len(S.text(J.JArr{Con{h, t}}, False{}, r))), J.Run{S.text(J.JArr{Con{h, t}}, False{}, r), stk, J.MValue{}}),
        J.loop(A.add(slack, A.len(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)))), J.Run{S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{J.FArr{[]}, stk}, J.MValueOrClose{}}),
        J.loop(A.add(w2, A.len(r)), J.emit(J.JArr{Con{h, t}}, r, stk)),
        step(slack, S.text(J.JArr{Con{h, t}}, False{}, r), A.len(S.text(h, False{}, S.text(J.JArr{t}, True{}, r))), stk, J.MValue{}, {==}),
        Equal.trans(J.St,
          J.loop(A.add(slack, A.len(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)))), J.Run{S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{J.FArr{[]}, stk}, J.MValueOrClose{}}),
          J.loop(A.add(w1, A.len(S.text(J.JArr{t}, True{}, r))), J.Run{S.text(J.JArr{t}, True{}, r), Con{J.FArr{[h]}, stk}, J.MCommaOrClose{}}),
          J.loop(A.add(w2, A.len(r)), J.emit(J.JArr{Con{h, t}}, r, stk)),
          p1,
          p2)))
    case J.MValueOrClose{}:
      (w2, Equal.trans(J.St,
        J.loop(A.add(slack, A.len(S.text(J.JArr{Con{h, t}}, False{}, r))), J.Run{S.text(J.JArr{Con{h, t}}, False{}, r), stk, J.MValueOrClose{}}),
        J.loop(A.add(slack, A.len(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)))), J.Run{S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{J.FArr{[]}, stk}, J.MValueOrClose{}}),
        J.loop(A.add(w2, A.len(r)), J.emit(J.JArr{Con{h, t}}, r, stk)),
        step(slack, S.text(J.JArr{Con{h, t}}, False{}, r), A.len(S.text(h, False{}, S.text(J.JArr{t}, True{}, r))), stk, J.MValueOrClose{}, {==}),
        Equal.trans(J.St,
          J.loop(A.add(slack, A.len(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)))), J.Run{S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{J.FArr{[]}, stk}, J.MValueOrClose{}}),
          J.loop(A.add(w1, A.len(S.text(J.JArr{t}, True{}, r))), J.Run{S.text(J.JArr{t}, True{}, r), Con{J.FArr{[h]}, stk}, J.MCommaOrClose{}}),
          J.loop(A.add(w2, A.len(r)), J.emit(J.JArr{Con{h, t}}, r, stk)),
          p1,
          p2)))
    case J.MKeyOrClose{}:
      match vm:
    case J.MKey{}:
      match vm:
    case J.MColon{}:
      match vm:
    case J.MCommaOrClose{}:
      match vm:

law arr_f.2:
  for +h: J.Json
  for +t: List<&2, J.Json>
  for +stk: List<&2, J.Frame>
  for +r: String
  for +slack: Nat
  for +m: J.Mode
  for vm: ValMode(m)
  for +w1: Nat
  for p1: {J.loop(A.add(slack, A.len(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)))), J.Run{S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{J.FArr{[]}, stk}, J.MValueOrClose{}}) == J.loop(A.add(w1, A.len(S.text(J.JArr{t}, True{}, r))), result(False{}, h, Con{J.FArr{[]}, stk}, S.text(J.JArr{t}, True{}, r))) : J.St}
  for g2: Goal(J.JArr{t}, True{}, J.MCommaOrClose{}, Con{J.FArr{[h]}, stk}, r, w1)
  Goal(J.JArr{Con{h, t}}, False{}, m, stk, r, slack)

def arr_f.2(h, t, stk, r, slack, m, vm, w1, p1, g2):
  (+w2, p2) = g2
  arr_f.3(h, t, stk, r, slack, m, vm, w1, p1, w2, p2)

law arr_f.1:
  for +h: J.Json
  for +t: List<&2, J.Json>
  for +stk: List<&2, J.Frame>
  for +r: String
  for +slack: Nat
  for +m: J.Mode
  for vm: ValMode(m)
  for g1: Goal(h, False{}, J.MValueOrClose{}, Con{J.FArr{[]}, stk}, S.text(J.JArr{t}, True{}, r), slack)
  for ih2: @w: Nat -> Goal(J.JArr{t}, True{}, J.MCommaOrClose{}, Con{J.FArr{[h]}, stk}, r, w)
  Goal(J.JArr{Con{h, t}}, False{}, m, stk, r, slack)

def arr_f.1(h, t, stk, r, slack, m, vm, g1, ih2):
  (+w1, p1) = g1
  arr_f.2(h, t, stk, r, slack, m, vm, w1, p1, ih2(w1))

law arr_t.3:
  for +h: J.Json
  for +t: List<&2, J.Json>
  for +acc: List<&2, J.Json>
  for +up: List<&2, J.Frame>
  for +r: String
  for +slack: Nat
  for +w1: Nat
  for p1: {J.loop(A.add(slack, A.len(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)))), J.Run{S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{J.FArr{acc}, up}, J.MValue{}}) == J.loop(A.add(w1, A.len(S.text(J.JArr{t}, True{}, r))), result(False{}, h, Con{J.FArr{acc}, up}, S.text(J.JArr{t}, True{}, r))) : J.St}
  for +w2: Nat
  for p2: {J.loop(A.add(w1, A.len(S.text(J.JArr{t}, True{}, r))), J.Run{S.text(J.JArr{t}, True{}, r), Con{J.FArr{Con{h, acc}}, up}, J.MCommaOrClose{}}) == J.loop(A.add(w2, A.len(r)), result(True{}, J.JArr{t}, Con{J.FArr{Con{h, acc}}, up}, r)) : J.St}
  Goal(J.JArr{Con{h, t}}, True{}, J.MCommaOrClose{}, Con{J.FArr{acc}, up}, r, slack)

def arr_t.3(h, t, acc, up, r, slack, w1, p1, w2, p2):
  (w2, Equal.trans(J.St,
        J.loop(A.add(slack, A.len(S.text(J.JArr{Con{h, t}}, True{}, r))), J.Run{S.text(J.JArr{Con{h, t}}, True{}, r), Con{J.FArr{acc}, up}, J.MCommaOrClose{}}),
        J.loop(A.add(slack, A.len(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)))), J.Run{S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{J.FArr{acc}, up}, J.MValue{}}),
        J.loop(A.add(w2, A.len(r)), J.emit(J.JArr{rlj(acc, Con{h, t})}, r, up)),
        step(slack, S.text(J.JArr{Con{h, t}}, True{}, r), A.len(S.text(h, False{}, S.text(J.JArr{t}, True{}, r))), Con{J.FArr{acc}, up}, J.MCommaOrClose{}, {==}),
        Equal.trans(J.St,
          J.loop(A.add(slack, A.len(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)))), J.Run{S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{J.FArr{acc}, up}, J.MValue{}}),
          J.loop(A.add(w1, A.len(S.text(J.JArr{t}, True{}, r))), J.Run{S.text(J.JArr{t}, True{}, r), Con{J.FArr{Con{h, acc}}, up}, J.MCommaOrClose{}}),
          J.loop(A.add(w2, A.len(r)), J.emit(J.JArr{rlj(acc, Con{h, t})}, r, up)),
          p1,
          p2)))

law arr_t.2:
  for +h: J.Json
  for +t: List<&2, J.Json>
  for +acc: List<&2, J.Json>
  for +up: List<&2, J.Frame>
  for +r: String
  for +slack: Nat
  for +w1: Nat
  for p1: {J.loop(A.add(slack, A.len(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)))), J.Run{S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{J.FArr{acc}, up}, J.MValue{}}) == J.loop(A.add(w1, A.len(S.text(J.JArr{t}, True{}, r))), result(False{}, h, Con{J.FArr{acc}, up}, S.text(J.JArr{t}, True{}, r))) : J.St}
  for g2: Goal(J.JArr{t}, True{}, J.MCommaOrClose{}, Con{J.FArr{Con{h, acc}}, up}, r, w1)
  Goal(J.JArr{Con{h, t}}, True{}, J.MCommaOrClose{}, Con{J.FArr{acc}, up}, r, slack)

def arr_t.2(h, t, acc, up, r, slack, w1, p1, g2):
  (+w2, p2) = g2
  arr_t.3(h, t, acc, up, r, slack, w1, p1, w2, p2)

law arr_t.1:
  for +h: J.Json
  for +t: List<&2, J.Json>
  for +acc: List<&2, J.Json>
  for +up: List<&2, J.Frame>
  for +r: String
  for +slack: Nat
  for g1: Goal(h, False{}, J.MValue{}, Con{J.FArr{acc}, up}, S.text(J.JArr{t}, True{}, r), slack)
  for ih2: @w: Nat -> Goal(J.JArr{t}, True{}, J.MCommaOrClose{}, Con{J.FArr{Con{h, acc}}, up}, r, w)
  Goal(J.JArr{Con{h, t}}, True{}, J.MCommaOrClose{}, Con{J.FArr{acc}, up}, r, slack)

def arr_t.1(h, t, acc, up, r, slack, g1, ih2):
  (+w1, p1) = g1
  arr_t.2(h, t, acc, up, r, slack, w1, p1, ih2(w1))

law obj_f.4:
  for +k: String
  for +v: J.Json
  for +t: List<&2, J.Field>
  for +stk: List<&2, J.Frame>
  for +r: String
  for +slack: Nat
  for +m: J.Mode
  for vm: ValMode(m)
  for +x: Nat
  for ex: {A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})) == A.add(x, A.len(SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})) : Nat}
  for +w1: Nat
  for p1: {J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)))), J.Run{S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{J.FObj{[], k}, stk}, J.MValue{}}) == J.loop(A.add(w1, A.len(S.text(J.JObj{t}, True{}, r))), result(False{}, v, Con{J.FObj{[], k}, stk}, S.text(J.JObj{t}, True{}, r))) : J.St}
  for +w2: Nat
  for p2: {J.loop(A.add(w1, A.len(S.text(J.JObj{t}, True{}, r))), J.Run{S.text(J.JObj{t}, True{}, r), Con{J.FObj{[J.Field{k, v}], ""}, stk}, J.MCommaOrClose{}}) == J.loop(A.add(w2, A.len(r)), result(True{}, J.JObj{t}, Con{J.FObj{[J.Field{k, v}], ""}, stk}, r)) : J.St}
  Goal(J.JObj{Con{J.Field{k, v}, t}}, False{}, m, stk, r, slack)

def obj_f.4(k, v, t, stk, r, slack, m, vm, x, ex, w1, p1, w2, p2):
  match m:
    case J.MValue{}:
      (w2, Equal.trans(J.St,
        J.loop(A.add(slack, A.len(S.text(J.JObj{Con{J.Field{k, v}, t}}, False{}, r))), J.Run{S.text(J.JObj{Con{J.Field{k, v}, t}}, False{}, r), stk, J.MValue{}}),
        J.loop(A.add(slack, A.len(S.str(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}))), J.Run{S.str(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}), Con{J.FObj{[], ""}, stk}, J.MKeyOrClose{}}),
        J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{Con{J.Field{k, v}, t}}, r, stk)),
        step(slack, S.text(J.JObj{Con{J.Field{k, v}, t}}, False{}, r), A.len(S.str(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))})), stk, J.MValue{}, {==}),
        Equal.trans(J.St,
          J.loop(A.add(slack, A.len(S.str(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}))), J.Run{S.str(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}), Con{J.FObj{[], ""}, stk}, J.MKeyOrClose{}}),
          J.loop(A.add(slack, A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}))), J.key(J.lex_str(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), J.SGo{"", 0}), Con{J.FObj{[], ""}, stk})),
          J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{Con{J.Field{k, v}, t}}, r, stk)),
          step(slack, S.str(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}), A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})), Con{J.FObj{[], ""}, stk}, J.MKeyOrClose{}, {==}),
          Equal.trans(J.St,
            J.loop(A.add(slack, A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}))), J.key(J.lex_str(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), J.SGo{"", 0}), Con{J.FObj{[], ""}, stk})),
            J.loop(A.add(slack, A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}))), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{[], k}, stk}, J.MColon{}}),
            J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{Con{J.Field{k, v}, t}}, r, stk)),
            Equal.cong(J.Lex, J.St, y => J.loop(A.add(slack, A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}))), J.key(y, Con{J.FObj{[], ""}, stk})), J.lex_str(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), J.SGo{"", 0}), J.LOk{k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}, Str.body(k, "", SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))})),
            Equal.trans(J.St,
              J.loop(A.add(slack, A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}))), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{[], k}, stk}, J.MColon{}}),
              J.loop(A.add(slack, A.add(x, A.add(1n, A.len(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))})))), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{[], k}, stk}, J.MColon{}}),
              J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{Con{J.Field{k, v}, t}}, r, stk)),
              Equal.cong(Nat, J.St, f => J.loop(A.add(slack, f), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{[], k}, stk}, J.MColon{}}), A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})), A.add(x, A.add(1n, A.len(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}))), ex),
              Equal.trans(J.St,
                J.loop(A.add(slack, A.add(x, A.add(1n, A.len(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))})))), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{[], k}, stk}, J.MColon{}}),
                J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))})), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{[], k}, stk}, J.MColon{}}),
                J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{Con{J.Field{k, v}, t}}, r, stk)),
                regroup2(slack, x, 1n, A.len(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{[], k}, stk}, J.MColon{}}),
                Equal.trans(J.St,
                  J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))})), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{[], k}, stk}, J.MColon{}}),
                  J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)))), J.Run{S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{J.FObj{[], k}, stk}, J.MValue{}}),
                  J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{Con{J.Field{k, v}, t}}, r, stk)),
                  step(A.add(A.add(slack, x), 1n), SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, A.len(S.text(v, False{}, S.text(J.JObj{t}, True{}, r))), Con{J.FObj{[], k}, stk}, J.MColon{}, {==}),
                  Equal.trans(J.St,
                    J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)))), J.Run{S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{J.FObj{[], k}, stk}, J.MValue{}}),
                    J.loop(A.add(w1, A.len(S.text(J.JObj{t}, True{}, r))), J.Run{S.text(J.JObj{t}, True{}, r), Con{J.FObj{[J.Field{k, v}], ""}, stk}, J.MCommaOrClose{}}),
                    J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{Con{J.Field{k, v}, t}}, r, stk)),
                    p1,
                    p2))))))))
    case J.MValueOrClose{}:
      (w2, Equal.trans(J.St,
        J.loop(A.add(slack, A.len(S.text(J.JObj{Con{J.Field{k, v}, t}}, False{}, r))), J.Run{S.text(J.JObj{Con{J.Field{k, v}, t}}, False{}, r), stk, J.MValueOrClose{}}),
        J.loop(A.add(slack, A.len(S.str(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}))), J.Run{S.str(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}), Con{J.FObj{[], ""}, stk}, J.MKeyOrClose{}}),
        J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{Con{J.Field{k, v}, t}}, r, stk)),
        step(slack, S.text(J.JObj{Con{J.Field{k, v}, t}}, False{}, r), A.len(S.str(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))})), stk, J.MValueOrClose{}, {==}),
        Equal.trans(J.St,
          J.loop(A.add(slack, A.len(S.str(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}))), J.Run{S.str(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}), Con{J.FObj{[], ""}, stk}, J.MKeyOrClose{}}),
          J.loop(A.add(slack, A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}))), J.key(J.lex_str(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), J.SGo{"", 0}), Con{J.FObj{[], ""}, stk})),
          J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{Con{J.Field{k, v}, t}}, r, stk)),
          step(slack, S.str(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}), A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})), Con{J.FObj{[], ""}, stk}, J.MKeyOrClose{}, {==}),
          Equal.trans(J.St,
            J.loop(A.add(slack, A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}))), J.key(J.lex_str(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), J.SGo{"", 0}), Con{J.FObj{[], ""}, stk})),
            J.loop(A.add(slack, A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}))), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{[], k}, stk}, J.MColon{}}),
            J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{Con{J.Field{k, v}, t}}, r, stk)),
            Equal.cong(J.Lex, J.St, y => J.loop(A.add(slack, A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}))), J.key(y, Con{J.FObj{[], ""}, stk})), J.lex_str(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), J.SGo{"", 0}), J.LOk{k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}, Str.body(k, "", SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))})),
            Equal.trans(J.St,
              J.loop(A.add(slack, A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}))), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{[], k}, stk}, J.MColon{}}),
              J.loop(A.add(slack, A.add(x, A.add(1n, A.len(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))})))), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{[], k}, stk}, J.MColon{}}),
              J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{Con{J.Field{k, v}, t}}, r, stk)),
              Equal.cong(Nat, J.St, f => J.loop(A.add(slack, f), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{[], k}, stk}, J.MColon{}}), A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})), A.add(x, A.add(1n, A.len(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}))), ex),
              Equal.trans(J.St,
                J.loop(A.add(slack, A.add(x, A.add(1n, A.len(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))})))), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{[], k}, stk}, J.MColon{}}),
                J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))})), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{[], k}, stk}, J.MColon{}}),
                J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{Con{J.Field{k, v}, t}}, r, stk)),
                regroup2(slack, x, 1n, A.len(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{[], k}, stk}, J.MColon{}}),
                Equal.trans(J.St,
                  J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))})), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{[], k}, stk}, J.MColon{}}),
                  J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)))), J.Run{S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{J.FObj{[], k}, stk}, J.MValue{}}),
                  J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{Con{J.Field{k, v}, t}}, r, stk)),
                  step(A.add(A.add(slack, x), 1n), SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, A.len(S.text(v, False{}, S.text(J.JObj{t}, True{}, r))), Con{J.FObj{[], k}, stk}, J.MColon{}, {==}),
                  Equal.trans(J.St,
                    J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)))), J.Run{S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{J.FObj{[], k}, stk}, J.MValue{}}),
                    J.loop(A.add(w1, A.len(S.text(J.JObj{t}, True{}, r))), J.Run{S.text(J.JObj{t}, True{}, r), Con{J.FObj{[J.Field{k, v}], ""}, stk}, J.MCommaOrClose{}}),
                    J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{Con{J.Field{k, v}, t}}, r, stk)),
                    p1,
                    p2))))))))
    case J.MKeyOrClose{}:
      match vm:
    case J.MKey{}:
      match vm:
    case J.MColon{}:
      match vm:
    case J.MCommaOrClose{}:
      match vm:

law obj_f.3:
  for +k: String
  for +v: J.Json
  for +t: List<&2, J.Field>
  for +stk: List<&2, J.Frame>
  for +r: String
  for +slack: Nat
  for +m: J.Mode
  for vm: ValMode(m)
  for +x: Nat
  for ex: {A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})) == A.add(x, A.len(SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})) : Nat}
  for +w1: Nat
  for p1: {J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)))), J.Run{S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{J.FObj{[], k}, stk}, J.MValue{}}) == J.loop(A.add(w1, A.len(S.text(J.JObj{t}, True{}, r))), result(False{}, v, Con{J.FObj{[], k}, stk}, S.text(J.JObj{t}, True{}, r))) : J.St}
  for g2: Goal(J.JObj{t}, True{}, J.MCommaOrClose{}, Con{J.FObj{[J.Field{k, v}], ""}, stk}, r, w1)
  Goal(J.JObj{Con{J.Field{k, v}, t}}, False{}, m, stk, r, slack)

def obj_f.3(k, v, t, stk, r, slack, m, vm, x, ex, w1, p1, g2):
  (+w2, p2) = g2
  obj_f.4(k, v, t, stk, r, slack, m, vm, x, ex, w1, p1, w2, p2)

law obj_f.2:
  for +k: String
  for +v: J.Json
  for +t: List<&2, J.Field>
  for +stk: List<&2, J.Frame>
  for +r: String
  for +slack: Nat
  for +m: J.Mode
  for vm: ValMode(m)
  for +x: Nat
  for ex: {A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})) == A.add(x, A.len(SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})) : Nat}
  for g1: Goal(v, False{}, J.MValue{}, Con{J.FObj{[], k}, stk}, S.text(J.JObj{t}, True{}, r), A.add(A.add(slack, x), 1n))
  for ih2: @w: Nat -> Goal(J.JObj{t}, True{}, J.MCommaOrClose{}, Con{J.FObj{[J.Field{k, v}], ""}, stk}, r, w)
  Goal(J.JObj{Con{J.Field{k, v}, t}}, False{}, m, stk, r, slack)

def obj_f.2(k, v, t, stk, r, slack, m, vm, x, ex, g1, ih2):
  (+w1, p1) = g1
  obj_f.3(k, v, t, stk, r, slack, m, vm, x, ex, w1, p1, ih2(w1))

law obj_f.1:
  for +k: String
  for +v: J.Json
  for +t: List<&2, J.Field>
  for +stk: List<&2, J.Frame>
  for +r: String
  for +slack: Nat
  for +m: J.Mode
  for vm: ValMode(m)
  for pk: A.Pre(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})
  for ih1: @s: Nat -> Goal(v, False{}, J.MValue{}, Con{J.FObj{[], k}, stk}, S.text(J.JObj{t}, True{}, r), s)
  for ih2: @w: Nat -> Goal(J.JObj{t}, True{}, J.MCommaOrClose{}, Con{J.FObj{[J.Field{k, v}], ""}, stk}, r, w)
  Goal(J.JObj{Con{J.Field{k, v}, t}}, False{}, m, stk, r, slack)

def obj_f.1(k, v, t, stk, r, slack, m, vm, pk, ih1, ih2):
  (+x, ex) = pk
  obj_f.2(k, v, t, stk, r, slack, m, vm, x, ex, ih1(A.add(A.add(slack, x), 1n)), ih2)

law obj_t.4:
  for +k: String
  for +v: J.Json
  for +t: List<&2, J.Field>
  for +acc: List<&2, J.Field>
  for +k0: String
  for +up: List<&2, J.Frame>
  for +r: String
  for +slack: Nat
  for +x: Nat
  for ex: {A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})) == A.add(x, A.len(SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})) : Nat}
  for +w1: Nat
  for p1: {J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)))), J.Run{S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{J.FObj{acc, k}, up}, J.MValue{}}) == J.loop(A.add(w1, A.len(S.text(J.JObj{t}, True{}, r))), result(False{}, v, Con{J.FObj{acc, k}, up}, S.text(J.JObj{t}, True{}, r))) : J.St}
  for +w2: Nat
  for p2: {J.loop(A.add(w1, A.len(S.text(J.JObj{t}, True{}, r))), J.Run{S.text(J.JObj{t}, True{}, r), Con{J.FObj{Con{J.Field{k, v}, acc}, ""}, up}, J.MCommaOrClose{}}) == J.loop(A.add(w2, A.len(r)), result(True{}, J.JObj{t}, Con{J.FObj{Con{J.Field{k, v}, acc}, ""}, up}, r)) : J.St}
  Goal(J.JObj{Con{J.Field{k, v}, t}}, True{}, J.MCommaOrClose{}, Con{J.FObj{acc, k0}, up}, r, slack)

def obj_t.4(k, v, t, acc, k0, up, r, slack, x, ex, w1, p1, w2, p2):
  (w2, Equal.trans(J.St,
        J.loop(A.add(slack, A.len(S.text(J.JObj{Con{J.Field{k, v}, t}}, True{}, r))), J.Run{S.text(J.JObj{Con{J.Field{k, v}, t}}, True{}, r), Con{J.FObj{acc, k0}, up}, J.MCommaOrClose{}}),
        J.loop(A.add(slack, A.len(S.str(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}))), J.Run{S.str(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}), Con{J.FObj{acc, k0}, up}, J.MKey{}}),
        J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{rlf(acc, Con{J.Field{k, v}, t})}, r, up)),
        step(slack, S.text(J.JObj{Con{J.Field{k, v}, t}}, True{}, r), A.len(S.str(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))})), Con{J.FObj{acc, k0}, up}, J.MCommaOrClose{}, {==}),
        Equal.trans(J.St,
          J.loop(A.add(slack, A.len(S.str(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}))), J.Run{S.str(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}), Con{J.FObj{acc, k0}, up}, J.MKey{}}),
          J.loop(A.add(slack, A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}))), J.key(J.lex_str(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), J.SGo{"", 0}), Con{J.FObj{acc, k0}, up})),
          J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{rlf(acc, Con{J.Field{k, v}, t})}, r, up)),
          step(slack, S.str(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}), A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})), Con{J.FObj{acc, k0}, up}, J.MKey{}, {==}),
          Equal.trans(J.St,
            J.loop(A.add(slack, A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}))), J.key(J.lex_str(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), J.SGo{"", 0}), Con{J.FObj{acc, k0}, up})),
            J.loop(A.add(slack, A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}))), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{acc, k}, up}, J.MColon{}}),
            J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{rlf(acc, Con{J.Field{k, v}, t})}, r, up)),
            Equal.cong(J.Lex, J.St, y => J.loop(A.add(slack, A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}))), J.key(y, Con{J.FObj{acc, k0}, up})), J.lex_str(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), J.SGo{"", 0}), J.LOk{k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}, Str.body(k, "", SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))})),
            Equal.trans(J.St,
              J.loop(A.add(slack, A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}))), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{acc, k}, up}, J.MColon{}}),
              J.loop(A.add(slack, A.add(x, A.add(1n, A.len(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))})))), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{acc, k}, up}, J.MColon{}}),
              J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{rlf(acc, Con{J.Field{k, v}, t})}, r, up)),
              Equal.cong(Nat, J.St, f => J.loop(A.add(slack, f), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{acc, k}, up}, J.MColon{}}), A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})), A.add(x, A.add(1n, A.len(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}))), ex),
              Equal.trans(J.St,
                J.loop(A.add(slack, A.add(x, A.add(1n, A.len(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))})))), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{acc, k}, up}, J.MColon{}}),
                J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))})), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{acc, k}, up}, J.MColon{}}),
                J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{rlf(acc, Con{J.Field{k, v}, t})}, r, up)),
                regroup2(slack, x, 1n, A.len(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{acc, k}, up}, J.MColon{}}),
                Equal.trans(J.St,
                  J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))})), J.Run{SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{J.FObj{acc, k}, up}, J.MColon{}}),
                  J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)))), J.Run{S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{J.FObj{acc, k}, up}, J.MValue{}}),
                  J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{rlf(acc, Con{J.Field{k, v}, t})}, r, up)),
                  step(A.add(A.add(slack, x), 1n), SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, A.len(S.text(v, False{}, S.text(J.JObj{t}, True{}, r))), Con{J.FObj{acc, k}, up}, J.MColon{}, {==}),
                  Equal.trans(J.St,
                    J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)))), J.Run{S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{J.FObj{acc, k}, up}, J.MValue{}}),
                    J.loop(A.add(w1, A.len(S.text(J.JObj{t}, True{}, r))), J.Run{S.text(J.JObj{t}, True{}, r), Con{J.FObj{Con{J.Field{k, v}, acc}, ""}, up}, J.MCommaOrClose{}}),
                    J.loop(A.add(w2, A.len(r)), J.emit(J.JObj{rlf(acc, Con{J.Field{k, v}, t})}, r, up)),
                    p1,
                    p2))))))))

law obj_t.3:
  for +k: String
  for +v: J.Json
  for +t: List<&2, J.Field>
  for +acc: List<&2, J.Field>
  for +k0: String
  for +up: List<&2, J.Frame>
  for +r: String
  for +slack: Nat
  for +x: Nat
  for ex: {A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})) == A.add(x, A.len(SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})) : Nat}
  for +w1: Nat
  for p1: {J.loop(A.add(A.add(A.add(slack, x), 1n), A.len(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)))), J.Run{S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{J.FObj{acc, k}, up}, J.MValue{}}) == J.loop(A.add(w1, A.len(S.text(J.JObj{t}, True{}, r))), result(False{}, v, Con{J.FObj{acc, k}, up}, S.text(J.JObj{t}, True{}, r))) : J.St}
  for g2: Goal(J.JObj{t}, True{}, J.MCommaOrClose{}, Con{J.FObj{Con{J.Field{k, v}, acc}, ""}, up}, r, w1)
  Goal(J.JObj{Con{J.Field{k, v}, t}}, True{}, J.MCommaOrClose{}, Con{J.FObj{acc, k0}, up}, r, slack)

def obj_t.3(k, v, t, acc, k0, up, r, slack, x, ex, w1, p1, g2):
  (+w2, p2) = g2
  obj_t.4(k, v, t, acc, k0, up, r, slack, x, ex, w1, p1, w2, p2)

law obj_t.2:
  for +k: String
  for +v: J.Json
  for +t: List<&2, J.Field>
  for +acc: List<&2, J.Field>
  for +k0: String
  for +up: List<&2, J.Frame>
  for +r: String
  for +slack: Nat
  for +x: Nat
  for ex: {A.len(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})) == A.add(x, A.len(SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})) : Nat}
  for g1: Goal(v, False{}, J.MValue{}, Con{J.FObj{acc, k}, up}, S.text(J.JObj{t}, True{}, r), A.add(A.add(slack, x), 1n))
  for ih2: @w: Nat -> Goal(J.JObj{t}, True{}, J.MCommaOrClose{}, Con{J.FObj{Con{J.Field{k, v}, acc}, ""}, up}, r, w)
  Goal(J.JObj{Con{J.Field{k, v}, t}}, True{}, J.MCommaOrClose{}, Con{J.FObj{acc, k0}, up}, r, slack)

def obj_t.2(k, v, t, acc, k0, up, r, slack, x, ex, g1, ih2):
  (+w1, p1) = g1
  obj_t.3(k, v, t, acc, k0, up, r, slack, x, ex, w1, p1, ih2(w1))

law obj_t.1:
  for +k: String
  for +v: J.Json
  for +t: List<&2, J.Field>
  for +acc: List<&2, J.Field>
  for +k0: String
  for +up: List<&2, J.Frame>
  for +r: String
  for +slack: Nat
  for pk: A.Pre(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})
  for ih1: @s: Nat -> Goal(v, False{}, J.MValue{}, Con{J.FObj{acc, k}, up}, S.text(J.JObj{t}, True{}, r), s)
  for ih2: @w: Nat -> Goal(J.JObj{t}, True{}, J.MCommaOrClose{}, Con{J.FObj{Con{J.Field{k, v}, acc}, ""}, up}, r, w)
  Goal(J.JObj{Con{J.Field{k, v}, t}}, True{}, J.MCommaOrClose{}, Con{J.FObj{acc, k0}, up}, r, slack)

def obj_t.1(k, v, t, acc, k0, up, r, slack, pk, ih1, ih2):
  (+x, ex) = pk
  obj_t.2(k, v, t, acc, k0, up, r, slack, x, ex, ih1(A.add(A.add(slack, x), 1n)), ih2)

# the main lemma: from any point where the text of j starts, the loop
# reads it and lands on result(...), with fuel to spare
law run:
  for +j: J.Json
  for +more: Bool
  for +m: J.Mode
  for +stk: List<&2, J.Frame>
  for +r: String
  for +slack: Nat
  for ctx: Ctx(more, j, m, stk)
  for dl: Num.Delim(r)
  Goal(j, more, m, stk, r, slack)

def run(j, more, m, stk, r, slack, ctx, dl):
  match j:
    case J.JNull{}:
      match more:
        case False{}:
          g_null(slack, m, ctx, stk, r)
        case True{}:
          match ctx:
    case J.JBool{True{}}:
      match more:
        case False{}:
          g_true(slack, m, ctx, stk, r)
        case True{}:
          match ctx:
    case J.JBool{False{}}:
      match more:
        case False{}:
          g_false(slack, m, ctx, stk, r)
        case True{}:
          match ctx:
    case J.JNum{n}:
      match more:
        case False{}:
          g_num(n, slack, m, ctx, stk, r, dl)
        case True{}:
          match ctx:
    case J.JStr{s}:
      match more:
        case False{}:
          g_str(s, slack, m, ctx, stk, r)
        case True{}:
          match ctx:
    case J.JArr{Nil{}}:
      match more:
        case False{}:
          g_arr_nil(slack, m, ctx, stk, r)
        case True{}:
          match m:
            case J.MCommaOrClose{}:
              match stk:
                case Con{J.FArr{acc}, up}:
                  g_arr_nil_t(acc, up, r, slack)
                case Con{J.FObj{_, _}, _}:
                  match ctx:
                case Nil{}:
                  match ctx:
            case J.MValue{}:
              match ctx:
            case J.MValueOrClose{}:
              match ctx:
            case J.MKeyOrClose{}:
              match ctx:
            case J.MKey{}:
              match ctx:
            case J.MColon{}:
              match ctx:
    case J.JArr{Con{h, t}}:
      match more:
        case False{}:
          arr_f.1(h, t, stk, r, slack, m, ctx,
            run(h, False{}, J.MValueOrClose{}, Con{J.FArr{[]}, stk}, S.text(J.JArr{t}, True{}, r), slack, Unit{}, delim_arr(t, r)),
            w => run(J.JArr{t}, True{}, J.MCommaOrClose{}, Con{J.FArr{[h]}, stk}, r, w, Unit{}, dl))
        case True{}:
          match m:
            case J.MCommaOrClose{}:
              match stk:
                case Con{J.FArr{acc}, up}:
                  arr_t.1(h, t, acc, up, r, slack, run(h, False{}, J.MValue{}, Con{J.FArr{acc}, up}, S.text(J.JArr{t}, True{}, r), slack, Unit{}, delim_arr(t, r)), w => run(J.JArr{t}, True{}, J.MCommaOrClose{}, Con{J.FArr{Con{h, acc}}, up}, r, w, Unit{}, dl))
                case Con{J.FObj{_, _}, _}:
                  match ctx:
                case Nil{}:
                  match ctx:
            case J.MValue{}:
              match ctx:
            case J.MValueOrClose{}:
              match ctx:
            case J.MKeyOrClose{}:
              match ctx:
            case J.MKey{}:
              match ctx:
            case J.MColon{}:
              match ctx:
    case J.JObj{Nil{}}:
      match more:
        case False{}:
          g_obj_nil(slack, m, ctx, stk, r)
        case True{}:
          match m:
            case J.MCommaOrClose{}:
              match stk:
                case Con{J.FObj{acc, k0}, up}:
                  g_obj_nil_t(acc, k0, up, r, slack)
                case Con{J.FArr{_}, _}:
                  match ctx:
                case Nil{}:
                  match ctx:
            case J.MValue{}:
              match ctx:
            case J.MValueOrClose{}:
              match ctx:
            case J.MKeyOrClose{}:
              match ctx:
            case J.MKey{}:
              match ctx:
            case J.MColon{}:
              match ctx:
    case J.JObj{Con{J.Field{k, v}, t}}:
      match more:
        case False{}:
          obj_f.1(k, v, t, stk, r, slack, m, ctx, A.pre_esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}),
            s => run(v, False{}, J.MValue{}, Con{J.FObj{[], k}, stk}, S.text(J.JObj{t}, True{}, r), s, Unit{}, delim_obj(t, r)),
            w => run(J.JObj{t}, True{}, J.MCommaOrClose{}, Con{J.FObj{[J.Field{k, v}], ""}, stk}, r, w, Unit{}, dl))
        case True{}:
          match m:
            case J.MCommaOrClose{}:
              match stk:
                case Con{J.FObj{acc, k0}, up}:
                  obj_t.1(k, v, t, acc, k0, up, r, slack, A.pre_esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), s => run(v, False{}, J.MValue{}, Con{J.FObj{acc, k}, up}, S.text(J.JObj{t}, True{}, r), s, Unit{}, delim_obj(t, r)), w => run(J.JObj{t}, True{}, J.MCommaOrClose{}, Con{J.FObj{Con{J.Field{k, v}, acc}, ""}, up}, r, w, Unit{}, dl))
                case Con{J.FArr{_}, _}:
                  match ctx:
                case Nil{}:
                  match ctx:
            case J.MValue{}:
              match ctx:
            case J.MValueOrClose{}:
              match ctx:
            case J.MKeyOrClose{}:
              match ctx:
            case J.MKey{}:
              match ctx:
            case J.MColon{}:
              match ctx:

# no printed value starts with a byte order mark
law bom:
  for +j: J.Json
  {J.skip_bom(S.text(j, False{}, "")) == S.text(j, False{}, "") : String}

def bom(j):
  match j:
    case J.JNull{}:
      {==}
    case J.JBool{True{}}:
      {==}
    case J.JBool{False{}}:
      {==}
    case J.JStr{_}:
      {==}
    case J.JArr{Nil{}}:
      {==}
    case J.JArr{Con{_, _}}:
      {==}
    case J.JObj{Nil{}}:
      {==}
    case J.JObj{Con{J.Field{_, _}, _}}:
      {==}
    case J.JNum{J.Number{True{}, _, _, _}}:
      {==}
    case J.JNum{J.Number{False{}, J.IZero{}, _, _}}:
      {==}
    case J.JNum{J.Number{False{}, J.INon{J.L1{}, _}, _, _}}:
      {==}
    case J.JNum{J.Number{False{}, J.INon{J.L2{}, _}, _, _}}:
      {==}
    case J.JNum{J.Number{False{}, J.INon{J.L3{}, _}, _, _}}:
      {==}
    case J.JNum{J.Number{False{}, J.INon{J.L4{}, _}, _, _}}:
      {==}
    case J.JNum{J.Number{False{}, J.INon{J.L5{}, _}, _, _}}:
      {==}
    case J.JNum{J.Number{False{}, J.INon{J.L6{}, _}, _, _}}:
      {==}
    case J.JNum{J.Number{False{}, J.INon{J.L7{}, _}, _, _}}:
      {==}
    case J.JNum{J.Number{False{}, J.INon{J.L8{}, _}, _, _}}:
      {==}
    case J.JNum{J.Number{False{}, J.INon{J.L9{}, _}, _, _}}:
      {==}

def RJ() -> Type:
  Result<&2, &2, J.Error, J.Json>

law round_trip.go:
  for +j: J.Json
  for g: Goal(j, False{}, J.MValue{}, [], "", 1n)
  {J.finish(S.text(j, False{}, ""), J.loop(1n+A.len(S.text(j, False{}, "")), J.Run{S.text(j, False{}, ""), [], J.MValue{}})) == Done{j} : RJ()}

def round_trip.go(j, g):
  (+w, p) = g
  +t : String = S.text(j, False{}, "")
  Equal.cong(J.St, RJ(), x => J.finish(t, x),
    J.loop(1n+A.len(t), J.Run{t, [], J.MValue{}}), J.Fin{j},
    Equal.trans(J.St, J.loop(1n+A.len(t), J.Run{t, [], J.MValue{}}), J.loop(A.add(w, 0n), J.Fin{j}), J.Fin{j},
      p,
      loop_fin(A.add(w, 0n), j)))

# parsing what the printer wrote gives back the value, for every value
law round_trip:
  for +j: J.Json
  {J.parse(J.stringify(j)) == Done{j} : RJ()}

def round_trip(j):
  +t : String = S.text(j, False{}, "")
  %Equal.sym(String, J.stringify(j), t, P.print(j)) : {J.parse(_) == Done{j} : RJ()}
  %Equal.sym(String, J.skip_bom(t), t, bom(j)) : {J.finish(t, J.loop(1n+A.len(t), J.Run{_, [], J.MValue{}})) == Done{j} : RJ()}
  round_trip.go(j, run(j, False{}, J.MValue{}, [], "", 1n, Unit{}, Unit{}))
