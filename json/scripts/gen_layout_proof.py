"""Generate proof/layout.bend: the parser reads back any layout of j.

S.lay(j, more, p, u, d, k) is the text the printer writes, compact (p is
False) or indented by u per level. Every value's text may sit behind
white space `pre`, which the loop skips at no step (adv). The proof is
proof/parse.bend's, with that space threaded through: long and regular, so
it is generated.

  python3 scripts/gen_layout_proof.py
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "proof/layout.bend"
BAD = ["J.MKeyOrClose{}", "J.MKey{}", "J.MColon{}", "J.MCommaOrClose{}"]
VAL = ["J.MValue{}", "J.MValueOrClose{}"]


def add(a, b):
    return f"A.add({a}, {b})"


def ln(s):
    return f"A.len({s})"


def loop(f, st):
    return f"J.loop({f}, {st})"


def run(s, stk, m):
    return f"J.Run{{{s}, {stk}, {m}}}"


def lay(j, more, d, k):
    return f"S.lay({j}, {more}, p, S.wstr(cs), {d}, {k})"


def bw(n):
    return f"S.bw(p, S.wstr(cs), {n})"


def tr(ts, ps, ind=4, ty="J.St"):
    if len(ps) == 1:
        return ps[0]
    pad = " " * ind
    return (f"Equal.trans({ty},\n{pad}  {ts[0]},\n{pad}  {ts[1]},\n{pad}  {ts[-1]},\n{pad}  {ps[0]},\n{pad}  "
            + tr(ts[1:], ps[1:], ind + 2, ty) + ")")


SW = add("slack", ln("pre"))
out = []


def law(name, params, claim, args, body):
    out.append(f"law {name}:\n" + "".join(f"  for {p}\n" for p in params) + f"  {claim}\n\n"
               f"def {name}({', '.join(args)}):\n{body}\n")


def by_mode(branch, modes=VAL):
    s = "  match m:\n"
    for m in modes:
        s += f"    case {m}:\n      " + branch(m).replace("\n", "\n    ") + "\n"
    for m in BAD:
        s += f"    case {m}:\n      match vm:\n"
    return s.rstrip("\n")


W_PARAMS = ["+pre: String", "wp: Ws(pre)", "+slack: Nat", "+p: Bool", "+cs: List<&2, S.WsC>", "+d: Nat",
            "+m: J.Mode", "vm: PA.ValMode(m)", "+stk: List<&2, J.Frame>", "+r: String"]
W_ARGS = ["pre", "wp", "slack", "p", "cs", "d", "m", "vm", "stk", "r"]


def goal(pre, j, more, d, m, stk, r, slack):
    return f"Goal({pre}, {j}, {more}, p, cs, {d}, {m}, {stk}, {r}, {slack})"


# literals
for name, j, word, n in [("g_null", "J.JNull{}", "null", "3n"), ("g_true", "J.JBool{True{}}", "true", "3n"),
                         ("g_false", "J.JBool{False{}}", "false", "4n")]:
    txt = f'"{word}" ++ r'
    em = f"J.emit({j}, r, stk)"

    def br(m, txt=txt, em=em, n=n):
        ts = [loop(add("slack", ln(f"pre ++ ({txt})")), run(f"pre ++ ({txt})", "stk", m)),
              loop(add(SW, add(n, ln("r"))), em), loop(add(add(SW, n), ln("r")), em)]
        ps = [f"adv(slack, pre, {txt}, {add(n, ln('r'))}, stk, {m}, {{==}}, wp({txt}))",
              f"PA.regroup({SW}, {n}, {ln('r')}, {em})"]
        return f"({add(SW, n)}, " + tr(ts, ps) + ")"
    law(name, W_PARAMS, goal("pre", j, "False{}", "d", "m", "stk", "r", "slack"), W_ARGS, by_mode(br))

# strings
E = "S.esc(s, SCon{'\"', r})"
em = "J.emit(J.JStr{s}, r, stk)"


def str_br(m):
    ts = [loop(add("slack", ln("pre ++ S.str(s, r)")), run("pre ++ S.str(s, r)", "stk", m)),
          loop(add(SW, ln(E)), f"J.token(~J.mk_str, J.lex_str({E}, J.SGo{{\"\", 0}}), stk)"),
          loop(add(SW, ln(E)), em),
          loop(add(SW, add("x", add("1n", ln("r")))), em),
          loop(add(add(add(SW, "x"), "1n"), ln("r")), em)]
    ps = [f"adv(slack, pre, S.str(s, r), {ln(E)}, stk, {m}, {{==}}, wp(S.str(s, r)))",
          f"Equal.cong(J.Lex, J.St, y => {loop(add(SW, ln(E)), 'J.token(~J.mk_str, y, stk)')}, "
          f"J.lex_str({E}, J.SGo{{\"\", 0}}), J.LOk{{s, r}}, Str.body(s, \"\", r))",
          f"Equal.cong(Nat, J.St, f => {loop(add(SW, 'f'), em)}, {ln(E)}, {add('x', add('1n', ln('r')))}, ex)",
          f"PA.regroup2({SW}, x, 1n, {ln('r')}, {em})"]
    return f"({add(add(SW, 'x'), '1n')}, " + tr(ts, ps) + ")"


law("g_str.x", ["+s: String"] + W_PARAMS + ["+x: Nat", f"ex: {{{ln(E)} == {add('x', ln(chr(83) + 'Con{' + chr(39) + chr(34) + chr(39) + ', r}'))} : Nat}}"],
    goal("pre", "J.JStr{s}", "False{}", "d", "m", "stk", "r", "slack"), ["s"] + W_ARGS + ["x", "ex"], by_mode(str_br))
law("g_str.w", ["+s: String"] + W_PARAMS + [f"w: A.Pre({E}, SCon{{'\"', r}})"],
    goal("pre", "J.JStr{s}", "False{}", "d", "m", "stk", "r", "slack"), ["s"] + W_ARGS + ["w"],
    "  (+x, ex) = w\n  g_str.x(s, " + ", ".join(W_ARGS) + ", x, ex)")
law("g_str", ["+s: String"] + W_PARAMS, goal("pre", "J.JStr{s}", "False{}", "d", "m", "stk", "r", "slack"),
    ["s"] + W_ARGS, "  g_str.w(s, " + ", ".join(W_ARGS) + ", A.pre_esc(s, SCon{'\"', r}))")

# numbers
N = "J.num_k(n, r)"
em = "J.emit(J.JNum{n}, r, stk)"
ts = [loop(add("slack", ln(f"pre ++ {N}")), run(f"pre ++ {N}", "stk", "m")),
      loop(add(SW, add("x", ln("r"))), f"J.dispatch(m, J.skip_ws({N}), stk)"),
      loop(add(SW, add("x", ln("r"))), f"J.number(J.lex_num({N}, J.NStart{{}}), stk)"),
      loop(add(SW, add("x", ln("r"))), em),
      loop(add(add(SW, "x"), ln("r")), em)]
ps = [f"adv(slack, pre, {N}, {add('x', ln('r'))}, stk, m, ex, wp({N}))",
      f"Equal.cong(J.St, J.St, y => {loop(add(SW, add('x', ln('r'))), 'y')}, J.dispatch(m, J.skip_ws({N}), stk), "
      f"J.number(J.lex_num({N}, J.NStart{{}}), stk), PA.num_dispatch(n, r, stk, m, vm))",
      f"Equal.cong(J.NLex, J.St, y => {loop(add(SW, add('x', ln('r'))), 'J.number(y, stk)')}, "
      f"J.lex_num({N}, J.NStart{{}}), J.NOk{{n, r}}, Num.number(n, r, dl))",
      f"PA.regroup({SW}, x, {ln('r')}, {em})"]
law("g_num.w", ["+n: J.Number"] + W_PARAMS + ["dl: Num.Delim(r)", f"w: A.Pre1({N}, r)"],
    goal("pre", "J.JNum{n}", "False{}", "d", "m", "stk", "r", "slack"), ["n"] + W_ARGS + ["dl", "w"],
    "  (+x, ex) = w\n  (" + add(SW, "x") + ", " + tr(ts, ps, 2) + ")")
law("g_num", ["+n: J.Number"] + W_PARAMS + ["dl: Num.Delim(r)"],
    goal("pre", "J.JNum{n}", "False{}", "d", "m", "stk", "r", "slack"), ["n"] + W_ARGS + ["dl"],
    "  g_num.w(n, " + ", ".join(W_ARGS) + ", dl, A.num_len(n, r))")

# empty containers
for name, o, c, frame, mode, jv in [("g_arr_nil", "[", "]", "J.FArr{[]}", "J.MValueOrClose{}", "J.JArr{[]}"),
                                    ("g_obj_nil", "{", "}", "J.FObj{[], \"\"}", "J.MKeyOrClose{}", "J.JObj{[]}")]:
    txt = f"SCon{{'{o}', SCon{{'{c}', r}}}}"

    def br(m, txt=txt, c=c, frame=frame, mode=mode, jv=jv):
        ts = [loop(add("slack", ln(f"pre ++ {txt}")), run(f"pre ++ {txt}", "stk", m)),
              loop(add(SW, ln(f"SCon{{'{c}', r}}")), run(f"SCon{{'{c}', r}}", f"Con{{{frame}, stk}}", mode)),
              loop(add(SW, ln("r")), f"J.emit({jv}, r, stk)")]
        ps = [f"adv(slack, pre, {txt}, {ln(chr(83) + 'Con{' + chr(39) + c + chr(39) + ', r}')}, stk, {m}, {{==}}, wp({txt}))",
              f"PA.step({SW}, SCon{{'{c}', r}}, {ln('r')}, Con{{{frame}, stk}}, {mode}, {{==}})"]
        return f"({SW}, " + tr(ts, ps) + ")"
    law(name, W_PARAMS, goal("pre", jv, "False{}", "d", "m", "stk", "r", "slack"), W_ARGS, by_mode(br))

# closing a container that had items: the line break, then the closer
for name, c, fr, fpat, jv in [("g_arr_nil_t", "]", "J.FArr{acc}", ["+acc: List<&2, J.Json>"], "J.JArr{[]}"),
                              ("g_obj_nil_t", "}", "J.FObj{acc, k0}", ["+acc: List<&2, J.Field>", "+k0: String"], "J.JObj{[]}")]:
    stk = f"Con{{{fr}, up}}"
    rj = "J.JArr{rlj(acc, [])}" if c == "]" else "J.JObj{rlf(acc, [])}"
    rj = rj.replace("rlj", "PA.rlj").replace("rlf", "PA.rlf")
    txt = f"SCon{{'{c}', r}}"
    fargs = [x.split(":")[0].lstrip("+") for x in fpat]
    law(name, fpat + ["+up: List<&2, J.Frame>", "+r: String", "+slack: Nat", "+p: Bool", "+cs: List<&2, S.WsC>", "+d: Nat"],
        goal('""', jv, "True{}", "d", "J.MCommaOrClose{}", stk, "r", "slack"),
        fargs + ["up", "r", "slack", "p", "cs", "d"],
        f"  ({add('slack', ln(bw('d')))}, adv(slack, {bw('d')}, {txt}, {ln('r')}, {stk}, J.MCommaOrClose{{}}, {{==}}, bw_ws(p, cs, d, {txt})))")

# arrays: '[' or ',' then a line break, then the item, then the rest
K = lay("J.JArr{t}", "True{}", "d", "r")
H = lay("h", "False{}", "1n+d", K)
BH = f"{bw('1n+d')} ++ {H}"


def arr_chain(first, stk0, m, frame0, frame1, mode1, fin, slack1, step):
    ts = [loop(add("slack", ln(first)), run(first, stk0, m)),
          loop(add(slack1, ln(BH)), run(BH, frame0, mode1)),
          loop(add("w1", ln(K)), run(K, frame1, "J.MCommaOrClose{}")),
          loop(add("w2", ln("r")), fin)]
    return ts, [step, "p1", "p2"]


def p1(pre, frame0, mode1, slack1):
    return (f"p1: {{{loop(add(slack1, ln(f'{pre} ++ {H}')), run(f'{pre} ++ {H}', frame0, mode1))} == "
            f"{loop(add('w1', ln(K)), f'PA.result(False{{}}, h, {frame0}, {K})')} : J.St}}")


def p2(frame1, fin_more):
    return (f"p2: {{{loop(add('w1', ln(K)), run(K, frame1, 'J.MCommaOrClose{}'))} == "
            f"{loop(add('w2', ln('r')), f'PA.result(True{{}}, J.JArr{{t}}, {frame1}, r)')} : J.St}}")


LAYP = ["+p: Bool", "+cs: List<&2, S.WsC>", "+d: Nat"]
first = f"pre ++ SCon{{'[', {BH}}}"


def arr_f(m):
    ts, ps = arr_chain(first, "stk", m, "Con{J.FArr{[]}, stk}", "Con{J.FArr{[h]}, stk}", "J.MValueOrClose{}",
                       "J.emit(J.JArr{Con{h, t}}, r, stk)", SW,
                       f"adv(slack, pre, SCon{{'[', {BH}}}, {ln(BH)}, stk, {m}, {{==}}, wp(SCon{{'[', {BH}}}))")
    return "(w2, " + tr(ts, ps) + ")"


AF = ["+h: J.Json", "+t: List<&2, J.Json>", "+stk: List<&2, J.Frame>", "+r: String", "+pre: String", "wp: Ws(pre)",
      "+slack: Nat", "+m: J.Mode", "vm: PA.ValMode(m)"] + LAYP
AFA = ["h", "t", "stk", "r", "pre", "wp", "slack", "m", "vm", "p", "cs", "d"]
G_AF = goal("pre", "J.JArr{Con{h, t}}", "False{}", "d", "m", "stk", "r", "slack")
law("arr_f.3", AF + ["+w1: Nat", p1(bw("1n+d"), "Con{J.FArr{[]}, stk}", "J.MValueOrClose{}", SW), "+w2: Nat",
                     p2("Con{J.FArr{[h]}, stk}", None)], G_AF, AFA + ["w1", "p1", "w2", "p2"], by_mode(arr_f))
law("arr_f.2", AF + ["+w1: Nat", p1(bw("1n+d"), "Con{J.FArr{[]}, stk}", "J.MValueOrClose{}", SW),
                     f"g2: {goal(chr(34) * 2, 'J.JArr{t}', 'True{}', 'd', 'J.MCommaOrClose{}', 'Con{J.FArr{[h]}, stk}', 'r', 'w1')}"],
    G_AF, AFA + ["w1", "p1", "g2"], "  (+w2, p2) = g2\n  arr_f.3(" + ", ".join(AFA) + ", w1, p1, w2, p2)")
law("arr_f.1", AF + [f"g1: {goal(bw('1n+d'), 'h', 'False{}', '1n+d', 'J.MValueOrClose{}', 'Con{J.FArr{[]}, stk}', K, SW)}",
                     f"ih2: @w: Nat -> {goal(chr(34) * 2, 'J.JArr{t}', 'True{}', 'd', 'J.MCommaOrClose{}', 'Con{J.FArr{[h]}, stk}', 'r', 'w')}"],
    G_AF, AFA + ["g1", "ih2"], "  (+w1, p1) = g1\n  arr_f.2(" + ", ".join(AFA) + ", w1, p1, ih2(w1))")

AT = ["+h: J.Json", "+t: List<&2, J.Json>", "+acc: List<&2, J.Json>", "+up: List<&2, J.Frame>", "+r: String",
      "+slack: Nat"] + LAYP
ATA = ["h", "t", "acc", "up", "r", "slack", "p", "cs", "d"]
STK_T = "Con{J.FArr{acc}, up}"
G_AT = goal('""', "J.JArr{Con{h, t}}", "True{}", "d", "J.MCommaOrClose{}", STK_T, "r", "slack")
ts, ps = arr_chain(f"SCon{{',', {BH}}}", STK_T, "J.MCommaOrClose{}", STK_T, "Con{J.FArr{Con{h, acc}}, up}", "J.MValue{}",
                   "J.emit(J.JArr{PA.rlj(acc, Con{h, t})}, r, up)", "slack",
                   f"PA.step(slack, SCon{{',', {BH}}}, {ln(BH)}, {STK_T}, J.MCommaOrClose{{}}, {{==}})")
law("arr_t.3", AT + ["+w1: Nat", p1(bw("1n+d"), STK_T, "J.MValue{}", "slack"), "+w2: Nat",
                     p2("Con{J.FArr{Con{h, acc}}, up}", None)], G_AT, ATA + ["w1", "p1", "w2", "p2"],
    "  (w2, " + tr(ts, ps, 2) + ")")
law("arr_t.2", AT + ["+w1: Nat", p1(bw("1n+d"), STK_T, "J.MValue{}", "slack"),
                     f"g2: {goal(chr(34) * 2, 'J.JArr{t}', 'True{}', 'd', 'J.MCommaOrClose{}', 'Con{J.FArr{Con{h, acc}}, up}', 'r', 'w1')}"],
    G_AT, ATA + ["w1", "p1", "g2"], "  (+w2, p2) = g2\n  arr_t.3(" + ", ".join(ATA) + ", w1, p1, w2, p2)")
law("arr_t.1", AT + [f"g1: {goal(bw('1n+d'), 'h', 'False{}', '1n+d', 'J.MValue{}', STK_T, K, 'slack')}",
                     f"ih2: @w: Nat -> {goal(chr(34) * 2, 'J.JArr{t}', 'True{}', 'd', 'J.MCommaOrClose{}', 'Con{J.FArr{Con{h, acc}}, up}', 'r', 'w')}"],
    G_AT, ATA + ["g1", "ih2"], "  (+w1, p1) = g1\n  arr_t.2(" + ", ".join(ATA) + ", w1, p1, ih2(w1))")

# objects: '{' or ',', a line break, the key, ':', a space, the value, the rest
KO = lay("J.JObj{t}", "True{}", "d", "r")
V = lay("v", "False{}", "1n+d", KO)
SV = f"S.sp(p) ++ {V}"
C = f"SCon{{':', {SV}}}"
EK = f"S.esc(k, SCon{{'\"', {C}}})"
BK = f"{bw('1n+d')} ++ S.str(k, {C})"


def obj_chain(first, stk0, m, mode_key, stk_key, fin, slack0, step0):
    s2 = add(slack0, ln(bw("1n+d")))
    s3 = add(add(s2, "x"), "1n")
    stk_k = stk_key.replace("KEY", "k")
    stk_v = stk_key.replace("KEY", '""').replace("FIELDS", "")
    kst = f"Con{{J.FObj{{FIELDS, KEY}}, UP}}"
    ts = [loop(add("slack", ln(first)), run(first, stk0, m)),
          loop(add(slack0, ln(BK)), run(BK, stk_key.replace("KEY", "K0"), mode_key)),
          loop(add(s2, ln(EK)), f"J.key(J.lex_str({EK}, J.SGo{{\"\", 0}}), {stk_key.replace('KEY', 'K0')})"),
          loop(add(s2, ln(EK)), run(C, stk_k, "J.MColon{}")),
          loop(add(s2, add("x", add("1n", ln(C)))), run(C, stk_k, "J.MColon{}")),
          loop(add(s3, ln(C)), run(C, stk_k, "J.MColon{}")),
          loop(add(s3, ln(SV)), run(SV, stk_k, "J.MValue{}")),
          loop(add("w1", ln(KO)), run(KO, "STK1", "J.MCommaOrClose{}")),
          loop(add("w2", ln("r")), fin)]
    ps = [step0,
          f"adv({slack0}, {bw('1n+d')}, S.str(k, {C}), {ln(EK)}, {stk_key.replace('KEY', 'K0')}, {mode_key}, {{==}}, bw_ws(p, cs, 1n+d, S.str(k, {C})))",
          f"Equal.cong(J.Lex, J.St, y => {loop(add(s2, ln(EK)), 'J.key(y, ' + stk_key.replace('KEY', 'K0') + ')')}, "
          f"J.lex_str({EK}, J.SGo{{\"\", 0}}), J.LOk{{k, {C}}}, Str.body(k, \"\", {C}))",
          f"Equal.cong(Nat, J.St, f => {loop(add(s2, 'f'), run(C, stk_k, 'J.MColon{}'))}, {ln(EK)}, {add('x', add('1n', ln(C)))}, ex)",
          f"PA.regroup2({s2}, x, 1n, {ln(C)}, {run(C, stk_k, 'J.MColon{}')})",
          f"PA.step({s3}, {C}, {ln(SV)}, {stk_k}, J.MColon{{}}, {{==}})",
          "p1", "p2"]
    return ts, ps, s3


def objsub(x, fields, k0, upv, stk1):
    return x.replace("FIELDS", fields).replace("K0", k0).replace("UP", upv).replace("STK1", stk1)


EX = f"ex: {{{ln(EK)} == {add('x', ln(chr(83) + 'Con{' + chr(39) + chr(34) + chr(39) + ', ' + C + '}'))} : Nat}}"
PK = f"pk: A.Pre({EK}, SCon{{'\"', {C}}})"


def op1(stk_k, slack):
    return (f"p1: {{{loop(add(slack, ln(SV)), run(SV, stk_k, 'J.MValue{}'))} == "
            f"{loop(add('w1', ln(KO)), f'PA.result(False{{}}, v, {stk_k}, {KO})')} : J.St}}")


def op2(stk1):
    return (f"p2: {{{loop(add('w1', ln(KO)), run(KO, stk1, 'J.MCommaOrClose{}'))} == "
            f"{loop(add('w2', ln('r')), f'PA.result(True{{}}, J.JObj{{t}}, {stk1}, r)')} : J.St}}")


OF = ["+k: String", "+v: J.Json", "+t: List<&2, J.Field>", "+stk: List<&2, J.Frame>", "+r: String", "+pre: String",
      "wp: Ws(pre)", "+slack: Nat", "+m: J.Mode", "vm: PA.ValMode(m)"] + LAYP
OFA = ["k", "v", "t", "stk", "r", "pre", "wp", "slack", "m", "vm", "p", "cs", "d"]
G_OF = goal("pre", "J.JObj{Con{J.Field{k, v}, t}}", "False{}", "d", "m", "stk", "r", "slack")
FIRST_O = f"pre ++ SCon{{'{{', {BK}}}"
STK1_F = "Con{J.FObj{[J.Field{k, v}], \"\"}, stk}"
S3_F = add(add(add(SW, ln(bw("1n+d"))), "x"), "1n")


def obj_f(m):
    ts, ps, _ = obj_chain(FIRST_O, "stk", m, "J.MKeyOrClose{}", "Con{J.FObj{[], KEY}, stk}",
                          "J.emit(J.JObj{Con{J.Field{k, v}, t}}, r, stk)", SW,
                          f"adv(slack, pre, SCon{{'{{', {BK}}}, {ln(BK)}, stk, {m}, {{==}}, wp(SCon{{'{{', {BK}}}))")
    ts = [objsub(x, "[]", '""', "stk", STK1_F) for x in ts]
    ps = [objsub(x, "[]", '""', "stk", STK1_F) for x in ps]
    return "(w2, " + tr(ts, ps) + ")"


STK_KF = "Con{J.FObj{[], k}, stk}"
law("obj_f.4", OF + ["+x: Nat", EX, "+w1: Nat", op1(STK_KF, S3_F), "+w2: Nat", op2(STK1_F)], G_OF,
    OFA + ["x", "ex", "w1", "p1", "w2", "p2"], by_mode(obj_f))
law("obj_f.3", OF + ["+x: Nat", EX, "+w1: Nat", op1(STK_KF, S3_F),
                     f"g2: {goal(chr(34) * 2, 'J.JObj{t}', 'True{}', 'd', 'J.MCommaOrClose{}', STK1_F, 'r', 'w1')}"],
    G_OF, OFA + ["x", "ex", "w1", "p1", "g2"], "  (+w2, p2) = g2\n  obj_f.4(" + ", ".join(OFA) + ", x, ex, w1, p1, w2, p2)")
law("obj_f.2", OF + ["+x: Nat", EX, f"g1: {goal('S.sp(p)', 'v', 'False{}', '1n+d', 'J.MValue{}', STK_KF, KO, S3_F)}",
                     f"ih2: @w: Nat -> {goal(chr(34) * 2, 'J.JObj{t}', 'True{}', 'd', 'J.MCommaOrClose{}', STK1_F, 'r', 'w')}"],
    G_OF, OFA + ["x", "ex", "g1", "ih2"], "  (+w1, p1) = g1\n  obj_f.3(" + ", ".join(OFA) + ", x, ex, w1, p1, ih2(w1))")
law("obj_f.1", OF + [PK, f"ih1: @s: Nat -> {goal('S.sp(p)', 'v', 'False{}', '1n+d', 'J.MValue{}', STK_KF, KO, 's')}",
                     f"ih2: @w: Nat -> {goal(chr(34) * 2, 'J.JObj{t}', 'True{}', 'd', 'J.MCommaOrClose{}', STK1_F, 'r', 'w')}"],
    G_OF, OFA + ["pk", "ih1", "ih2"],
    "  (+x, ex) = pk\n  obj_f.2(" + ", ".join(OFA) + f", x, ex, ih1({S3_F.replace('x', 'x')}), ih2)")

OT = ["+k: String", "+v: J.Json", "+t: List<&2, J.Field>", "+acc: List<&2, J.Field>", "+k0: String",
      "+up: List<&2, J.Frame>", "+r: String", "+slack: Nat"] + LAYP
OTA = ["k", "v", "t", "acc", "k0", "up", "r", "slack", "p", "cs", "d"]
STK_T0 = "Con{J.FObj{acc, k0}, up}"
STK1_T = "Con{J.FObj{Con{J.Field{k, v}, acc}, \"\"}, up}"
STK_KT = "Con{J.FObj{acc, k}, up}"
G_OT = goal('""', "J.JObj{Con{J.Field{k, v}, t}}", "True{}", "d", "J.MCommaOrClose{}", STK_T0, "r", "slack")
S3_T = add(add(add("slack", ln(bw("1n+d"))), "x"), "1n")
ts, ps, _ = obj_chain(f"SCon{{',', {BK}}}", STK_T0, "J.MCommaOrClose{}", "J.MKey{}", "Con{J.FObj{acc, KEY}, up}",
                      "J.emit(J.JObj{PA.rlf(acc, Con{J.Field{k, v}, t})}, r, up)", "slack",
                      f"PA.step(slack, SCon{{',', {BK}}}, {ln(BK)}, {STK_T0}, J.MCommaOrClose{{}}, {{==}})")
ts = [objsub(x, "acc", "k0", "up", STK1_T) for x in ts]
ps = [objsub(x, "acc", "k0", "up", STK1_T) for x in ps]
law("obj_t.4", OT + ["+x: Nat", EX, "+w1: Nat", op1(STK_KT, S3_T), "+w2: Nat", op2(STK1_T)], G_OT,
    OTA + ["x", "ex", "w1", "p1", "w2", "p2"], "  (w2, " + tr(ts, ps, 2) + ")")
law("obj_t.3", OT + ["+x: Nat", EX, "+w1: Nat", op1(STK_KT, S3_T),
                     f"g2: {goal(chr(34) * 2, 'J.JObj{t}', 'True{}', 'd', 'J.MCommaOrClose{}', STK1_T, 'r', 'w1')}"],
    G_OT, OTA + ["x", "ex", "w1", "p1", "g2"], "  (+w2, p2) = g2\n  obj_t.4(" + ", ".join(OTA) + ", x, ex, w1, p1, w2, p2)")
law("obj_t.2", OT + ["+x: Nat", EX, f"g1: {goal('S.sp(p)', 'v', 'False{}', '1n+d', 'J.MValue{}', STK_KT, KO, S3_T)}",
                     f"ih2: @w: Nat -> {goal(chr(34) * 2, 'J.JObj{t}', 'True{}', 'd', 'J.MCommaOrClose{}', STK1_T, 'r', 'w')}"],
    G_OT, OTA + ["x", "ex", "g1", "ih2"], "  (+w1, p1) = g1\n  obj_t.3(" + ", ".join(OTA) + ", x, ex, w1, p1, ih2(w1))")
law("obj_t.1", OT + [PK, f"ih1: @s: Nat -> {goal('S.sp(p)', 'v', 'False{}', '1n+d', 'J.MValue{}', STK_KT, KO, 's')}",
                     f"ih2: @w: Nat -> {goal(chr(34) * 2, 'J.JObj{t}', 'True{}', 'd', 'J.MCommaOrClose{}', STK1_T, 'r', 'w')}"],
    G_OT, OTA + ["pk", "ih1", "ih2"], f"  (+x, ex) = pk\n  obj_t.2(" + ", ".join(OTA) + f", x, ex, ih1({S3_T}), ih2)")

HEAD = '''import Base
import ../bjson.bend as J
import ./spec.bend as S
import ./arith.bend as A
import ./strings.bend as Str
import ./numbers.bend as Num
import ./print.bend as P
import ./parse.bend as PA
import ./fast_text.bend as T

# generated by scripts/gen_layout_proof.py; do not edit
#
# The parser loop reads S.lay(j) back to j, for either layout. A value's
# text may sit behind white space pre, which the loop skips at no step.

def Goal(+pre: String, +j: J.Json, +more: Bool, +p: Bool, +cs: List<&2, S.WsC>, +d: Nat, +m: J.Mode, +stk: List<&2, J.Frame>, +r: String, +slack: Nat) -> Type:
  &w: Nat -> {J.loop(A.add(slack, A.len(pre ++ S.lay(j, more, p, S.wstr(cs), d, r))), J.Run{pre ++ S.lay(j, more, p, S.wstr(cs), d, r), stk, m}) == J.loop(A.add(w, A.len(r)), PA.result(more, j, stk, r)) : J.St}

# white space: the loop's skip_ws goes through it
def Ws(+pre: String) -> Type:
  @s: String -> {J.skip_ws(pre ++ s) == J.skip_ws(s) : String}

law ws_nil:
  for +s: String
  {J.skip_ws("" ++ s) == J.skip_ws(s) : String}

def ws_nil(s):
  {==}

law cs_ws:
  for +cs: List<&2, S.WsC>
  for +s: String
  {J.skip_ws(S.wstr(cs) ++ s) == J.skip_ws(s) : String}

def cs_ws(cs, s):
  match cs:
    case Nil{}:
      {==}
    case Con{S.WSpace{}, t}:
      cs_ws(t, s)
    case Con{S.WTab{}, t}:
      cs_ws(t, s)

law ind_ws:
  for +n: Nat
  for +cs: List<&2, S.WsC>
  for +s: String
  {J.skip_ws(S.ind(n, S.wstr(cs)) ++ s) == J.skip_ws(s) : String}

def ind_ws(n, cs, s):
  match n:
    case 0n:
      {==}
    case 1n+q:
      +u : String = S.wstr(cs)
      Equal.trans(String, J.skip_ws((u ++ S.ind(q, u)) ++ s), J.skip_ws(u ++ (S.ind(q, u) ++ s)), J.skip_ws(s),
        Equal.cong(String, String, x => J.skip_ws(x), (u ++ S.ind(q, u)) ++ s, u ++ (S.ind(q, u) ++ s), T.app_assoc(u, S.ind(q, u), s)),
        Equal.trans(String, J.skip_ws(u ++ (S.ind(q, u) ++ s)), J.skip_ws(S.ind(q, u) ++ s), J.skip_ws(s),
          cs_ws(cs, S.ind(q, u) ++ s),
          ind_ws(q, cs, s)))

law bw_ws:
  for +p: Bool
  for +cs: List<&2, S.WsC>
  for +n: Nat
  for +s: String
  {J.skip_ws(S.bw(p, S.wstr(cs), n) ++ s) == J.skip_ws(s) : String}

def bw_ws(p, cs, n, s):
  match p:
    case True{}:
      ind_ws(n, cs, s)
    case False{}:
      {==}

law sp_ws:
  for +p: Bool
  for +s: String
  {J.skip_ws(S.sp(p) ++ s) == J.skip_ws(s) : String}

def sp_ws(p, s):
  match p:
    case True{}:
      {==}
    case False{}:
      {==}

# one step of the loop past white space and one more char
law adv.go:
  for +sw: Nat
  for +pre: String
  for +s: String
  for +q: Nat
  for +stk: List<&2, J.Frame>
  for +m: J.Mode
  for e: {A.len(s) == 1n+q : Nat}
  for ew: {J.skip_ws(pre ++ s) == J.skip_ws(s) : String}
  {J.loop(A.add(sw, A.len(s)), J.Run{pre ++ s, stk, m}) == J.loop(A.add(sw, q), J.dispatch(m, J.skip_ws(s), stk)) : J.St}

def adv.go(sw, pre, s, q, stk, m, e, ew):
  %Equal.sym(Nat, A.len(s), 1n+q, e) : {J.loop(A.add(sw, _), J.Run{pre ++ s, stk, m}) == J.loop(A.add(sw, q), J.dispatch(m, J.skip_ws(s), stk)) : J.St}
  %Equal.sym(Nat, A.add(sw, 1n+q), 1n+A.add(sw, q), A.add_succ(sw, q)) : {J.loop(_, J.Run{pre ++ s, stk, m}) == J.loop(A.add(sw, q), J.dispatch(m, J.skip_ws(s), stk)) : J.St}
  Equal.cong(String, J.St, x => J.loop(A.add(sw, q), J.dispatch(m, x, stk)), J.skip_ws(pre ++ s), J.skip_ws(s), ew)

law adv:
  for +slack: Nat
  for +pre: String
  for +s: String
  for +q: Nat
  for +stk: List<&2, J.Frame>
  for +m: J.Mode
  for e: {A.len(s) == 1n+q : Nat}
  for ew: {J.skip_ws(pre ++ s) == J.skip_ws(s) : String}
  {J.loop(A.add(slack, A.len(pre ++ s)), J.Run{pre ++ s, stk, m}) == J.loop(A.add(A.add(slack, A.len(pre)), q), J.dispatch(m, J.skip_ws(s), stk)) : J.St}

def adv(slack, pre, s, q, stk, m, e, ew):
  Equal.trans(J.St, J.loop(A.add(slack, A.len(pre ++ s)), J.Run{pre ++ s, stk, m}),
    J.loop(A.add(slack, A.add(A.len(pre), A.len(s))), J.Run{pre ++ s, stk, m}),
    J.loop(A.add(A.add(slack, A.len(pre)), q), J.dispatch(m, J.skip_ws(s), stk)),
    Equal.cong(Nat, J.St, f => J.loop(A.add(slack, f), J.Run{pre ++ s, stk, m}), A.len(pre ++ s), A.add(A.len(pre), A.len(s)), A.len_app(pre, s)),
    Equal.trans(J.St, J.loop(A.add(slack, A.add(A.len(pre), A.len(s))), J.Run{pre ++ s, stk, m}),
      J.loop(A.add(A.add(slack, A.len(pre)), A.len(s)), J.Run{pre ++ s, stk, m}),
      J.loop(A.add(A.add(slack, A.len(pre)), q), J.dispatch(m, J.skip_ws(s), stk)),
      PA.regroup(slack, A.len(pre), A.len(s), J.Run{pre ++ s, stk, m}),
      adv.go(A.add(slack, A.len(pre)), pre, s, q, stk, m, e, ew)))

law delim_arr:
  for +t: List<&2, J.Json>
  for +r: String
  for +p: Bool
  for +cs: List<&2, S.WsC>
  for +d: Nat
  Num.Delim(S.lay(J.JArr{t}, True{}, p, S.wstr(cs), d, r))

def delim_arr(t, r, p, cs, d):
  match t p:
    case Nil{} True{}:
      {==}
    case Nil{} False{}:
      {==}
    case Con{_, _} _:
      {==}

law delim_obj:
  for +t: List<&2, J.Field>
  for +r: String
  for +p: Bool
  for +cs: List<&2, S.WsC>
  for +d: Nat
  Num.Delim(S.lay(J.JObj{t}, True{}, p, S.wstr(cs), d, r))

def delim_obj(t, r, p, cs, d):
  match t p:
    case Nil{} True{}:
      {==}
    case Nil{} False{}:
      {==}
    case Con{J.Field{_, _}, _} _:
      {==}

# a text that follows a comma has no space before it
def NoPre(more: Bool, pre: String) -> Type:
  match more:
    case False{}:
      Unit
    case True{}:
      {pre == "" : String}

'''


def run_body():
    L = []
    a = L.append
    a("  match j:")
    for c, g in [("J.JNull{}", "g_null"), ("J.JBool{True{}}", "g_true"), ("J.JBool{False{}}", "g_false")]:
        a(f"    case {c}:\n      match more:\n        case False{{}}:\n          {g}(pre, wp, slack, p, cs, d, m, ctx, stk, r)\n        case True{{}}:\n          match ctx:")
    a("    case J.JNum{n}:\n      match more:\n        case False{}:\n          g_num(n, pre, wp, slack, p, cs, d, m, ctx, stk, r, dl)\n        case True{}:\n          match ctx:")
    a("    case J.JStr{s}:\n      match more:\n        case False{}:\n          g_str(s, pre, wp, slack, p, cs, d, m, ctx, stk, r)\n        case True{}:\n          match ctx:")

    def closing(jc, frame_pat, other_pat, call, gname, jv):
        rest = "".join(f"            case {mm}:\n              match ctx:\n" for mm in
                       ["J.MValue{}", "J.MValueOrClose{}", "J.MKeyOrClose{}", "J.MKey{}", "J.MColon{}"])
        return (f"        case True{{}}:\n"
                f"          match m:\n            case J.MCommaOrClose{{}}:\n              match stk:\n"
                f"                case {frame_pat}:\n"
                f"                  %Equal.sym(String, pre, \"\", np) : Goal(_, {jv}, True{{}}, p, cs, d, J.MCommaOrClose{{}}, {frame_pat}, r, slack)\n"
                f"                  {call}\n"
                f"                case {other_pat}:\n                  match ctx:\n"
                f"                case Nil{{}}:\n                  match ctx:\n" + rest.rstrip("\n"))

    a("    case J.JArr{Nil{}}:\n      match more:\n        case False{}:\n          g_arr_nil(pre, wp, slack, p, cs, d, m, ctx, stk, r)")
    a(closing("", "Con{J.FArr{acc}, up}", "Con{J.FObj{_, _}, _}", "g_arr_nil_t(acc, up, r, slack, p, cs, d)", "", "J.JArr{[]}"))
    KT = "S.lay(J.JArr{t}, True{}, p, S.wstr(cs), d, r)"
    a("    case J.JArr{Con{h, t}}:\n      match more:\n        case False{}:\n"
      f"          arr_f.1(h, t, stk, r, pre, wp, slack, m, ctx, p, cs, d,\n"
      f"            run(h, False{{}}, S.bw(p, S.wstr(cs), 1n+d), w => bw_ws(p, cs, 1n+d, w), Unit{{}}, p, cs, 1n+d, J.MValueOrClose{{}}, Con{{J.FArr{{[]}}, stk}}, {KT}, A.add(slack, A.len(pre)), Unit{{}}, delim_arr(t, r, p, cs, d)),\n"
      f"            w => run(J.JArr{{t}}, True{{}}, \"\", s => {{==}}, {{==}}, p, cs, d, J.MCommaOrClose{{}}, Con{{J.FArr{{[h]}}, stk}}, r, w, Unit{{}}, dl))")
    a(closing("", "Con{J.FArr{acc}, up}", "Con{J.FObj{_, _}, _}",
              f"arr_t.1(h, t, acc, up, r, slack, p, cs, d, run(h, False{{}}, S.bw(p, S.wstr(cs), 1n+d), w => bw_ws(p, cs, 1n+d, w), Unit{{}}, p, cs, 1n+d, J.MValue{{}}, Con{{J.FArr{{acc}}, up}}, {KT}, slack, Unit{{}}, delim_arr(t, r, p, cs, d)), w => run(J.JArr{{t}}, True{{}}, \"\", s => {{==}}, {{==}}, p, cs, d, J.MCommaOrClose{{}}, Con{{J.FArr{{Con{{h, acc}}}}, up}}, r, w, Unit{{}}, dl))",
              "", "J.JArr{Con{h, t}}"))
    a("    case J.JObj{Nil{}}:\n      match more:\n        case False{}:\n          g_obj_nil(pre, wp, slack, p, cs, d, m, ctx, stk, r)")
    a(closing("", "Con{J.FObj{acc, k0}, up}", "Con{J.FArr{_}, _}", "g_obj_nil_t(acc, k0, up, r, slack, p, cs, d)", "", "J.JObj{[]}"))
    KO_ = "S.lay(J.JObj{t}, True{}, p, S.wstr(cs), d, r)"
    a("    case J.JObj{Con{J.Field{k, v}, t}}:\n      match more:\n        case False{}:\n"
      f"          obj_f.1(k, v, t, stk, r, pre, wp, slack, m, ctx, p, cs, d, A.pre_esc(k, SCon{{'\"', {C}}}),\n"
      f"            s => run(v, False{{}}, S.sp(p), w => sp_ws(p, w), Unit{{}}, p, cs, 1n+d, J.MValue{{}}, Con{{J.FObj{{[], k}}, stk}}, {KO_}, s, Unit{{}}, delim_obj(t, r, p, cs, d)),\n"
      f"            w => run(J.JObj{{t}}, True{{}}, \"\", s => {{==}}, {{==}}, p, cs, d, J.MCommaOrClose{{}}, Con{{J.FObj{{[J.Field{{k, v}}], \"\"}}, stk}}, r, w, Unit{{}}, dl))")
    a(closing("", "Con{J.FObj{acc, k0}, up}", "Con{J.FArr{_}, _}",
              f"obj_t.1(k, v, t, acc, k0, up, r, slack, p, cs, d, A.pre_esc(k, SCon{{'\"', {C}}}), s => run(v, False{{}}, S.sp(p), w => sp_ws(p, w), Unit{{}}, p, cs, 1n+d, J.MValue{{}}, Con{{J.FObj{{acc, k}}, up}}, {KO_}, s, Unit{{}}, delim_obj(t, r, p, cs, d)), w => run(J.JObj{{t}}, True{{}}, \"\", s => {{==}}, {{==}}, p, cs, d, J.MCommaOrClose{{}}, Con{{J.FObj{{Con{{J.Field{{k, v}}, acc}}, \"\"}}, up}}, r, w, Unit{{}}, dl))",
              "", "J.JObj{Con{J.Field{k, v}, t}}"))
    return "\n".join(L)


TAIL = '''
# the main lemma: from any point where the text of j starts, maybe behind
# white space, the loop reads it and lands on result(...), with fuel to spare
law run:
  for +j: J.Json
  for +more: Bool
  for +pre: String
  for wp: Ws(pre)
  for np: NoPre(more, pre)
  for +p: Bool
  for +cs: List<&2, S.WsC>
  for +d: Nat
  for +m: J.Mode
  for +stk: List<&2, J.Frame>
  for +r: String
  for +slack: Nat
  for ctx: PA.Ctx(more, j, m, stk)
  for dl: Num.Delim(r)
  Goal(pre, j, more, p, cs, d, m, stk, r, slack)

def run(j, more, pre, wp, np, p, cs, d, m, stk, r, slack, ctx, dl):
RUN

# no laid-out value starts with a byte order mark
law bom:
  for +j: J.Json
  for +p: Bool
  for +u: String
  {J.skip_bom(S.lay(j, False{}, p, u, 0n, "")) == S.lay(j, False{}, p, u, 0n, "") : String}

def bom(j, p, u):
  match j:
BOM

law parse.go:
  for +j: J.Json
  for +p: Bool
  for +cs: List<&2, S.WsC>
  for g: Goal("", j, False{}, p, cs, 0n, J.MValue{}, [], "", 1n)
  {J.finish(J.lines(S.lay(j, False{}, p, S.wstr(cs), 0n, ""), 0, []), J.loop(1n+A.len(S.lay(j, False{}, p, S.wstr(cs), 0n, "")), J.Run{S.lay(j, False{}, p, S.wstr(cs), 0n, ""), [], J.MValue{}})) == Done{j} : PA.RJ()}

def parse.go(j, p, cs, g):
  (+w, e) = g
  +t : String = S.lay(j, False{}, p, S.wstr(cs), 0n, "")
  Equal.cong(J.St, PA.RJ(), x => J.finish(J.lines(t, 0, []), x),
    J.loop(1n+A.len(t), J.Run{t, [], J.MValue{}}), J.Fin{j},
    Equal.trans(J.St, J.loop(1n+A.len(t), J.Run{t, [], J.MValue{}}), J.loop(A.add(w, 0n), J.Fin{j}), J.Fin{j},
      e,
      PA.loop_fin(A.add(w, 0n), j)))

# the parser reads back what the pretty printer writes, for any indent unit
# made of spaces and tabs
law parse_pretty:
  for +j: J.Json
  for +cs: List<&2, S.WsC>
  {J.parse(J.pretty(j, S.wstr(cs))) == Done{j} : PA.RJ()}

def parse_pretty(j, cs):
  +t : String = S.lay(j, False{}, True{}, S.wstr(cs), 0n, "")
  %Equal.sym(String, J.pretty(j, S.wstr(cs)), t, P.pretty(j, S.wstr(cs))) : {J.parse(_) == Done{j} : PA.RJ()}
  %Equal.sym(String, J.skip_bom(t), t, bom(j, True{}, S.wstr(cs))) : {J.finish(J.lines(t, 0, []), J.loop(1n+A.len(t), J.Run{_, [], J.MValue{}})) == Done{j} : PA.RJ()}
  parse.go(j, True{}, cs, run(j, False{}, "", s => {==}, Unit{}, True{}, cs, 0n, J.MValue{}, [], "", 1n, Unit{}, Unit{}))

# what bjson writes
law pretty_round_trip:
  for +j: J.Json
  {J.parse(J.pretty(j, "  ")) == Done{j} : PA.RJ()}

def pretty_round_trip(j):
  parse_pretty(j, [S.WSpace{}, S.WSpace{}])
'''

BOMC = ["J.JNull{}", "J.JBool{True{}}", "J.JBool{False{}}", "J.JStr{_}", "J.JArr{Nil{}}", "J.JArr{Con{_, _}}",
        "J.JObj{Nil{}}", "J.JObj{Con{J.Field{_, _}, _}}", "J.JNum{J.Number{True{}, _, _, _}}",
        "J.JNum{J.Number{False{}, J.IZero{}, _, _}}"] + [f"J.JNum{{J.Number{{False{{}}, J.INon{{J.L{i}{{}}, _}}, _, _}}}}" for i in range(1, 10)]
bom = "\n".join(f"    case {c}:\n      {{==}}" for c in BOMC)
OUT.write_text(HEAD + "\n".join(out) + TAIL.replace("RUN", run_body()).replace("BOM", bom))
print(f"{len(out)} lemmas -> {OUT.relative_to(ROOT)}")
