"""Append the main induction and the theorem to proof/fast_run.bend.

proof/fast_run.bend's lemmas above `def Ctx(` are written by hand or by
earlier steps; this writes everything from `def Ctx(` on, which is long and
regular: one helper chain per container case, threading the existential
results of the recursive calls.

  python3 scripts/gen_fast_proof.py
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "proof/fast_run.bend"

AFT = ["F.VAfter{}", "F.NZero{}", "F.NInt{}", "F.NFrac{}", "F.NExp{}"]
ALLM = ["F.VStart{}", "F.VTop{}", "F.VFirst{}", "F.VItem{}", "F.VObjFirst{}", "F.VKey{}", "F.VColon{}",
        "F.VObjVal{}", "F.VAfter{}", "F.SStr{}", "F.SEsc{}", "F.SU4{}", "F.SU3{}", "F.SU2{}", "F.SU1{}",
        "F.SHi{}", "F.SHiU{}", "F.NMin{}", "F.NZero{}", "F.NInt{}", "F.NDot{}", "F.NFrac{}", "F.NE{}",
        "F.NESign{}", "F.NExp{}", "F.T1{}", "F.T2{}", "F.T3{}", "F.F1{}", "F.F2{}", "F.F3{}", "F.F4{}",
        "F.U1{}", "F.U2{}", "F.U3{}", "F.BCtrl{}", "F.BUni{}", "F.BLone{}", "F.BEsc{}"]


def A(n, v="at"):
    return v if n == 0 else f"({A(n - 1, v)} + 1 : U32)"


def G(inp, mode, out, at, ea="ea", key="key", stk="stk"):
    return f"F.gc({inp}, {mode}, {inp}, {stk}, {out}, 0, 0, {key}, {at}, {ea})"


def tr(ts, ps, ind=4):
    if len(ps) == 1:
        return ps[0]
    pad = " " * ind
    return (f"Equal.trans(F.Out,\n{pad}  {ts[0]},\n{pad}  {ts[1]},\n{pad}  {ts[-1]},\n{pad}  {ps[0]},\n{pad}  "
            + tr(ts[1:], ps[1:], ind + 2) + ")")


HEAD = '''def Ctx(+more: Bool, +j: J.Json, +m: F.Mode, +stk: List<&2, F.Box>) -> Type:
  match more:
    case False{}:
      ValM(m)
    case True{}:
      match j:
        case J.JArr{_}:
          match stk:
            case Con{F.BArr{}, _}:
              Aft(m)
            case _:
              Empty
        case J.JObj{_}:
          match stk:
            case Con{F.BObj{}, _}:
              Aft(m)
            case _:
              Empty
        case _:
          Empty

def popd(+more: Bool, +stk: List<&2, F.Box>) -> List<&2, F.Box>:
  match more:
    case False{}:
      stk
    case True{}:
      match stk:
        case Con{_, up}:
          up
        case Nil{}:
          []

def Goal(+j: J.Json, +more: Bool, +m: F.Mode, +stk: List<&2, F.Box>, +r: String, +out: String, +key: Bool, +at: U32, +ea: U32) -> Type:
  V(S.text(j, more, r), m, stk, out, key, at, ea, r, popd(more, stk), push(S.text(j, more, ""), out))

# a value, then more text y: its output then y's is its text before y
law out_seq:
  for +h: J.Json
  for +y: String
  for +o: String
  {push(y, push(S.text(h, False{}, ""), o)) == push(S.text(h, False{}, y), o) : String}

def out_seq(h, y, o):
  Equal.trans(String, push(y, push(S.text(h, False{}, ""), o)), push(S.text(h, False{}, "") ++ y, o), push(S.text(h, False{}, y), o),
    Equal.sym(String, push(S.text(h, False{}, "") ++ y, o), push(y, push(S.text(h, False{}, ""), o)), T.push_app(S.text(h, False{}, ""), y, o)),
    Equal.cong(String, String, z => push(z, o), S.text(h, False{}, "") ++ y, S.text(h, False{}, y),
      Equal.sym(String, S.text(h, False{}, y), S.text(h, False{}, "") ++ y, T.text(h, False{}, "", y))))

# a key's output, then the value's, is the key's text before the value
law out_key:
  for +k: String
  for +tv: String
  for +o: String
  {push(tv, SCon{':', push(S.esc(k, "\\""), o)}) == push(S.esc(k, SCon{'"', SCon{':', tv}}), o) : String}

def out_key(k, tv, o):
  Equal.trans(String, push(tv, SCon{':', push(S.esc(k, "\\""), o)}), push(S.esc(k, "\\"") ++ SCon{':', tv}, o), push(S.esc(k, SCon{'"', SCon{':', tv}}), o),
    Equal.sym(String, push(S.esc(k, "\\"") ++ SCon{':', tv}, o), push(SCon{':', tv}, push(S.esc(k, "\\""), o)), T.push_app(S.esc(k, "\\""), SCon{':', tv}, o)),
    Equal.cong(String, String, z => push(z, o), S.esc(k, "\\"") ++ SCon{':', tv}, S.esc(k, SCon{'"', SCon{':', tv}}),
      Equal.sym(String, S.esc(k, SCon{'"', SCon{':', tv}}), S.esc(k, "\\"") ++ SCon{':', tv}, T.esc(k, "\\"", SCon{':', tv}))))
'''


def str_value():
    x = "S.esc(s, SCon{'\"', r})"
    g0 = G(f"SCon{{'\"', {x}}}", "m", "out", "at")
    g1 = G(x, "F.SStr{}", "SCon{'\"', out}", A(1), key="False{}")
    return f'''
# a string value
law str_v.k:
  for +s: String
  for +m: F.Mode
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for s1: {{{g0} == {g1} : F.Out}}
  for g: FS.SB(s, r, stk, SCon{{'"', out}}, False{{}}, (at + 1 : U32), ea)
  Goal(J.JStr{{s}}, False{{}}, m, stk, r, out, key, at, ea)

def str_v.k(s, m, r, stk, out, key, at, ea, s1, g):
  (+p, e2) = g
  (Q{{F.VAfter{{}}, False{{}}, FS.p_at(p), FS.p_ea(p)}}, (Unit{{}}, Equal.trans(F.Out, {g0}, {g1},
    F.gc(r, F.VAfter{{}}, r, stk, push(S.esc(s, "\\""), SCon{{'"', out}}), 0, 0, False{{}}, FS.p_at(p), FS.p_ea(p)), s1, e2)))
'''


def seq(tag, kind, more):
    """The helpers for a container with items: returns (text, the call from run)."""
    box = "F.BArr{}" if kind == "arr" else "F.BObj{}"
    stk_in = f"Con{{{box}, up}}" if more else "stk"
    stk_c = f"Con{{{box}, up}}" if more else f"Con{{{box}, stk}}"
    res = "up" if more else "stk"
    stkp = "  for +up: List<&2, F.Box>\n" if more else "  for +stk: List<&2, F.Box>\n"
    stka = "up" if more else "stk"
    moreb = "True{}" if more else "False{}"
    opch = "','" if more else ("'['" if kind == "arr" else "'{'")
    jj = "J.JArr{Con{h, t}}" if kind == "arr" else "J.JObj{Con{J.Field{k, v}, t}}"
    jt = "J.JArr{t}" if kind == "arr" else "J.JObj{t}"
    R = f"S.text({jt}, True{{}}, r)"
    Y = f"S.text({jt}, True{{}}, \"\")"
    hp = ("  for +h: J.Json\n  for +t: List<&2, J.Json>\n" if kind == "arr"
          else "  for +k: String\n  for +v: J.Json\n  for +t: List<&2, J.Field>\n")
    ha = "h, t" if kind == "arr" else "k, v, t"
    common = hp + stkp + "  for +m: F.Mode\n" + '''  for +r: String
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
'''
    cargs = f"{ha}, {stka}, m, r, out, key, at, ea"
    goal = f"Goal({jj}, {moreb}, m, {stk_in}, r, out, key, at, ea)"
    target = f"push(S.text({jj}, {moreb}, \"\"), out)"
    O1 = f"SCon{{{opch}, out}}"
    txt = ""
    if kind == "arr":
        XV = f"S.text(h, False{{}}, {R})"
        vmode = "F.VItem{}" if more else "F.VFirst{}"
        t0 = G(f"SCon{{{opch}, {XV}}}", "m", "out", "at", stk=stk_in)
        vstart = G(XV, vmode, O1, A(1), stk=stk_c)
        step = (f"a_comma(m, ctx, {XV}, up, out, key, at, ea)" if more
                else f"v_arr(m, ctx, {XV}, stk, out, key, at, ea)")
        OV2 = f"push(S.text(h, False{{}}, \"\"), {O1})"
        fast_out = f"push({Y}, {OV2})"
        ih2t = f"@m2: F.Mode -> @k2: Bool -> @a2: U32 -> @e2: U32 -> @aft: Aft(m2) -> Goal({jt}, True{{}}, m2, {stk_c}, r, {OV2}, k2, a2, e2)"
        pre_t = f"{{{t0} == {vstart} : F.Out}}"
        aq = f"after({R}, {stk_c}, {OV2}, Q{{m1, k1, a1, e1}})"
        txt += f'''
law {tag}.k3:
{common}  for pre: {pre_t}
  for +m1: F.Mode
  for +k1: Bool
  for +a1: U32
  for +e1: U32
  for eq1: {{{vstart} == {aq} : F.Out}}
  for g2: Goal({jt}, True{{}}, m1, {stk_c}, r, {OV2}, k1, a1, e1)
  {goal}

def {tag}.k3({cargs}, pre, m1, k1, a1, e1, eq1, g2):
  (+q2, pr2) = g2
  (aft2, eq2) = pr2
  (q2, (aft2, {tr([t0, vstart, aq, f"after(r, {res}, {fast_out}, q2)", f"after(r, {res}, {target}, q2)"],
                  ["pre", "eq1", "eq2", f"Equal.cong(String, F.Out, z => after(r, {res}, z, q2), {fast_out}, {target}, out_seq(h, {Y}, {O1}))"], 6)}))

law {tag}.k2:
{common}  for pre: {pre_t}
  for +q1: Q
  for aft1: AftQ(q1)
  for eq1: {{{vstart} == after({R}, {stk_c}, {OV2}, q1) : F.Out}}
  for ih2: {ih2t}
  {goal}

def {tag}.k2({cargs}, pre, q1, aft1, eq1, ih2):
  match q1:
    case Q{{m1, k1, a1, e1}}:
      {tag}.k3({cargs}, pre, m1, k1, a1, e1, eq1, ih2(m1, k1, a1, e1, aft1))

law {tag}.k1:
{common}  for pre: {pre_t}
  for g1: Goal(h, False{{}}, {vmode}, {stk_c}, {R}, {O1}, key, {A(1)}, ea)
  for ih2: {ih2t}
  {goal}

def {tag}.k1({cargs}, pre, g1, ih2):
  (+q1, pr1) = g1
  (aft1, eq1) = pr1
  {tag}.k2({cargs}, pre, q1, aft1, eq1, ih2)
'''
        call = (f"{tag}.k1({cargs}, {step},\n"
                f"            run(h, False{{}}, {vmode}, {stk_c}, {R}, {O1}, key, {A(1)}, ea, Unit{{}}),\n"
                f"            +m2 => +k2 => +a2 => +e2 => aft => run({jt}, True{{}}, m2, {stk_c}, r, {OV2}, k2, a2, e2, aft))")
        return txt, call
    # objects: opener (or comma), the key's quote, its body (FS.sb), ':', the value, the rest
    XV = f"S.text(v, False{{}}, {R})"
    K1 = f"SCon{{':', {XV}}}"
    E = f"S.esc(k, SCon{{'\"', {K1}}})"
    mode1 = "F.VKey{}" if more else "F.VObjFirst{}"
    O2 = f"SCon{{'\"', {O1}}}"
    PK = f"push(S.esc(k, \"\\\"\"), {O2})"
    OVv = f"SCon{{':', {PK}}}"
    OV2 = f"push(S.text(v, False{{}}, \"\"), {OVv})"
    t0 = G(f"SCon{{{opch}, SCon{{'\"', {E}}}}}", "m", "out", "at", stk=stk_in)
    t1 = G(f"SCon{{'\"', {E}}}", mode1, O1, A(1), stk=stk_c)
    t2 = G(E, "F.SStr{}", O2, A(2), key="True{}", stk=stk_c)
    step = (f"o_comma(m, ctx, SCon{{'\"', {E}}}, up, out, key, at, ea)" if more
            else f"v_obj(m, ctx, SCon{{'\"', {E}}}, stk, out, key, at, ea)")
    pre0 = tr([t0, t1, t2], [step, "{==}"], 6)
    pre_t = f"{{{t0} == {t2} : F.Out}}"
    tk = G(K1, "F.VColon{}", PK, "pa", ea="pe", key="True{}", stk=stk_c)
    tv = G(XV, "F.VObjVal{}", OVv, "(pa + 1 : U32)", ea="pe", key="True{}", stk=stk_c)
    pre_v = f"{{{t0} == {tv} : F.Out}}"
    ih2t = f"@m2: F.Mode -> @k2: Bool -> @a2: U32 -> @e2: U32 -> @aft: Aft(m2) -> Goal({jt}, True{{}}, m2, {stk_c}, r, {OV2}, k2, a2, e2)"
    ih1t = f"@pa2: U32 -> @pe2: U32 -> Goal(v, False{{}}, F.VObjVal{{}}, {stk_c}, {R}, SCon{{':', {PK}}}, True{{}}, (pa2 + 1 : U32), pe2)"
    TV = f"S.text(v, False{{}}, {Y})"
    fast_out = f"push({Y}, {OV2})"
    mid = f"push({TV}, SCon{{':', {PK}}})"
    aq = f"after({R}, {stk_c}, {OV2}, Q{{m1, k1, a1, e1}})"
    txt += f'''
law {tag}.k5:
{common}  for +pa: U32
  for +pe: U32
  for pre: {pre_v}
  for +m1: F.Mode
  for +k1: Bool
  for +a1: U32
  for +e1: U32
  for eq1: {{{tv} == {aq} : F.Out}}
  for g2: Goal({jt}, True{{}}, m1, {stk_c}, r, {OV2}, k1, a1, e1)
  {goal}

def {tag}.k5({cargs}, pa, pe, pre, m1, k1, a1, e1, eq1, g2):
  (+q2, pr2) = g2
  (aft2, eq2) = pr2
  (q2, (aft2, {tr([t0, tv, aq, f"after(r, {res}, {fast_out}, q2)", f"after(r, {res}, {mid}, q2)", f"after(r, {res}, {target}, q2)"],
                  ["pre", "eq1", "eq2",
                   f"Equal.cong(String, F.Out, z => after(r, {res}, z, q2), {fast_out}, {mid}, out_seq(v, {Y}, {OVv}))",
                   f"Equal.cong(String, F.Out, z => after(r, {res}, z, q2), {mid}, {target}, out_key(k, {TV}, {O2}))"], 6)}))

law {tag}.k4:
{common}  for +pa: U32
  for +pe: U32
  for pre: {pre_v}
  for +q1: Q
  for aft1: AftQ(q1)
  for eq1: {{{tv} == after({R}, {stk_c}, {OV2}, q1) : F.Out}}
  for ih2: {ih2t}
  {goal}

def {tag}.k4({cargs}, pa, pe, pre, q1, aft1, eq1, ih2):
  match q1:
    case Q{{m1, k1, a1, e1}}:
      {tag}.k5({cargs}, pa, pe, pre, m1, k1, a1, e1, eq1, ih2(m1, k1, a1, e1, aft1))

law {tag}.k3:
{common}  for +pa: U32
  for +pe: U32
  for pre: {pre_v}
  for g1: Goal(v, False{{}}, F.VObjVal{{}}, {stk_c}, {R}, {OVv}, True{{}}, (pa + 1 : U32), pe)
  for ih2: {ih2t}
  {goal}

def {tag}.k3({cargs}, pa, pe, pre, g1, ih2):
  (+q1, pr1) = g1
  (aft1, eq1) = pr1
  {tag}.k4({cargs}, pa, pe, pre, q1, aft1, eq1, ih2)

law {tag}.k2:
{common}  for pre: {pre_t}
  for +pa: U32
  for +pe: U32
  for eqk: {{{t2} == {tk} : F.Out}}
  for ih1: {ih1t}
  for ih2: {ih2t}
  {goal}

def {tag}.k2({cargs}, pre, pa, pe, eqk, ih1, ih2):
  {tag}.k3({cargs}, pa, pe, {tr([t0, t2, tk, tv], ["pre", "eqk", "{==}"], 4)},
    ih1(pa, pe), ih2)

law {tag}.k1:
{common}  for pre: {pre_t}
  for gk: FS.SB(k, {K1}, {stk_c}, {O2}, True{{}}, {A(2)}, ea)
  for ih1: {ih1t}
  for ih2: {ih2t}
  {goal}

def {tag}.k1({cargs}, pre, gk, ih1, ih2):
  (+p, eqk) = gk
  {tag}.k2({cargs}, pre, FS.p_at(p), FS.p_ea(p), eqk, ih1, ih2)
'''
    call = (f"{tag}.k1({cargs}, {pre0},\n"
            f"            FS.sb(k, {K1}, {stk_c}, {O2}, True{{}}, {A(2)}, ea),\n"
            f"            +pa2 => +pe2 => run(v, False{{}}, F.VObjVal{{}}, {stk_c}, {R}, SCon{{':', {PK}}}, True{{}}, (pa2 + 1 : U32), pe2, Unit{{}}),\n"
            f"            +m2 => +k2 => +a2 => +e2 => aft => run({jt}, True{{}}, m2, {stk_c}, r, {OV2}, k2, a2, e2, aft))")
    return txt, call


def main():
    out = HEAD + str_value()
    calls = {}
    for tag, kind, more in [("arr.f", "arr", False), ("arr.t", "arr", True), ("obj.f", "obj", False), ("obj.t", "obj", True)]:
        t, c = seq(tag, kind, more)
        out += t
        calls[tag] = c
    a1, a2, a4, a5 = A(1), A(2), A(4), A(5)
    out += f'''
# the main lemma: from where the text of j may start, the loop reads it
# and lands, with the same text pushed, where what follows may come
law run:
  for +j: J.Json
  for +more: Bool
  for +m: F.Mode
  for +stk: List<&2, F.Box>
  for +r: String
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for ctx: Ctx(more, j, m, stk)
  Goal(j, more, m, stk, r, out, key, at, ea)

def run(j, more, m, stk, r, out, key, at, ea, ctx):
  match j:
    case J.JNull{{}}:
      match more:
        case False{{}}:
          (Q{{F.VAfter{{}}, key, {a4}, ea}}, (Unit{{}}, v_null(m, ctx, r, stk, out, key, at, ea)))
        case True{{}}:
          match ctx:
    case J.JBool{{True{{}}}}:
      match more:
        case False{{}}:
          (Q{{F.VAfter{{}}, key, {a4}, ea}}, (Unit{{}}, v_true(m, ctx, r, stk, out, key, at, ea)))
        case True{{}}:
          match ctx:
    case J.JBool{{False{{}}}}:
      match more:
        case False{{}}:
          (Q{{F.VAfter{{}}, key, {a5}, ea}}, (Unit{{}}, v_false(m, ctx, r, stk, out, key, at, ea)))
        case True{{}}:
          match ctx:
    case J.JNum{{n}}:
      match more:
        case False{{}}:
          num(n, m, ctx, r, stk, out, key, at, ea)
        case True{{}}:
          match ctx:
    case J.JStr{{s}}:
      match more:
        case False{{}}:
          str_v.k(s, m, r, stk, out, key, at, ea, v_quote(m, ctx, S.esc(s, SCon{{'"', r}}), stk, out, key, at, ea),
            FS.sb(s, r, stk, SCon{{'"', out}}, False{{}}, {a1}, ea))
        case True{{}}:
          match ctx:
    case J.JArr{{Nil{{}}}}:
      match more:
        case False{{}}:
          (Q{{F.VAfter{{}}, key, {a2}, ea}}, (Unit{{}}, v_arr0(m, ctx, r, stk, out, key, at, ea)))
        case True{{}}:
          match stk:
            case Con{{F.BArr{{}}, up}}:
              (Q{{F.VAfter{{}}, key, {a1}, ea}}, (Unit{{}}, a_close(m, ctx, r, up, out, key, at, ea)))
            case Con{{F.BObj{{}}, _}}:
              match ctx:
            case Nil{{}}:
              match ctx:
    case J.JArr{{Con{{h, t}}}}:
      match more:
        case False{{}}:
          {calls["arr.f"]}
        case True{{}}:
          match stk:
            case Con{{F.BArr{{}}, up}}:
              {calls["arr.t"]}
            case Con{{F.BObj{{}}, _}}:
              match ctx:
            case Nil{{}}:
              match ctx:
    case J.JObj{{Nil{{}}}}:
      match more:
        case False{{}}:
          (Q{{F.VAfter{{}}, key, {a2}, ea}}, (Unit{{}}, v_obj0(m, ctx, r, stk, out, key, at, ea)))
        case True{{}}:
          match stk:
            case Con{{F.BObj{{}}, up}}:
              (Q{{F.VAfter{{}}, key, {a1}, ea}}, (Unit{{}}, o_close(m, ctx, r, up, out, key, at, ea)))
            case Con{{F.BArr{{}}, _}}:
              match ctx:
            case Nil{{}}:
              match ctx:
    case J.JObj{{Con{{J.Field{{k, v}}, t}}}}:
      match more:
        case False{{}}:
          {calls["obj.f"]}
        case True{{}}:
          match stk:
            case Con{{F.BObj{{}}, up}}:
              {calls["obj.t"]}
            case Con{{F.BArr{{}}, _}}:
              match ctx:
            case Nil{{}}:
              match ctx:
'''
    fin_cases = "\n".join(f"    case {m}:\n      {{==}}" if m in AFT else f"    case {m}:\n      match aft:" for m in ALLM)
    out += f'''
# at the end of the input, the loop after a value answers its output
law finish.m:
  for +m: F.Mode
  for +k: Bool
  for +a: U32
  for +e: U32
  for +out: String
  for aft: Aft(m)
  {{after("", [], out, Q{{m, k, a, e}}) == F.Ok{{String.reverse(out)}} : F.Out}}

def finish.m(m, k, a, e, out, aft):
  match m:
{fin_cases}

law finish:
  for +out: String
  for +q: Q
  for aft: AftQ(q)
  {{after("", [], out, q) == F.Ok{{String.reverse(out)}} : F.Out}}

def finish(out, q, aft):
  match q:
    case Q{{m, k, a, e}}:
      finish.m(m, k, a, e, out, aft)

law rev_rev:
  for +a: String
  {{String.reverse(push(a, "")) == a : String}}

def rev_rev(a):
  Equal.trans(String, String.reverse(push(a, "")), a ++ "", a, P.rr(a, "", ""), T.app_nil(a))

law round_trip.go:
  for +t: String
  for g: V(t, F.VStart{{}}, [], "", False{{}}, 0, 0, "", [], push(t, ""))
  {{F.gc(t, F.VStart{{}}, t, [], "", 0, 0, False{{}}, 0, 0) == F.Ok{{t}} : F.Out}}

def round_trip.go(t, g):
  (+q, pr) = g
  (aft, eq) = pr
  Equal.trans(F.Out, F.gc(t, F.VStart{{}}, t, [], "", 0, 0, False{{}}, 0, 0), after("", [], push(t, ""), q), F.Ok{{t}},
    eq,
    Equal.trans(F.Out, after("", [], push(t, ""), q), F.Ok{{String.reverse(push(t, ""))}}, F.Ok{{t}},
      finish(push(t, ""), q, aft),
      Equal.cong(String, F.Out, z => F.Ok{{z}}, String.reverse(push(t, "")), t, rev_rev(t))))

# the fast loop reads what the printer writes back to the same text
law fast_round_trip:
  for +j: J.Json
  {{F.reformat(J.encode(j)) == F.Ok{{J.encode(j)}} : F.Out}}

def fast_round_trip(j):
  +t : String = S.text(j, False{{}}, "")
  %Equal.sym(String, J.encode(j), t, P.print(j)) : {{F.reformat(_) == F.Ok{{_}} : F.Out}}
  round_trip.go(t, run(j, False{{}}, F.VStart{{}}, [], "", "", False{{}}, 0, 0, Unit{{}}))
'''
    text = OUT.read_text()
    text = text[:text.index("\ndef Ctx(") + 1] if "\ndef Ctx(" in text else text
    OUT.write_text(text + out)
    print("proof/fast_run.bend: main lemma written")


main()
