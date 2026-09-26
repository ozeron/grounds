"""Generate fast.bend: the one-pass reformat loop.

The loop has a case per (mode, char) transition, so it is generated.
The helpers above it live in scripts/fast_head.bend.in.

Every failing case returns J.parse's reason and offset, so the two can be
compared on every input (suite.bend, scripts/integration.py).
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VALUE = ["VTop", "VFirst", "VItem", "VObjVal"]
ACC = ["NZero", "NInt", "NFrac", "NExp"]
WS = ["' '", "'\\t'", "'\\n'", "'\\r'"]
DIGITS = [str(i) for i in range(10)]
rows = []
PRETTY = False  # set per loop below: the compact loop has no pretty code


def row(mode, s, stack, body):
    rows.append(f"    case SCon{{_, f}} {mode} {s} {stack}:\n      {body}")


def nlx(out, d="d"):
    return f"nl({d}, {out})" if PRETTY else out


def go(mode, t="t", stack="stk", out="out", hi="0", code="0", key="key", ea="ea", d="d"):
    name = "gp" if PRETTY else "gc"
    extra = f", {d}" if PRETTY else ""
    return f"{name}(f, {mode}, {t}, {stack}, {out}, {hi}, {code}, {key}, (at + 1 : U32), {ea}{extra})"


def err(reason, at="at"):
    return f"Err{{{reason}, {at}}}"


def ch(c):
    return f"SCon{{'{c}', t}}"


BS = "\\\\"  # a backslash, as it reads inside a Bend char literal


def build():
    global rows
    rows = []
    # Strings: the hot path. Plain chars are the last case
    row("SStr{}", ch('"'), "stk", go("close_mode(key)", out="SCon{'\"', out}"))
    row("SStr{}", ch(BS), "stk", go("SEsc{}", ea="at"))
    row("SStr{}", "SCon{+c, t}", "stk",
        "+cc = ctrl(c)\n      "
        + go("Bool.pick(Mode, cc, BCtrl{}, SStr{})", out="SCon{c, out}", ea="Bool.pick(U32, cc, at, ea)"))
    ESC = [('"', "SCon{'\"', SCon{'" + BS + "', out}}"), (BS, "SCon{'" + BS + "', SCon{'" + BS + "', out}}"),
           ("/", "SCon{'/', out}")] + [(c, f"SCon{{'{c}', SCon{{'{BS}', out}}}}") for c in "bfnrt"]
    for c, out in ESC:
        row("SEsc{}", ch(c), "stk", go("SStr{}", out=out))
    row("SEsc{}", ch("u"), "stk", go("SU4{}", hi="hi"))
    row("SEsc{}", "_", "_", err("J.InvalidEscape{}", "ea"))
    # \u digits: the code builds up; a non-hex char is BUni, reported at the backslash
    for frm, to in [("SU4", "SU3"), ("SU3", "SU2"), ("SU2", "SU1")]:
        row(frm + "{}", "SCon{+c, t}", "stk",
            go(f"hex_mode(hex_digit(c), {to}{{}})", hi="hi", code="hex_add(hex_digit(c), code)"))
    row("SU1{}", "SCon{+c, t}", "stk",
        go("u_mode(code_of(c, code), hi)", out="u_out(code_of(c, code), hi, out)", hi="u_hi(code_of(c, code), hi)"))
    # a high surrogate waits for \u and its low half
    row("SHi{}", ch(BS), "stk", go("SHiU{}", hi="hi", ea="at"))
    row("SHi{}", "SCon{+c, _}", "_", f"Bool.pick(Out, ctrl(c), {err('J.ControlChar{}')}, {err('J.LoneSurrogate{}')})")
    row("SHiU{}", ch("u"), "stk", go("SU4{}", hi="hi"))
    for c, _ in ESC:
        row("SHiU{}", ch(c), "_", err("J.LoneSurrogate{}", "ea"))
    row("SHiU{}", "_", "_", err("J.InvalidEscape{}", "ea"))


    # Numbers, a char at a time
    def num(frm, c, to):
        row(frm + "{}", ch(c), "stk", go(to + "{}", out=f"SCon{{'{c}', out}}"))


    for st in ["NInt", "NFrac", "NExp"]:
        for d in DIGITS:
            num(st, d, st)
    num("NMin", "0", "NZero")
    for d in DIGITS[1:]:
        num("NMin", d, "NInt")
    for st in ["NZero", "NInt"]:
        num(st, ".", "NDot")
        num(st, "e", "NE")
        num(st, "E", "NE")
    num("NFrac", "e", "NE")
    num("NFrac", "E", "NE")
    for d in DIGITS:
        num("NDot", d, "NFrac")
    num("NE", "+", "NESign")
    num("NE", "-", "NESign")
    for d in DIGITS:
        num("NE", d, "NExp")
        num("NESign", d, "NExp")
    for st in ["NMin", "NDot", "NE", "NESign"]:
        row(st + "{}", "_", "_", err("J.InvalidNumber{}"))

    # After a value, or where a number ends: white space, a comma or a closer.
    # At the top only white space may follow; inside, a wrong char is itself
    for m in ["VAfter"] + ACC:
        for w in WS:
            row(m + "{}", f"SCon{{{w}, t}}", "stk", go("VAfter{}"))
        row(m + "{}", ch(","), "Con{BArr{}, up}", go("VItem{}", stack="Con{BArr{}, up}", out=nlx("SCon{',', out}")))
        row(m + "{}", ch(","), "Con{BObj{}, up}", go("VKey{}", stack="Con{BObj{}, up}", out=nlx("SCon{',', out}")))
        row(m + "{}", ch("]"), "Con{BArr{}, up}", go("VAfter{}", stack="up", out="SCon{']', " + nlx("out", "dec(d)") + "}", d="dec(d)"))
        row(m + "{}", ch("}"), "Con{BObj{}, up}", go("VAfter{}", stack="up", out="SCon{'}', " + nlx("out", "dec(d)") + "}", d="dec(d)"))
        row(m + "{}", "_", "Nil{}", err("J.TrailingInput{}"))
        row(m + "{}", "SCon{c, _}", "_", err("J.UnexpectedChar{c}"))

    # Literals, a char at a time: the first char picks the word
    for word, modes in [("true", ["T1", "T2", "T3"]), ("false", ["F1", "F2", "F3", "F4"]), ("null", ["U1", "U2", "U3"])]:
        for i, m in enumerate(modes):
            to = modes[i + 1] if i + 1 < len(modes) else "VAfter"
            c = word[i + 1]
            row(m + "{}", ch(c), "stk", go(to + "{}", out=f"SCon{{'{c}', out}}"))
            row(m + "{}", "SCon{c, _}", "_", err("J.UnexpectedChar{c}"))


    # Where a value may start. VStart is VTop at the very first char, where a
    # byte order mark may be skipped (it still counts in the offset)
    def value_rows(m, after_ws):
        o = nlx("out") if m == "VFirst" else "out"
        for w in WS:
            row(m + "{}", f"SCon{{{w}, t}}", "stk", go(after_ws + "{}"))
        row(m + "{}", ch("["), "stk", go("VFirst{}", stack="Con{BArr{}, stk}", out=f"SCon{{'[', {o}}}", d="1n+d"))
        row(m + "{}", ch("{"), "stk", go("VObjFirst{}", stack="Con{BObj{}, stk}", out=f"SCon{{'{{', {o}}}", d="1n+d"))
        row(m + "{}", ch('"'), "stk", go("SStr{}", out=f"SCon{{'\"', {o}}}", key="False{}"))
        row(m + "{}", ch("-"), "stk", go("NMin{}", out=f"SCon{{'-', {o}}}"))
        row(m + "{}", ch("0"), "stk", go("NZero{}", out=f"SCon{{'0', {o}}}"))
        for dg in DIGITS[1:]:
            row(m + "{}", ch(dg), "stk", go("NInt{}", out=f"SCon{{'{dg}', {o}}}"))
        for c, to in [("t", "T1"), ("f", "F1"), ("n", "U1")]:
            row(m + "{}", ch(c), "stk", go(to + "{}", out=f"SCon{{'{c}', {o}}}"))
        if m == "VFirst":
            row("VFirst{}", ch("]"), "Con{_, up}", go("VAfter{}", stack="up", out="SCon{']', out}", d="dec(d)"))
        if m == "VStart":
            row("VStart{}", "SCon{'\\u{FEFF}', t}", "stk", go("VTop{}"))
        row(m + "{}", "SCon{c, _}", "_", err("J.UnexpectedChar{c}"))


    for m in VALUE:
        value_rows(m, m)
    value_rows("VStart", "VTop")

    # Object keys and colons
    for m in ["VObjFirst", "VKey", "VColon"]:
        for w in WS:
            row(m + "{}", f"SCon{{{w}, t}}", "stk", go(m + "{}"))
    row("VObjFirst{}", ch('"'), "stk", go("SStr{}", out="SCon{'\"', " + nlx("out") + "}", key="True{}"))
    row("VKey{}", ch('"'), "stk", go("SStr{}", out="SCon{'\"', out}", key="True{}"))
    row("VObjFirst{}", ch("}"), "Con{_, up}", go("VAfter{}", stack="up", out="SCon{'}', out}", d="dec(d)"))
    row("VColon{}", ch(":"), "stk", go("VObjVal{}", out="SCon{' ', SCon{':', out}}" if PRETTY else "SCon{':', out}"))
    for m in ["VObjFirst", "VKey", "VColon"]:
        row(m + "{}", "SCon{c, _}", "_", err("J.UnexpectedChar{c}"))


    return rows


def loop(name, pretty):
    global PRETTY
    PRETTY = pretty
    rs = build()
    extra = ", +d: Nat" if pretty else ""
    fin = "finish(m, stk, out, at)"
    return f"""
def {name}(fuel: String, mode: Mode, s: String, stack: List<&2, Box>, out: String, +hi: U32, +code: U32, +key: Bool, +at: U32, +ea: U32{extra}) -> Out:
  match fuel mode s stack:
    case _ BCtrl{{}} _ _:
      Err{{J.ControlChar{{}}, ea}}
    case _ BUni{{}} _ _:
      Err{{J.InvalidUnicode{{}}, ea}}
    case _ BLone{{}} _ _:
      Err{{J.LoneSurrogate{{}}, ea}}
    case _ m SNil{{}} stk:
      {fin}
    case SNil{{}} _ _ _:
      Err{{J.Internal{{}}, at}}
{chr(10).join(rs)}
"""


text = f'''# generated by scripts/gen_fast.py; do not edit

# one char per call; fuel is the input itself, so it never runs out first.
# at is the offset of the char read now; ea the offset of the backslash of
# the current escape, or of an error found inside a string (the B modes
# report it at the next step). hi is a pending high surrogate, code the
# \\\\u digits so far, key whether the string is an object key. gc writes
# compact text; gp the same loop indenting, with d the depth
{loop("gc", False)}{loop("gp", True)}
# the fuel must be the very list the loop reads: a second list over the
# same chars makes every node shared, which doubles the time
def start.c(+t: String) -> Out:
  gc(t, VStart{{}}, t, [], "", 0, 0, False{{}}, 0, 0)

def start.p(+t: String) -> Out:
  gp(t, VStart{{}}, t, [], "", 0, 0, False{{}}, 0, 0, 0n)

# compact text, as J.stringify writes it
def reformat(s: String) -> Out:
  start.c(s)

# indented text, as J.pretty(j, "  ") writes it
def pretty(s: String) -> Out:
  start.p(s)
'''
head = (ROOT / "scripts/fast_head.bend.in").read_text()
(ROOT / "fast.bend").write_text(head + text)
print(f"{len(build())} cases per loop -> fast.bend")
