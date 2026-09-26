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


def row(mode, s, stack, body):
    rows.append(f"    case SCon{{_, f}} {mode} {s} {stack}:\n      {body}")


def go(mode, t="t", stack="stk", out="out", hi="0", code="0", key="key", ea="ea"):
    return f"go(f, {mode}, {t}, {stack}, {out}, {hi}, {code}, {key}, (at + 1 : U32), {ea})"


def err(reason, at="at"):
    return f"Err{{{reason}, {at}}}"


def ch(c):
    return f"SCon{{'{c}', t}}"


BS = "\\\\"  # a backslash, as it reads inside a Bend char literal


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
    row(m + "{}", ch(","), "Con{BArr{}, up}", go("VItem{}", stack="Con{BArr{}, up}", out="SCon{',', out}"))
    row(m + "{}", ch(","), "Con{BObj{}, up}", go("VKey{}", stack="Con{BObj{}, up}", out="SCon{',', out}"))
    row(m + "{}", ch("]"), "Con{BArr{}, up}", go("VAfter{}", stack="up", out="SCon{']', out}"))
    row(m + "{}", ch("}"), "Con{BObj{}, up}", go("VAfter{}", stack="up", out="SCon{'}', out}"))
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
    for w in WS:
        row(m + "{}", f"SCon{{{w}, t}}", "stk", go(after_ws + "{}"))
    row(m + "{}", ch("["), "stk", go("VFirst{}", stack="Con{BArr{}, stk}", out="SCon{'[', out}"))
    row(m + "{}", ch("{"), "stk", go("VObjFirst{}", stack="Con{BObj{}, stk}", out="SCon{'{', out}"))
    row(m + "{}", ch('"'), "stk", go("SStr{}", out="SCon{'\"', out}", key="False{}"))
    row(m + "{}", ch("-"), "stk", go("NMin{}", out="SCon{'-', out}"))
    row(m + "{}", ch("0"), "stk", go("NZero{}", out="SCon{'0', out}"))
    for d in DIGITS[1:]:
        row(m + "{}", ch(d), "stk", go("NInt{}", out=f"SCon{{'{d}', out}}"))
    for c, to in [("t", "T1"), ("f", "F1"), ("n", "U1")]:
        row(m + "{}", ch(c), "stk", go(to + "{}", out=f"SCon{{'{c}', out}}"))
    if m == "VFirst":
        row("VFirst{}", ch("]"), "Con{_, up}", go("VAfter{}", stack="up", out="SCon{']', out}"))
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
for m in ["VObjFirst", "VKey"]:
    row(m + "{}", ch('"'), "stk", go("SStr{}", out="SCon{'\"', out}", key="True{}"))
row("VObjFirst{}", ch("}"), "Con{_, up}", go("VAfter{}", stack="up", out="SCon{'}', out}"))
row("VColon{}", ch(":"), "stk", go("VObjVal{}", out="SCon{':', out}"))
for m in ["VObjFirst", "VKey", "VColon"]:
    row(m + "{}", "SCon{c, _}", "_", err("J.UnexpectedChar{c}"))

loop = f'''# generated by scripts/gen_fast.py; do not edit

# one char per call; fuel is the input itself, so it never runs out first.
# at is the offset of the char read now; ea the offset of the backslash of
# the current escape, or of an error found inside a string (the B modes
# report it at the next step). hi is a pending high surrogate, code the
# \\\\u digits so far, key whether the string is an object key
def go(fuel: String, mode: Mode, s: String, stack: List<&2, Box>, out: String, +hi: U32, +code: U32, +key: Bool, +at: U32, +ea: U32) -> Out:
  match fuel mode s stack:
    case _ BCtrl{{}} _ _:
      Err{{J.ControlChar{{}}, ea}}
    case _ BUni{{}} _ _:
      Err{{J.InvalidUnicode{{}}, ea}}
    case _ BLone{{}} _ _:
      Err{{J.LoneSurrogate{{}}, ea}}
    case _ m SNil{{}} stk:
      finish(m, stk, out, at)
    case SNil{{}} _ _ _:
      Err{{J.Internal{{}}, at}}
{chr(10).join(rows)}

# the fuel must be the very list the loop reads: a second list over the
# same chars makes every node shared, which doubles the time
def start(+t: String) -> Out:
  go(t, VStart{{}}, t, [], "", 0, 0, False{{}}, 0, 0)

def reformat(s: String) -> Out:
  start(s)
'''
head = (ROOT / "scripts/fast_head.bend.in").read_text()
(ROOT / "fast.bend").write_text(head + loop)
print(f"{len(rows)} cases -> fast.bend")
