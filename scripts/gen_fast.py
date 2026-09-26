"""Generate fast.bend: the one-pass reformat loop.

The loop has a case per (mode, char) transition, so it is generated.
The helpers above the loop live in scripts/fast_head.bend.in.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VMODES = ["VTop", "VFirst", "VItem", "VObjVal"]
ACC = ["NZero", "NInt", "NFrac", "NExp"]
WS = ["' '", "'\\t'", "'\\n'", "'\\r'"]
rows = []


def row(mode, s, stack, body):
    rows.append(f"    case SCon{{_, f}} {mode} {s} {stack}:\n      {body}")


def go(mode, t, stack, out, bad="bad", hi="0", code="0", key="key"):
    return f"go(f, {mode}, {t}, {stack}, {out}, {bad}, {hi}, {code}, {key})"


def esc(c):
    return "SCon{'\\\\', SCon{'" + c + "', t}}"


# strings, the hot path: one char per case, plain chars last
row("SStr{}", "SCon{'\"', t}", "stk", go("close_mode(key)", "t", "stk", "SCon{'\"', out}"))
row("SStr{}", "SCon{'\\\\', t}", "stk", go("SEsc{}", "t", "stk", "out"))
row("SStr{}", "SCon{+c, t}", "stk", go("SStr{}", "t", "stk", "SCon{c, out}", "Bool.or(bad, ctrl(c))"))
for c, out in [('"', "SCon{'\"', SCon{'\\\\', out}}"), ("\\\\", "SCon{'\\\\', SCon{'\\\\', out}}"),
               ("/", "SCon{'/', out}"), ("b", "SCon{'b', SCon{'\\\\', out}}"),
               ("f", "SCon{'f', SCon{'\\\\', out}}"), ("n", "SCon{'n', SCon{'\\\\', out}}"),
               ("r", "SCon{'r', SCon{'\\\\', out}}"), ("t", "SCon{'t', SCon{'\\\\', out}}")]:
    row("SEsc{}", f"SCon{{'{c}', t}}", "stk", go("SStr{}", "t", "stk", out))
row("SEsc{}", "SCon{'u', t}", "stk", go("SU4{}", "t", "stk", "out", hi="hi"))
row("SEsc{}", "_", "_", "None{}")
# the four hex digits of \\u; the code builds up in code
for frm, to in [("SU4", "SU3"), ("SU3", "SU2"), ("SU2", "SU1")]:
    row(frm + "{}", "SCon{+c, t}", "stk",
        go(f"hex_mode(hex_digit(c), {to}{{}})", "t", "stk", "out", hi="hi", code="hex_add(hex_digit(c), code)"))
# the record u_last.go returns is not shared: sharing it would make every
# String in the program reference counted
row("SU1{}", "SCon{+c, t}", "stk",
    go("u_mode(u_hi(u_last.go(hex_digit(c), code, hi, \"\")))", "t", "stk",
       "u_out(u_last.go(hex_digit(c), code, hi, out))",
       "Bool.or(bad, u_bad(u_last.go(hex_digit(c), code, hi, \"\")))",
       hi="u_hi(u_last.go(hex_digit(c), code, hi, \"\"))"))
# after a high surrogate only \\u may come
row("SHi{}", "SCon{'\\\\', t}", "stk", go("SHiU{}", "t", "stk", "out", hi="hi"))
row("SHi{}", "_", "_", "None{}")
row("SHiU{}", "SCon{'u', t}", "stk", go("SU4{}", "t", "stk", "out", hi="hi"))
row("SHiU{}", "_", "_", "None{}")


def num(frm, ch, to):
    row(frm + "{}", f"SCon{{'{ch}', t}}", "stk", go(to + "{}", "t", "stk", f"SCon{{'{ch}', out}}"))


# numbers, a digit at a time; accepting states end at a delimiter below
for st in ["NInt", "NFrac", "NExp"]:
    for i in range(10):
        num(st, str(i), st)
num("NMin", "0", "NZero")
for i in range(1, 10):
    num("NMin", str(i), "NInt")
row("NMin{}", "_", "_", "None{}")
for st in ["NZero", "NInt"]:
    num(st, ".", "NDot")
    num(st, "e", "NE")
    num(st, "E", "NE")
num("NFrac", "e", "NE")
num("NFrac", "E", "NE")
for i in range(10):
    num("NDot", str(i), "NFrac")
row("NDot{}", "_", "_", "None{}")
num("NE", "+", "NESign")
num("NE", "-", "NESign")
for i in range(10):
    num("NE", str(i), "NExp")
row("NE{}", "_", "_", "None{}")
for i in range(10):
    num("NESign", str(i), "NExp")
row("NESign{}", "_", "_", "None{}")

# after a value, or where a number ends: white space, a comma or a closer
for m in ["VAfter"] + ACC:
    for w in WS:
        row(m + "{}", f"SCon{{{w}, t}}", "stk", go("VAfter{}", "t", "stk", "out"))
    row(m + "{}", "SCon{',', t}", "Con{BArr{}, up}", go("VItem{}", "t", "Con{BArr{}, up}", "SCon{',', out}"))
    row(m + "{}", "SCon{',', t}", "Con{BObj{}, up}", go("VKey{}", "t", "Con{BObj{}, up}", "SCon{',', out}"))
    row(m + "{}", "SCon{']', t}", "Con{BArr{}, up}", go("VAfter{}", "t", "up", "SCon{']', out}"))
    row(m + "{}", "SCon{'}', t}", "Con{BObj{}, up}", go("VAfter{}", "t", "up", "SCon{'}', out}"))
    row(m + "{}", "_", "_", "None{}")

# literals, a char at a time: the first char picks the word
for word, modes in [("true", ["T1", "T2", "T3"]), ("false", ["F1", "F2", "F3", "F4"]), ("null", ["U1", "U2", "U3"])]:
    for i, m in enumerate(modes):
        ch = word[i + 1]
        to = modes[i + 1] if i + 1 < len(modes) else "VAfter"
        row(m + "{}", f"SCon{{'{ch}', t}}", "stk", go(to + "{}", "t", "stk", f"SCon{{'{ch}', out}}"))
        row(m + "{}", "_", "_", "None{}")

# where a value may start
for m in VMODES:
    for w in WS:
        row(m + "{}", f"SCon{{{w}, t}}", "stk", go(m + "{}", "t", "stk", "out"))
    row(m + "{}", "SCon{'[', t}", "stk", go("VFirst{}", "t", "Con{BArr{}, stk}", "SCon{'[', out}"))
    row(m + "{}", "SCon{'{', t}", "stk", go("VObjFirst{}", "t", "Con{BObj{}, stk}", "SCon{'{', out}"))
    row(m + "{}", "SCon{'\"', t}", "stk", go("SStr{}", "t", "stk", "SCon{'\"', out}", key="False{}"))
    row(m + "{}", "SCon{'-', t}", "stk", go("NMin{}", "t", "stk", "SCon{'-', out}"))
    row(m + "{}", "SCon{'0', t}", "stk", go("NZero{}", "t", "stk", "SCon{'0', out}"))
    for i in range(1, 10):
        row(m + "{}", f"SCon{{'{i}', t}}", "stk", go("NInt{}", "t", "stk", f"SCon{{'{i}', out}}"))
    row(m + "{}", "SCon{'t', t}", "stk", go("T1{}", "t", "stk", "SCon{'t', out}"))
    row(m + "{}", "SCon{'f', t}", "stk", go("F1{}", "t", "stk", "SCon{'f', out}"))
    row(m + "{}", "SCon{'n', t}", "stk", go("U1{}", "t", "stk", "SCon{'n', out}"))
    if m == "VFirst":
        row("VFirst{}", "SCon{']', t}", "Con{_, up}", go("VAfter{}", "t", "up", "SCon{']', out}"))
    row(m + "{}", "_", "_", "None{}")

# object keys and colons
for m in ["VObjFirst", "VKey", "VColon"]:
    for w in WS:
        row(m + "{}", f"SCon{{{w}, t}}", "stk", go(m + "{}", "t", "stk", "out"))
for m in ["VObjFirst", "VKey"]:
    row(m + "{}", "SCon{'\"', t}", "stk", go("SStr{}", "t", "stk", "SCon{'\"', out}", key="True{}"))
row("VObjFirst{}", "SCon{'}', t}", "Con{_, up}", go("VAfter{}", "t", "up", "SCon{'}', out}"))
row("VColon{}", "SCon{':', t}", "stk", go("VObjVal{}", "t", "stk", "SCon{':', out}"))
for m in ["VObjFirst", "VKey", "VColon"]:
    row(m + "{}", "_", "_", "None{}")

loop = f'''# generated by scripts/gen_fast.py; do not edit

# one char, or one escape or literal, per call; fuel is the input itself,
# so it never runs out first. bad records a control char seen in a string,
# hi a pending high surrogate, code the \\u digits so far, key whether the
# string is an object key
def go(fuel: String, mode: Mode, s: String, stack: List<&2, Box>, out: String, +bad: Bool, +hi: U32, +code: U32, +key: Bool) -> Maybe<&2, String>:
  match fuel mode s stack:
    case _ Bad{{}} _ _:
      None{{}}
    case _ m SNil{{}} stk:
      finish(m, stk, out, bad)
    case SNil{{}} _ _ _:
      None{{}}
{chr(10).join(rows)}

# the fuel must be the very list the loop reads: a second list over the
# same chars makes every node shared, which doubles the time
def start(+t: String) -> Maybe<&2, String>:
  go(t, VTop{{}}, t, [], "", False{{}}, 0, 0, False{{}})

def bom(s: String) -> String:
  match s:
    case SCon{{'\\u{{FEFF}}', t}}:
      t
    case rest:
      rest

def reformat(s: String) -> Maybe<&2, String>:
  start(bom(s))
'''
head = (ROOT / "scripts/fast_head.bend.in").read_text()
(ROOT / "fast.bend").write_text(head + loop)
print(f"{len(rows)} cases -> fast.bend")
