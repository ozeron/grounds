"""Fail if a program makes any constructor "hot" (reference counted).

Bend counts references on every value of a type once any value of it is
shared (used twice) somewhere reachable from main, and then each
constructor of that type pays a heap cell for its fields. For String
that halves the speed of everything. This builds the program's C and
reads the compiler's constructor table: CID_HOT_T in Bend 2.0.27, the
hot column of CID_T in Bend 2.0.34, or the hot field of its Cid rows in
Bend 2.0.38. Unknown layouts fail the check.
A .c argument is C the compiler already wrote, so it is read, not rebuilt.

  python3 scripts/cold.py main.bend [more.bend | built.c ...]
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def hot_constructors(text):
    definitions = re.findall(r"^#define CID_([A-Za-z0-9_]+) (\d+)\s*$", text, re.M)
    names = {int(n): k for k, n in definitions}
    legacy = re.findall(r"\bCID_HOT_T\[\] = \{([^{}]*)\};", text)
    combined = re.findall(r"\bCID_T\[\]\[2\] = \{(.*?)\};", text, re.S)
    rows = re.findall(r"\bCid CID_T\[\] = \{(.*?)\};", text, re.S)
    if len(legacy) + len(combined) + len(rows) != 1:
        raise ValueError("expected one recognized constructor table")
    if rows and not re.search(r"typedef struct \{ u8 ar, hot; u16 spine; \} Cid;", text):
        raise ValueError("unrecognized Cid row layout")
    macro = re.search(r"^#define cid_hot\(x\)\s+([^\n]+)$", text, re.M)
    expected = ("((bool)CID_HOT_T[x])" if legacy else "((bool)CID_T[x][1])" if combined
                else "CID_T[x].hot")
    if macro is None or re.sub(r"\s+", "", macro.group(1)) != expected:
        raise ValueError("unrecognized constructor hot-column accessor")
    if legacy:
        body = legacy[0].strip()
        if not re.fullmatch(r"\d+(?:\s*,\s*\d+)*\s*,?", body):
            raise ValueError("malformed CID_HOT_T flags")
        flags = [int(x) for x in body.split(",") if x.strip()]
    elif rows:
        row = r"\{\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\}"
        body = rows[0].strip()
        if not re.fullmatch(row + r"(?:\s*,\s*" + row + r")*\s*,?", body):
            raise ValueError("malformed Cid rows")
        flags = [int(hot) for _arity, hot, _spine in re.findall(row, body)]
    else:
        row = r"\{\s*(\d+)\s*,\s*(\d+)\s*\}"
        body = combined[0].strip()
        if not re.fullmatch(row + r"(?:\s*,\s*" + row + r")*\s*,?", body):
            raise ValueError("malformed CID_T rows")
        flags = [int(hot) for _arity, hot in re.findall(row, body)]
    if any(flag not in (0, 1) for flag in flags):
        raise ValueError("constructor hot flags must be zero or one")
    if (len(names) != len(definitions) or len(set(names.values())) != len(names)
            or set(names) != set(range(len(flags)))):
        raise ValueError("constructor IDs do not match the table rows")
    return [names[i] for i, flag in enumerate(flags) if flag]


def hot(src):
    if src.endswith(".c"):
        return hot_constructors(Path(src).read_text())
    with tempfile.TemporaryDirectory() as d:
        c = Path(d) / "out.c"
        subprocess.run(["bend", src, "-o", str(c)], cwd=ROOT, check=True, capture_output=True)
        text = c.read_text()
    return hot_constructors(text)


def main():
    if len(sys.argv) == 1:
        sys.exit("usage: cold.py main.bend [more.bend ...]")
    bad = False
    for src in sys.argv[1:]:
        try:
            h = hot(src)
        except ValueError as error:
            sys.exit(f"{src}: cannot verify cold constructors: {error}")
        if h:
            bad = True
            print(f"{src}: hot constructors: {', '.join(h)}")
        else:
            print(f"{src}: cold")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
