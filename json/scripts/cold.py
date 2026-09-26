"""Fail if a program makes any constructor "hot" (reference counted).

Bend counts references on every value of a type once any value of it is
shared (used twice) somewhere reachable from main, and then each
constructor of that type pays a heap cell for its fields. For String
that halves the speed of everything. This builds the program's C and
reads the compiler's CID_HOT_T table.

  python3 scripts/cold.py main.bend [more.bend ...]
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def hot(src):
    with tempfile.TemporaryDirectory() as d:
        c = Path(d) / "out.c"
        subprocess.run(["bend", src, "-o", str(c)], cwd=ROOT, check=True, capture_output=True)
        text = c.read_text()
    names = {int(n): k for k, n in re.findall(r"#define CID_([A-Z0-9_]+) (\d+)\n", text)}
    table = re.search(r"CID_HOT_T\[\] = \{([^}]*)\}", text).group(1)
    flags = [int(x) for x in table.replace("\n", "").split(",") if x.strip()]
    return [names.get(i, f"#{i}") for i, f in enumerate(flags) if f]


def main():
    bad = False
    for src in sys.argv[1:]:
        h = hot(src)
        if h:
            bad = True
            print(f"{src}: hot constructors: {', '.join(h)}")
        else:
            print(f"{src}: cold")
    sys.exit(1 if bad else 0)


main()
