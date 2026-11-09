#!/usr/bin/env python3
"""Attribute optimized arm64 instructions to emitted-C lines.

Usage: asm_lines.py program.c program.s PATTERN...

program.s must come from `clang -O3 -g -S` over the exact emitted C. Every
C line matching one of the regular expressions is located; the instructions
whose .loc points at that line are collected across all inlined copies, and
the report says whether any conditional branch (b.cond, cbz/cbnz, tbz/tbnz)
or conditional select (csel family) was emitted for it. A masked secret
selection should compile to plain ALU operations (and/orr/eor/mul/neg/...)
or csel, never to a conditional branch.
"""
import collections
import re
import sys

BRANCH = re.compile(r"^(b\.[a-z]+|cbz|cbnz|tbz|tbnz)$")
SELECT = re.compile(r"^(csel|csinc|csinv|csneg|cset|csetm|cinc|cinv|cneg)$")


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    c_path, s_path, patterns = sys.argv[1], sys.argv[2], [re.compile(p) for p in sys.argv[3:]]
    with open(c_path) as handle:
        c_lines = handle.read().split("\n")
    wanted = {i + 1: line.strip() for i, line in enumerate(c_lines)
              if any(p.search(line) for p in patterns)}
    files = {}
    current = None
    found = collections.defaultdict(collections.Counter)
    with open(s_path) as handle:
        for raw in handle:
            line = raw.strip()
            if line.startswith(".file"):
                parts = line.split()
                quoted = re.findall(r'"([^"]*)"', line)
                if len(parts) >= 3 and parts[1].isdigit() and quoted:
                    files[parts[1]] = quoted[-1]
                continue
            if line.startswith(".loc"):
                parts = line.split()
                name = files.get(parts[1], "")
                current = int(parts[2]) if name.endswith(c_path.split("/")[-1]) else None
                continue
            if current not in wanted or not line or line.startswith((".", ";", "//")) or line.endswith(":"):
                continue
            found[current][line.split()[0]] += 1
    total_branches = 0
    for number in sorted(wanted):
        ops = found.get(number, collections.Counter())
        branches = {k: v for k, v in ops.items() if BRANCH.match(k)}
        selects = {k: v for k, v in ops.items() if SELECT.match(k)}
        total_branches += sum(branches.values())
        text = wanted[number]
        print(f"C:{number}: {text[:150]}{'...' if len(text) > 150 else ''}")
        print(f"  instructions={sum(ops.values())} branches={branches or 'none'} selects={selects or 'none'}")
        print(f"  ops={dict(ops.most_common(12))}")
    print(f"lines={len(wanted)} conditional_branches={total_branches}")


if __name__ == "__main__":
    main()
