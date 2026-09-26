"""Integration tests: build the bjson CLI and check it against Python's json.

- valid docs (fixtures + random): output parses in Python to the same value,
  compact and pretty, and printing is a fixed point
- invalid docs (fixtures + random mutations): both reject, with exit code 1
  and a path:line:col message
- byte-mutated docs: where Python's UTF-8 decoder rejects the bytes, both
  report invalid UTF-8 at the same line and column
- examples/regress/: inputs that once failed, checked as bytes on every run;
  FAIL_DIR=dir saves this run's failing inputs there, to add to it
- bjson prints exactly what spec_cli.bend (the CLI on the proven parser)
  prints, errors included
"""
import json
import math
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "bjson"
SPEC = ROOT / "spec-bjson"
SEED = int(os.environ.get("SEED", "1"))
N = int(os.environ.get("N", "300"))
rng = random.Random(SEED)
tmp = Path(tempfile.mkdtemp(prefix="bjson-it-"))
failures = []
counts = {"valid": 0, "invalid": 0}


def build():
    subprocess.run(["bend", "main.bend", "-o", str(BIN)], cwd=ROOT, check=True)
    subprocess.run(["bend", "spec_cli.bend", "-o", str(SPEC)], cwd=ROOT, check=True)


def run(text, *flags, binary=BIN):
    return run_bytes(text.encode("utf-8", "surrogatepass"), *flags, binary=binary)


def run_bytes(raw, *flags, binary=BIN):
    path = tmp / "in.json"
    path.write_bytes(raw)
    p = subprocess.run([str(binary), *flags, str(path)], capture_output=True)
    return p.returncode, p.stdout.decode("utf-8"), p.stderr.decode("utf-8")


def strict_loads(text):
    """Python's json, minus its extensions: NaN/Infinity and lone surrogates.
    A leading BOM is skipped, as RFC 8259 §8.1 allows and bjson does."""
    def no_const(name):
        raise ValueError(name)
    v = json.loads(text.removeprefix("\ufeff"), parse_constant=no_const)
    json.dumps(v, ensure_ascii=False).encode("utf-8")  # raises on lone surrogates
    return v


def same(a, b):
    """Equal as JSON values; numbers compare by value, floats by repr."""
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b or (math.isnan(a) and math.isnan(b))
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(same(a[k], b[k]) for k in a)
    return type(a) is type(b) and a == b


def fail(name, why, text):
    raw = text if isinstance(text, bytes) else text.encode("utf-8", "surrogatepass")
    failures.append(f"{name}: {why}\n    input: {raw[:200]!r}")
    if os.environ.get("FAIL_DIR"):
        d = Path(os.environ["FAIL_DIR"])
        d.mkdir(parents=True, exist_ok=True)
        (d / f"seed{SEED}-{name.replace('#', '-').replace('/', '-')}.json").write_bytes(raw)


# Random documents
# ----------------

CHARS = ['a', 'Z', ' ', '"', '\\', '/', '\n', '\r', '\t', '\b', '\f', '\x00', '\x1f',
         '\x7f', 'é', '中', '😀', ' ', '﻿']


def rand_str():
    return "".join(rng.choice(CHARS) for _ in range(rng.randint(0, 8)))


def rand_num():
    return rng.choice([
        0, -0.0, 1, -1, 42, 2**31, -(2**53) + 1, 10**30, 0.5, -3.25, 1e-7, 6.02e23,
        rng.randint(-10**6, 10**6), rng.uniform(-1e6, 1e6),
    ])


def rand_value(depth=0):
    kinds = ["null", "bool", "num", "str"] + (["arr", "obj"] * 2 if depth < 5 else [])
    k = rng.choice(kinds)
    if k == "null":
        return None
    if k == "bool":
        return rng.random() < 0.5
    if k == "num":
        return rand_num()
    if k == "str":
        return rand_str()
    if k == "arr":
        return [rand_value(depth + 1) for _ in range(rng.randint(0, 5))]
    return {rand_str(): rand_value(depth + 1) for _ in range(rng.randint(0, 5))}


def rand_text(v):
    """Serialize v with random whitespace and escaping choices."""
    ws = lambda: "".join(rng.choice(" \t\n\r") for _ in range(rng.randint(0, 2)))
    return ws() + json.dumps(v, ensure_ascii=rng.random() < 0.5,
                             indent=rng.choice([None, 0, 2, "\t"]),
                             separators=rng.choice([None, (",", ":"), (" , ", " : ")])) + ws()


MUTATIONS = [
    lambda s, i: s[:i] + s[i + 1:],                       # drop a char
    lambda s, i: s[:i] + rng.choice('{}[],:"\\x01') + s[i:],  # insert structure
    lambda s, i: s[:i] + rng.choice(["tru", "nul", "01", "1.", "-", "+1", ".5", "1e", "NaN",
                                     "\\x", "\\u12", "'a'", "\x01"]) + s[i:],
    lambda s, i: s + rng.choice([",", "]", "}", "x", " 1"]),
]


# bytes that are not UTF-8, or are only just
BAD_BYTES = [b"\xff", b"\xfe", b"\x80", b"\xbf", b"\xc0\xaf", b"\xc1\xbf", b"\xe0\x80\xaf",
             b"\xf0\x80\x80\xaf", b"\xed\xa0\x80", b"\xed\xbf\xbf", b"\xf4\x90\x80\x80",
             b"\xf5\x80\x80\x80", b"\xe2\x82", b"\xf0\x9f\x98", b"\xc3", b"\xef\xbf\xbd",
             b"\xf4\x8f\xbf\xbf", b"\xed\x9f\xbf", b"\xc2\x80"]


def mutate_bytes(raw):
    i = rng.randrange(len(raw) + 1)
    k = rng.random()
    if k < 0.6:
        return raw[:i] + rng.choice(BAD_BYTES) + raw[i:]
    if k < 0.8:
        return raw[:i] + bytes([rng.randrange(128, 256)]) + raw[i:]
    return raw[:i]  # may cut a multibyte char


def check_bytes(name, raw):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        counts["invalid"] += 1
        before = raw[:e.start].decode("utf-8")
        line = before.count("\n") + 1
        col = len(before) - (before.rfind("\n") + 1) + 1
        want = f"{tmp / 'in.json'}:{line}:{col}: invalid UTF-8"
        for flags in [("--compact",), ()]:
            got = run_bytes(raw, *flags)
            if got[0] != 1 or got[2].strip() != want:
                return fail(name, f"bad UTF-8 not reported as {want!r}: {got[2].strip()!r}", raw)
            if run_bytes(raw, *flags, binary=SPEC) != got:
                return fail(name, "differs from the proven parser's CLI on bad UTF-8", raw)
        return
    check(name, text)


# Checks
# ------

def check_valid(name, text):
    want = strict_loads(text)
    for flags in [("--compact",), ()]:
        code, out, err = run(text, *flags)
        if code != 0:
            return fail(name, f"rejected valid input: {err.strip()}", text)
        try:
            got = json.loads(out)
        except ValueError as e:
            return fail(name, f"printed invalid JSON ({e}): {out[:120]!r}", text)
        if not same(got, want):
            return fail(name, f"value changed: {out[:120]!r}", text)
        code2, out2, _ = run(out, *flags)
        if code2 != 0 or out2 != out:
            return fail(name, "printing is not a fixed point", text)
        if run(text, *flags, binary=SPEC) != (code, out, err):
            return fail(name, f"bjson {' '.join(flags)} differs from the proven parser's CLI", text)


def check_invalid(name, text):
    code, out, err = run(text)
    if code != 1:
        return fail(name, f"accepted invalid input (exit {code}): {out[:80]!r}", text)
    for flags in [("--compact",), ()]:
        got, want = run(text, *flags), run(text, *flags, binary=SPEC)
        if got != want:
            return fail(name, f"error differs from the proven parser's: {got[2].strip()!r} vs {want[2].strip()!r}", text)
    if not err.startswith(str(tmp / "in.json") + ":") or err.count(":") < 3:
        return fail(name, f"bad error message: {err.strip()!r}", text)


def check(name, text):
    try:
        strict_loads(text)
    except (ValueError, UnicodeEncodeError, RecursionError):
        counts["invalid"] += 1
        return check_invalid(name, text)
    counts["valid"] += 1
    check_valid(name, text)


def main():
    build() if not os.environ.get("NOBUILD") else None
    fixtures = sorted((ROOT / "examples").glob("*.json"))
    for f in fixtures:
        check(f.name, f.read_text())
    regress = sorted((ROOT / "examples/regress").glob("*"))
    for f in regress:
        check_bytes(f"regress/{f.name}", f.read_bytes())
    for i in range(N):
        text = rand_text(rand_value())
        check(f"random#{i}", text)
        mutated = rng.choice(MUTATIONS)(text, rng.randrange(len(text) + 1))
        check(f"mutated#{i}", mutated)
    for i in range(N // 3):
        raw = rand_text(rand_value()).encode("utf-8")
        check_bytes(f"bytes#{i}", mutate_bytes(raw))
    # a big one
    big = json.dumps([rand_value() for _ in range(2000)])
    check("big", big)

    total = len(fixtures) + len(regress) + 2 * N + N // 3 + 1
    print(f"{total - len(failures)}/{total} passed (seed {SEED}; "
          f"{counts['valid']} valid, {counts['invalid']} invalid)")
    for f in failures:
        print(f)
    sys.exit(1 if failures else 0)


main()
