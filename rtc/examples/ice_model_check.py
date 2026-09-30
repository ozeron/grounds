"""Full-sort Python reference for Bend candidate priority/checklist formation."""
import copy
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

COMMAND = sys.argv[1:]
COUNT = 0
RNG = random.Random(8445)


def run(fixture):
    global COUNT
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "fixture.json"
        path.write_text(json.dumps(fixture))
        result = subprocess.run(COMMAND + [str(path)], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    COUNT += 1
    return result.stdout.splitlines()


def cand(component=1, priority=100, foundation="f", port=10000, kind="host", host=(127, 0, 0, 1)):
    return [component, priority, foundation, kind, [*host, port]]


def valid(c):
    comp, priority, foundation, kind, address = c
    return (1 <= comp <= 256 and 1 <= priority <= 2**31 - 1 and
            1 <= len(foundation) <= 32 and all(ch.isascii() and (ch.isalnum() or ch in "+/") for ch in foundation) and
            kind in ("host", "srflx", "prflx", "relay") and len(address) == 5 and
            all(0 <= v <= 255 for v in address[:4]) and 1 <= address[4] <= 65535)


def reference(control, limit, streams, actions=()):
    if not (1 <= limit <= 256 and 1 <= len(streams) <= 16 and len({s[0] for s in streams}) == len(streams)):
        return ["invalid"]
    lists = []
    for stream_id, locals_, remotes in streams:
        if (len(locals_) > 64 or len(remotes) > 64 or len({l[0][1] for l in locals_}) != len(locals_) or
                len({r[1] for r in remotes}) != len(remotes)):
            return ["invalid"]
        for original, base in locals_:
            if not (valid(original) and valid(base) and original[0] == base[0] and base[3] in ("host", "relay") and
                    (original[3] in ("srflx", "prflx") or original == base)):
                return ["invalid"]
        if not all(map(valid, remotes)):
            return ["invalid"]
        pairs = []
        for original, base in locals_:
            for remote in remotes:
                if original[0] != remote[0]:
                    continue
                g, d = (original[1], remote[1]) if control else (remote[1], original[1])
                rank = 2**32 * min(g, d) + 2 * max(g, d) + (g > d)
                pairs.append([original, base, remote, rank, 0])
        pairs.sort(key=lambda p: p[3], reverse=True)
        unique = []
        seen_keys = set()
        for p in pairs:
            key = (tuple(p[1][4]), *p[2][:4], tuple(p[2][4]))
            if key not in seen_keys:
                seen_keys.add(key)
                unique.append(p)
        # Apply the global limit AFTER sorting/deduplication, independently of
        # Bend's incremental bounded top-list algorithm.
        lists.append([stream_id, unique])
    excess = sum(len(pairs) for _, pairs in lists) - limit
    while excess > 0:
        for _, pairs in lists:
            if pairs and excess > 0:
                pairs.pop()
                excess -= 1
    seen = set()
    foundation = lambda p: (p[1][2], p[2][2])
    for _, pairs in lists:
        for p in pairs:
            f = foundation(p)
            if f not in seen and not any(foundation(q) == f and q[2][0] < p[2][0] for q in pairs):
                p[4] = 1
                seen.add(f)
    for action, stream_id, index in actions:
        target = next((pairs for i, pairs in lists if i == stream_id), [])
        if index >= len(target):
            return ["invalid"]
        p = target[index]
        if action == "begin" and p[4] == 1:
            p[4] = 2
        elif action in ("success", "failure") and p[4] == 2:
            p[4] = 3 if action == "success" else 4
            if action == "success":
                for _, pairs in lists:
                    for q in pairs:
                        if q[4] == 0 and foundation(q) == foundation(p):
                            q[4] = 1
        else:
            return ["invalid"]
    lines = []
    for stream_id, pairs in lists:
        lines.append(f"stream:{stream_id}")
        for original, base, remote, rank, state in pairs:
            addr = lambda c: ".".join(map(str, c[4][:4])) + "/" + str(c[4][4])
            lines.append(":".join(map(str, ["pair", original[0], original[1], base[1], addr(base), remote[1], addr(remote),
                                              base[2], remote[2], rank >> 32, rank & 0xFFFFFFFF, state])))
    return lines


def check(streams, control=True, limit=100, actions=()):
    fixture = ["checklists", control, limit, streams, list(actions)]
    expected = reference(control, limit, copy.deepcopy(streams), actions)
    actual = run(fixture)
    assert actual == expected, (fixture, expected, actual)


# Exact candidate formula, extremes, zero result and invalid bounds.
priorities = [(p, l, c) for p in (0, 100, 110, 126) for l in (0, 1, 65535) for c in (1, 2, 255, 256)]
priorities += [(127, 0, 1), (2**32-1, 0, 1), (0, 65536, 1), (0, 0, 0), (0, 0, 257)]
actual = run(["priorities", priorities])
expected = [str(2**24*p + 256*l + 256-c) if p <= 126 and l <= 65535 and 1 <= c <= 256 and (p or l or c != 256)
            else "invalid" for p, l, c in priorities]
assert actual == expected, (actual, expected)

# Pair rank retains all bits, including role-dependent low parity, compared to
# independent Python bigint rather than the same two-word implementation.
pairs = [(g, d) for g in (1, 2, 2130706431, 2**31-1) for d in (1, 2, 2130706431, 2**31-1)]
pairs += [(RNG.randint(1, 2**31-1), RNG.randint(1, 2**31-1)) for _ in range(80)]
pairs += [(0, 1), (1, 0), (2**31, 1), (1, 2**32-1)]
actual = run(["pair-priorities", pairs])
expected = []
for g, d in pairs:
    if not (1 <= g < 2**31 and 1 <= d < 2**31):
        expected.append("invalid")
    else:
        rank = 2**32 * min(g, d) + 2 * max(g, d) + (g > d)
        expected.append(f"{rank >> 32}:{rank & 0xFFFFFFFF}")
assert actual == expected

# Lowest component beats higher priority when initially unfreezing a foundation;
# later streams stay frozen for that foundation. Success thaws it across streams.
streams = []
for sid in range(1, 4):
    locals_ = []
    remotes = []
    for comp in (1, 2):
        local = cand(comp, 100 + comp, "local", 10000 + sid * 10 + comp)
        locals_.append([local, local])
        for fi in range(sid + 2):
            remotes.append(cand(comp, 200 + comp * 10 + fi, f"f{fi}", 20000 + fi * 10 + comp))
    streams.append([sid, locals_, remotes])
check(streams)
check(streams, False)
check(streams, actions=[("begin", 1, 3), ("success", 1, 3)])
check(streams, actions=[("begin", 1, 3), ("failure", 1, 3)])
check(streams, actions=[("success", 1, 3)])
check(streams, actions=[("begin", 1, 0)])  # component 2 begins frozen
check(streams, actions=[("begin", 99, 0)])
check(streams, actions=[("begin", 1, 999)])
for limit in (1, 2, 3, 7, 100, 256):
    check(streams, limit=limit)

# Reflexive base substitution, duplicate high-priority paths and unique lower
# survivors under a tight cap. Role reversal must change pair rank parity.
base = cand(priority=500, foundation="base", port=30000)
reflexive = cand(priority=900, foundation="rfx", port=31000, kind="srflx", host=(192, 0, 2, 1))
other = cand(priority=100, foundation="other", port=32000)
remotes = [cand(priority=1000, foundation="remote", port=40000), cand(priority=10, foundation="low", port=40001)]
for control in (False, True):
    for limit in (1, 2, 3, 4):
        check([[1, [[base, base], [reflexive, base], [other, other]], remotes]], control, limit)

# A pair foundation is a tuple, not ambiguous concatenation.
a = cand(priority=10, foundation="a", port=11000)
ab = cand(priority=20, foundation="ab", port=12000)
check([[1, [[a, a]], [cand(priority=30, foundation="bc", port=13000)]],
       [2, [[ab, ab]], [cand(priority=40, foundation="c", port=14000)]]])

# Missing/unmatched components and empty streams preserve set ordering.
check([[1, [[base, base]], [cand(component=2)]], [2, [], []]])

for _ in range(80):
    streams = []
    for sid in range(RNG.randint(1, 4)):
        locals_ = []
        for i in range(RNG.randint(1, 6)):
            component = RNG.choice((1, 2))
            port = 10000 + 10 * sid + i % 3
            original = cand(component, 1000 + i, f"l{i % 3}", port)
            locals_.append([original, original])
        remotes = [cand(RNG.choice((1, 2)), 2000 + i, f"r{i % 2}", 20000 + i) for i in range(RNG.randint(1, 6))]
        streams.append([sid, locals_, remotes])
    check(streams, RNG.choice((False, True)), RNG.choice((1, 2, 3, 7, 100)))

# Malformed/unsupported candidate records, limits and duplicated priorities/IDs.
simple = [[1, [[base, base]], [remotes[0]]]]
for index, bad in [(0, 0), (0, 257), (1, 0), (1, 2**31), (2, ""), (2, "x"*33), (2, "has space"), (3, "tcp")]:
    value = copy.deepcopy(simple)
    value[0][2][0][index] = bad
    check(value)
for index, bad in [(0, 256), (4, 0), (4, 65536)]:
    value = copy.deepcopy(simple)
    value[0][2][0][4][index] = bad
    check(value)
for limit in (0, 257, 2**32-1):
    check(simple, limit=limit)
check(simple * 2)
check([])
check([[1, [[base, base]]*2, [remotes[0]]]])
check([[1, [[base, base]], [remotes[0]]*2]])
bad_base = copy.deepcopy(base)
bad_base[0] = 2
check([[1, [[reflexive, bad_base]], remotes]])
bad_base[0] = 1
bad_base[3] = "srflx"
check([[1, [[reflexive, bad_base]], remotes]])
check([[1, [[base, other]], remotes]])

# Bounded storage and global cap with the largest supported input.
locals_ = []
for i in range(64):
    c = cand(priority=1000+i, foundation=f"l{i}", port=10000+i)
    locals_.append([c, c])
remotes = [cand(priority=2000+i, foundation=f"r{i}", port=20000+i) for i in range(64)]
check([[1, locals_, remotes]], limit=100)
check([[i, locals_, remotes] for i in range(16)], limit=100)
check([[1, locals_ + [locals_[0]], remotes]])
check([[1, locals_, remotes + [remotes[0]]]])
check([[i, [], []] for i in range(17)])
print(f"ICE model: {COUNT} fixtures; {len(priorities)} candidate and {len(pairs)} bigint pair priority vectors passed")
