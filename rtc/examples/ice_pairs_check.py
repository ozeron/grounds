"""Independent bigint/full-sort checks of transport references and role changes."""
import copy
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

COMMAND = sys.argv[1:]
COUNT = 0
RNG = random.Random(7314)


def candidate(priority, port, component=1, foundation=None, kind="host"):
    return [component, priority, foundation or f"f{port}", kind, [127, 0, 0, 1, port]]


def rank(local, remote, control):
    g, d = (local, remote) if control else (remote, local)
    return (min(g, d) << 32) + 2 * max(g, d) + int(g > d)


def key(stream, pair):
    return stream, pair[2][0], tuple(pair[1][4]), tuple(pair[2][4])


def reference(control, streams, steps):
    lists = []
    for sid, locals_, remotes in copy.deepcopy(streams):
        pairs = [[original, base, remote, rank(original[1], remote[1], control), 0]
                 for original, base in locals_ for remote in remotes if original[0] == remote[0]]
        pairs.sort(key=lambda p: p[3], reverse=True)
        unique = []
        for p in pairs:
            if not any(p[1][4] == q[1][4] and p[2] == q[2] for q in unique):
                unique.append(p)
        lists.append([sid, unique])
    foundation = lambda p: (p[1][2], p[2][2])
    seen = set()
    for _, pairs in lists:
        for p in pairs:
            if foundation(p) not in seen and not any(foundation(q) == foundation(p) and q[2][0] < p[2][0] for q in pairs):
                p[4] = 1
                seen.add(foundation(p))
    saved = {}
    output = []
    for step in steps:
        action = step[0]
        if action == "role":
            for _, pairs in lists:
                for p in pairs:
                    p[3] = rank(p[0][1], p[2][1], step[1])
                pairs.sort(key=lambda p: p[3], reverse=True)
            continue
        if action == "remember":
            _, name, stream, index = step
            ps = next((ps for sid, ps in lists if sid == stream), [])
            if index >= len(ps):
                return output + ["invalid"]
            saved[name] = key(stream, ps[index])
            continue
        if action == "reference":
            _, name, sid, component, base, remote = step
            saved[name] = (sid, component, tuple(base), tuple(remote))
            continue
        matches = [(sid, i, p) for sid, ps in lists for i, p in enumerate(ps) if key(sid, p) == saved.get(step[1])]
        if action == "locate":
            output.append(f"location:{matches[0][0]}:{matches[0][1]}" if len(matches) == 1 else "missing")
            continue
        if len(matches) != 1:
            return output + ["invalid"]
        p = matches[0][2]
        if action == "begin" and p[4] == 1:
            p[4] = 2
        elif action in ("success", "failure") and p[4] == 2:
            p[4] = 3 if action == "success" else 4
            if action == "success":
                for _, ps in lists:
                    for q in ps:
                        if q[4] == 0 and foundation(p) == foundation(q):
                            q[4] = 1
        else:
            return output + ["invalid"]
    addr = lambda c: ".".join(map(str, c[4][:4])) + "/" + str(c[4][4])
    for sid, pairs in lists:
        output.append(f"stream:{sid}")
        for original, base, remote, priority, state in pairs:
            output.append(":".join(map(str, ["pair", original[0], original[1], base[1], addr(base), remote[1],
                addr(remote), base[2], remote[2], priority >> 32, priority & 0xFFFFFFFF, state])))
    return output


def check(streams, steps=(), control=True):
    global COUNT
    fixture = [control, streams, list(steps)]
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "pairs.json"
        path.write_text(json.dumps(fixture))
        result = subprocess.run(COMMAND + [str(path)], capture_output=True, text=True, timeout=15)
    expected = reference(control, streams, steps)
    assert result.returncode == 0, result.stderr
    actual = result.stdout.splitlines()
    assert actual == expected, (fixture, expected, actual)
    COUNT += 1
    return actual


# Mirror priorities reverse relative order when the controlling role changes.
local_a, local_b = candidate(100, 10001), candidate(200, 10002)
remote_a, remote_b = candidate(100, 20001), candidate(200, 20002)
mirror = [[1, [[local_a, local_a], [local_b, local_b]], [remote_a, remote_b]]]
steps = [["remember", "target", 1, 1], ["locate", "target"], ["begin", "target"],
         ["role", False], ["locate", "target"], ["success", "target"]]
assert check(mirror, steps)[:2] == ["location:1:1", "location:1:2"]
check(mirror, steps + [["role", True], ["locate", "target"]])
for control in (False, True):
    for result in ("success", "failure"):
        for index in range(4):
            check(mirror, [["remember", "t", 1, index], ["begin", "t"], ["role", not control],
                           [result, "t"], ["role", control], ["locate", "t"]], control)
    check(mirror, [["remember", "t", 1, 0], ["success", "t"]], control)
    check(mirror, [["remember", "t", 1, 0], ["begin", "t"], ["begin", "t"]], control)

# Reflexive advertised priorities differ from the actual sending base.
base = candidate(50, 11000)
reflexive = candidate(2100000000, 12000, kind="srflx")
for control in (False, True):
    check([[7, [[reflexive, base]], [candidate(2147483647, 21000)]]],
          [["remember", "t", 7, 0], ["role", not control], ["begin", "t"], ["success", "t"]], control)

# Component/stream/port are part of identity; matching candidate metadata is not.
for sid, comp, bp, rp in ((2, 1, 10001, 20001), (1, 2, 10001, 20001), (1, 1, 10003, 20001), (1, 1, 10001, 20003)):
    steps = [["reference", "unknown", sid, comp, [127, 0, 0, 1, bp], [127, 0, 0, 1, rp]],
             ["locate", "unknown"], ["begin", "unknown"]]
    assert check(mirror, steps) == ["missing", "invalid"]
check(mirror, [["locate", "unsaved"]])

# Two candidate records can share an endpoint. Refuse ambiguous lookup/mutation.
alias = candidate(201, 20001, foundation="alias")
ambiguous = [[1, [[local_a, local_a]], [remote_a, alias]]]
for control in (False, True):
    assert check(ambiguous, [["remember", "t", 1, 0], ["role", not control], ["locate", "t"], ["begin", "t"]], control) == ["missing", "invalid"]

# Cross-stream foundation thawing still targets the saved pair after reversal.
shared_local = candidate(100, 13000, foundation="local")
shared_remote = candidate(200, 23000, foundation="remote")
shared = [[1, [[shared_local, shared_local]], [shared_remote]],
          [2, [[shared_local, shared_local]], [shared_remote]]]
check(shared, [["remember", "t", 1, 0], ["begin", "t"], ["role", False], ["success", "t"]])
check(shared, [["remember", "t", 2, 0], ["role", False], ["begin", "t"]])
check([[1, [], []]], [["role", False]])

# Independent randomized bigint ranks/order; state stays attached to endpoints.
for n in range(30):
    ls = [candidate(p, 14000 + i) for i, p in enumerate(RNG.sample(range(1, 2147483648), 4))]
    rs = [candidate(p, 24000 + i) for i, p in enumerate(RNG.sample(range(1, 2147483648), 4))]
    streams = [[3, [[c, c] for c in ls], rs]]
    steps = [["remember", "t", 3, RNG.randrange(16)], ["begin", "t"], ["role", False],
             ["role", True], ["role", False], ["locate", "t"], ["failure" if n % 2 else "success", "t"]]
    check(streams, steps)
print(f"ICE pair references: {COUNT} role/order/identity/state/bigint cases passed")
