"""Independent full-sort/bigint transition model for the pure ICE scheduler."""
import copy
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

COMMAND = sys.argv[1:]
COUNT = 0
RNG = random.Random(617314)


def candidate(priority=100, port=10001, component=1, foundation=None, kind="host"):
    return [component, priority, foundation or f"f{port}", kind, [127, 0, 0, 1, port]]


def valid(c):
    return (1 <= c[0] <= 256 and 1 <= c[1] <= 2**31 - 1 and 1 <= len(c[2]) <= 32 and
            all(ch.isascii() and (ch.isalnum() or ch in "+/") for ch in c[2]) and
            c[3] in ("host", "relay", "srflx", "prflx") and len(c[4]) == 5 and
            all(0 <= n <= 255 for n in c[4][:4]) and 1 <= c[4][4] <= 65535)


def local_valid(local):
    a, b = local
    return valid(a) and valid(b) and a[0] == b[0] and b[3] in ("host", "relay") and (a[3] in ("prflx", "srflx") or a == b)


def rank(a, b, control):
    g, d = (a, b) if control else (b, a)
    return (min(g, d) << 32) + 2 * max(g, d) + int(g > d)


def identity(sid, p):
    return sid, p[2][0], tuple(p[1][4]), tuple(p[2][4])


def foundation(p):
    return p[1][2], p[2][2]


def address(a):
    return ".".join(map(str, a[:4])) + "/" + str(a[4])


def ref_text(ref):
    sid, comp, base, remote = ref
    return f"{sid}:{comp}:{address(base)}:{address(remote)}"


def role_text(role):
    return f"{'controlling' if role[0] else 'controlled'}:{role[1]}:{role[2]}"


class Model:
    def __init__(self, streams, control, cap, gen):
        assert 1 <= cap <= 256 and 1 <= len(streams) <= 16 and len({s[0] for s in streams}) == len(streams)
        self.lists = []
        for sid, ls, rs in copy.deepcopy(streams):
            assert len(ls) <= 64 and len(rs) <= 64 and len({l[0][1] for l in ls}) == len(ls) and len({r[1] for r in rs}) == len(rs)
            assert all(map(local_valid, ls)) and all(map(valid, rs))
            pairs = [[a, b, r, rank(a[1], r[1], control), 0] for a, b in ls for r in rs if a[0] == r[0]]
            pairs.sort(key=lambda p: p[3], reverse=True)
            unique = []
            for p in pairs:
                if not any(p[1][4] == q[1][4] and p[2] == q[2] for q in unique):
                    unique.append(p)
            self.lists.append([sid, unique])
        excess = sum(len(ps) for _, ps in self.lists) - cap
        while excess > 0:
            for _, ps in self.lists:
                if ps and excess > 0:
                    ps.pop()
                    excess -= 1
        seen = set()
        refs = set()
        for sid, ps in self.lists:
            for p in ps:
                ref = identity(sid, p)
                assert ref not in refs
                refs.add(ref)
                f = foundation(p)
                if f not in seen and not any(foundation(q) == f and q[2][0] < p[2][0] for q in ps):
                    p[4] = 1
                    seen.add(f)
        self.queues = {sid: [] for sid, _ in self.lists}
        self.flights = []
        self.role = (control, 1, 2)
        self.cursor, self.next, self.gen, self.cap = 0, 0, gen, cap

    def find(self, ref):
        values = [p for sid, ps in self.lists for p in ps if identity(sid, p) == ref]
        return values[0] if len(values) == 1 else None

    def trigger(self, ref):
        p = self.find(ref)
        if p is None:
            return "rejected"
        if p[4] == 3:
            return "triggered:none"
        p[4] = 1
        if ref not in self.queues[ref[0]]:
            self.queues[ref[0]].append(ref)
        interrupted = next((t for t, r, _ in self.flights if r == ref), None)
        self.flights = [f for f in self.flights if f[1] != ref]
        return f"triggered:{interrupted if interrupted is not None else 'none'}"

    def switch(self, role):
        self.role = role
        for _, ps in self.lists:
            for p in ps:
                p[3] = rank(p[0][1], p[2][1], role[0])
            ps.sort(key=lambda p: p[3], reverse=True)

    def select(self):
        if self.next > 2**32 - 1:
            return "rejected"
        for _ in self.lists:
            sid, ps = self.lists[self.cursor]
            self.cursor = (self.cursor + 1) % len(self.lists)
            queue = self.queues[sid]
            p = self.find(queue[0]) if queue else None
            if not queue:
                waiting = [p for p in ps if p[4] == 1]
                if not waiting:
                    for q in ps:
                        active = any(r[4] in (1, 2) and foundation(q) == foundation(r) for _, rs in self.lists for r in rs)
                        if q[4] == 0 and not active:
                            q[4] = 1
                    waiting = [p for p in ps if p[4] == 1]
                p = max(waiting, key=lambda p: (p[3], -p[2][0]), default=None)
            if p is None:
                continue
            if p[4] != 1:
                return "rejected"
            p[4] = 2
            ref, token = identity(sid, p), self.next
            self.next += 1
            if queue:
                queue.pop(0)
            self.flights.insert(0, (token, ref, self.role))
            return f"selected:{token}:{ref_text(ref)}:{role_text(self.role)}"
        return "idle"

    def act(self, step):
        op = step[0]
        if op == "select":
            return self.select()
        if op == "propose":
            return "proposed:" + copy.deepcopy(self).select()
        if op == "allocator":
            self.next = step[1]
            return "changed"
        if op == "trigger":
            _, sid, i = step
            ps = next((ps for got, ps in self.lists if got == sid), [])
            return self.trigger(identity(sid, ps[i])) if i < len(ps) else "rejected"
        if op == "role":
            self.switch(tuple(step[1:]))
            return "changed"
        if op in ("complete", "repair"):
            _, token, gen, *rest = step
            flight = next((f for f in self.flights if f[0] == token), None)
            if gen != self.gen or flight is None:
                return "rejected"
            _, ref, sent = flight
            if op == "repair":
                high, low = rest
                if (high, low) in (sent[1:], self.role[1:]):
                    return "rejected"
                self.switch((not sent[0], high, low))
                return self.trigger(ref)
            p = self.find(ref)
            if p is None or p[4] != 2:
                return "rejected"
            p[4] = 3 if rest[0] else 4
            self.flights = [f for f in self.flights if f[1] != ref]
            if rest[0]:
                for _, ps in self.lists:
                    for q in ps:
                        if q[4] == 0 and foundation(q) == foundation(p):
                            q[4] = 1
            return "changed"
        if op == "insert":
            _, sid, ls, r = step
            if not (local_valid(ls) and valid(r) and ls[0][3] in ("host", "relay") and ls[0][0] == r[0]):
                return "rejected"
            pair = [*copy.deepcopy(ls), copy.deepcopy(r), rank(ls[0][1], r[1], self.role[0]), 1]
            ref = identity(sid, pair)
            if self.find(ref) is not None:
                return self.trigger(ref)
            ps = next((ps for got, ps in self.lists if got == sid), None)
            if ps is None or sum(len(ps) for _, ps in self.lists) >= self.cap:
                return "rejected"
            ps.append(pair)
            ps.sort(key=lambda p: p[3], reverse=True)
            return self.trigger(ref)
        return "rejected"

    def snapshot(self):
        lines = [f"state:{role_text(self.role)}:{self.cursor}:{self.next}:{self.gen}:{self.cap}"]
        for sid, ps in self.lists:
            lines.append(f"stream:{sid}")
            for a, b, r, rank_, state in ps:
                lines.append(":".join(map(str, ["pair", a[0], a[1], b[1], address(b[4]), r[1], address(r[4]), b[2], r[2], rank_ >> 32, rank_ & 0xFFFFFFFF, state])))
        for sid, _ in self.lists:
            lines.append(f"queue:{sid}")
            lines.extend("queued:" + ref_text(ref) for ref in self.queues[sid])
        lines.extend(f"flight:{t}:{ref_text(ref)}:{role_text(role)}" for t, ref, role in self.flights)
        return lines


def check(streams, steps=(), control=True, cap=256, gen=7):
    global COUNT
    fixture = [control, cap, gen, streams, list(steps)]
    try:
        model = Model(streams, control, cap, gen)
    except AssertionError:
        expected = ["invalid"]
    else:
        expected = model.snapshot()
        for step in steps:
            expected.append(model.act(step))
            expected.extend(model.snapshot())
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "scheduler.json"
        path.write_text(json.dumps(fixture))
        result = subprocess.run(COMMAND + [str(path)], capture_output=True, text=True, timeout=20)
    actual = result.stdout.splitlines()
    assert result.returncode == 0, result.stderr
    assert actual == expected, (fixture, expected, actual)
    COUNT += 1
    return actual


la, lb = candidate(100, 10001), candidate(200, 10002)
ra, rb = candidate(100, 20001), candidate(200, 20002)
mirror = [[1, [[la, la], [lb, lb]], [ra, rb]]]
# FIFO beats priority; duplicate triggers remain one entry. Old completions may
# not complete or fail a replacement attempt, including after a role reversal.
for control in (False, True):
    for success in (False, True):
        check(mirror, [["trigger", 1, 3], ["trigger", 1, 2], ["trigger", 1, 3],
                      ["select"], ["trigger", 1, 3], ["role", not control, 3, 4],
                      ["select"], ["complete", 0, 7, success], ["complete", 1, 8, success],
                      ["complete", 1, 7, success], ["select"], ["select"]], control)
        check(mirror, [["select"], ["complete", 0, 7, success], ["trigger", 1, 0], ["select"]], control)
    check(mirror, [["select"], ["repair", 0, 7, 1, 2], ["role", not control, 3, 4],
                  ["repair", 0, 7, 3, 4], ["repair", 0, 8, 5, 6], ["repair", 0, 7, 5, 6],
                  ["select"], ["complete", 0, 7, True], ["complete", 1, 7, True]], control)
    check(mirror, [["allocator", 2**32 - 1], ["select"], ["select"], ["complete", 2**32-1, 7, True]], control)

# The enclosing engine can defer/reject a speculative selection under pacing or
# retained-listener capacity pressure. Neither FIFO entries nor tokens disappear.
for control in (False, True):
    check(mirror, [["propose"], ["propose"], ["select"], ["complete", 0, 7, True]], control)
    check(mirror, [["trigger", 1, 3], ["propose"], ["propose"], ["role", not control, 3, 4],
                  ["propose"], ["select"], ["complete", 0, 7, True]], control)
    check([[1, [], []]], [["propose"], ["propose"], ["select"]], control)

# Round robin, foundation blocking/thawing across streams and components,
# idle skipping, all-idle preservation, and success thaw versus failure thaw.
l1 = candidate(100, 11001, foundation="local")
l2 = candidate(110, 11002, component=2, foundation="local")
r1 = candidate(200, 21001, foundation="remote")
r2 = candidate(210, 21002, component=2, foundation="remote")
shared = [[1, [[l1, l1], [l2, l2]], [r1, r2]], [2, [[l1, l1], [l2, l2]], [r1, r2]], [3, [], []]]
for success in (False, True):
    check(shared, [["select"], ["select"], ["complete", 0, 7, success], ["select"], ["select"],
                  ["complete", 1, 7, success], ["select"], ["complete", 2, 7, success],
                  ["select"], ["complete", 3, 7, success], ["select"], ["select"]])
check([[1, [], []], [2, [[la, la]], [ra]], [3, [], []]], [["select"], ["select"], ["complete", 0, 7, True], ["select"]])
check([[1, [], []]], [["select"], ["select"], ["trigger", 1, 0]])
check(shared, [["trigger", 2, 1], ["trigger", 1, 1], ["select"], ["select"], ["select"]])

# Observed peer-reflexive insertion only forms one pair, even with multiple
# locals; existing endpoint metadata wins. Capacity rejection is atomic.
pr = candidate(500, 25001, kind="prflx")
for control in (False, True):
    check(mirror, [["insert", 1, [la, la], pr], ["insert", 1, [la, la], pr], ["select"],
                  ["insert", 1, [la, la], pr], ["select"], ["complete", 0, 7, False],
                  ["complete", 1, 7, True]], control)
    check(mirror, [["insert", 1, [la, la], candidate(500, 20001, kind="prflx")], ["select"]], control, cap=4)
    check(mirror, [["insert", 1, [la, la], pr], ["select"]], control, cap=4)
    check([[1, [], []]], [["insert", 1, [la, la], pr], ["select"], ["complete", 0, 7, True]], control, cap=1)
for sid, ls, r in ((9, [la, la], pr), (1, [la, la], candidate(500, 25001, component=2)),
                   (1, [candidate(300, 15001, kind="srflx"), la], pr),
                   (1, [la, la], candidate(0, 25001)), (1, [la, la], candidate(500, 0)),
                   (1, [candidate(300, 15001, foundation="bad-"), la], pr)):
    check(mirror, [["insert", sid, ls, r], ["select"]])
reflexive = candidate(2147483647, 12001, kind="srflx")
check([[1, [[reflexive, la]], [ra, rb]]], [["select"], ["role", False, 5, 6], ["complete", 0, 7, True]])
relay = candidate(500, 16001, kind="relay")
check([[1, [], []]], [["insert", 1, [relay, relay], pr], ["select"]])

# Formation bounds and ambiguous endpoint aliases reject at the public seam.
check([], [["select"]])
check(mirror, cap=0)
check(mirror, cap=257)
check([[1, [[la, la]], [ra, candidate(201, 20001, foundation="alias")]]])
check([[1, [[la, la]], [ra]], [1, [], []]])
check([[i, [], []] for i in range(17)])
check(mirror, [["trigger", 9, 0], ["trigger", 1, 99], ["complete", 999, 7, False], ["repair", 999, 7, 3, 4]])

# Long independent randomized schedules interleave roles, arrivals, completions
# and stale tokens. Compare all state, queue and sent-role snapshots, not just
# the final checklist or chosen endpoint.
for case in range(60):
    streams = []
    for sid in range(1, 1 + RNG.randrange(1, 4)):
        ls = [candidate(p, 10000+100*sid+i, foundation=f"l{i % 2}") for i, p in enumerate(RNG.sample(range(1, 2**31), 3))]
        rs = [candidate(p, 20000+100*sid+i, foundation=f"r{i % 2}") for i, p in enumerate(RNG.sample(range(1, 2**31), 3))]
        streams.append([sid, [[c, c] for c in ls], rs])
    steps = []
    for turn in range(55):
        op = RNG.choice(("select", "select", "trigger", "complete", "role", "repair", "insert"))
        sid = RNG.choice(streams)[0]
        if op == "select":
            step = [op]
        elif op == "trigger":
            step = [op, sid, RNG.randrange(10)]
        elif op == "complete":
            step = [op, RNG.randrange(20), RNG.choice((7, 7, 8)), bool(RNG.getrandbits(1))]
        elif op == "role":
            step = [op, bool(RNG.getrandbits(1)), RNG.randrange(2**32), RNG.randrange(2**32)]
        elif op == "repair":
            step = [op, RNG.randrange(20), 7, RNG.randrange(2**32), RNG.randrange(2**32)]
        else:
            local = next(ls[0] for got, ls, _ in streams if got == sid)
            step = [op, sid, local, candidate(1000+turn, 30000+turn, kind="prflx")]
        steps.append(step)
    check(streams, steps, control=bool(case % 2), cap=RNG.choice((3, 15, 40, 100)))
print(f"ICE scheduler: {COUNT} FIFO/ordinary/role/attempt/generation/insertion/full-sort cases passed")
