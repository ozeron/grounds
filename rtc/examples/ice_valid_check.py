"""Independent signed packet and bigint checks of mapped valid-list ownership."""
import copy
import json
import random
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from stun_reference import COOKIE, attr, packet, sign, validate

COMMAND = sys.argv[1:]
LOCAL_KEY = b"LocalFixturePassword123456"
REMOTE_KEY = b"SyntheticPassword123456789"
COUNT = 0
RNG = random.Random(845531)


def cand(priority=2130706431, port=10001, foundation="host", component=1, ip=(127, 0, 0, 1), kind="host"):
    return [component, priority, foundation, kind, [*ip, port]]


LA = cand()
LB = cand(2130706175, 10002, "other")
RA = cand(2100000000, 20001, "remote")
RB = cand(2099999999, 20002, "remote2")
BASE = LA[4]
SOURCE = RA[4]
MAPPED = [203, 0, 113, 5, 31001]
STREAMS = [[1, [[LA, LA]], [RA]]]
BIND = ["bind", "localFrag", "remoteFrag", REMOTE_KEY.decode()]


def tx(n):
    return struct.pack("!III", n, 2, 3)


def mapped(address):
    return attr(0x20, b"\x00\x01" + struct.pack("!H", address[4] ^ 0x2112)
                + bytes(a ^ b for a, b in zip(address[:4], COOKIE)))


def response(n=1, address=MAPPED, mode="legacy", error=0, key=REMOTE_KEY):
    body = attr(9, bytes((0, 0, error // 100, error % 100)) + b"Error") if error else mapped(address)
    return sign(packet(body, kind=0x111 if error else 0x101, transaction=tx(n)), key, mode)


def request(n=90, control=False, nominate=False, priority=1845494271, remote=b"remoteFrag"):
    body = attr(6, b"localFrag:" + remote) + attr(0x24, struct.pack("!I", priority))
    body += attr(0x802A if control else 0x8029, struct.pack("!Q", 2))
    if nominate:
        body += attr(0x25, b"")
    return sign(packet(body, transaction=tx(n)), LOCAL_KEY, "dual")


def receive(raw, now=10, base=BASE, source=SOURCE, sid=1, component=1):
    return ["receive", now, sid, component, base, source, list(raw)]


def run(steps, streams=STREAMS, limit=100, capacity=4, valid_limit=100, mode="dual"):
    global COUNT
    data = [streams, mode, capacity, limit, valid_limit, steps]
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "valid.json"
        path.write_text(json.dumps(data))
        result = subprocess.run(COMMAND + [str(path)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, (data, result.stdout, result.stderr)
    frames, frame = [], []
    for line in result.stdout.splitlines():
        if line in ("changed", "rejected"):
            frames.append(frame)
            frame = [line]
        else:
            frame.append(line)
    frames.append(frame)
    assert len(frames) == len(steps) + 1 or frames == [["invalid"]], (data, frames)
    COUNT += 1
    return frames


def lines(frame, prefix):
    return [line for line in frame if line.startswith(prefix)]


def address(text):
    host, port = text.split("/")
    return [*map(int, host.split(".")), int(port)]


def paths(frame):
    parsed = []
    for line in lines(frame, "valid:"):
        values = line.split(":")
        high, low = map(int, values[11].split("/"))
        parsed.append({"sid": int(values[1]), "component": int(values[2]), "priority": int(values[3]),
                       "foundation": values[4], "kind": int(values[5]), "address": address(values[6]),
                       "base": address(values[7]), "remote_priority": int(values[8]), "remote_foundation": values[9],
                       "remote": address(values[10]), "rank": (high << 32) + low,
                       "token": int(values[12]), "generation": int(values[13]), "nominated": values[-1] == "1"})
    return parsed


def rank(local, remote, controlling=True):
    g, d = (local, remote) if controlling else (remote, local)
    return (min(g, d) << 32) + 2 * max(g, d) + (g > d)


def sent_priority(local):
    return (110 << 24) + (local[1] & 0xFFFF00) + 256 - local[0]


def checked(frame, expected, *, controlling=True):
    got = paths(frame)
    assert len(got) == len(expected), (got, expected, frame)
    for actual, wanted in zip(got, expected):
        for key, value in wanted.items():
            assert actual[key] == value, (key, actual, wanted)
        assert actual["rank"] == rank(actual["priority"], actual["remote_priority"], controlling), actual
        assert not actual["nominated"] and actual["generation"] == 7
    assert [p["rank"] for p in got] == sorted((p["rank"] for p in got), reverse=True)
    assert "valid-fault:0" in frame, frame
    return got


def ordinary(address_value, streams=STREAMS):
    return run([BIND, ["start", 0, 1, 2], ["ack", 0], receive(response(address=address_value))], streams=streams)


def pair_states(frame):
    sid, result = None, {}
    for line in frame:
        if line.startswith("stream:"):
            sid = int(line.split(":")[1])
        elif line.startswith("pair:"):
            fields = line.split(":")
            result[(sid, int(fields[1]), tuple(address(fields[4])), tuple(address(fields[6])))] = int(fields[-1])
    return result


def pair_state(frame, local=LA, remote=RA, sid=1):
    return pair_states(frame)[(sid, local[0], tuple(local[4]), tuple(remote[4]))]


# A mapped host can represent a different checklist pair. Complete it from
# every prior state, without manufacturing the original base as a valid path.
TWO = [[1, [[LA, LA], [LB, LB]], [RA]]]
for frozen in (False, True):
    lb = copy.deepcopy(LB)
    lb[2] = LA[2] if frozen else LB[2]
    ss = [[1, [[LA, LA], [lb, lb]], [RA]]]
    f = ordinary(lb[4], ss)
    assert pair_state(f[0], lb) == (0 if frozen else 1)
    assert pair_state(f[-1]) == pair_state(f[-1], lb) == 3, f[-1]
    checked(f[-1], [{"address": lb[4], "base": lb[4], "priority": lb[1], "token": 0}])
    assert not lines(f[-1], "flight:")

active = [BIND, ["start", 0, 1, 2], ["ack", 0], ["start", 50, 2, 2], ["ack", 50]]
for prior in ("active", "failed", "succeeded"):
    steps = active[:]
    if prior != "active":
        steps += [receive(response(2, LB[4], error=500 if prior == "failed" else 0), 60, base=LB[4])]
    f = run(steps + [receive(response(1, LB[4]), 70)], TWO)
    assert pair_state(f[-2], LB) == {"active": 2, "failed": 4, "succeeded": 3}[prior]
    assert pair_state(f[-1]) == pair_state(f[-1], LB) == 3, f[-1]
    assert not lines(f[-1], "flight:")
    checked(f[-1], [{"address": LB[4], "base": LB[4], "priority": LB[1]}])
    assert bool(lines(f[-1], "stopped:1:")) == (prior == "active")

# A current 487 retains a repair flight but has already retired its network
# transaction. Counterpart validation must retire that now-unusable repair
# record, while preserving an unrelated current role-conflict repair.
ss = [[1, [[LA, LA], [LB, LB]], [RA, RB]]]
f = run(active + [["start", 100, 3, 2], ["ack", 100],
                 receive(response(2, error=487), 110, base=LB[4]),
                 receive(response(3, error=487), 120, source=RB[4]),
                 receive(response(1, LB[4]), 130), ["repair", 1, 7, 0, 5], ["repair", 2, 7, 0, 5]], ss)
assert lines(f[-3], "record:2:") and not lines(f[-3], "record:1:")
assert pair_state(f[-3], LB) == 3 and f[-2][0] == "rejected"
assert f[-1][0] == "changed" and not lines(f[-1], "record:")

# The stopped counterpart retains correlation: late success/error and expiry
# cannot turn its Succeeded state into a failure or issue redundant retries.
for outcome in ("success", "error", "expiry"):
    steps = active + [receive(response(1, LB[4]), 60)]
    steps += [["tick", 1050]] if outcome == "expiry" else [receive(response(2, LB[4], error=500 if outcome == "error" else 0), 70, base=LB[4])]
    f = run(steps + [["tick", 1100], ["start", 1150, 3, 2]], TWO)
    assert pair_state(f[-1], LB) == 3 and not lines(f[-1], "flight:")
    assert not lines(f[-2], "send:") and not lines(f[-1], "send:")
    assert lines(f[-3], "retired:1:" if outcome == "expiry" else "late:1:")
    assert not lines(f[-3], "finished:1:")

# A send directive that has not been acknowledged becomes stale on completion.
f = run(active[:-1] + [receive(response(1, LB[4]), 60), ["ack", 60], ["tick", 600]], TWO)
assert "queued-send:0" in f[-3] and not lines(f[-2], "sent:1") and not lines(f[-1], "send:")
assert lines(f[-3], "stopped:1:") and pair_state(f[-1], LB) == 3

# Remove only the counterpart from a triggered FIFO; preserve unrelated work.
f = run([BIND, ["start", 0, 1, 2], ["ack", 0], receive(request(90), 10, base=LB[4]),
         receive(request(91), 11, base=LB[4], source=RB[4]), receive(response(1, LB[4]), 20), ["start", 50, 2, 2]],
        [[1, [[LA, LA], [LB, LB]], [RA, RB]]])
assert len(lines(f[-2], "queued:")) == 1 and f"{RB[4][4]}" in lines(f[-2], "queued:")[0]
assert pair_state(f[-2], LB) == 3 and pair_state(f[-1], LB, RB) == 2

# Thaw Frozen pairs matching the counterpart's foundation across checklists,
# even when the original check has a different foundation.
lc2 = cand(2130705918, 10003, LB[2], component=2)
rc2 = cand(2099999742, 20003, RA[2], component=2)
ss = TWO + [[2, [[lc2, lc2]], [rc2]]]
f = ordinary(LB[4], ss)
assert pair_state(f[0], lc2, rc2, 2) == 0 and pair_state(f[-1], lc2, rc2, 2) == 1

# A reflexive mapped address is not the checked base pair it refers to.
f = ordinary([203, 0, 113, 5, 31001],
             [[1, [[LA, LA], [cand(1677721855, 31001, "srflx", ip=(203, 0, 113, 5), kind="srflx"), LB]], [RA]]])
assert pair_state(f[-1], LB) == 1 and pair_state(f[-1]) == 3

# Late old results may learn mapped paths, but must not complete the original
# replacement or a different active/queued counterpart.
for mapped_address in (BASE, LB[4]):
    steps = active + [receive(request(90), 60), ["start", 100, 3, 2], ["ack", 100], receive(response(1, mapped_address), 110)]
    f = run(steps, TWO)
    assert pair_state(f[-1]) == pair_state(f[-1], LB) == 2
    assert {int(s.split(":")[1]) for s in lines(f[-1], "flight:")} == {1, 2}
    assert lines(f[-1], "validated:0:1:") and not lines(f[-1], "stopped:")
    checked(f[-1], [{"address": mapped_address, "token": 0}])


# Existing candidates retain advertised metadata; bases omitted from signaling
# still count as known local candidates and never become peer reflexive.
f = ordinary(BASE)
checked(f[-1], [{"priority": LA[1], "kind": 0, "foundation": LA[2], "address": BASE, "base": BASE}])
assert not lines(f[-1], "local-learned:")
REFLEXIVE = cand(1677721855, 31001, "srflx", ip=(203, 0, 113, 5), kind="srflx")
ref_streams = [[1, [[REFLEXIVE, LA]], [RA]]]
f = ordinary(REFLEXIVE[4], ref_streams)
checked(f[-1], [{"priority": REFLEXIVE[1], "kind": 1, "foundation": "srflx", "address": REFLEXIVE[4], "base": BASE}])
f = ordinary(BASE, ref_streams)
checked(f[-1], [{"priority": LA[1], "kind": 0, "address": BASE}])

# New mappings use the ACTUAL signed request priority, not the host priority.
f = ordinary(MAPPED)
checked(f[-1], [{"priority": sent_priority(LA), "kind": 2, "address": MAPPED, "base": BASE, "remote": SOURCE, "token": 0}])
assert len(lines(f[-1], "local-learned:")) == 1
raw = bytes.fromhex(lines(f[2], "send:")[0].split(":")[-1])
attrs = validate(raw, REMOTE_KEY, "dual")
assert any(kind == 0x24 and struct.unpack("!I", value)[0] == sent_priority(LA) for kind, value, _ in attrs)
assert lines(f[2], "request-info:")[0].startswith(f"request-info:{sent_priority(LA)}:0:")

# Local foundations ignore ports/components/streams and use base/peer IPs.
for other_ip, peer_ip, same in [((127, 0, 0, 1), (127, 0, 0, 1), True),
                               ((192, 0, 2, 4), (127, 0, 0, 1), False),
                               ((127, 0, 0, 1), (192, 0, 2, 5), False)]:
    lb = cand(2130706175, 10002, "other", ip=other_ip)
    rb = cand(2099999999, 20002, "remote2", ip=peer_ip)
    ss = [[1, [[LA, LA]], [RA]], [2, [[lb, lb]], [rb]]]
    steps = [BIND, ["start", 0, 1, 2], ["ack", 0], ["start", 50, 2, 2], ["ack", 50],
             receive(response(1), 60), receive(response(2, [203, 0, 113, 6, 31002]), 70, base=lb[4], source=rb[4], sid=2)]
    got = checked(run(steps, ss)[-1], [{"sid": 1, "priority": sent_priority(LA)}, {"sid": 2, "priority": sent_priority(lb)}])
    assert (got[0]["foundation"] == got[1]["foundation"]) == same

# Allocated names cannot collide with host/reflexive/base names.
host = cand(foundation="v0")
reflexive = copy.deepcopy(REFLEXIVE)
reflexive[2] = "v1"
f = ordinary([203, 0, 113, 9, 33333], [[1, [[host, host], [reflexive, host]], [RA]]])
assert paths(f[-1])[0]["foundation"] == "v2"

# A role change reranks existing valid paths from advertised priorities.
f = run([BIND, ["start", 0, 1, 2], ["ack", 0], receive(response(address=BASE)), receive(request(control=True), 20)])
checked(f[-1], [{"priority": LA[1], "address": BASE}], controlling=False)

# Interrupted old success creates its own mapped path, while the replacement
# remains In-Progress. Its later success can produce a second mapped identity.
steps = [BIND, ["start", 0, 1, 2], ["ack", 0], receive(request(), 10), ["start", 50, 2, 2], ["ack", 50],
         receive(response(1), 60), receive(response(2, [203, 0, 113, 6, 31002]), 70)]
f = run(steps)
assert any(line.startswith("flight:1:") for line in f[-2]), f[-2]
assert any(line.startswith("validated:1:1:") for line in f[-2]), f[-2]
checked(f[-1], [{"address": MAPPED, "token": 0}, {"address": [203, 0, 113, 6, 31002], "token": 1}])

# An invalid late mapping cannot fault or finish its replacement.
f = run(steps[:-2] + [receive(response(1, [203, 0, 113, 5, 0]), 60)])
assert "valid-fault:0" in f[-1] and not paths(f[-1])
assert lines(f[-1], "valid-invalid:") and any(line.startswith("flight:1:") for line in f[-1])

# Duplicate mapped outcomes at a full list remain valid and consume no slots.
steps[-1] = receive(response(2), 70)
f = run(steps, valid_limit=1)
checked(f[-1], [{"address": MAPPED, "token": 0}])
assert len(lines(f[-1], "local-learned:")) == 1

# A rejected second mapping commits no candidate or foundation; the owner is
# explicitly faulted and emits no further sends. The existing path survives.
steps[-1] = receive(response(2, [203, 0, 113, 6, 31002]), 70)
f = run(steps + [["start", 80, 3, 2], ["tick", 600]], valid_limit=1)
assert "valid-fault:1" in f[-1] and len(paths(f[-1])) == 1
assert len(lines(f[-1], "local-learned:")) == 1
assert lines(f[-3], "valid-capacity:") and not lines(f[-1], "send:") and not lines(f[-2], "send:")

# Authenticated malformed mapping is an explicit fault, never a usable path.
f = ordinary([203, 0, 113, 5, 0])
assert lines(f[-1], "valid-invalid:") and "valid-fault:1" in f[-1] and not paths(f[-1])

# No path is created by unauthenticated, non-symmetric, wrong-transaction,
# expired, error or invalid packets, including old errors after replacement.
for bad in [response(key=b"wrong"), response(9), response(error=487), response(error=500), b"malformed"]:
    f = run([BIND, ["start", 0, 1, 2], ["ack", 0], receive(bad)])
    assert not paths(f[-1]) and not lines(f[-1], "local-learned:")
for base, source in [(LB[4], SOURCE), (BASE, RB[4])]:
    f = run([BIND, ["start", 0, 1, 2], ["ack", 0], receive(response(), base=base, source=source)],
            [[1, [[LA, LA], [LB, LB]], [RA, RB]]])
    assert not paths(f[-1]) and not lines(f[-1], "local-learned:")
f = run([BIND, ["start", 0, 1, 1], ["ack", 0], receive(response(), now=500)])
assert not paths(f[-1])

# Both integrity modes and seeded candidate priorities compare every resulting
# rank/metadata with an independent Python bigint reference.
for mode in ("legacy", "sha256", "dual"):
    for _ in range(10):
        local = cand(RNG.randint(1, 2147483647), foundation="seeded")
        remote = cand(RNG.randint(1, 2147483647), 20001, "seededPeer")
        p = sent_priority(local)
        steps = [BIND, ["start", 0, 1, 2], ["ack", 0], receive(response(mode="sha256" if mode != "legacy" else "legacy"))]
        f = run(steps, [[1, [[local, local]], [remote]]], mode=mode)
        checked(f[-1], [{"priority": p, "remote_priority": remote[1], "address": MAPPED, "base": local[4], "remote": remote[4]}])

for invalid in (0, 257, 4294967295):
    assert run([], valid_limit=invalid) == [["invalid"]]
print(f"ICE valid lists: {COUNT} signed mapping/priority/foundation/bigint/role/late/capacity/rejection cases passed")
