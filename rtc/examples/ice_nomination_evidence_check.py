"""Authenticated nomination ownership evidence; no nominated/selected claim."""
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from stun_reference import COOKIE, attr, packet, sign, validate

COMMAND = sys.argv[1:]
KEY = b"SyntheticPassword123456789"
LOCAL_KEY = b"LocalFixturePassword123456"
LA = [1, 2130706431, "host", "host", [127, 0, 0, 1, 10001]]
LB = [1, 2130706175, "other", "host", [127, 0, 0, 1, 10002]]
RA = [1, 2100000000, "remote", "host", [127, 0, 0, 1, 20001]]
RB = [1, 2099999999, "otherPeer", "host", [127, 0, 0, 1, 20002]]
MAP = [203, 0, 113, 5, 31001]
OTHER_MAP = [203, 0, 113, 6, 31002]
REFLEXIVE = [1, 1677721855, "srflx", "srflx", MAP]
STREAMS = [[1, [[LA, LA]], [RA]]]
TWO_BASES = [[1, [[LA, LA], [LB, LB]], [RA]]]
BIND = ["bind", "localFrag", "remoteFrag", KEY.decode()]
COUNT = 0


def tx(n):
    return struct.pack("!III", n, 2, 3)


def incoming(n=90, nominate=True, controlling=True, fragment="remoteFrag", tie=2,
             mode="dual", key=LOCAL_KEY):
    body = attr(6, b"localFrag:" + fragment.encode()) + attr(0x24, struct.pack("!I", 1845494271))
    body += attr(0x802A if controlling else 0x8029, struct.pack("!Q", tie))
    if nominate:
        body += attr(0x25, b"")
    return sign(packet(body, transaction=tx(n)), key, mode)


def response(n, address=MAP, mode="legacy", error=0, key=KEY):
    body = attr(9, bytes((0, 0, error // 100, error % 100)) + b"Error") if error else attr(
        0x20, b"\x00\x01" + struct.pack("!H", address[4] ^ 0x2112)
        + bytes(a ^ b for a, b in zip(address[:4], COOKIE)))
    return sign(packet(body, kind=0x111 if error else 0x101, transaction=tx(n)), key, mode)


def receive(raw, now=0, base=LA[4], remote=RA[4], sid=1):
    return ["receive", now, sid, 1, base, remote, list(raw)]


def lines(frame, prefix):
    return [s for s in frame if s.startswith(prefix)]


def run(steps, streams=STREAMS, mode="dual", capacity=4, limit=100, valid_limit=100):
    global COUNT
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "fixture.json"
        p.write_text(json.dumps([streams, mode, capacity, limit, valid_limit, steps]))
        result = subprocess.run(COMMAND + [str(p)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, (result.stderr, result.stdout)
    frames, frame = [], []
    for line in result.stdout.splitlines():
        if line in ("changed", "rejected"):
            frames.append(frame)
            frame = [line]
        else:
            frame.append(line)
    frames.append(frame)
    assert len(frames) == len(steps) + 1, result.stdout
    assert all("nomination-fault:0" in f for f in frames), result.stdout
    # This layer carries evidence and leaves nomination outcome application open.
    assert all(s.endswith(":0") for f in frames for s in lines(f, "valid:"))
    COUNT += 1
    return frames


def addr(address):
    return ".".join(map(str, address[:4])) + "/" + str(address[4])


def ref(base=LA[4], remote=RA[4], sid=1):
    return f"{sid}:1:{addr(base)}:{addr(remote)}"


def associated(frame, base=LA[4], remote=RA[4], sid=1):
    found = lines(frame, "resolved:" + ref(base, remote, sid) + ":")
    assert len(found) == 1, frame
    return found[0].split(":", 5)[-1]


def request_suffix(n=90, fragment="remoteFrag", controlling=True, tie=2, mode="dual"):
    mode = "sha256" if mode == "dual" else mode
    return f"{tx(n).hex()}:{fragment}:1845494271:{'controlling' if controlling else 'controlled'}:0:{tie}:1:{mode}"


def bound(frame, token=0, request=90):
    found = lines(frame, f"intent-binding:{token}:7:")
    assert len(found) == 1 and found[0].endswith(request_suffix(request)), frame
    assert f":controlled:0:1:0:{tx(token + 1).hex()}:" in found[0], frame
    return found[0]


def raw_send(frame):
    found = lines(frame, "send:")
    assert len(found) == 1, frame
    return bytes.fromhex(found[0].split(":")[-1])


# Successful current checks associate both original and represented counterparts;
# mapped reflexive addresses remain distinct from the base transport reference.
for mode in ("legacy", "sha256", "dual"):
    reply_mode = "legacy" if mode == "legacy" else "sha256"
    for address, streams, link_count in ((LA[4], STREAMS, 1), (MAP, STREAMS, 1),
                                         (MAP, [[1, [[REFLEXIVE, LA]], [RA]]], 1),
                                         (LB[4], TWO_BASES, 2)):
        f = run([BIND, ["start", 0, 1, 2], ["ack", 0], receive(response(1, address, reply_mode), 20)], streams, mode)
        assert len(lines(f[-1], "association:")) == link_count
        assert addr(address) in associated(f[-1])
        if link_count == 2:
            assert addr(address) in associated(f[-1], LB[4])
        assert ":0:7:" + ref() + ":controlling:0:1:" in associated(f[-1])

# A late original success learns another valid path without replacing the path
# proven by the current attempt. The old listener's endpoint identity is equal.
ordinary = incoming(nominate=False, controlling=False)
steps = [BIND, ["start", 0, 1, 2], ["ack", 0], receive(ordinary, 10), ["start", 50, 2, 2], ["ack", 50],
         receive(response(2, OTHER_MAP), 60), receive(response(1, MAP), 70)]
f = run(steps)
assert len(lines(f[-1], "valid:")) == 2 and addr(OTHER_MAP) in associated(f[-1])
assert ":1:7:" + ref() in associated(f[-1]) and not lines(f[-1], "intent-map:")

# If a late path enters first, V retains its old origin on duplicate insertion.
# The association must return the newer generating record, not that old origin.
f = run(steps[:-2] + [receive(response(1, MAP), 60), receive(response(2, MAP), 70)])
assert ":0:7:" + ref() in lines(f[-1], "valid:")[0]
assert ":1:7:" + ref() in associated(f[-1])

# Current A maps B, completing and stopping active B. Late B cannot replace the
# counterpart's association with the mapping produced by its interrupted check.
f = run([BIND, ["start", 0, 1, 2], ["ack", 0], ["start", 50, 2, 2], ["ack", 50],
         receive(response(1, LB[4]), 60), receive(response(2, MAP), 70, base=LB[4])], TWO_BASES)
assert len(lines(f[-1], "association:")) == 2
assert addr(LB[4]) in associated(f[-1], LB[4]) and ":0:7:" + ref() in associated(f[-1], LB[4])

# Direct and pre-answer accepted intent is qualified only after materialization
# with matching signaled credentials. The triggered controlled request itself
# contains no USE-CANDIDATE, and its original incoming request remains exact.
for mode in ("legacy", "sha256", "dual"):
    for preanswer in (False, True):
        q = receive(incoming(mode=mode))
        prefix = [q, BIND] if preanswer else [BIND, q]
        f = run(prefix + [["start", 0, 1, 2], ["ack", 0], ["tick", 500], receive(response(1, mode="legacy" if mode == "legacy" else "sha256"), 600)], mode=mode)
        if preanswer:
            assert lines(f[1], "pending:") and not lines(f[1], "intent:")
        assert len(lines(f[2], "intent:")) == 1 and lines(f[2], "intent:")[0].endswith(request_suffix(mode=mode))
        found = lines(f[3], "intent-binding:")
        assert len(found) == 1 and found[0].endswith(request_suffix(mode=mode))
        assert not any(k == 0x25 for k, _, _ in validate(raw_send(f[3]), KEY, mode))
        assert raw_send(f[3]) == raw_send(f[5])
        assert len(lines(f[5], "intent-binding:")) == 1
        assert not lines(f[-1], "intent-binding:")
        assert lines(f[-1], "intent-map:0:") and lines(f[-1], "intent-outcome:")

# The Succeeded counterpart resolves to the path from A, even though its
# associated generating reference is A and incoming USE-CANDIDATE arrives at B.
f = run([BIND, ["start", 0, 1, 2], ["ack", 0], receive(response(1, LB[4]), 20),
         receive(incoming(), 30, base=LB[4])], TWO_BASES)
assert lines(f[-1], "intent:") and ref(LB[4]) in lines(f[-1], "intent:")[0]
assert addr(LB[4]) in associated(f[-1], LB[4]) and ":0:7:" + ref() in associated(f[-1], LB[4])
assert not lines(f[-1], "flight:") and not lines(f[-1], "intent-binding:")

# Ordinary packets do not acquire old queued intent. An applied ordinary request
# supersedes an unbound nomination on the same reference before selection.
f = run([BIND, receive(incoming()), receive(incoming(91, nominate=False), 10), ["start", 0, 1, 2]])
assert lines(f[2], "intent:") and not lines(f[3], "intent:") and not lines(f[-1], "intent-binding:")
f = run([BIND, receive(incoming()), receive(incoming(91), 10), ["start", 0, 1, 2]])
assert len(lines(f[3], "intent:")) == 1 and lines(f[3], "intent:")[0].endswith(request_suffix(91))
bound(f[-1], request=91)

# Controlled USE-CANDIDATE is rejected by the parser and cannot poison later
# accepted intent. Ordinary pre-answer requests preserve the actual later UC;
# subsequent ordinary controlling requests preserve the earlier actual UC.
f = run([receive(incoming(controlling=False)), receive(incoming(91)), BIND, ["start", 0, 1, 2]])
assert lines(f[1], "reply:") and not lines(f[1], "pending:") and not lines(f[1], "accepted:")
bound(f[-1], request=91)
f = run([receive(incoming(nominate=False, controlling=False)), receive(incoming(91)), BIND, ["start", 0, 1, 2]])
bound(f[-1], request=91)
f = run([receive(incoming()), receive(incoming(91, nominate=False)), BIND, ["start", 0, 1, 2]])
bound(f[-1], request=90)

# Wrong fragments have independent pending entries. Binding filters them before
# resolving Applied, including a same-reference ordinary request for the peer.
for nominate in (False, True):
    f = run([receive(incoming(fragment="wrongFrag")), receive(incoming(91, nominate=nominate)), BIND, ["start", 0, 1, 2]])
    assert not lines(f[3], "pending:") and lines(f[3], "unbound:")
    if nominate:
        bound(f[-1], request=91)
    else:
        assert not lines(f[3], "intent:") and not lines(f[-1], "intent-binding:")

# A bad MAC cannot introduce intent; invalid response integrity cannot consume
# already bound intent or emit a nomination outcome/mapping.
f = run([BIND, receive(incoming(key=b"WrongLocalPassword123456")), ["start", 0, 1, 2]])
assert not lines(f[2], "intent:") and not lines(f[-1], "intent-binding:")
f = run([BIND, receive(incoming()), ["start", 0, 1, 2], ["ack", 0],
         receive(response(1, key=b"WrongRemotePassword123456"), 20), receive(response(1), 30)])
bound(f[5]); assert not lines(f[5], "intent-outcome:") and not lines(f[5], "intent-map:")
assert lines(f[-1], "intent-map:0:")

# A replacement ordinary check cannot inherit its predecessor's nomination.
# The old response-only listener retains the actual incoming intent separately.
steps = [BIND, receive(incoming()), ["start", 0, 1, 2], ["ack", 0], receive(incoming(91, nominate=False), 10),
         ["start", 50, 2, 2], ["ack", 50], receive(response(1, MAP), 60), receive(response(2, OTHER_MAP), 70)]
f = run(steps, limit=1)
bound(f[6]); assert not lines(f[6], "intent-binding:1:")
assert lines(f[8], "intent-map:1:") and request_suffix() in lines(f[8], "intent-map:")[0]
assert lines(f[8], "flight:1:") and not lines(f[8], "association:")
assert not lines(f[-1], "intent-map:") and addr(OTHER_MAP) in associated(f[-1])

# A newer actual nomination gets a separate binding even with a one-pair limit.
# Late outcomes for the older listener retain its request; the current flight
# later resolves the newer request and becomes the association's origin.
steps[4] = receive(incoming(91), 10)
f = run(steps, limit=1)
bound(f[6]); bound(f[6], token=1, request=91)
assert len(lines(f[6], "intent-binding:")) == 2
assert request_suffix(90) in lines(f[8], "intent-map:")[0]
assert request_suffix(91) in lines(f[-1], "intent-map:0:")[0]
assert ":1:7:" + ref() in associated(f[-1])

# Interrupted listeners retain their original deadline and expire without a
# mapping or completion of the newer active attempt.
f = run(steps[:7] + [["tick", 1000]], limit=1)
assert lines(f[-1], "retired:0:") and lines(f[-1], "intent-outcome:0:")
assert not lines(f[-1], "intent-map:") and not lines(f[-1], "intent-binding:0:")
assert lines(f[-1], "flight:1:") and lines(f[-1], "intent-binding:1:")

# Unrecoverable current errors and timeouts carry the original qualified
# request, then retire its binding; recoverable 487 retains it until role repair.
for suffix in ([receive(response(1, error=400), 20)], [["tick", 500], ["tick", 1000]]):
    f = run([BIND, receive(incoming()), ["start", 0, 1, 2], ["ack", 0]] + suffix)
    assert lines(f[-1], "intent-outcome:0:") and not lines(f[-1], "intent-binding:")
    assert not lines(f[-1], "intent-map:") and not lines(f[-1], "association:")
f = run([BIND, receive(incoming()), ["start", 0, 1, 2], ["ack", 0], receive(response(1, error=487), 20),
         ["repair", 0, 7, 0, 5]])
bound(f[5]); assert lines(f[5], "intent-outcome:0:") and not lines(f[-1], "intent-binding:")
assert not lines(f[-1], "intent:")

# A non-symmetric authenticated response preserves nomination failure ownership.
f = run([BIND, receive(incoming()), ["start", 0, 1, 2], ["ack", 0],
         receive(response(1), 20, base=LB[4])], TWO_BASES)
assert lines(f[-1], "intent-non-symmetric:1:") and not lines(f[-1], "intent-binding:")
assert not lines(f[-1], "intent-map:")

# Listener capacity cannot consume queued intent or bind a speculative flight.
f = run(steps[:5] + [["start", 50, 2, 2], ["tick", 1000], ["start", 1000, 2, 2]], capacity=1, limit=1)
assert "capacity" in f[6] and lines(f[6], "intent:") and not lines(f[6], "intent-binding:1:")
bound(f[-1], token=1, request=91)

# Signaled role changes clear queued controlled-side intent, while sent role
# metadata remains authoritative for an already bound listener's late outcome.
f = run([BIND, receive(incoming()), receive(incoming(91, nominate=False, controlling=False, tie=0), 10), ["start", 0, 1, 2]])
assert not lines(f[3], "intent:") and not lines(f[-1], "intent-binding:")

# Generation replacement is a synthetic owner boundary test. It drops all old
# links/intent/bindings; this does not exercise a complete credential restart.
for prefix in ([BIND, receive(incoming()), ["start", 0, 1, 2], ["ack", 0]],
               [BIND, ["start", 0, 1, 2], ["ack", 0], receive(response(1), 20)]):
    f = run(prefix + [["synthetic-generation", 8], ["lookup", 1, 1, LA[4], RA[4]]])
    assert not lines(f[-1], "association:") and not lines(f[-1], "intent:") and not lines(f[-1], "intent-binding:")
    assert lines(f[-1], "lookup:") == ["lookup:none"]

# Generation guarding must not depend on the core having removed old records.
# This deliberately inconsistent synthetic core retains old flights/listeners.
f = run([BIND, receive(incoming()), ["start", 0, 1, 2], ["ack", 0],
         ["synthetic-retained-generation", 8]])
assert lines(f[-1], "record:0:7:") and not lines(f[-1], "intent-binding:")

# Fresh creation is explicit. Rewrapping a bound/running session loses evidence
# and is rejected rather than fabricating associations from retained path data.
f = run([["recreate"], BIND, ["recreate"], ["start", 0, 1, 2], ["recreate"], ["ack", 0],
         receive(response(1), 20), ["recreate"]])
assert f[1][0] == "changed" and all(f[i][0] == "rejected" for i in (3, 5, 8))

# Lookup scopes stream, component, base and peer exactly.
queries = [["lookup", 2, 1, LA[4], RA[4]], ["lookup", 1, 2, LA[4], RA[4]],
           ["lookup", 1, 1, LB[4], RA[4]], ["lookup", 1, 1, LA[4], RB[4]]]
f = run([BIND, ["start", 0, 1, 2], ["ack", 0], receive(response(1), 20)] + queries)
assert all(lines(frame, "lookup:") == ["lookup:none"] for frame in f[-4:])

# A later invalid mapping quarantines the valid owner. Earlier live links remain
# inspectable evidence, but cannot supply a nomination path through path_for.
f = run([BIND, ["start", 0, 1, 2], ["ack", 0], receive(response(1, LA[4]), 20),
         ["start", 50, 2, 2], ["ack", 50], receive(response(2, [0, 0, 0, 0, 0]), 60, base=LB[4]),
         ["lookup", 1, 1, LA[4], RA[4]]], TWO_BASES)
assert "valid-fault:1" in f[-1] and lines(f[-1], "lookup:") == ["lookup:none"]

print(f"ICE nomination evidence: {COUNT} current-path/pending-intent/flight/role/late/generation cases passed")
