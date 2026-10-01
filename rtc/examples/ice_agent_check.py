"""Independent authenticated ICE nomination/lifecycle scenarios on compiled Bend."""
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
RB = [1, 2100000100, "otherPeer", "host", [127, 0, 0, 1, 20002]]
MAP = [203, 0, 113, 5, 31001]
OTHER_MAP = [203, 0, 113, 6, 31002]
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


def response(n, address=MAP, mode="sha256", error=0, key=KEY):
    body = attr(9, bytes((0, 0, error // 100, error % 100)) + b"Error") if error else attr(
        0x20, b"\x00\x01" + struct.pack("!H", address[4] ^ 0x2112)
        + bytes(a ^ b for a, b in zip(address[:4], COOKIE)))
    return sign(packet(body, kind=0x111 if error else 0x101, transaction=tx(n)), key, mode)


def receive(raw, now=0, base=LA[4], remote=RA[4], sid=1, comp=1):
    return ["receive", now, sid, comp, base, remote, list(raw)]


def lines(frame, prefix):
    return [s for s in frame if s.startswith(prefix)]


def run(steps, streams=STREAMS, mode="dual", capacity=4, limit=100, valid_limit=100,
        pac=39500, automatic=True):
    global COUNT
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "fixture.json"
        p.write_text(json.dumps([streams, mode, capacity, limit, valid_limit, pac, automatic, steps]))
        result = subprocess.run(COMMAND + [str(p)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, (result.stderr, result.stdout)
    frames, frame = [], []
    for line in result.stdout.splitlines():
        if line in ("changed", "rejected"):
            frames.append(frame)
            frame = [line]
        else:
            frame.append(line)
    frames.append(frame)
    assert len(frames) == len(steps) + 1, (steps, result.stdout)
    assert not any("invalid" == line for frame in frames for line in frame), result.stdout
    COUNT += 1
    return frames


def state(frame, expected):
    assert lines(frame, "agent-status:") == ["agent-status:" + expected], frame


def raw_send(frame):
    found = lines(frame, "send:")
    assert len(found) == 1, frame
    return bytes.fromhex(found[0].split(":")[-1])


def use_candidate(frame, wanted, mode="dual"):
    assert any(k == 0x25 for k, _, _ in validate(raw_send(frame), KEY, mode)) == wanted, frame


def addr(a):
    return ".".join(map(str, a[:4])) + "/" + str(a[4])


def selected(frame, address=MAP, sid=1, comp=1):
    found = lines(frame, f"selected:{sid}:{comp}:")
    assert len(found) == 1 and addr(address) in found[0] and found[0].endswith(":1"), frame
    return found[0]


ORDINARY = [BIND, ["signal", 0], ["start", 0, 1, 2], ["ack", 0], receive(response(1), 20)]

# Ordinary success remains valid-only. A fresh repeat carries USE-CANDIDATE and
# its authenticated response nominates the actual returned mapping.
for mode in ("legacy", "sha256", "dual"):
    reply_mode = "legacy" if mode == "legacy" else "sha256"
    prefix = [BIND, ["signal", 0], ["start", 0, 1, 2], ["ack", 0], receive(response(1, mode=reply_mode), 20)]
    for mapped in (MAP, OTHER_MAP, LA[4]):
        f = run(prefix + [["start", 50, 2, 2], ["ack", 50], ["tick", 550],
                          receive(response(2, mapped, reply_mode), 600), ["start", 650, 3, 2]], mode=mode)
        state(f[5], "running")
        assert lines(f[5], "valid:")[0].endswith(":0") and not lines(f[5], "nominated:")
        use_candidate(f[3], False, mode)
        use_candidate(f[6], True, reply_mode)
        assert raw_send(f[6]) == raw_send(f[8])
        selected(f[9], mapped)
        state(f[9], "completed")
        assert not lines(f[9], "pair:") and not lines(f[9], "flight:") and not lines(f[10], "send:")
        assert len(lines(f[9], "nominated:")) == 1

# Manual policy resolves owned proof, queues once, and rejects a second plan.
f = run(ORDINARY + [["nominate", 1, 1], ["nominate", 1, 1], ["start", 50, 2, 2],
                    ["ack", 50], receive(response(2), 60)], automatic=False)
assert f[7][0] == "rejected" and len(lines(f[6], "plan:")) == 1
use_candidate(f[8], True, "sha256")
selected(f[-1])

# The generating check A can produce a represented mapped local B; repeat A,
# even though B's base/candidate metadata is retained in the valid identity.
f = run([BIND, ["start", 0, 1, 2], ["ack", 0], receive(response(1, LB[4]), 20),
         ["start", 50, 2, 2], ["ack", 50], receive(response(2, LB[4]), 60)], TWO_BASES)
assert ":127.0.0.1/10001:127.0.0.1/20001:" in lines(f[5], "plan:")[0], f[5]
selected(f[-1], LB[4])
assert "other:" in selected(f[-1], LB[4]), f[-1]

# Deferred admission leaves the plan and scheduler reference available. A later
# Ta opportunity admits exactly one nomination; a premature start is ordinary-free.
f = run(ORDINARY + [["start", 25, 2, 2], ["start", 50, 2, 2], ["ack", 50], receive(response(2), 60)])
assert len(lines(f[6], "plan:")) == 1 and not lines(f[6], "send:")
use_candidate(f[7], True, "sha256")
selected(f[-1])

# Controlled nomination binds the actual authenticated request before its check;
# pre-answer requests wait for matching remote credentials. Its check has no UC.
for mode in ("legacy", "sha256", "dual"):
    reply_mode = "legacy" if mode == "legacy" else "sha256"
    for preanswer in (False, True):
        q = receive(incoming(mode=mode))
        prefix = [q, ["signal", 0], BIND] if preanswer else [BIND, ["signal", 0], q]
        f = run(prefix + [["start", 0, 1, 2], ["ack", 0], receive(response(1, mode=reply_mode), 20)], mode=mode)
        use_candidate(f[4], False, mode)
        selected(f[-1])
        state(f[-1], "completed")
        assert len(lines(f[-1], "nominated:")) == 1

# A succeeded check is associated with its valid mapping, and accepting UC
# nominates immediately, without an extra outgoing check.
f = run([BIND, receive(incoming(nominate=False), 0), ["start", 0, 1, 2], ["ack", 0],
         receive(response(1), 20), receive(incoming(91), 30)])
selected(f[-1])
assert not lines(f[-1], "send:") and len(lines(f[-1], "nominated:")) == 1

# Controlled UC on a Succeeded represented B counterpart resolves the mapping
# generated by A, preserving B's local/base metadata and removing both pairs.
f = run([BIND, receive(incoming(nominate=False), 0), ["start", 0, 1, 2], ["ack", 0],
         receive(response(1, LB[4]), 20), receive(incoming(91), 30, base=LB[4])], TWO_BASES)
selected(f[-1], LB[4])
assert not lines(f[-1], "pair:") and not lines(f[-1], "send:")

# PAC starts only after both signaling gates, starts once in either order, and
# cannot be extended by duplicate signals, binds, invalid packets or ticks.
NO_PEERS = [[1, [[LA, LA]], []]]
for ordering in ((["signal", 100], BIND), (BIND, ["signal", 100])):
    f = run(list(ordering) + [["signal", 200], BIND, ["tick", 39599], ["tick", 39600]], NO_PEERS)
    assert not lines(f[1], "pac-started:") and lines(f[2], "pac-started:") == ["pac-started:39600"]
    assert lines(f[3], "pac:") == ["pac:started:39600"] and not lines(f[4], "pac-started:")
    state(f[5], "running")
    state(f[6], "failed")
    assert lines(f[6], "pac-expired") == ["pac-expired"]
f = run([BIND, ["tick", 100000]], NO_PEERS)
state(f[-1], "running")
assert lines(f[-1], "pac:") == ["pac:dormant:0"]
f = run([["signal", 0], BIND, ["tick", 99], ["tick", 100]], NO_PEERS, pac=100)
state(f[-2], "running")
state(f[-1], "failed")

# An interrupted controlled nomination failure can recover during PAC after a
# new authenticated request/check, but the failure cannot nominate the old path.
f = run([BIND, ["signal", 0], receive(incoming(), 0), ["start", 0, 1, 2], ["ack", 0],
         receive(response(1, error=500), 20), receive(incoming(91), 30), ["start", 50, 2, 2],
         ["ack", 50], receive(response(2), 60)])
assert lines(f[6], "nomination-failed:") and not lines(f[6], "valid:")
selected(f[-1])
state(f[-1], "completed")

# All valid but unnominated paths can await nomination after PAC expires.
f = run(ORDINARY + [["tick", 39500]], automatic=False)
state(f[-1], "running")
assert lines(f[-1], "valid:") and not lines(f[-1], "nominated:")

# Ordinary exhaustion and even a PAC expiry observed during start obey the same
# session boundary; a failed stream stops checks on the other stream as well.
f = run([BIND, ["signal", 0], ["start", 0, 1, 1], ["ack", 0], ["tick", 500],
         ["tick", 39499], ["start", 39500, 2, 2]])
state(f[-2], "running")
state(f[-1], "failed")
assert not lines(f[-1], "send:")
f = run([BIND, ["signal", 0], ["start", 0, 1, 2], ["ack", 0], ["tick", 100], ["start", 150, 2, 2]],
        NO_PEERS + [[2, [[LB, LB]], [RA]]], pac=100)
state(f[5], "failed")
assert lines(f[5], "stopped:") and not lines(f[5], "pair:") and not lines(f[5], "flight:")
assert not lines(f[6], "send:")

# Capacity and invalid-mapping faults abort the owner explicitly; they are not
# premature ICE failures. Every other flight stops, with original listeners kept.
for mapped in (OTHER_MAP, [0, 0, 0, 0, 0]):
    prefix = [BIND, ["signal", 0], ["start", 0, 1, 2], ["ack", 0], receive(response(1), 20),
              ["start", 50, 2, 2], ["ack", 50], receive(response(2, mapped), 60)]
    f = run(prefix + [["start", 100, 3, 2]], valid_limit=1)
    state(f[8], "faulted")
    assert lines(f[8], "session-changed:") == ["session-changed:faulted"]
    assert lines(f[8], "pac:") == ["pac:started:39500"] and not lines(f[8], "pair:")
    assert lines(f[8], "stream-status:") == ["stream-status:1:running:1,:"]
    assert not lines(f[9], "send:") and lines(f[8], "selected:1:1:") == ["selected:1:1:none"]
f = run([BIND, ["signal", 0], ["start", 0, 1, 2], ["ack", 0], ["start", 50, 2, 2], ["ack", 50],
         receive(response(1), 60), ["start", 100, 3, 2], ["ack", 100], receive(response(3, OTHER_MAP), 110, sid=1)],
        STREAMS + [[2, [[LB, LB]], [RA]]], valid_limit=1)
state(f[-1], "faulted")
assert lines(f[-1], "stopped:") and not lines(f[-1], "flight:") and not lines(f[-1], "pair:")

# Unrecoverable current nomination outcomes remove the selected valid identity.
# Their checklist failure is deferred by PAC, not converted into success.
for error in (400, 500):
    f = run(ORDINARY + [["start", 50, 2, 2], ["ack", 50], receive(response(2, error=error), 60),
                        ["tick", 39499], ["tick", 39500]])
    assert len(lines(f[8], "nomination-failed:")) == 1 and not lines(f[8], "valid:")
    state(f[9], "running")
    state(f[10], "failed")
f = run(ORDINARY + [["start", 50, 2, 1], ["ack", 50], ["tick", 550], ["tick", 39500]])
assert lines(f[8], "nomination-failed:") and not lines(f[8], "valid:")
state(f[-1], "failed")
f = run(ORDINARY + [["start", 50, 2, 2], ["fail", 1, 5], ["tick", 39500]])
assert lines(f[7], "nomination-failed:")
state(f[-1], "failed")
f = run([BIND, ["signal", 0], ["start", 0, 1, 2], ["ack", 0], receive(response(1, LB[4]), 20),
         ["start", 50, 2, 2], ["ack", 50], receive(response(2, error=500), 60)], TWO_BASES)
assert len(lines(f[-1], "pair:")) == 2 and all(s.endswith(":4") for s in lines(f[-1], "pair:")), f[-1]
assert not lines(f[-1], "valid:")

# A failed session serves Binding without recreating a checklist or accepting UC.
f = run([["signal", 0], BIND, ["tick", 39500], receive(incoming(nominate=False), 39510),
         receive(incoming(), 39520), ["start", 39600, 1, 2]], NO_PEERS)
assert not lines(f[-1], "send:") and not lines(f[-2], "pair:") and not lines(f[-3], "pair:")
assert ":400:" in lines(f[-2], "reply:")[0]

# Recoverable 487 requires role repair; it neither nominates nor fails PAC.
f = run(ORDINARY + [["start", 50, 2, 2], ["ack", 50], receive(response(2, error=487), 60),
                    ["repair", 1, 7, 0, 3], ["start", 100, 3, 2]])
assert not lines(f[8], "nomination-failed:") and lines(f[8], "plan:")
assert not lines(f[9], "plan:")
use_candidate(f[10], False, "sha256")

# Authentication failures cannot nominate. An authenticated non-symmetric current
# response fails only its nomination, while unrelated traffic leaves it active.
f = run(ORDINARY + [["start", 50, 2, 2], ["ack", 50], receive(response(2, key=b"WrongPassword123456789000"), 60)])
state(f[-1], "running")
assert not lines(f[-1], "nominated:") and not lines(f[-1], "nomination-failed:")
f = run(ORDINARY + [["start", 50, 2, 2], ["ack", 50], receive(response(2), 60, remote=RB[4])])
assert lines(f[-1], "nomination-failed:") and not lines(f[-1], "nominated:")
f = run([BIND, ["signal", 0], ["start", 0, 1, 2], ["ack", 0], receive(response(1), 20),
         ["start", 50, 2, 2], ["ack", 50], receive(response(2), 60, base=LB[4])], TWO_BASES)
assert lines(f[-1], "nomination-failed:") and not lines(f[-1], "nominated:")

# Old interrupted errors never fail a replacement. A retained signed UC success
# may conclude the component, explicitly stopping the replacement's retries.
interrupt = receive(incoming(nominate=False, controlling=False), 60)
prefix = ORDINARY + [["start", 50, 2, 2], ["ack", 50], interrupt, ["start", 100, 3, 2], ["ack", 100]]
f = run(prefix + [receive(response(2, error=500), 110), receive(response(3), 120)])
assert not lines(f[11], "nomination-failed:") and lines(f[11], "flight:")
selected(f[12])
f = run(prefix + [receive(response(2), 110), ["tick", 600], receive(response(3, OTHER_MAP), 610)])
selected(f[11])
assert lines(f[11], "stopped:") and not lines(f[12], "send:")
assert len(lines(f[13], "valid:")) == 2 and not lines(f[13], "nominated:")

# Concluded components keep the Binding server active without check recreation.
# Repeated nominations on the accepted path succeed; new paths are protected400.
finished = ORDINARY + [["start", 50, 2, 2], ["ack", 50], receive(response(2), 60)]
for q, remote, code in ((incoming(nominate=False, controlling=False), RB[4], 0),
                        (incoming(controlling=True, tie=2), RA[4], 0),
                        (incoming(controlling=True, tie=2), RB[4], 400)):
    f = run(finished + [receive(q, 70, remote=remote), ["start", 100, 3, 2]])
    replies = lines(f[9], "reply:")
    assert len(replies) == 1 and f":{code}:" in replies[0], f[9]
    validate(bytes.fromhex(replies[0].split(":")[-1]), LOCAL_KEY, "sha256")
    assert not lines(f[9], "applied:") and not lines(f[9], "pair:") and not lines(f[10], "send:")

# Required components and streams complete separately. Selection is exposed
# once every component of that stream is nominated, with unrelated work intact.
LC = [2, 2130706430, "host2", "host", [127, 0, 0, 1, 10003]]
RC = [2, 2099999900, "remote2", "host", [127, 0, 0, 1, 20003]]
multi = [[1, [[LA, LA], [LC, LC]], [RA, RC]], [2, [[LB, LB]], [RA]]]
f = run([BIND, ["start", 0, 1, 2], ["ack", 0], receive(response(1), 20),
         ["start", 50, 2, 2], ["ack", 50], receive(response(2, LB[4]), 60, base=LB[4], sid=2),
         ["start", 100, 3, 2], ["ack", 100], receive(response(3), 110),
         ["start", 150, 4, 2], ["ack", 150], receive(response(4, LB[4]), 160, base=LB[4], sid=2),
         ["start", 200, 5, 2], ["ack", 200], receive(response(5, LC[4]), 210, base=LC[4], remote=RC[4], comp=2),
         ["start", 250, 6, 2], ["ack", 250], receive(response(6, LC[4]), 260, base=LC[4], remote=RC[4], comp=2)], multi)
state(f[10], "running")
use_candidate(f[8], True, "sha256")
use_candidate(f[11], True, "sha256")
assert lines(f[10], "selected:1:1:") == ["selected:1:1:none"]
selected(f[13], LB[4], sid=2)
state(f[13], "running")
selected(f[-1])
selected(f[-1], LC[4], comp=2)
state(f[-1], "completed")

# Multiple UC checks accepted before conclusion can finish via retained listeners;
# legacy aggressive nomination selects the highest-ranked nominated identity.
f = run([BIND, receive(incoming(90), 0), ["start", 0, 1, 2], ["ack", 0],
         receive(incoming(91), 10, remote=RB[4]), ["start", 50, 2, 2], ["ack", 50],
         receive(response(1), 60), receive(response(2, OTHER_MAP), 70, remote=RB[4])],
        [[1, [[LA, LA]], [RA, RB]]])
assert len(lines(f[-1], "valid:")) == 2 and all(s.endswith(":1") for s in lines(f[-1], "valid:"))
selected(f[-1], OTHER_MAP)
assert "127.0.0.1/20002" in selected(f[-1], OTHER_MAP)

print(f"ICE agent nomination/lifecycle: {COUNT} scenarios passed")
