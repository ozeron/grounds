"""Independent checks of original-pair repeat scheduling and signed intent.

This verifies nomination request plumbing, not nominated/selected agent state.
"""
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
COUNT = 0
LA = [1, 2130706431, "host", "host", [127, 0, 0, 1, 10001]]
LB = [1, 2130706175, "other", "host", [127, 0, 0, 1, 10002]]
RA = [1, 2100000000, "remote", "host", [127, 0, 0, 1, 20001]]
RB = [1, 2099999999, "otherPeer", "host", [127, 0, 0, 1, 20002]]
MAPPED = [203, 0, 113, 5, 31001]
REFLEXIVE = [1, 1677721855, "srflx", "srflx", MAPPED]
STREAMS = [[1, [[LA, LA]], [RA]]]
BIND = ["bind", "localFrag", "remoteFrag", KEY.decode()]


def tx(n):
    return struct.pack("!III", n, 2, 3)


def response(n, address=MAPPED, mode="legacy", error=0):
    body = attr(9, bytes((0, 0, error // 100, error % 100)) + b"Error") if error else attr(
        0x20, b"\x00\x01" + struct.pack("!H", address[4] ^ 0x2112)
        + bytes(a ^ b for a, b in zip(address[:4], COOKIE)))
    return sign(packet(body, kind=0x111 if error else 0x101, transaction=tx(n)), KEY, mode)


def incoming(control=False):
    body = attr(6, b"localFrag:remoteFrag") + attr(0x24, struct.pack("!I", 1845494271))
    body += attr(0x802A if control else 0x8029, struct.pack("!Q", 2))
    return sign(packet(body, transaction=tx(90)), LOCAL_KEY, "dual")


def receive(raw, now, base=LA[4], remote=RA[4], sid=1):
    return ["receive", now, sid, 1, base, remote, list(raw)]


def start(n=2, now=50, base=LA[4], remote=RA[4], sid=1):
    return ["start-intent", now, n, 2, sid, 1, base, remote]


def run(steps, streams=STREAMS, mode="dual", capacity=4):
    global COUNT
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "fixture.json"
        p.write_text(json.dumps([streams, mode, capacity, 100, 100, steps]))
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
    assert len(frames) == len(steps) + 1
    COUNT += 1
    return frames


def lines(frame, prefix):
    return [s for s in frame if s.startswith(prefix)]


def sent(frame):
    sends = lines(frame, "send:")
    assert len(sends) == 1, frame
    return bytes.fromhex(sends[0].split(":")[-1])


def expected(n, priority, mode, nominate=True, controlling=True, tie=1):
    body = attr(6, b"remoteFrag:localFrag") + attr(0x24, struct.pack("!I", priority))
    body += attr(0x802A if controlling else 0x8029, struct.pack("!Q", tie))
    if nominate:
        body += attr(0x25, b"")
    return sign(packet(body, transaction=tx(n)), KEY, mode)


def ordinary_success(address=MAPPED, response_mode="legacy"):
    return [BIND, ["start", 0, 1, 2], ["ack", 0], receive(response(1, address, response_mode), 20)]


# Repeat the ORIGINAL pair even for a reflexive or different known host map.
# Negotiated response integrity selects the next request, while retries retain
# its complete signed USE-CANDIDATE bytes and transaction.
for mode in ("legacy", "sha256", "dual"):
    negotiated = "legacy" if mode == "legacy" else "sha256"
    for address, streams in ((LA[4], STREAMS), (MAPPED, STREAMS),
                             (MAPPED, [[1, [[REFLEXIVE, LA]], [RA]]]),
                             (LB[4], [[1, [[LA, LA], [LB, LB]], [RA]]])):
        steps = ordinary_success(address, negotiated) + [["queue-nomination", 0], start(), ["ack", 50], ["tick", 550],
                                                         receive(response(2, address, negotiated), 600)]
        f = run(steps, streams, mode)
        assert lines(f[5], "queued:") == ["queued:1:1:127.0.0.1/10001:127.0.0.1/20001"]
        p = (110 << 24) + (LA[1] & 0xFFFF00) + 255
        raw = sent(f[6])
        assert raw == expected(2, p, negotiated) == sent(f[8])
        fields = validate(raw, KEY, negotiated)
        assert sum(k == 0x25 for k, _, _ in fields) == 1
        assert any(s.startswith(f"request-info:{p}:1:") for s in f[6])
        assert lines(f[9], "finished:1:success-")
        # The request layer does not claim nominated/selected agent state.
        assert all(s.endswith(":0") for s in lines(f[-1], "valid:"))

# Intent targets exact stream/component/base/peer identity, not whichever pair
# happens to be selected. A mismatched target sends an ordinary check.
for target in (start(base=LB[4]), start(remote=RB[4]), start(sid=2)):
    f = run(ordinary_success() + [["queue-nomination", 0], target])
    assert sent(f[-1]) == expected(2, 1862270975, "legacy", nominate=False)

# A paced attempt cannot consume the queue, state, allocator or intent bytes.
f = run(ordinary_success() + [["queue-nomination", 0], start(now=49), start(now=50)])
assert lines(f[-2], "waiting:") == ["waiting:50"] and not lines(f[-2], "send:")
assert lines(f[-2], "queued:") == lines(f[-3], "queued:")
assert sent(f[-1]) == expected(2, 1862270975, "legacy")

# Interrupted nomination retries become listeners with the original protected
# flag intact. A late original outcome does not complete its newer flight.
steps = ordinary_success() + [["queue-nomination", 0], start(), ["ack", 50],
                             receive(incoming(), 60), ["queue-nomination", 0], start(3, 100), ["ack", 100],
                             receive(response(2, [203, 0, 113, 6, 31002]), 110)]
f = run(steps)
assert lines(f[8], "stopped:1:") and any(s.startswith("request-info:1862270975:1:1:") for s in f[8])
assert sent(f[10]) == expected(3, 1862270975, "legacy")
assert lines(f[-1], "late:1:") and lines(f[-1], "flight:2:") and not lines(f[-1], "stopped:")

# Controlled senders reject nomination with a speculative selection rollback.
# The same queued pair can then send an ordinary controlled check.
f = run(ordinary_success() + [["queue-nomination", 0], receive(incoming(True), 30), start(), ["start", 50, 3, 2]])
assert "invalid" in f[-2] and not lines(f[-2], "send:") and not lines(f[-2], "flight:")
assert lines(f[-2], "queued:") == lines(f[-3], "queued:")
assert sent(f[-1]) == expected(3, 1862270975, "legacy", nominate=False, controlling=False)

# A 487 requires fresh-tie role repair before nomination can requeue its pair.
f = run(ordinary_success() + [["queue-nomination", 0], start(), ["ack", 50], receive(response(2, error=487), 60),
                             ["queue-nomination", 0], ["repair", 1, 7, 0, 5], ["queue-nomination", 0]])
assert f[-3][0] == f[-1][0] == "rejected" and f[-2][0] == "changed"
assert lines(f[-3], "record:1:") and not lines(f[-2], "record:1:")

# Retained response listeners reserve capacity. Neither admission failure can
# consume the original nomination; its cached flag appears once capacity frees.
ss = STREAMS + [[2, [[LB, LB]], [RB]]]
f = run(ordinary_success() + [["start", 50, 2, 2], ["ack", 50], ["queue-nomination", 0], start(3, 100),
                             receive(incoming(), 110, base=LB[4], remote=RB[4], sid=2), start(3, 150),
                             ["tick", 1050], start(3, 1050)], ss, capacity=1)
assert "capacity" in f[8] and "capacity" in f[10]
assert lines(f[8], "queued:") == lines(f[7], "queued:")
assert sent(f[-1]) == expected(3, 1862270975, "legacy")

for index in (0, 99, 4294967295):
    assert run([["queue-nomination", index]])[-1][0] == "rejected"
print(f"ICE nomination requests: {COUNT} original-pair/intent/bytes/retry/listener/role/pacing/capacity cases passed")
