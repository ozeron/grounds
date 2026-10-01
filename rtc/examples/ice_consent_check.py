"""Independent RFC 7675 packet, deadline and lifecycle checks on compiled Bend."""
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from stun_reference import COOKIE, attr, packet, sign, validate

COMMAND = sys.argv[1:]
KEY = b"SyntheticPassword123456789"
BASE = [127, 0, 0, 1, 10001]
PEER = [127, 0, 0, 1, 20001]
COUNT = 0


def tx(n):
    return struct.pack("!III", n, 2, 3)


def response(n, mode="sha256", error=0, key=KEY, extra=b"", kind=None):
    body = attr(9, bytes((0, 0, error // 100, error % 100)) + b"Error") if error else attr(
        0x20, b"\x00\x01" + struct.pack("!H", BASE[4] ^ 0x2112)
        + bytes(a ^ b for a, b in zip(BASE[:4], COOKIE)))
    return sign(packet(body + extra, kind=kind or (0x111 if error else 0x101), transaction=tx(n)), key, mode)


def receive(raw, now, base=BASE, peer=PEER, generation=7):
    return ["receive", now, base, peer, generation, list(raw)]


def start(now, n, jitter=0, gate=0):
    return ["start", now, n, jitter, gate]


def lines(frame, prefix):
    return [s for s in frame if s.startswith(prefix)]


def run(steps, mode="dual", rto=500, now=0, valid=True):
    global COUNT
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "fixture.json"
        path.write_text(json.dumps([mode, rto, now, steps]))
        result = subprocess.run(COMMAND + [str(path)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, (result.stdout, result.stderr)
    COUNT += 1
    if not valid:
        assert result.stdout.strip() == "invalid", result.stdout
        return []
    frames, frame = [], []
    for line in result.stdout.splitlines():
        if line in ("ready", "changed", "rejected") or line.startswith(("later:", "gate:")):
            frames.append(frame)
            frame = [line]
        else:
            frame.append(line)
    frames.append(frame)
    assert len(frames) == len(steps) + 1 and not any("invalid" in f for f in frames), result.stdout
    return frames


def status(frame, expected, allowed):
    assert lines(frame, "status:") == ["status:" + expected], frame
    assert lines(frame, "allowed:") == ["allowed:" + str(int(allowed))], frame


def clock(frame):
    found = lines(frame, "clock:")
    assert len(found) == 1, frame
    return tuple(map(int, found[0].split(":")[1:]))


def raw(frame):
    found = lines(frame, "send:")
    assert len(found) == 1, frame
    return bytes.fromhex(found[0].split(":")[-1])


def no_send(frame):
    assert not lines(frame, "send:"), frame


# New selection is closed to application data; only a matching authenticated
# round trip on the selected receiving base grants the first window.
for mode in ("legacy", "sha256", "dual"):
    reply_mode = "legacy" if mode == "legacy" else "sha256"
    f = run([start(0, 1, 1000), ["ack", 10], receive(response(1, reply_mode), 30),
             ["ack", 40], ["tick", 30029], ["tick", 30030],
             receive(response(1, reply_mode), 30031), start(30032, 2)], mode=mode)
    status(f[0], "awaiting", False)
    status(f[1], "awaiting", False)
    request = raw(f[1])
    assert request[8:20] == tx(1)
    attrs = validate(request, KEY, mode)
    assert [value for k, value, _ in attrs if k == 6] == [b"remoteFrag:localFrag"]
    assert not any(k == 0x25 for k, _, _ in attrs), attrs
    assert "current-send:1" in f[1] and "current-send:0" in f[2]
    assert clock(f[2])[:2] == (30000, 5010), f[2]
    status(f[3], "granted", True)
    assert clock(f[3]) == (30030, 5010, 500, 20, 10), f[3]
    assert clock(f[4]) == clock(f[3]) and not lines(f[4], "sent:")
    status(f[5], "granted", True)
    status(f[6], "expired", False)
    assert "status-changed:expired" in f[6] and not lines(f[6], "probe:")
    status(f[7], "expired", False)
    assert not lines(f[7], "renewed:")
    assert f[8][0] == "rejected" and "timeout:60000" in f[8]

# Four/six-second boundaries are independent of the 30-second expiry. Shared
# socket admission and delayed actual sends cannot shorten those periods.
for jitter in (0, 1000, 2000):
    period = 4000 + jitter
    f = run([start(0, 1, jitter), ["ack", 100], ["tick", 599], ["tick", 600],
             start(period + 99, 2, jitter), start(period + 100, 2, jitter, period + 200),
             start(period + 200, 2, jitter), ["ack", period + 250],
             start(period * 2 + 249, 3, jitter), start(period * 2 + 250, 3, jitter)])
    assert clock(f[2])[1] == period + 100
    assert lines(f[3], "probe:") and not lines(f[4], "probe:")
    assert "timedout:1" in f[4]
    assert f[5][0] == f"later:{period + 100}"
    assert f[6][0] == f"later:{period + 200}"
    assert f[7][0] == "ready" and f[9][0] == f"later:{period * 2 + 250}"
    assert f[10][0] == "ready"
    for frame in f:
        assert not any(line.startswith("send:") and frame is not f[1] and frame is not f[7] and frame is not f[10] for line in frame)

# No retransmissions, even with overdue ticks or prolonged loss; every admitted
# send gets a distinct signed 96-bit identifier and retains no hidden retry.
steps = []
for i in range(1, 8):
    n = (i - 1) * 4000
    steps += [start(n, i), ["ack", n], ["tick", n + 500], ["tick", n + 1500]]
steps += [["tick", 30000], start(30001, 8)]
f = run(steps)
packets = [raw(frame) for frame in f if lines(frame, "send:")]
assert len(packets) == len(set(packets)) == len({p[8:20] for p in packets}) == 7
status(f[-1], "expired", False)

# An earlier request may respond after a later one. Negotiation affects future
# requests, while outstanding requests retain their original algorithm policy.
f = run([start(0, 1), ["ack", 0], start(4000, 2), ["ack", 4000],
         receive(response(2), 4050), receive(response(1, "legacy"), 4500),
         receive(response(1, "legacy"), 4501), start(8000, 3)], rto=10000)
assert len(lines(f[4], "probe:")) == 2
assert clock(f[5]) == (34050, 8000, 500, 50, 25)
assert clock(f[6]) == (34500, 8000, 5130, 606, 1131), f[6]
assert lines(f[6], "renewed:") == ["renewed:1:34500"]
assert clock(f[7]) == clock(f[6]) and not lines(f[7], "renewed:")
assert "algorithm:sha256" in f[6], "an older dual-policy response downgraded the pinned endpoint policy"
validate(raw(f[8]), KEY, "sha256")

# Malformed/unauthenticated traffic, wrong 5-tuples and generations cannot
# grant or revoke consent. A valid reply afterwards still settles the request.
bad = [b"", b"\x00", response(2), response(1, key=b"WrongPassword12345678900"),
       response(1, kind=1), response(1, error=403, key=b"WrongPassword12345678900"),
       response(1)[:-1] + bytes([response(1)[-1] ^ 1])]
for raw_bad in bad:
    f = run([start(0, 1), ["ack", 0], receive(raw_bad, 20), receive(response(1), 30)])
    status(f[3], "awaiting", False)
    assert len(lines(f[3], "probe:")) == 1
    status(f[4], "granted", True)
for kwargs in ({"base": [127, 0, 0, 1, 10002]}, {"base": [127, 0, 0, 2, 10001]},
               {"peer": [127, 0, 0, 1, 20002]}, {"peer": [127, 0, 0, 2, 20001]}, {"generation": 8}):
    f = run([start(0, 1), ["ack", 0], receive(response(1), 20, **kwargs), receive(response(1), 30)])
    status(f[3], "awaiting", False)
    status(f[4], "granted", True)

# The actual application gate is bound to generation and the entire transport
# identity, even while the selected path itself has unexpired consent.
gates = [["gate", 21, 1, 1, BASE, PEER, 7], ["gate", 21, 2, 1, BASE, PEER, 7],
         ["gate", 21, 1, 2, BASE, PEER, 7], ["gate", 21, 1, 1, BASE, PEER, 8],
         ["gate", 21, 1, 1, [127, 0, 0, 1, 10002], PEER, 7],
         ["gate", 21, 1, 1, BASE, [127, 0, 0, 1, 20002], 7],
         ["gate", 30019, 1, 1, BASE, PEER, 7], ["gate", 30020, 1, 1, BASE, PEER, 7]]
f = run([start(0, 1), ["ack", 0], receive(response(1), 20)] + gates)
assert [frame[0] for frame in f[4:]] == ["gate:1", "gate:0", "gate:0", "gate:0", "gate:0", "gate:0", "gate:1", "gate:0"]

# Authenticated errors consume a request without extending consent. Only a
# protected 403 revokes; malformed protected payloads also cannot renew.
for code in (400, 487, 500):
    f = run([start(0, 1), ["ack", 0], receive(response(1), 20), start(4000, 2), ["ack", 4000],
             receive(response(2, error=code), 4010), receive(response(2), 4020)])
    status(f[6], "granted", True)
    assert clock(f[6])[0] == 30020 and f"error:2:{code}" in f[6]
    assert not lines(f[7], "renewed:") and not lines(f[7], "probe:")
for established in (False, True):
    prefix = [start(0, 1), ["ack", 0]]
    if established:
        prefix += [receive(response(1), 20), start(4000, 2), ["ack", 4000]]
    n, at = (2, 4010) if established else (1, 20)
    f = run(prefix + [receive(response(n, error=403), at), receive(response(n), at + 1), start(at + 2, 3)])
    status(f[-3], "revoked", False)
    assert "status-changed:revoked" in f[-3] and not lines(f[-3], "probe:")
    status(f[-2], "revoked", False)
    assert f[-1][0] == "rejected"
f = run([start(0, 1), ["ack", 0], receive(response(1, extra=attr(0x7777, b"")), 20)])
status(f[-1], "awaiting", False)
assert "invalid-response:1" in f[-1] and not lines(f[-1], "probe:")

# The exact response-window boundary wins over a response, and the consent
# boundary discards all overlapping requests before processing any late success.
for at, expected in ((499, True), (500, False), (501, False)):
    f = run([start(0, 1), ["ack", 0], receive(response(1), at)])
    status(f[-1], "granted" if expected else "awaiting", expected)
f = run([start(0, 1), ["ack", 0], receive(response(1), 9000), start(10000, 2), ["ack", 10000],
         start(14000, 3), ["ack", 14000], receive(response(3), 39000), receive(response(2), 39001)], rto=10000)
assert len(lines(f[7], "probe:")) == 2
status(f[8], "expired", False)
assert not lines(f[8], "probe:") and not lines(f[8], "renewed:")
status(f[9], "expired", False)

# A receive before actual-send acknowledgement is not evidence. An old queued
# directive expires, and duplicate acknowledgements cannot extend its window.
f = run([start(0, 1), receive(response(1), 10), ["ack", 20], receive(response(1), 30)])
status(f[2], "awaiting", False)
status(f[4], "granted", True)
f = run([start(0, 1), ["ack", 500], ["tick", 501], receive(response(1), 502)])
assert not lines(f[2], "sent:") and "current-send:0" in f[2]
status(f[-1], "awaiting", False)

# Reused entropy, bad jitter and illegal RTO estimates are rejected. Transmit
# failure/cancellation releases probes without manufacturing remote revocation.
f = run([start(0, 1), ["ack", 0], ["tick", 500], start(4000, 1), start(4000, 2, 2001),
         start(4000, 2), ["fail", 2, 5], ["fail", 2, 5], ["close"], ["close"], start(9000, 3)])
assert f[4][0] == f[5][0] == "rejected" and f[6][0] == "ready"
assert "transport-error:2:5" in f[7] and not lines(f[7], "probe:")
assert not lines(f[8], "transport-error:")
status(f[9], "closed", False)
assert not lines(f[10], "status-changed:") and f[11][0] == "rejected"
for rto in (0, 499, 60001, 4294967295):
    run([], rto=rto, valid=False)

# Uptime-sized clocks do not build successor chains or wrap 32-bit deadlines.
f = run([start(4000000000, 1), ["ack", 4000000000], receive(response(1), 4000000030),
         ["tick", 4000030030]], now=4000000000)
assert clock(f[3])[0] == 4000030030
status(f[4], "expired", False)
steps = []
for i in range(1, 71):
    n = (i - 1) * 4000
    steps += [start(n, i), ["ack", n], receive(response(i), n + 20)]
f = run(steps)
assert "history:64" in f[-1]
assert sum(len(lines(frame, "send:")) for frame in f) == 70
print(f"ICE consent: {COUNT} independent packet/deadline/lifecycle scenarios passed")
