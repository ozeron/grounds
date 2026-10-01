"""Independent signed nomination/consent/restart checks against compiled Bend."""
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from stun_reference import COOKIE, attr, packet, sign, validate, fingerprint, length

COMMAND = sys.argv[1:]
KEY = b"SyntheticPassword123456789"
LOCAL_KEY = b"LocalFixturePassword123456"
NEW_KEY = b"NewRemoteFixturePassword123"
NEW_LOCAL_KEY = b"NewLocalFixturePassword1234"
BASE = [127, 0, 0, 1, 10001]
BASE_B = [127, 0, 0, 1, 10002]
PEER = [127, 0, 0, 1, 20001]
LA = [1, 2130706431, "host", "host", BASE]
LB = [1, 2130706175, "other", "host", BASE_B]
RA = [1, 2100000000, "remote", "host", PEER]
STREAMS = [[1, [[LA, LA]], [RA]]]
REF = [1, 1, BASE, PEER]
BIND = ["bind", "localFrag", "remoteFrag", KEY.decode()]
NEW_BIND = ["bind", "nextLocal", "nextRemote", NEW_KEY.decode()]
COUNT = 0


def tx(n):
    return struct.pack("!III", n, 2, 3)


def response(n, address=BASE, key=KEY, mode="sha256", error=0):
    body = attr(9, bytes((0, 0, error // 100, error % 100)) + b"Error") if error else attr(
        0x20, b"\x00\x01" + struct.pack("!H", address[4] ^ 0x2112)
        + bytes(a ^ b for a, b in zip(address[:4], COOKIE)))
    return sign(packet(body, kind=0x111 if error else 0x101, transaction=tx(n)), key, mode)


def incoming(n=90, local="localFrag", remote="remoteFrag", key=LOCAL_KEY, mode="dual", extra=b""):
    return sign(packet(attr(6, (local + ":" + remote).encode()) + extra, transaction=tx(n)), key, mode)


def receive(raw, now, ref=REF):
    return ["receive", now, ref, list(raw)]


def probe(now, n, gen=7, ref=REF, jitter=1000):
    return ["probe", now, n, jitter, gen, ref]


def restart(now=110, local="nextLocal", key=NEW_LOCAL_KEY, streams=STREAMS):
    return ["restart", now, local, key.decode(), streams]


def nominated(mode="dual"):
    algorithm = "legacy" if mode == "legacy" else "sha256"
    return [BIND, ["signal", 0], ["start", 0, 1, 3], ["ack", 0, 0],
            receive(response(1, mode=algorithm), 20), ["start", 50, 2, 3], ["ack", 50, 0],
            receive(response(2, mode=algorithm), 70)]


def granted(mode="dual"):
    algorithm = "legacy" if mode == "legacy" else "sha256"
    return nominated(mode) + [probe(75, 3), ["ack", 75, 0], receive(response(3, mode=algorithm), 100)]


def lines(frame, prefix):
    return [line for line in frame if line.startswith(prefix)]


def run(steps, streams=STREAMS, mode="dual", pac=39500, automatic=True, slots=256):
    global COUNT
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "fixture.json"
        path.write_text(json.dumps([streams, mode, pac, automatic, slots, steps]))
        result = subprocess.run(COMMAND + [str(path)], capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, (result.stdout, result.stderr)
    frames = [f.splitlines() for f in result.stdout.split("frame\n")[1:]]
    assert len(frames) == len(steps) + 1, result.stdout
    assert lines(frames[0], "owner:") and not any("invalid-action" in frame for frame in frames), result.stdout
    COUNT += 1
    return frames


def owner(frame):
    return lines(frame, "owner:")[0].split(":")[1:]


def slot(frame, generation=7):
    found = lines(frame, f"slot:{generation}:")
    assert len(found) == 1, frame
    # reference contains ':' separators; trailing status/clock/mode are stable.
    return found[0].split(":")[-7:]


def sent(frame):
    found = lines(frame, "transmit:")
    assert len(found) == 1, frame
    return bytes.fromhex(found[0].rsplit(":", 1)[1])


def no_send(frame):
    assert not lines(frame, "transmit:"), frame


def gate(frame, expected):
    assert lines(frame, "gate:") == ["gate:" + str(int(expected))], frame



def check():
    # A real signed ordinary check and a separate regular nomination establish
    # each selected route; no test supplies a fabricated selected-state flag.
    for mode in ("legacy", "sha256", "dual"):
        algorithm = "legacy" if mode == "legacy" else "sha256"
        f = run(granted(mode) + [["gate", 100, 7, REF], ["gate", 100, 8, REF],
                                 ["route", 100, 1, 1], ["tick", 30100]], mode=mode)
        assert slot(f[8])[0] == "awaiting", f[8]
        assert slot(f[11])[:2] == ["granted", "30100"], f[11]
        gate(f[12], True)
        gate(f[13], False)
        assert lines(f[14], "route:")[0].startswith("route:7:"), f[14]
        assert slot(f[15])[0] == "expired", f[15]
        items = validate(sent(f[9]), KEY, algorithm)
        assert [kind for kind, _, _ in items] == [6, 8 if algorithm == "legacy" else 28, 0x8028], items
        assert sent(f[9])[8:20] == tx(3)
        assert lines(f[8], "ice:")[0].split(":")[2:6] == ["0"] * 4, f[8]

    # Incoming consent has no ICE role/PRIORITY attributes, cannot grant outgoing
    # consent, and produces a protected actual-source mapping without ICE work.
    for mode in ("legacy", "sha256", "dual"):
        f = run(nominated() + [receive(incoming(mode=mode), 75), ["gate", 75, 7, REF]])
        reply = bytes.fromhex(lines(f[9], "reply:")[0].rsplit(":", 1)[1])
        items = validate(reply, LOCAL_KEY, "legacy" if mode == "legacy" else "sha256")
        assert reply[:2] == b"\x01\x01" and reply[8:20] == tx(90), reply.hex()
        mapped = next(value for kind, value, _ in items if kind == 0x20)
        assert mapped == b"\x00\x01" + struct.pack("!H", PEER[4] ^ 0x2112) + bytes(a ^ b for a, b in zip(PEER[:4], COOKIE)), mapped
        assert lines(f[8], "ice:") == lines(f[9], "ice:"), f[9]
        gate(f[10], False)

    for extra, expected in ((attr(0x31, b"unknown"), 420), (b"", 401)):
        raw = incoming(extra=extra, remote="otherRemote" if expected == 401 else "remoteFrag")
        f = run(nominated() + [receive(raw, 75)])
        line = lines(f[-1], "reply:")[0]
        assert line.startswith(f"reply:7:{expected}:"), line
        validate(bytes.fromhex(line.rsplit(":", 1)[1]), LOCAL_KEY, "sha256")
        assert lines(f[8], "ice:") == lines(f[9], "ice:"), f[9]

    bad = bytearray(incoming())
    bad[-12] ^= 1
    bad = fingerprint(length(bytes(bad[:-8]), len(bad) - 28))
    for raw in (bytes(bad), incoming(key=b"WrongKey"), incoming()[:-1], packet(attr(6, b"localFrag:remoteFrag"))):
        f = run(nominated() + [receive(raw, 75)])
        assert not lines(f[-1], "reply:"), f[-1]
        assert lines(f[8], "ice:") == lines(f[9], "ice:"), f[9]

    # Packet ownership covers the physical source, logical alias and generation.
    for ref in ([1, 1, BASE_B, PEER], [1, 1, BASE, [127, 0, 0, 1, 20002]], [2, 1, BASE, PEER]):
        f = run(nominated() + [probe(75, 3), ["ack", 75, 0], receive(response(3), 100, ref), ["gate", 100, 7, REF]])
        # Actual metadata resolves a consent response across shared aliases.
        gate(f[-1], ref[0] == 2)

    f = run(nominated() + [probe(75, 3), ["current", 75, 0], ["ack", 80, 0],
                           ["current", 80, 0], ["ack", 90, 0], ["tick", 580],
                           ["probe", 5080, 4, 1000, 7, REF], ["ack", 5080, 0], receive(response(4), 5100)])
    assert lines(f[10], "current:") == ["current:1"], f[10]
    assert lines(f[12], "current:") == ["current:0"], f[12]
    assert slot(f[13])[2] == "5080", f[13]
    assert lines(f[14], "timedout:") == ["timedout:1"], f[14]
    assert slot(f[-1])[:2] == ["granted", "35100"], f[-1]
    no_send(f[14])

    f = run(nominated() + [probe(75, 3), probe(75, 4), ["fail", 76, 0, 5],
                           ["tick", 5075], probe(5075, 3), probe(5075, 4)])
    no_send(f[10])
    assert lines(f[11], "transport-error:") == ["transport-error:1:5"], f[11]
    no_send(f[13])
    sent(f[14])

    # Restart leaves old consent timestamps intact and resets all ICE ownership.
    f = run(granted() + [restart(), ["gate", 110, 7, REF], ["gate", 110, 8, REF],
                         receive(incoming(), 115), NEW_BIND, ["signal", 115],
                         ["start", 115, 4, 3], ["ack", 115, 0],
                         receive(response(4, key=NEW_KEY), 135), ["start", 165, 5, 3], ["ack", 165, 0],
                         receive(response(5, key=NEW_KEY), 185), ["gate", 185, 7, REF], ["gate", 185, 8, REF],
                         probe(190, 6, gen=8), ["ack", 190, 0], receive(response(6, key=NEW_KEY), 210),
                         ["gate", 210, 8, REF], ["route", 210, 1, 1], receive(incoming(), 215)])
    assert lines(f[12], "restarted:") == ["restarted:8"], f[12]
    assert lines(f[12], "ice:")[0].split(":")[2:6] == ["0"] * 4, f[12]
    assert slot(f[12])[:2] == ["granted", "30100"], f[12]
    gate(f[13], True)
    gate(f[14], False)
    assert lines(f[15], "reply:")[0].startswith("reply:7:0:"), f[15]
    gate(f[24], False)
    gate(f[25], False)
    gate(f[29], True)
    assert lines(f[30], "route:")[0].startswith("route:8:"), f[30]
    assert owner(f[31])[:2] == ["8", "completed"], f[31]

    for local, password in (("localFrag", NEW_LOCAL_KEY), ("nextLocal", LOCAL_KEY)):
        f = run(granted() + [restart(local=local, key=password)])
        assert "rejected" in f[-1] and owner(f[-1])[0] == "7", f[-1]
    for fragment, password in (("remoteFrag", NEW_KEY), ("nextRemote", KEY)):
        f = run(granted() + [restart(), ["bind", "nextLocal", fragment, password.decode()], ["start", 120, 4, 3]])
        assert "rejected" in f[-2], f[-2]
        no_send(f[-1])
    f = run(granted() + [restart(), NEW_BIND, NEW_BIND, restart(120, "thirdLocal", b"ThirdLocalPassword12345678"),
                         ["bind", "thirdLocal", "remoteFrag", "ThirdRemotePassword123456"]])
    assert owner(f[-1])[0] == "9" and "rejected" in f[-1], f[-1]

    # Old issued callbacks affect actual pacing, never replacement proof or queue.
    f = run(nominated() + [probe(75, 3), restart(80), NEW_BIND, ["start", 80, 4, 3],
                           ["current", 80, 1], ["ack", 100, 1], ["current", 104, 0], ["current", 105, 0],
                           ["ack", 105, 0], receive(response(3), 110), ["gate", 110, 7, REF],
                           receive(response(4, key=NEW_KEY), 125)])
    assert lines(f[13], "current:") == ["current:0"], f[13]
    assert owner(f[14])[3] == "105", f[14]
    assert lines(f[15], "current:") == ["current:0"], f[15]
    assert lines(f[16], "current:") == ["current:1"], f[16]
    gate(f[19], True)
    assert owner(f[-1])[0] == "8", f[-1]

    f = run(granted() + [restart(), NEW_BIND, ["signal", 110], ["tick", 30100],
                         ["gate", 30100, 7, REF], receive(incoming(), 30101),
                         probe(30102, 4), ["route", 30102, 1, 1]])
    assert slot(f[15])[0] == "expired", f[15]
    gate(f[16], False)
    assert not lines(f[17], "reply:"), f[17]
    no_send(f[18])
    assert lines(f[19], "route:") == ["route:none"], f[19]

    f = run(granted() + [probe(5075, 4), ["ack", 5075, 0], restart(5080),
                         receive(response(4, error=403), 5100), ["gate", 5100, 7, REF],
                         NEW_BIND, ["start", 5105, 5, 3]])
    assert slot(f[15])[0] == "revoked", f[15]
    gate(f[16], False)
    assert owner(f[-1])[0] == "8", f[-1]
    sent(f[-1])

    # Known mapped B has a different actual base from the generating check A.
    streams = [[1, [[LA, LA], [LB, LB]], [RA]]]
    b_ref = [1, 1, BASE_B, PEER]
    steps = [BIND, ["signal", 0], ["start", 0, 1, 3], ["ack", 0, 0],
             receive(response(1, address=BASE_B), 20), ["start", 50, 2, 3], ["ack", 50, 0],
             receive(response(2, address=BASE_B), 70), probe(75, 3, ref=b_ref), ["ack", 75, 0],
             receive(response(3), 100), ["gate", 100, 7, b_ref],
             probe(5075, 4, ref=b_ref), ["ack", 5075, 0], receive(response(4, address=BASE_B), 5100, b_ref),
             ["gate", 5100, 7, b_ref], ["gate", 5100, 7, REF]]
    f = run(steps, streams=streams)
    assert "/10002:" in lines(f[9], "transmit:")[0], f[9]
    gate(f[12], False)
    gate(f[16], True)
    gate(f[17], False)

    # Shared physical routes produce one consent slot with two logical aliases.
    streams = STREAMS + [[2, [[LA, LA]], [RA]]]
    alias = [2, 1, BASE, PEER]
    steps = nominated() + [["start", 100, 3, 3], ["ack", 100, 0], receive(response(3), 120, alias),
                           ["start", 150, 4, 3], ["ack", 150, 0], receive(response(4), 170, alias),
                           probe(175, 5, ref=alias), ["ack", 175, 0], receive(response(5), 200, alias),
                           ["gate", 200, 7, REF], ["gate", 200, 7, alias]]
    f = run(steps, streams=streams)
    assert lines(f[14], "slot-count:") == ["slot-count:1:0"], f[14]
    gate(f[-2], True)
    gate(f[-1], True)

    # Check and consent transaction identities share one admission namespace.
    f = run(nominated() + [probe(75, 3), ["ack", 75, 0], receive(response(3), 100),
                           ["start", 5075, 3, 3], probe(5075, 3), probe(5075, 4)])
    no_send(f[12])
    no_send(f[13])
    sent(f[14])
    f = run([BIND, ["signal", 0], ["start", 0, 1, 3], ["start", 499, 2, 3], ["current", 499, 0], ["tick", 500], ["tick", 39500]])
    no_send(f[4])
    assert lines(f[5], "current:") == ["current:1"], f[5]
    assert lines(f[6], "pending:") == ["pending:none"], f[6]
    assert owner(f[-1])[2] == "1", f[-1]

    for steps in ([restart(streams=[])], [["close"], ["close"], restart(), NEW_BIND, probe(120, 4), receive(incoming(), 125)]):
        f = run(granted() + steps)
        if steps[0][0] == "close":
            assert owner(f[-1])[2] == "1", f[-1]
            assert lines(f[-1], "pending:") == ["pending:none"], f[-1]
            no_send(f[-1])
        else:
            assert "rejected" in f[-1], f[-1]


    # Consent loss remains a tombstone under the same generation/credentials.
    f = run(granted() + [probe(5075, 4), ["ack", 5075, 0], receive(response(4, error=403), 5100),
                         receive(incoming(), 5101), probe(5102, 5), ["gate", 5102, 7, REF]])
    assert slot(f[14])[0] == "revoked", f[14]
    assert not lines(f[15], "reply:"), f[15]
    no_send(f[16])
    gate(f[17], False)

    # ICE role attributes are passed to ICE; trailing unprotected role bytes
    # are ignored and cannot mutate its role, queues, or selected evidence.
    role = attr(0x24, struct.pack("!I", 1845494271)) + attr(0x802A, struct.pack("!Q", 0))
    raw = incoming(extra=role)
    f = run(granted() + [restart(), receive(raw, 115)])
    assert lines(f[-1], "reply:")[0].startswith("reply:7:487:"), f[-1]
    assert lines(f[-1], "role:") == ["role:controlling:0:1"], f[-1]
    assert lines(f[-2], "ice:") == lines(f[-1], "ice:"), f[-1]
    raw = incoming()[:-8] + role
    raw = fingerprint(length(raw, len(raw) - 20))
    f = run(nominated() + [receive(raw, 75)])
    assert lines(f[-1], "reply:")[0].startswith("reply:7:0:"), f[-1]
    assert lines(f[-1], "role:") == ["role:controlling:0:1"], f[-1]
    assert lines(f[-2], "ice:") == lines(f[-1], "ice:"), f[-1]

    f = run([BIND, ["signal", 0], ["start", 0, 1, 3], ["current", 500, 0], ["ack", 500, 0]])
    assert lines(f[4], "current:") == ["current:0"], f[4]
    assert lines(f[5], "pending:") == ["pending:none"], f[5]
    assert not lines(f[5], "sent:"), f[5]

    # Repeated restarts cannot make older local or remote namespaces reusable.
    steps = granted() + [restart(), NEW_BIND, restart(120, "thirdLocal", b"ThirdLocalPassword12345678")]
    f = run(steps + [["restart", 130, "localFrag", "FourthLocalPassword123456", STREAMS]])
    assert "rejected" in f[-1] and owner(f[-1])[0] == "9", f[-1]
    f = run(steps + [receive(incoming(), 130)])
    assert lines(f[-1], "reply:")[0].startswith("reply:7:0:"), f[-1]
    assert lines(f[-1], "role:") == ["role:controlling:0:1"], f[-1]

    # Actual ICE and old-route consent sends use one five-ms completion gate.
    f = run(granted() + [restart(), NEW_BIND, ["start", 5075, 4, 3], ["ack", 5075, 0],
                         probe(5079, 5), probe(5080, 5)])
    no_send(f[-2])
    assert "waiting:5080" in f[-2], f[-2]
    sent(f[-1])

    for nonce in (1, 2):
        f = run(nominated() + [probe(75, nonce), ["ack", 75, 0], receive(response(nonce), 100), ["gate", 100, 7, REF]])
        gate(f[-1], False)
        no_send(f[9])
        assert "rejected" in f[9], f[9]
    f = run(granted() + [restart(), NEW_BIND, ["start", 120, 2, 3]])
    no_send(f[-1])

    # History capacity fails explicitly without reviving an older namespace.
    steps = [BIND] + [restart(i, f"fresh{i:04d}", f"FixtureFreshKey{i:04d}Password".encode()) for i in range(1, 65)]
    f = run(steps)
    assert owner(f[-2])[0] == owner(f[-1])[0] == "70", f[-1]
    assert owner(f[-1])[-1] == "64" and "rejected" in f[-1], f[-1]

    # Capacity exhaustion closes the dispatcher and all selected consent slots.
    streams = STREAMS + [[2, [[LB, LB]], [RA]]]
    ref = [2, 1, BASE_B, PEER]
    steps = [BIND, ["signal", 0], ["start", 0, 1, 3], ["ack", 0, 0], receive(response(1), 20),
             ["start", 50, 2, 3], ["ack", 50, 0], receive(response(2, address=BASE_B), 70, ref),
             ["start", 100, 3, 3], ["ack", 100, 0], receive(response(3), 120),
             ["start", 150, 4, 3], ["ack", 150, 0], receive(response(4, address=BASE_B), 170, ref)]
    f = run(steps, streams=streams, slots=1)
    assert "exhausted" in f[-1] and "closed" in f[-1] and owner(f[-1])[2] == "1", f[-1]
    assert slot(f[-1])[0] == "closed" and lines(f[-1], "pending:") == ["pending:none"], f[-1]

    # 487 stays repairable, and a changed role survives a fresh restart.
    steps = nominated()[:-1] + [receive(response(2, error=487), 60),
                               ["repair", 65, 1, 7, 0, 3], ["start", 100, 3, 3],
                               ["ack", 100, 0], restart(110)]
    f = run(steps)
    assert lines(f[-1], "role:") == ["role:controlled:0:3"], f[-1]
    assert owner(f[-1])[0] == "8", f[-1]
    assert lines(f[-1], "ice:")[0].split(":")[2:6] == ["0"] * 4, f[-1]

    # Retained old server contexts preserve the role actually reached before
    # restart, including a role conflict received after the initial selection.
    controlling = attr(0x24, struct.pack("!I", 1845494271)) + attr(0x802A, struct.pack("!Q", 2))
    controlled = attr(0x24, struct.pack("!I", 1845494271)) + attr(0x8029, struct.pack("!Q", 2))
    f = run(granted() + [receive(incoming(extra=controlling), 105), restart(110), receive(incoming(n=91, extra=controlled), 115)])
    assert lines(f[-2], "role:") == ["role:controlled:0:1"], f[-2]
    assert lines(f[-1], "reply:")[0].startswith("reply:7:487:"), f[-1]
    assert lines(f[-1], "role:") == ["role:controlled:0:1"], f[-1]

    print(f"ICE transport check passed {COUNT} independent nomination/consent/restart scenarios")


if __name__ == "__main__":
    check()
