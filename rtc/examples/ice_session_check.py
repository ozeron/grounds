"""Independent authenticated packet/clock/lifecycle checks of the session owner."""
import copy
import json
import random
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from stun_reference import COOKIE, attr, attributes, fingerprint, packet, sign, validate

COMMAND = sys.argv[1:]
LOCAL_KEY = b"LocalFixturePassword123456"
REMOTE_KEY = b"SyntheticPassword123456789"
COUNT = 0
RNG = random.Random(7301)


def cand(priority=2130706431, port=10001, foundation="local", kind="host", component=1):
    return [component, priority, foundation, kind, [127, 0, 0, 1, port]]


LA = cand()
LB = cand(2130706175, 10002, "other")
RA = cand(2100000000, 20001, "remote")
RB = cand(2099999999, 20002, "p0")
BASE = LA[4]
SOURCE = RA[4]
STREAMS = [[1, [[LA, LA]], [RA]]]
EMPTY = [[1, [[LA, LA], [LB, LB]], []]]
BIND = ["bind", "localFrag", "remoteFrag", REMOTE_KEY.decode()]


def tx(n):
    return struct.pack("!III", n, 2, 3)


def request(n=90, mode="dual", remote=b"remoteFrag", control=False, tie=2, priority=1845494271, nominate=False, key=LOCAL_KEY):
    body = attr(6, b"localFrag:" + remote) + attr(0x24, struct.pack("!I", priority))
    body += attr(0x802A if control else 0x8029, struct.pack("!Q", tie))
    if nominate:
        body += attr(0x25, b"")
    return sign(packet(body, transaction=tx(n)), key, mode)


def mapping(address):
    return attr(0x20, b"\x00\x01" + struct.pack("!H", address[4] ^ 0x2112) + bytes(a ^ b for a, b in zip(address[:4], COOKIE)))


def response(n, mode="legacy", error=0, key=REMOTE_KEY):
    body = attr(9, bytes((0, 0, error // 100, error % 100)) + b"Error") if error else mapping(BASE)
    return sign(packet(body, kind=0x111 if error else 0x101, transaction=tx(n)), key, mode)


def receive(raw, now=10, source=SOURCE, base=BASE, sid=1, component=1):
    return ["receive", now, sid, component, base, source, list(raw)]


def run(steps=(), streams=STREAMS, capacity=4, limit=100, mode="dual"):
    global COUNT
    fixture = [streams, mode, capacity, limit, list(steps)]
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "session.json"
        path.write_text(json.dumps(fixture))
        result = subprocess.run(COMMAND + [str(path)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, (fixture, result.stderr, result.stdout)
    frames, current = [], []
    for line in result.stdout.splitlines():
        if line in ("changed", "rejected"):
            frames.append(current)
            current = [line]
        else:
            current.append(line)
    frames.append(current)
    assert len(frames) == 1 + len(steps) or frames == [["invalid"]], (fixture, frames)
    COUNT += 1
    return frames


def lines(frame, prefix):
    return [s for s in frame if s.startswith(prefix)]


def one(frame, prefix):
    values = lines(frame, prefix)
    assert len(values) == 1, (prefix, frame)
    return values[0]


def sends(frame, mode=None):
    values = lines(frame, "send:")
    for value in values:
        raw = bytes.fromhex(value.split(":")[-1])
        if mode:
            fields = validate(raw, REMOTE_KEY, mode)
            assert next(v for k, v, _ in fields if k == 6) == b"remoteFrag:localFrag"
            assert next(v for k, v, _ in fields if k == 0x24) == struct.pack("!I", 1862270719 if "/10002:" in value else 1862270975)
        assert raw[8:20][4:] == struct.pack("!II", 2, 3)
    return [bytes.fromhex(value.split(":")[-1]) for value in values]


def replies(frame, mode="sha256", code=0, signed=True):
    values = lines(frame, "reply:")
    for value in values:
        raw = bytes.fromhex(value.split(":")[-1])
        fields = validate(raw, LOCAL_KEY, mode) if signed else attributes(raw)
        assert all(k != 6 for k, _, _ in fields)
        if code:
            error = next(v for k, v, _ in fields if k == 9)
            assert (error[2] & 7) * 100 + error[3] == code
        else:
            assert next(v for k, v, _ in fields if k == 0x20) == mapping(SOURCE)[4:]
    return values


def pair_states(frame):
    return [int(s.split(":")[-1]) for s in lines(frame, "pair:")]


def records(frame):
    return {int(s.split(":")[1]): s for s in lines(frame, "record:")}


# A real authenticated pre-answer request stays bounded and cannot send a check
# until a matching answer supplies the REMOTE password. Duplicates preserve UC.
for incoming_mode in ("legacy", "sha256", "dual"):
    raw = request(mode=incoming_mode)
    frames = run([receive(raw), receive(request(91, incoming_mode, nominate=True, control=True)), ["start", 0, 1, 3],
                  ["bind", "wrongLocal", "remoteFrag", REMOTE_KEY.decode()], BIND, ["start", 0, 1, 3]], streams=EMPTY)
    chosen = "legacy" if incoming_mode == "legacy" else "sha256"
    assert replies(frames[1], chosen) and replies(frames[2], chosen)
    assert len(lines(frames[2], "pending:")) == 1 and lines(frames[2], "pending:")[0].endswith(":1")
    assert "credentials" in frames[3] and not sends(frames[3])
    assert frames[4][0] == "rejected"
    assert not lines(frames[5], "pending:") and len(lines(frames[5], "remote:")) == 1
    assert len(lines(frames[5], "pair:")) == 1, "learned peer formed a local cross-product"
    assert pair_states(frames[5]) == [1] and "session:1:1:dual" in frames[5]
    sent = sends(frames[6], "dual")
    assert len(sent) == 1 and sent[0][8:20] == tx(1)

# Binding is idempotent, local-fragment checked and immutable within a generation.
frames = run([BIND, BIND, ["bind", "localFrag", "otherFrag", REMOTE_KEY.decode()],
              ["bind", "localFrag", "remoteFrag", "OtherPassword123456789012"], ["start", 0, 1, 3]])
assert frames[2][0] == "changed" and frames[3][0] == frames[4][0] == "rejected"
assert len(sends(frames[5], "dual")) == 1
for local, remote, password in (("x", "remoteFrag", REMOTE_KEY.decode()), ("localFrag", "x", REMOTE_KEY.decode()),
                                ("localFrag", "bad-frag", REMOTE_KEY.decode()), ("localFrag", "remoteFrag", "short")):
    assert run([["bind", local, remote, password]])[1][0] == "rejected"

# Wrong bound fragment is answered, but cannot reorder roles, learn or trigger.
frames = run([BIND, receive(request(remote=b"otherFrag", control=True, tie=2))])
assert replies(frames[2]) and lines(frames[2], "unbound:")
assert one(frames[2], "schedule:") == "schedule:controlling:0:1:0:0:7"
assert not lines(frames[2], "queued:") and not lines(frames[2], "pending:")

# Unselected pre-answer fragments are dropped when binding the chosen answer.
frames = run([receive(request(remote=b"otherFrag")), receive(request(91)), BIND], streams=EMPTY)
assert len(lines(frames[2], "pending:")) == 2
assert len(lines(frames[3], "remote:")) == 1 and lines(frames[3], "unbound:") and not lines(frames[3], "pending:")

# Interruption retains original record and source/ID until timeout; replacement
# flight remains In-Progress when the old authenticated response arrives.
for response_mode in ("legacy", "sha256"):
    for error in (0, 487, 500):
        frames = run([BIND, ["start", 0, 1, 3], receive(request()), ["ack", 20],
                      ["start", 49, 2, 3], ["start", 50, 2, 3], receive(response(1, response_mode, error), 51),
                      ["repair", 0, 7, 0, 3], ["fail", 0, 22], ["tick", 500], ["tick", 550]])
        assert len(records(frames[3])) == 1 and "/listening" in one(frames[3], "engine:")
        assert "queued-send:0" in frames[3] and not lines(frames[4], "sent:")
        assert "waiting:50" in frames[5] and one(frames[5], "schedule:").endswith(":1:7")
        assert len(records(frames[6])) == 2 and len(sends(frames[6], "dual")) == 1
        assert lines(frames[7], "late:") and records(frames[7]).keys() == {1} and pair_states(frames[7]) == [2]
        assert frames[8][0] == "rejected" and not lines(frames[9], "finished:") and not sends(frames[10])
        assert sends(frames[11])[0] == sends(frames[6])[0], "replacement retry changed bytes"

# Capacity pressure from a listener preserves the selected FIFO entry and token.
frames = run([BIND, ["start", 0, 1, 3], receive(request()), ["start", 50, 2, 3],
              ["tick", 2000], ["start", 2000, 2, 3]], capacity=1)
assert "capacity" in frames[4] and pair_states(frames[4]) == [1] and len(lines(frames[4], "queued:")) == 1
assert one(frames[4], "schedule:").endswith(":1:7")
assert lines(frames[5], "retired:") and not lines(frames[5], "finished:") and pair_states(frames[5]) == [1]
assert sends(frames[6])[0][8:20] == tx(2) and records(frames[6]).keys() == {1}

# An unregistered base/stream/component remains invalid context; a response
# correlated and authenticated at another registered transport fails its ORIGINAL
# current pair immediately. Later symmetric traffic cannot revive that attempt.
streams = [[1, [[LA, LA], [LB, LB]], [RA]]]
for sid, comp, base in ((2, 1, BASE), (1, 2, BASE), (1, 1, [127, 0, 0, 1, 10003])):
    frames = run([BIND, ["start", 0, 1, 3], receive(response(1), 1, base=base, sid=sid, component=comp),
                  receive(response(1), 2)], streams=streams)
    assert "invalid" in frames[3] and records(frames[3]).keys() == {0}
    assert lines(frames[4], "finished:") and not records(frames[4]) and 3 in pair_states(frames[4])

for mode in ("legacy", "sha256"):
    for base, source in ((LB[4], SOURCE), (BASE, RB[4]), (BASE, [127, 0, 0, 2, 20001]), (LB[4], RB[4])):
        for error in (0, 487, 500):
            frames = run([BIND, ["start", 0, 1, 3], receive(response(1, mode, error), 1, source, base),
                          ["ack", 20], receive(response(1, mode), 21), ["repair", 0, 7, 0, 3], ["tick", 500]], streams=streams)
            assert one(frames[3], "non-symmetric:").startswith("non-symmetric:1:0:7:1:1:127.0.0.1/10001:127.0.0.1/20001:")
            assert one(frames[3], "non-symmetric:").endswith(f":observed:1:1:{'.'.join(map(str, base[:4]))}/{base[4]}:{'.'.join(map(str, source[:4]))}/{source[4]}")
            assert 4 in pair_states(frames[3]) and not records(frames[3]) and not lines(frames[3], "flight:")
            assert not lines(frames[3], "raw:")
            if source == SOURCE:
                assert one(frames[3], "policy:").endswith(":" + mode)
            else:
                assert not lines(frames[3], "policy:")
            assert not lines(frames[4], "sent:") and not lines(frames[5], "finished:")
            assert one(frames[5], "raw:") == "raw:" + response(1, mode).hex()
            assert frames[6][0] == "rejected" and not sends(frames[7])

# Authentication, algorithm, fingerprint, transaction and method checks precede
# the failure transition. Wrong-endpoint bad traffic cannot poison integrity state,
# negotiate an algorithm, stop queued sends or prevent a later symmetric success.
invalid = [response(1, key=b"bad"), response(1)[:-1] + bytes([response(1)[-1]^1]), response(999),
           fingerprint(packet(mapping(BASE), kind=0x101, transaction=tx(1))), response(1, "dual"),
           sign(packet(mapping(BASE), kind=0x102, transaction=tx(1)), REMOTE_KEY, "legacy"),
           sign(packet(mapping(BASE) + attr(6, b"unexpected"), kind=0x101, transaction=tx(1)), REMOTE_KEY, "legacy")]
for raw in invalid:
    frames = run([BIND, ["start", 0, 1, 3], receive(raw, base=LB[4]), ["ack", 20], receive(response(1), 21)], streams=streams)
    assert records(frames[3]).keys() == {0} and 2 in pair_states(frames[3])
    assert not lines(frames[3], "non-symmetric:") and not lines(frames[3], "policy:")
    assert one(frames[3], "datagram:") == "datagram:1:1:127.0.0.1/10002:127.0.0.1/20001"
    assert one(frames[3], "raw:") == "raw:" + raw.hex() and lines(frames[4], "sent:")
    assert lines(frames[5], "finished:") and 3 in pair_states(frames[5])
for configured in ("legacy", "sha256"):
    opposite = "sha256" if configured == "legacy" else "legacy"
    frames = run([BIND, ["start", 0, 1, 3], receive(response(1, opposite), source=RB[4]),
                  receive(response(1, configured))], mode=configured)
    assert not lines(frames[3], "non-symmetric:") and records(frames[3]).keys() == {0}
    assert lines(frames[4], "finished:") and 3 in pair_states(frames[4])
frames = run([BIND, ["start", 0, 1, 1], receive(response(1, key=b"bad"), source=RB[4]), ["tick", 500]])
assert one(frames[4], "finished:").startswith("finished:0:timeout:")

# Final timeout wins at its exact boundary; overdue intermediate retry deadlines
# still accept a response, matching the transaction engine's existing behavior.
for now, rc, outcome in ((499, 1, "non-symmetric:"), (500, 1, "finished:"), (501, 3, "non-symmetric:")):
    frames = run([BIND, ["start", 0, 1, rc], receive(response(1), now, base=LB[4])], streams=streams)
    assert lines(frames[3], outcome) and not records(frames[3]) and 4 in pair_states(frames[3])
    if outcome == "finished:":
        assert one(frames[3], outcome).startswith("finished:0:timeout:") and not lines(frames[3], "policy:")

# Authenticated non-symmetric late replies retire ONLY their old retained attempt.
# A replacement and another active base keep their records, roles, state and bytes.
for error in (0, 487, 500):
    frames = run([BIND, ["start", 0, 1, 3], receive(request()), ["start", 50, 2, 3], ["start", 100, 3, 3],
                  receive(response(1, "sha256", error), 101, base=LB[4]), receive(response(1), 102),
                  ["repair", 0, 7, 0, 3], ["tick", 550]], streams=streams)
    assert one(frames[6], "non-symmetric:").startswith("non-symmetric:0:0:7:")
    assert records(frames[6]).keys() == {1, 2} and pair_states(frames[6]) == [2, 2]
    assert one(frames[6], "policy:").endswith(":sha256") and not lines(frames[6], "finished:")
    assert not lines(frames[7], "finished:") and frames[8][0] == "rejected"
    assert sends(frames[9])[0] == sends(frames[4])[0]
frames = run([BIND, ["start", 0, 1, 3], receive(request()), ["start", 50, 2, 3],
              receive(response(1), 2000, base=LB[4])], streams=streams)
assert lines(frames[5], "retired:") and not lines(frames[5], "non-symmetric:") and not lines(frames[5], "finished:")
assert records(frames[5]).keys() == {1} and 2 in pair_states(frames[5])

# A wrong local base still receives a response from the original server's
# IP/port. Pin that server's algorithm after authentication, even though ICE fails
# its pair; a new triggered check uses it, while already signed retries stay fixed.
for algorithm in ("legacy", "sha256"):
    frames = run([BIND, ["start", 0, 1, 3], receive(response(1, algorithm), base=LB[4]), receive(request()),
                  ["start", 50, 2, 3], ["tick", 550]], streams=streams)
    assert one(frames[3], "policy:").endswith(":" + algorithm) and pair_states(frames[3])[0] == 4
    assert sends(frames[5], algorithm) and sends(frames[6])[0] == sends(frames[5])[0]
frames = run([BIND, ["start", 0, 1, 3], receive(request()), ["start", 50, 2, 3],
              receive(response(1, "sha256"), 51, base=LB[4]), ["tick", 550]], streams=streams)
assert one(frames[5], "policy:").endswith(":sha256")
assert sends(frames[6], "dual")[0] == sends(frames[4], "dual")[0]
# An older retained response cannot overwrite a first algorithm established by
# another current attempt at that endpoint, even if it arrives at the wrong base.
frames = run([BIND, ["start", 0, 1, 3], receive(request()), ["start", 50, 2, 3], receive(response(2)),
              receive(response(1, "sha256"), 60, base=LB[4])], streams=streams)
assert one(frames[6], "policy:").endswith(":legacy") and pair_states(frames[6])[0] == 3

# Failure does not thaw another pair of the same foundation. A second active
# pair is unaffected, and new triggered attempts never inherit an old reply.
frozen_base = cand(2130706175, 10002, "local")
frames = run([BIND, ["start", 0, 1, 3], receive(response(1), base=frozen_base[4])],
             streams=[[1, [[LA, LA], [frozen_base, frozen_base]], [RA]]])
assert pair_states(frames[3]) == [4, 0]
frames = run([BIND, ["start", 0, 1, 3], ["start", 50, 2, 3], receive(response(1), 51, source=RB[4]),
              receive(response(2), 52, base=LB[4])], streams=streams)
assert records(frames[4]).keys() == {1} and pair_states(frames[4]) == [4, 2]
assert records(frames[5]) == {} and pair_states(frames[5]) == [4, 3]
frames = run([BIND, ["start", 0, 1, 3], receive(response(1), 1, source=RB[4]), receive(request(), 10),
              ["start", 50, 2, 3], receive(response(1), 51, base=LB[4]), receive(response(2), 52)], streams=streams)
assert one(frames[3], "non-symmetric:").startswith("non-symmetric:1:0:")
assert records(frames[6]).keys() == {1} and 2 in pair_states(frames[6]) and not lines(frames[6], "non-symmetric:")
assert lines(frames[7], "finished:") and 3 in pair_states(frames[7])
# A bad late mismatch leaves the original listener's deadline/identity intact.
frames = run([BIND, ["start", 0, 1, 3], receive(request()), ["start", 50, 2, 3],
              receive(response(1, key=b"bad"), 51, base=LB[4]), receive(response(1), 52)], streams=streams)
assert records(frames[5]).keys() == {0, 1} and "/listening" in one(frames[5], "engine:")
assert not lines(frames[5], "non-symmetric:") and lines(frames[6], "late:") and records(frames[6]).keys() == {1}
# Already completed success/conflict outcomes cannot be replaced by a duplicate
# response arriving at another endpoint after their network transaction ended.
for error in (0, 487):
    frames = run([BIND, ["start", 0, 1, 3], receive(response(1, error=error)), receive(response(1), 20, source=RB[4])])
    assert not lines(frames[4], "non-symmetric:") and pair_states(frames[4]) == pair_states(frames[3])
    assert records(frames[4]) == records(frames[3]) and lines(frames[4], "raw:")

# Invalid/unrelated packets never trigger, mutate roles or postpone retirement.
for raw in (request(key=b"bad password"), request()[:-1] + bytes([request()[-1]^1]),
            fingerprint(packet(attr(6, b"localFrag:remoteFrag"), transaction=tx(9))), b"application data"):
    frames = run([BIND, ["start", 0, 1, 3], receive(raw), ["tick", 2000]])
    assert not lines(frames[3], "accepted:") and not lines(frames[3], "queued:")
    assert one(frames[3], "schedule:") == "schedule:controlling:0:1:0:1:7"
    # Due retries remain paced even if the logical test skips directly to 2000.
    assert sends(frames[4]) and records(frames[4]).keys() == {0}

# Current 487 requires auth and a fresh tie. An incoming request on another base
# changes current role while preserving the sent role; repair flips the sent role.
streams = [[1, [[LA, LA], [LB, LB]], [RA]]]
frames = run([BIND, ["start", 0, 1, 3], receive(request(control=True, tie=2), base=LB[4]),
              receive(response(1, error=487), 20), ["repair", 0, 8, 0, 3], ["repair", 0, 7, 0, 1],
              ["repair", 0, 7, 0, 3], ["start", 50, 2, 3], ["start", 100, 3, 3]], streams=streams)
assert one(frames[3], "schedule:").startswith("schedule:controlled:0:1:")
assert ":controlling:0:1:" in records(frames[4])[0] and records(frames[4])[0].split(":")[-2] == "1"
assert frames[5][0] == frames[6][0] == "rejected" and records(frames[6])[0].split(":")[-2] == "1"
assert one(frames[7], "schedule:").startswith("schedule:controlled:0:3:") and not records(frames[7])
assert sends(frames[8], "legacy") and sends(frames[9], "legacy")
for bad in (response(1, error=487, key=b"bad"), response(999, error=487)):
    frames = run([BIND, ["start", 0, 1, 3], receive(bad), ["repair", 0, 7, 0, 3]])
    assert frames[4][0] == "rejected" and records(frames[3])[0].split(":")[-2] == "0"

# Endpoint policy changes subsequent requests only after an authenticated reply;
# an in-flight retry still keeps its original cached dual bytes.
for algorithm in ("legacy", "sha256"):
    frames = run([BIND, ["start", 0, 1, 3], receive(response(1, algorithm, 500)), receive(request()), ["start", 50, 2, 3]])
    assert one(frames[3], "policy:").endswith(":" + algorithm)
    assert len(sends(frames[5], algorithm)) == 1 and len(attributes(sends(frames[5])[0])) == 5
frames = run([BIND, ["start", 0, 1, 3], receive(request()), ["start", 50, 2, 3],
              receive(response(1, "sha256"), 60), receive(response(2, "legacy", 500), 70),
              receive(request()), ["start", 100, 3, 3]])
assert one(frames[6], "policy:").endswith(":sha256") and sends(frames[8], "sha256")

# Explicit external algorithm selection rejects an authenticated opposite-mode
# response; failed integrity and transport outcomes release only their own flight.
for configured in ("legacy", "sha256"):
    opposite = "sha256" if configured == "legacy" else "legacy"
    frames = run([BIND, ["start", 0, 1, 3], receive(response(1, opposite)),
                  receive(response(1, configured, 500), 20), receive(request()), ["start", 50, 2, 3]], mode=configured)
    assert sends(frames[2], configured) and not lines(frames[3], "finished:") and not lines(frames[3], "policy:")
    assert one(frames[4], "policy:").endswith(":" + configured) and sends(frames[6], configured)
frames = run([BIND, ["start", 0, 1, 1], receive(response(1, key=b"bad key")), ["tick", 500]])
assert any(s.startswith("finished:0:integrity:") for s in frames[4]) and pair_states(frames[4]) == [4]
assert not records(frames[4]) and not lines(frames[4], "policy:")
frames = run([BIND, ["start", 0, 1, 3], ["fail", 0, 22], receive(request()), ["start", 50, 2, 3]])
assert any(s.startswith("finished:0:transport22:") for s in frames[3]) and pair_states(frames[3]) == [4]
assert pair_states(frames[4]) == [1] and records(frames[5]).keys() == {1} and sends(frames[5], "dual")
frames = run([BIND, ["start", 0, 1, 3], receive(request()), ["start", 50, 2, 3], ["fail", 0, 22]])
assert lines(frames[5], "retired:") and not lines(frames[5], "finished:") and pair_states(frames[5]) == [2]
frames = run([BIND, receive(request(nominate=True, control=False))])
assert replies(frames[2], code=400) and not lines(frames[2], "accepted:") and not lines(frames[2], "queued:")
assert run(mode="unknown") == [["invalid"]]

# Known signaled candidates keep metadata; learned foundations skip every
# signaled foundation, including candidates without a retained checklist pair.
frames = run([BIND, receive(request(priority=1000)), ["start", 0, 1, 3]])
assert one(frames[2], "remote:").startswith("remote:1:1:2100000000:remote:")
streams = [[1, [[LA, LA]], [cand(2100000000, 20001, "p0"), cand(2099999999, 20002, "p1")]]]
frames = run([BIND, receive(request(), source=[127, 0, 0, 1, 20003])], streams=streams, limit=3)
assert any(":p2:" in s for s in lines(frames[2], "remote:"))

# Atomic bounded pre-answer and learned-pair capacity handling.
frames = run([receive(request()), receive(request(91, nominate=True, control=True)), receive(request(92, control=True), source=RB[4]), BIND], streams=EMPTY, limit=1)
assert len(lines(frames[3], "pending:")) == 1 and any(s.endswith(":1") for s in lines(frames[3], "deferred:"))
assert len(lines(frames[4], "pair:")) == 1 and not lines(frames[4], "pending:")
frames = run([BIND, receive(request()), receive(request(91), source=RB[4]), ["drain"]], streams=EMPTY, limit=1)
assert len(lines(frames[4], "remote:")) == 1 and len(lines(frames[4], "pending:")) == 1
assert lines(frames[4], "deferred:") and "session:1:1:dual" in frames[4]

# Reject aliases even if pair pruning would hide them, and inconsistent base
# metadata across two reflexive advertised candidates.
for streams in ([], [[1, [[LA, LA]], [RA, cand(200, 20001, "alias")]]],
                [[1, [[LA, LA], [cand(2100000000, 15001, "reflex", "srflx"), cand(200, 10001, "changed")]], [RA]]]):
    assert run(streams=streams, limit=1) == [["invalid"]]
for capacity, limit in ((0, 100), (257, 100), (1, 0), (1, 257)):
    assert run(capacity=capacity, limit=limit) == [["invalid"]]

# Random signed arrivals test credential/source/role isolation and deduplication
# against independent expected endpoint and auth fields, not Bend-built inputs.
for n in range(30):
    source = [127, 0, 0, 1, 22000+n]
    priority = RNG.randrange(1, 2**31)
    incoming_mode = RNG.choice(("legacy", "sha256", "dual"))
    frames = run([BIND, receive(request(100+n, incoming_mode, priority=priority), source=source),
                  receive(request(200+n, incoming_mode, priority=priority), source=source), ["start", 0, n+1, 3]], streams=EMPTY)
    assert len(lines(frames[3], "pair:")) == 1 and len(lines(frames[3], "queued:")) == 1
    assert one(frames[3], "remote:").startswith(f"remote:1:1:{priority}:p0:")
    assert sends(frames[4], "dual") and records(frames[4]).keys() == {0}
print(f"ICE session: {COUNT} authenticated binding/registry/queue/attempt/clock/source/role/lifecycle cases passed")
