"""Independent real-UDP session checks over two retained local sockets."""
import contextlib
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from stun_reference import COOKIE, attr, attributes, packet, sign, validate

COMMAND = sys.argv[1:]
LOCAL_KEY = b"LocalFixturePassword123456"
REMOTE_KEY = b"SyntheticPassword123456789"
COUNT = 0


def request(n=90, control=False, tie=2, key=LOCAL_KEY):
    body = attr(6, b"localFrag:remoteFrag") + attr(0x24, struct.pack("!I", 1845494271))
    body += attr(0x802A if control else 0x8029, struct.pack("!Q", tie))
    return sign(packet(body, transaction=struct.pack("!III", n, 2, 3)), key, "dual")


def mapping(address):
    host, port = address
    return attr(0x20, b"\x00\x01" + struct.pack("!H", port ^ 0x2112) + bytes(a ^ b for a, b in zip(socket.inet_aton(host), COOKIE)))


def response(raw, address, mode="legacy", error=0):
    body = attr(9, bytes((0, 0, error//100, error%100)) + b"Error") if error else mapping(address)
    return sign(packet(body, kind=0x111 if error else 0x101, transaction=raw[8:20]), REMOTE_KEY, mode)


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Driver:
    def __init__(self, known=1, delay=0, duration=1300, capacity=4):
        self.first, self.second = ("127.0.0.1", free_port()), ("127.0.0.1", free_port())
        while self.second == self.first:
            self.second = ("127.0.0.1", free_port())
        self.peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.peer.bind(("127.0.0.1", 0))
        self.peer.settimeout(2)
        self.tmp = tempfile.TemporaryDirectory()
        self.output_path = Path(self.tmp.name) / "stdout"
        self.output = self.output_path.open("w")
        self.process = subprocess.Popen(COMMAND + [str(self.first[1]), str(self.second[1]), str(self.peer.getsockname()[1]),
                                       str(delay), str(duration), str(known), str(capacity)], stdout=self.output, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 2
        while "ready" not in self.output_path.read_text().splitlines():
            assert self.process.poll() is None, (self.process.poll(), self.process.stderr.read(), self.output_path.read_text())
            assert time.monotonic() < deadline, "session never became ready"
            time.sleep(0.01)

    def recv(self, mode="dual", timeout=2):
        self.peer.settimeout(timeout)
        raw, address = self.peer.recvfrom(65535)
        assert raw[:2] == b"\x00\x01", (raw.hex(), address)
        fields = validate(raw, REMOTE_KEY, mode)
        assert next(v for k, v, _ in fields if k == 6) == b"remoteFrag:localFrag"
        expected = 1862270975 if address == self.first else 1862270719
        assert address in (self.first, self.second)
        assert next(v for k, v, _ in fields if k == 0x24) == struct.pack("!I", expected)
        assert all(k != 0x25 for k, _, _ in fields)
        return raw, address, time.monotonic()

    def incoming(self, target=None, raw=None, signed=True, code=0):
        raw = raw or request()
        target = target or self.first
        self.peer.sendto(raw, target)
        self.peer.settimeout(1)
        reply, address = self.peer.recvfrom(65535)
        assert address == target and reply[8:20] == raw[8:20], (reply.hex(), address)
        fields = validate(reply, LOCAL_KEY, "sha256") if signed else attributes(reply)
        if code:
            error = next(v for k, v, _ in fields if k == 9)
            assert (error[2] & 7)*100 + error[3] == code
        else:
            assert next(v for k, v, _ in fields if k == 0x20) == mapping(self.peer.getsockname())[4:]
        return reply

    def finish(self):
        _, error = self.process.communicate(timeout=5)
        self.output.close()
        lines = self.output_path.read_text().splitlines()
        assert self.process.returncode == 0, (self.process.returncode, error, lines)
        assert lines[-1] == "done", lines
        for address in (self.first, self.second):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rebind:
                rebind.bind(address)
        return lines

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.communicate()
        self.output.close()
        self.peer.close()
        self.tmp.cleanup()


@contextlib.contextmanager
def driver(**kwargs):
    d = Driver(**kwargs)
    try:
        yield d
    finally:
        d.close()


# Pre-answer authentication responds before credentials, then creates ONLY the
# observed first-base pair. Invalid traffic cannot create a check on either base.
with driver(known=0, delay=350, duration=1200) as d:
    bad = request()
    d.peer.sendto(bad[:-1] + bytes([bad[-1]^1]), d.first)
    assert not select.select([d.peer], [], [], 0.06)[0], "answered invalid fingerprint"
    d.incoming(raw=request(key=b"bad password"), signed=False, code=401)
    first = d.incoming()
    assert d.incoming() == first, "duplicate reply changed"
    assert not select.select([d.peer], [], [], 0.1)[0], "check sent before answer"
    outgoing, address, _ = d.recv()
    assert address == d.first
    d.peer.sendto(response(outgoing, address), address)
    assert not select.select([d.peer], [], [], 0.3)[0], "learned peer paired with second base"
    log = d.finish()
    assert sum(s.startswith("send:") for s in log) == 1 and sum(s.startswith("pair:") for s in log) == 1, log
    assert any(s.startswith("deferred:") for s in log) and "session:1:1:dual" in log
    assert not any(s.startswith("record:") for s in log)
COUNT += 1

# Correlate actual receiving socket as well as peer source and transaction ID.
# A response on second base cannot finish first base; second checks/replies are
# independent, while the first retry preserves its original dual bytes and port.
with driver() as d:
    first, address, began = d.recv()
    assert address == d.first
    wrong_local_reply = response(first, address)
    d.peer.sendto(wrong_local_reply, d.second)
    second, address2, _ = d.recv()
    assert address2 == d.second and second[8:20] != first[8:20]
    d.peer.sendto(response(second, address2), address2)
    retry, retry_source, retried = d.recv()
    assert retry == first and retry_source == address and 0.44 <= retried - began <= 1.4
    d.peer.sendto(response(first, address), address)
    log = d.finish()
    assert "raw:" + wrong_local_reply.hex() in log
    assert f"datagram:1:1:127.0.0.1/{d.second[1]}:127.0.0.1/{d.peer.getsockname()[1]}" in log
    assert sum(s.startswith("finished:0:") for s in log) == 1 and sum(s.startswith("finished:1:") for s in log) == 1
    assert sum(s.startswith("pair:") and s.endswith(":3") for s in log) == 2
COUNT += 1

# Incoming check interrupts first attempt while second remains independent. Late
# success retains original sent-role metadata and never suppresses the replacement.
with driver(duration=1450) as d:
    first, address, began = d.recv()
    second, address2, _ = d.recv()
    d.incoming(raw=request(control=True, tie=2))
    replacement, replacement_source, replaced = d.recv()
    assert replacement_source == address and replacement[8:20] not in (first[8:20], second[8:20])
    role = next(v for k, v, _ in validate(replacement, REMOTE_KEY, "dual") if k == 0x8029)
    assert role == struct.pack("!Q", 1), "server switch changed its tie"
    d.peer.sendto(response(first, address, "sha256"), address)
    retried = set()
    while len(retried) < 2:
        retry, source, stamp = d.recv()
        assert retry[8:20] != first[8:20], "interrupted attempt retransmitted"
        if retry[8:20] == second[8:20]:
            assert retry == second and source == address2
            d.peer.sendto(response(second, address2), address2)
        else:
            assert retry == replacement and source == address and 0.44 <= stamp-replaced <= 1.4
            d.peer.sendto(response(replacement, address, "sha256"), address)
        retried.add(retry[8:20])
    log = d.finish()
    assert any(s.startswith("late:0:success-sha256:") and ":controlling:0:1:" in s for s in log)
    assert any(s.startswith("stopped:0:") for s in log) and sum(s.startswith("send:0:") for s in log) == 1
    assert not any(s.startswith("record:") for s in log)
COUNT += 1

# A signed 487 repairs from the role used in its request after another incoming
# check changed current role. New ID/tie and endpoint-specific response algorithms
# reach independent peers over their registered local base.
with driver(duration=1300) as d, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
    other.bind(("127.0.0.1", 0))
    other.settimeout(1)
    first, address, _ = d.recv()
    second, address2, _ = d.recv()
    incoming = request(91, control=True, tie=2)
    other.sendto(incoming, d.second)
    accepted, accepted_from = other.recvfrom(65535)
    assert accepted_from == d.second and accepted[8:20] == incoming[8:20]
    validate(accepted, LOCAL_KEY, "sha256")
    d.peer.sendto(response(first, address, error=487), address)
    learned, learned_source = other.recvfrom(65535)
    assert learned[:2] == b"\x00\x01" and learned_source == d.second
    validate(learned, REMOTE_KEY, "dual")
    other.sendto(response(learned, learned_source, "sha256"), learned_source)
    replacement, replacement_source, _ = d.recv("legacy")
    assert replacement_source == address and replacement[8:20] != first[8:20]
    fields = validate(replacement, REMOTE_KEY, "legacy")
    assert all(k != 0x802A for k, _, _ in fields), "repair flipped CURRENT instead of SENT role"
    assert next(v for k, v, _ in fields if k == 0x8029) != struct.pack("!Q", 1), "tie did not change"
    d.peer.sendto(response(replacement, address), address)
    d.peer.sendto(response(second, address2), address2)
    log = d.finish()
    assert any(s.startswith("finished:0:error487-legacy:") for s in log)
    assert any(s.startswith("policy:") and s.endswith(":sha256") for s in log)
    assert any(s.startswith("policy:") and s.endswith(":legacy") for s in log)
    assert not any(s.startswith("record:") for s in log)
COUNT += 1

# Retained-listener capacity cannot consume the triggered queue/token. At the
# original final deadline retirement unlocks a new check, without pair failure.
with driver(capacity=1, duration=2650) as d:
    first, address, began = d.recv()
    d.incoming()
    replacement, replacement_source, restarted = d.recv(timeout=2.5)
    assert replacement_source == address and replacement[8:20] != first[8:20]
    assert 1.94 <= restarted - began <= 2.5, restarted-began
    d.peer.sendto(response(replacement, address), address)
    other_base, other_source, _ = d.recv("legacy")
    assert other_source == d.second
    d.peer.sendto(response(other_base, other_source), other_source)
    log = d.finish()
    assert any(s.startswith("retired:0:") for s in log) and not any(s.startswith("finished:0:") for s in log)
    assert sum(s.startswith("send:0:") for s in log) == 1 and sum(s.startswith("send:1:") for s in log) == 1
    assert not any(s.startswith("record:") for s in log)
COUNT += 1

# Failed second bind and invalid session creation release any opened sockets.
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
    occupied.bind(("127.0.0.1", 0))
    first = free_port()
    result = subprocess.run(COMMAND + [str(first), str(occupied.getsockname()[1]), "20001", "0", "100", "1", "4"],
                            capture_output=True, text=True, timeout=2)
    assert result.returncode != 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rebind:
        rebind.bind(("127.0.0.1", first))
first, second = free_port(), free_port()
result = subprocess.run(COMMAND + [str(first), str(second), "20001", "0", "100", "1", "0"],
                        capture_output=True, text=True, timeout=2)
assert result.returncode != 0
for port in (first, second):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rebind:
        rebind.bind(("127.0.0.1", port))
COUNT += 1
print(f"ICE session UDP: {COUNT} pre-answer/two-base/loss/interruption/late/role/capacity/cleanup cases passed")
