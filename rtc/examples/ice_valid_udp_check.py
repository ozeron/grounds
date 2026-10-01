"""Independent live UDP proof of mapped paths, retained attempts and cleanup."""
import contextlib
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from stun_reference import COOKIE, attr, packet, sign, validate

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "wire"))
from udp_test_support import second_local_ipv4

COMMAND = sys.argv[1:]
KEY = b"SyntheticPassword123456789"
LOCAL_KEY = b"LocalFixturePassword123456"
COUNT = 0
SECOND = second_local_ipv4()


def mapped(address):
    host, port = address
    return attr(0x20, b"\x00\x01" + struct.pack("!H", port ^ 0x2112)
                + bytes(a ^ b for a, b in zip(socket.inet_aton(host), COOKIE)))


def response(raw, address, mode="legacy", error=0):
    body = attr(9, bytes((0, 0, error // 100, error % 100)) + b"Error") if error else mapped(address)
    return sign(packet(body, kind=0x111 if error else 0x101, transaction=raw[8:20]), KEY, mode)


def request():
    body = attr(6, b"localFrag:remoteFrag") + attr(0x24, struct.pack("!I", 1845494271))
    body += attr(0x8029, struct.pack("!Q", 2))
    return sign(packet(body, transaction=b"triggeredUDP"), LOCAL_KEY, "dual")


class Driver:
    def __init__(self, known=True, delay=0, duration=1300):
        self.peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.peer.bind(("127.0.0.1", 0))
        self.peer.settimeout(2)
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "stdout"
        self.output = self.path.open("w")
        self.process = subprocess.Popen(COMMAND + ["127.0.0.1", "0", SECOND, "0", str(self.peer.getsockname()[1]),
                                       str(delay), str(duration), str(int(known)), "4"],
                                       stdout=self.output, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 3
        while "ready" not in self.path.read_text().splitlines():
            assert self.process.poll() is None, (self.path.read_text(), self.process.stderr.read())
            assert time.monotonic() < deadline
            time.sleep(0.01)
        bases = next(s for s in self.path.read_text().splitlines() if s.startswith("bases:"))
        self.addresses = [(host, int(port)) for host, port in (s.split("/") for s in bases.split(":")[1:])]

    def recv(self, mode="dual"):
        raw, source = self.peer.recvfrom(65535)
        fields = validate(raw, KEY, mode)
        assert source in self.addresses and raw[:2] == b"\x00\x01"
        priority = struct.unpack("!I", next(v for k, v, _ in fields if k == 0x24))[0]
        assert priority == (1862270975 if source == self.addresses[0] else 1862270719)
        return raw, source, priority

    def trigger(self):
        raw = request()
        self.peer.sendto(raw, self.addresses[0])
        reply, source = self.peer.recvfrom(65535)
        assert source == self.addresses[0] and reply[8:20] == raw[8:20]
        validate(reply, LOCAL_KEY, "sha256")

    def finish(self):
        _, err = self.process.communicate(timeout=5)
        self.output.close()
        log = self.path.read_text().splitlines()
        assert self.process.returncode == 0 and log[-1] == "done", (err, log)
        assert "valid-fault:0" in log
        for address in self.addresses:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rebind:
                rebind.bind(address)
        return log

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


def paths(log):
    got = []
    for line in log:
        if line.startswith("valid:"):
            v = line.split(":")
            high, low = map(int, v[11].split("/"))
            lp, rp = int(v[3]), int(v[8])
            assert (high << 32) + low == (min(lp, rp) << 32) + 2 * max(lp, rp) + (lp > rp)
            assert v[-1] == "0"
            got.append({"mapped": v[6], "base": v[7], "kind": int(v[5]), "priority": lp, "token": int(v[12])})
    return got


# Two queried ephemeral bases lose a response, retry from the same source, and
# learn different synthetic mapped addresses with the exact sent priorities.
with driver() as d:
    first, a, pa = d.recv()
    second, b, pb = d.recv()
    d.peer.sendto(response(first, ("203.0.113.5", 31001)), a)
    retry, source, _ = d.recv()
    assert retry == second and source == b
    d.peer.sendto(response(second, ("203.0.113.6", 31002)), b)
    log = d.finish()
    assert paths(log) == [{"mapped": "203.0.113.5/31001", "base": f"{a[0]}/{a[1]}", "kind": 2, "priority": pa, "token": 0},
                          {"mapped": "203.0.113.6/31002", "base": f"{b[0]}/{b[1]}", "kind": 2, "priority": pb, "token": 1}]
COUNT += 1

# Pre-answer triggered learning uses the incoming remote priority, while its
# local mapped priority comes from the actual retained outgoing request.
with driver(known=False, delay=250, duration=950) as d:
    d.trigger()
    raw, source, p = d.recv()
    d.peer.sendto(response(raw, ("203.0.113.7", 32001), "sha256"), source)
    log = d.finish()
    got = paths(log)
    assert len(got) == 1 and got[0]["priority"] == p and got[0]["kind"] == 2
    assert any(s.startswith("valid:") and ":1845494271:" in s for s in log)
COUNT += 1

# An interrupted listener's late mapping is distinct from its replacement's.
# Neither event changes the replacement's bytes or transaction correlation.
with driver(known=False, delay=150, duration=1100) as d:
    d.trigger()
    old, source, p = d.recv()
    d.trigger()
    new, replacement_source, _ = d.recv()
    assert replacement_source == source and new[8:20] != old[8:20]
    d.peer.sendto(response(old, ("203.0.113.8", 32002)), source)
    d.peer.sendto(response(new, ("203.0.113.9", 32003)), source)
    log = d.finish()
    assert len(paths(log)) == 2
    assert any(s.startswith("validated:1:1:") for s in log)
    assert not select.select([d.peer], [], [], 0.05)[0]
COUNT += 1

# Only known host mappings become paths here; an authenticated mismatch at the
# other IP and an error response cannot learn any mapped candidate.
with driver() as d:
    first, a, _ = d.recv()
    d.peer.sendto(response(first, ("203.0.113.10", 32004)), d.addresses[1])
    second, b, _ = d.recv("legacy")
    d.peer.sendto(response(second, b), b)
    log = d.finish()
    got = paths(log)
    assert len(got) == 1 and got[0]["kind"] == 0 and got[0]["mapped"] == f"{b[0]}/{b[1]}"
    assert not any(s.startswith("local-learned:") for s in log)
COUNT += 1

with driver() as d:
    first, a, _ = d.recv()
    second, b, _ = d.recv()
    d.peer.sendto(response(first, a, error=500), a)
    d.peer.sendto(response(second, b, error=500), b)
    assert not paths(d.finish())
COUNT += 1
print(f"ICE valid UDP: {COUNT} mapping/loss/pre-answer/late/IP-gate/error/cleanup cases passed")
