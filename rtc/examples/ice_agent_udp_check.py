"""Real retained-socket nomination with an independent Python UDP ICE peer."""
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

COMMAND = sys.argv[1:]
KEY = b"SyntheticPassword123456789"
LOCAL_KEY = b"LocalFixturePassword123456"
COUNT = 0


def response(raw, mode="sha256", error=0, mapped="203.0.113.5", port=31001, key=KEY):
    body = attr(9, bytes((0, 0, error // 100, error % 100)) + b"Error") if error else attr(
        0x20, b"\x00\x01" + struct.pack("!H", port ^ 0x2112)
        + bytes(a ^ b for a, b in zip(socket.inet_aton(mapped), COOKIE)))
    return sign(packet(body, kind=0x111 if error else 0x101, transaction=raw[8:20]), key, mode)


def request(n=91, nomination=True, controlling=True, mode="dual", key=LOCAL_KEY):
    fields = attr(6, b"localFrag:remoteFrag") + attr(0x24, struct.pack("!I", 1845494271))
    fields += attr(0x802A if controlling else 0x8029, struct.pack("!Q", 2))
    if nomination:
        fields += attr(0x25, b"")
    return sign(packet(fields, transaction=struct.pack("!III", n, 2, 3)), key, mode)


class Driver:
    def __init__(self, mode="dual", scenario="controlling"):
        self.mode = mode
        self.scenario = scenario
        self.response_mode = "legacy" if mode == "legacy" else "sha256"
        self.peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.peer.bind(("127.0.0.1", 0))
        self.peer.settimeout(3)
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "stdout"
        self.output = self.path.open("w")
        self.process = subprocess.Popen(COMMAND + [str(self.peer.getsockname()[1]), mode, scenario],
                                        stdout=self.output, stderr=subprocess.PIPE, text=True)
        self.wait_line("ready")
        host, port = next(s for s in self.log() if s.startswith("base:"))[5:].split("/")
        self.address = host, int(port)

    def log(self):
        return self.path.read_text().splitlines()

    def wait_line(self, marker):
        end = time.monotonic() + 5
        while not any(marker in s for s in self.log()):
            assert self.process.poll() is None, self.log()
            assert time.monotonic() < end, (marker, self.log())
            time.sleep(0.01)

    def recv(self, nominate=False, mode=None, controlled=False):
        raw, source = self.peer.recvfrom(65535)
        assert source == self.address
        fields = validate(raw, KEY, mode or self.mode)
        assert fields[0][:2] == (6, b"remoteFrag:localFrag")
        assert fields[1][:2] == (0x24, struct.pack("!I", (110 << 24) + (65535 << 8) + 255))
        assert fields[2][:2] == (0x8029 if controlled else 0x802A, struct.pack("!Q", 1))
        assert any(k == 0x25 for k, _, _ in fields) == nominate
        assert raw[:2] == b"\x00\x01"
        return raw

    def ordinary(self):
        raw = self.recv(controlled=self.scenario == "controlled")
        self.peer.sendto(response(raw, self.response_mode), self.address)
        self.wait_line("validated:")
        return raw

    def nomination(self):
        return self.recv(nominate=True, mode=self.response_mode)

    def finish(self, expected="completed"):
        _, err = self.process.communicate(timeout=6)
        self.output.close()
        log = self.log()
        assert self.process.returncode == 0 and log[-1] == "done", (err, log)
        assert "terminal" in log and not any(s.startswith("fixture-") for s in log), log
        assert "agent-status:" + expected in log, log
        if expected == "completed":
            assert any(s.startswith("selected:1:1:") and s.endswith(":1") for s in log), log
        assert not any(s.startswith("pair:") or s.startswith("flight:") for s in log), log
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rebind:
            rebind.bind(self.address)
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


# Native/Bun exercise all integrity modes with dropped first nomination response.
# The repeat is a fresh transaction on the generating check's same bound socket;
# retransmission bytes and source are unchanged, and the mapping is nominated.
for mode in ("legacy", "sha256", "dual"):
    with driver(mode=mode) as d:
        ordinary = d.ordinary()
        nominal = d.nomination()
        assert ordinary[8:20] != nominal[8:20]
        sent_at = time.monotonic()
        retry = d.nomination()
        assert retry == nominal and time.monotonic() - sent_at >= 0.4
        d.peer.sendto(response(nominal, d.response_mode), d.address)
        log = d.finish()
        assert sum(s.startswith("nominated:") for s in log) == 1
        assert any("203.0.113.5/31001" in s for s in log if s.startswith("selected:1:1:"))
    COUNT += 1

# Authenticated failure causes PAC-delayed session failure; invalid MAC cannot
# complete the nomination, and its unchanged retry can subsequently succeed.
with driver() as d:
    d.ordinary()
    raw = d.nomination()
    d.peer.sendto(response(raw, key=b"wrong"), d.address)
    assert d.nomination() == raw
    d.peer.sendto(response(raw), d.address)
    assert not any(s.startswith("nomination-failed:") for s in d.finish())
COUNT += 1
with driver() as d:
    d.ordinary()
    raw = d.nomination()
    started = time.monotonic()
    d.peer.sendto(response(raw, error=500), d.address)
    log = d.finish("failed")
    assert time.monotonic() - started >= 1.5  # 1200ms configured PAC plus 800ms server grace.
    assert any(s.startswith("nomination-failed:") for s in log) and "pac-expired" in log
COUNT += 1
with driver() as d:
    d.ordinary()
    raw = d.nomination()
    assert d.nomination() == raw
    log = d.finish("failed")
    assert any("timed" in s or "timeout" in s for s in log if s.startswith("finished:")), log
COUNT += 1

# After conclusion the server still answers ordinary checks/repeated selected
# UC, while rejecting a new source's nomination before sending success.
with driver() as d:
    d.ordinary()
    raw = d.nomination()
    d.peer.sendto(response(raw), d.address)
    d.wait_line("nominated:")
    ordinary_request = request(nomination=False, controlling=False)
    d.peer.sendto(ordinary_request, d.address)
    reply, source = d.peer.recvfrom(65535)
    assert source == d.address and reply[:2] == b"\x01\x01" and reply[8:20] == ordinary_request[8:20]
    validate(reply, LOCAL_KEY, "sha256")
    nominal_request = request()
    d.peer.sendto(nominal_request, d.address)
    reply, source = d.peer.recvfrom(65535)
    assert source == d.address and reply[:2] == b"\x01\x01"
    validate(reply, LOCAL_KEY, "sha256")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
        other.bind(("127.0.0.1", 0))
        other.settimeout(2)
        other.sendto(request(92), d.address)
        rejected, source = other.recvfrom(65535)
        fields = validate(rejected, LOCAL_KEY, "sha256")
        assert source == d.address and rejected[:2] == b"\x01\x11"
        assert next(v for k, v, _ in fields if k == 9)[:4] == bytes((0, 0, 4, 0))
    log = d.finish()
    assert sum(s.startswith("applied:") for s in log) == 0
    assert sum(s.startswith("nominated:") for s in log) == 1
COUNT += 1

# The controlled side first establishes a valid pair, then accepting UC on its
# Succeeded check nominates immediately with no additional client request.
for mode in ("legacy", "sha256", "dual"):
    with driver(mode=mode, scenario="controlled") as d:
        d.ordinary()
        nominal_request = request(mode=mode)
        d.peer.sendto(nominal_request, d.address)
        reply, source = d.peer.recvfrom(65535)
        assert source == d.address and reply[:2] == b"\x01\x01"
        validate(reply, LOCAL_KEY, d.response_mode)
        log = d.finish()
        assert sum(s.startswith("nominated:") for s in log) == 1
        assert sum(s.startswith("send:") for s in log) == 1
    COUNT += 1

print(f"ICE agent retained UDP: {COUNT} scenarios passed")
