"""Real retained UDP nomination, consent service, and credential restart peers."""
import contextlib
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from stun_reference import COOKIE, attr, packet, sign, validate, attributes

COMMAND = sys.argv[1:]
KEY = b"SyntheticPassword123456789"
LOCAL_KEY = b"LocalFixturePassword123456"
NEW_KEY = b"NewRemoteFixturePassword123"
NEW_LOCAL_KEY = b"NewLocalFixturePassword1234"
COUNT = 0


def response(raw, address, mode, error=0, key=KEY):
    body = attr(9, bytes((0, 0, error // 100, error % 100)) + b"Error") if error else attr(
        0x20, b"\x00\x01" + struct.pack("!H", address[1] ^ 0x2112)
        + bytes(a ^ b for a, b in zip(socket.inet_aton(address[0]), COOKIE)))
    return sign(packet(body, kind=0x111 if error else 0x101, transaction=raw[8:20]), key, mode)


def incoming(n, gen=7):
    name = b"localFrag:remoteFrag" if gen == 7 else b"nextLocal:nextRemote"
    key = LOCAL_KEY if gen == 7 else NEW_LOCAL_KEY
    return sign(packet(attr(6, name), transaction=struct.pack("!III", n, 9, 10)), key, "sha256")


class Driver:
    def __init__(self, mode, scenario):
        self.mode, self.scenario = mode, scenario
        self.reply_mode = "legacy" if mode == "legacy" else "sha256"
        self.peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.peer.bind(("127.0.0.1", 0))
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "output"
        self.output = self.path.open("w")
        self.process = subprocess.Popen(COMMAND + [str(self.peer.getsockname()[1]), mode, scenario],
                                        stdout=self.output, stderr=subprocess.PIPE, text=True)
        self.wait_line("ready")
        host, port = next(line for line in self.log() if line.startswith("base:"))[5:].split("/")
        self.address = host, int(port)
        self.requests, self.probes, self.data = [], [], []

    def log(self):
        return self.path.read_text().splitlines()

    def wait_line(self, marker):
        end = time.monotonic() + 5
        while marker not in self.log():
            assert self.process.poll() is None, self.log()
            assert time.monotonic() < end, (marker, self.log())
            time.sleep(0.01)

    def recv(self, timeout=7):
        assert select.select([self.peer], [], [], timeout)[0], self.log()
        raw, source = self.peer.recvfrom(65535)
        assert source == self.address, source
        arrived = time.monotonic()
        if raw[:2] == bytes((165, 90)):
            assert len(raw) == 10 and raw[3:] == b"GROUNDS", raw
            assert raw[2] in (7, 8), raw
            self.data.append((raw[2], arrived))
            return "data", raw[2], raw
        assert raw[:2] in (b"\x00\x01", b"\x01\x01", b"\x01\x11"), raw.hex()
        if raw[:2] != b"\x00\x01":
            return "reply", 0, raw
        fields = attributes(raw)
        names = [value for kind, value, _ in fields if kind == 6]
        assert len(names) == 1 and names[0] in (b"remoteFrag:localFrag", b"nextRemote:nextLocal"), fields
        gen = 7 if names[0] == b"remoteFrag:localFrag" else 8
        key = KEY if gen == 7 else NEW_KEY
        types = [kind for kind, _, _ in fields]
        mode = "dual" if 8 in types and 28 in types else ("sha256" if 28 in types else "legacy")
        validate(raw, key, mode)
        is_probe = not any(kind in (0x24, 0x25, 0x8029, 0x802A) for kind in types)
        if is_probe:
            assert types == [6, 8 if mode == "legacy" else 28, 0x8028], types
            assert raw[8:20] not in [value[2][8:20] for value in self.probes], "consent nonce reused/retransmitted"
            self.probes.append((gen, arrived, raw))
        else:
            assert 0x24 in types and 0x802A in types and 0x8029 not in types, types
        self.requests.append((gen, arrived, raw))
        return "probe" if is_probe else ("nominate" if 0x25 in types else "check"), gen, raw

    def request(self, kind, gen=7):
        actual, generation, raw = self.recv()
        assert (actual, generation) == (kind, gen), (actual, generation, self.log())
        return raw

    def answer(self, raw, gen=7, error=0):
        self.peer.sendto(response(raw, self.address, self.reply_mode, error, KEY if gen == 7 else NEW_KEY), self.address)

    def handshake(self, gen=7):
        first = self.request("check", gen)
        self.answer(first, gen)
        nominate = self.request("nominate", gen)
        self.answer(nominate, gen)
        assert self.requests[-1][1] - self.requests[-2][1] >= 0.045, self.requests
        return self.request("probe", gen)

    def application(self, gen=7):
        kind, generation, _ = self.recv(timeout=2)
        assert (kind, generation) == ("data", gen), (kind, generation, self.log())

    def service(self, n, gen=7):
        raw = incoming(n, gen)
        self.peer.sendto(raw, self.address)
        kind, _, reply = self.recv(timeout=2)
        assert kind == "reply" and reply[:2] == b"\x01\x01" and reply[8:20] == raw[8:20], reply.hex()
        validate(reply, LOCAL_KEY if gen == 7 else NEW_LOCAL_KEY, "sha256")
        return reply

    def finish(self, gen, applications, status="granted"):
        global COUNT
        _, error = self.process.communicate(timeout=3)
        self.output.close()
        log = self.log()
        assert self.process.returncode == 0 and log[-1] == "done" and "terminal" in log, (log, error)
        assert any(line.startswith(f"slot:{gen}:") and f":{status}:" in line for line in log), log
        assert len(self.data) == applications, self.data
        assert sum(line.startswith("application-sent:") for line in log) == applications, log
        assert "application-blocked" in log, log
        assert not select.select([self.peer], [], [], 0.05)[0], "traffic survived completion"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
            other.bind(self.address)
        COUNT += 1

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.communicate()
        self.output.close()
        self.peer.close()
        self.tmp.cleanup()


for mode in ("legacy", "sha256", "dual"):
    with contextlib.closing(Driver(mode, "first")) as d:
        raw = d.handshake()
        d.service(90)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as wrong:
            wrong.bind(("127.0.0.1", 0))
            wrong.sendto(response(raw, d.address, d.reply_mode, 403), d.address)
        wrong_tx = raw[:8] + bytes([raw[8] ^ 1]) + raw[9:]
        d.peer.sendto(response(wrong_tx, d.address, d.reply_mode), d.address)
        d.peer.sendto(response(raw, d.address, d.reply_mode, 403, b"WrongPassword1234567890"), d.address)
        assert not select.select([d.peer], [], [], 0.05)[0], d.log()
        d.answer(raw)
        d.application()
        d.finish(7, 1)

with contextlib.closing(Driver("dual", "renew")) as d:
    d.handshake()  # The first role-free probe is deliberately lost.
    second = d.request("probe")
    d.answer(second)
    d.application()
    third = d.request("probe")
    d.answer(third)
    d.application()
    assert all(3.95 <= b[1] - a[1] <= 6.3 for a, b in zip(d.probes, d.probes[1:])), d.probes
    d.finish(7, 2)

with contextlib.closing(Driver("legacy", "revoke")) as d:
    d.answer(d.handshake())
    d.application()
    d.answer(d.request("probe"), error=403)
    d.finish(7, 1, "revoked")

# Hold replacement checks while the old tuple still needs consent. The peer
# observes old data, serves an old consent request and verifies both credential
# namespaces on one source port before completing the replacement nomination.
with contextlib.closing(Driver("dual", "restart")) as d:
    old = d.handshake()
    d.answer(old)
    d.application(7)
    d.application(7)  # A separately gated send immediately after local restart.
    first = d.request("check", 8)
    d.service(91, 7)
    d.answer(first, 8)
    nominate = d.request("nominate", 8)
    d.service(92, 7)
    # Keep replacement nomination in flight through an entire randomized old
    # consent period. Retransmissions must preserve the nomination's bytes.
    end = time.monotonic() + 7
    retries = 0
    while True:
        kind, generation, raw = d.recv()
        assert time.monotonic() < end, d.log()
        if (kind, generation) == ("nominate", 8):
            assert raw == nominate, "replacement retransmission changed signed bytes"
            retries += 1
            continue
        assert (kind, generation) == ("probe", 7), (kind, generation, d.log())
        d.answer(raw, 7)
        d.application(7)
        break
    assert retries >= 2, d.log()
    d.answer(nominate, 8)
    fresh = d.request("probe", 8)
    # A valid old-credential success and old incoming consent cannot authorize
    # the newly selected route, whose nomination retired the old namespace.
    d.peer.sendto(response(old, d.address, "sha256"), d.address)
    d.peer.sendto(incoming(93, 7), d.address)
    assert not select.select([d.peer], [], [], 0.05)[0], d.log()
    d.service(94, 8)
    d.answer(fresh, 8)
    d.application(8)
    assert all(b[1] - a[1] >= 0.004 for a, b in zip(d.requests, d.requests[1:])), d.requests
    d.finish(8, 4)

with contextlib.closing(Driver("dual", "expiry")) as d:
    first = d.handshake()
    answered = time.monotonic()
    d.answer(first)
    d.application()
    end = answered + 33
    while d.process.poll() is None:
        assert time.monotonic() < end, d.log()
        if not select.select([d.peer], [], [], 0.05)[0]:
            continue
        kind, generation, raw = d.recv()
        assert (kind, generation) == ("probe", 7), (kind, generation, d.log())
        d.peer.sendto(response(first, d.address, "sha256"), d.address)
        d.peer.sendto(response(raw, d.address, "sha256", 403, b"WrongPassword1234567890"), d.address)
    elapsed = time.monotonic() - answered
    assert 29.8 <= elapsed <= 31.5, (elapsed, d.log())
    assert 5 <= len(d.probes) <= 8, d.probes
    assert all(3.95 <= b[1] - a[1] <= 6.3 for a, b in zip(d.probes, d.probes[1:])), d.probes
    d.finish(7, 1, "expired")
    print(f"Actual integrated consent expiry: {elapsed:.3f}s, {len(d.probes)} unique one-shot probes")

print(f"ICE transport UDP: {COUNT} independent retained-socket scenarios passed")
