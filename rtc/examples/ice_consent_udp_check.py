"""Retained UDP consent against independent authenticated Python peers."""
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
DATA = bytes((165, 90, 71, 82, 79, 85, 78, 68, 83))
COUNT = 0


def response(raw, address, mode, error=0, key=KEY):
    body = attr(9, bytes((0, 0, error // 100, error % 100)) + b"Error") if error else attr(
        0x20, b"\x00\x01" + struct.pack("!H", address[1] ^ 0x2112)
        + bytes(a ^ b for a, b in zip(socket.inet_aton(address[0]), COOKIE)))
    return sign(packet(body, kind=0x111 if error else 0x101, transaction=raw[8:20]), key, mode)


class Driver:
    def __init__(self, mode, scenario):
        self.mode = mode
        self.reply_mode = "legacy" if mode == "legacy" else "sha256"
        self.peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.peer.bind(("127.0.0.1", 0))
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "output"
        self.output = self.path.open("w")
        self.process = subprocess.Popen(COMMAND + [str(self.peer.getsockname()[1]), mode, scenario],
                                        stdout=self.output, stderr=subprocess.PIPE, text=True)
        self.wait_line("ready")
        host, port = next(s for s in self.log() if s.startswith("base:"))[5:].split("/")
        self.address = host, int(port)
        self.probes, self.arrivals, self.data = [], [], []

    def log(self):
        return self.path.read_text().splitlines()

    def wait_line(self, marker):
        end = time.monotonic() + 5
        while marker not in self.log():
            assert self.process.poll() is None, self.log()
            assert time.monotonic() < end, (marker, self.log())
            time.sleep(0.01)

    def recv(self, timeout=7, mode=None):
        assert select.select([self.peer], [], [], timeout)[0], self.log()
        raw, source = self.peer.recvfrom(65535)
        assert source == self.address
        if raw == DATA:
            self.data.append(time.monotonic())
            return None
        fields = validate(raw, KEY, mode or self.mode)
        assert raw[:2] == b"\x00\x01" and fields[0][:2] == (6, b"remoteFrag:localFrag")
        assert not any(k == 0x25 for k, _, _ in fields)
        assert raw[8:20] not in [p[8:20] for p in self.probes], "a consent request was retransmitted/reused"
        self.probes.append(raw)
        self.arrivals.append(time.monotonic())
        return raw

    def probe(self, **kwargs):
        raw = self.recv(**kwargs)
        assert raw is not None, (self.probes, self.data, self.log())
        return raw

    def answer(self, raw, error=0):
        self.peer.sendto(response(raw, self.address, self.reply_mode, error), self.address)

    def application(self):
        assert self.recv(timeout=2) is None, self.log()

    def finish(self, status, applications):
        global COUNT
        _, error = self.process.communicate(timeout=3)
        self.output.close()
        log = self.log()
        assert self.process.returncode == 0 and log[-1] == "done", (log, error)
        assert "terminal" in log and "status:" + status in log, log
        assert "allowed:" + str(int(status == "granted")) in log, log
        assert log.count("application-sent") == len(self.data) == applications, log
        if status != "granted":
            assert "application-blocked" in log, log
        assert not select.select([self.peer], [], [], 0.05)[0], "queued traffic survived completion"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
            other.bind(self.address)
        COUNT += 1
        return log

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.communicate()
        self.output.close()
        self.peer.close()
        self.tmp.cleanup()


# All integrity modes, wrong source/transaction/key and forged revocation. No
# application datagram is sent before the matching authenticated success.
for mode in ("legacy", "sha256", "dual"):
    with contextlib.closing(Driver(mode, "first")) as d:
        raw = d.probe()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as wrong:
            wrong.bind(("127.0.0.1", 0))
            wrong.sendto(response(raw, d.address, d.reply_mode, 403), d.address)
        wrong_tx = raw[:8] + bytes([raw[8] ^ 1]) + raw[9:]
        d.peer.sendto(response(wrong_tx, d.address, d.reply_mode), d.address)
        d.peer.sendto(response(raw, d.address, d.reply_mode, 403, b"WrongPassword12345678900"), d.address)
        assert not select.select([d.peer], [], [], 0.05)[0], d.log()
        d.answer(raw)
        d.application()
        d.finish("granted", 1)

# Lost first probe is sent only once. Two later independent requests renew and
# authorize two actual application packets from the retained source port.
with contextlib.closing(Driver("dual", "renew")) as d:
    d.probe()
    second = d.probe()
    d.answer(second)
    d.application()
    third = d.probe(mode="sha256")
    d.answer(third)
    d.application()
    assert all(3.95 <= b - a <= 6.3 for a, b in zip(d.arrivals, d.arrivals[1:])), d.arrivals
    d.finish("granted", 2)

# Protected 403 immediately closes the application gate and retires all probes.
with contextlib.closing(Driver("legacy", "revoke")) as d:
    raw = d.probe()
    d.answer(raw)
    d.application()
    d.answer(d.probe(), 403)
    d.wait_line("application-blocked")
    d.finish("revoked", 1)

# Actual default 30-second expiry on both targets, measured from the only valid
# response. Old successes and forged 403s during loss cannot reset that clock.
with contextlib.closing(Driver("dual", "expiry")) as d:
    first = d.probe()
    answered = time.monotonic()
    d.answer(first)
    d.application()
    end = answered + 33
    while d.process.poll() is None:
        assert time.monotonic() < end, d.log()
        if not select.select([d.peer], [], [], 0.05)[0]:
            continue
        raw = d.recv(mode="sha256")
        assert raw is not None, "application data escaped during consent loss"
        d.peer.sendto(response(first, d.address, "sha256"), d.address)
        d.peer.sendto(response(raw, d.address, "sha256", 403, b"WrongPassword12345678900"), d.address)
    elapsed = time.monotonic() - answered
    assert 29.8 <= elapsed <= 31.5, (elapsed, d.log())
    assert 5 <= len(d.probes) <= 8, d.arrivals
    assert all(3.95 <= b - a <= 6.3 for a, b in zip(d.arrivals, d.arrivals[1:])), d.arrivals
    d.finish("expired", 1)
    print(f"Actual consent expiry: {elapsed:.3f}s, {len(d.probes)} unique one-shot probes")

print(f"ICE consent UDP: {COUNT} independent retained-socket scenarios passed")
