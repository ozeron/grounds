"""Independent USE-CANDIDATE wire/retained-transaction checks, not agent completion."""
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
COUNT = 0


def response(raw, mode="legacy", error=0, key=KEY):
    body = attr(9, bytes((0, 0, error // 100, error % 100)) + b"Error") if error else attr(
        0x20, b"\x00\x01" + struct.pack("!H", 31001 ^ 0x2112)
        + bytes(a ^ b for a, b in zip(socket.inet_aton("203.0.113.5"), COOKIE)))
    return sign(packet(body, kind=0x111 if error else 0x101, transaction=raw[8:20]), key, mode)


class Driver:
    def __init__(self, mode="dual", scenario="active"):
        self.mode = mode
        self.peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.peer.bind(("127.0.0.1", 0))
        self.peer.settimeout(2)
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "stdout"
        self.output = self.path.open("w")
        self.process = subprocess.Popen(COMMAND + [str(self.peer.getsockname()[1]), mode, scenario],
                                        stdout=self.output, stderr=subprocess.PIPE, text=True)
        self.wait_line("ready")
        text = next(s for s in self.log() if s.startswith("base:"))[5:]
        host, port = text.split("/")
        self.address = host, int(port)
        assert host == "127.0.0.1" and self.address[1] != 0

    def log(self):
        return self.path.read_text().splitlines()

    def wait_line(self, marker):
        end = time.monotonic() + 3
        while not any(marker in s for s in self.log()):
            assert self.process.poll() is None, self.log()
            assert time.monotonic() < end, (marker, self.log())
            time.sleep(0.01)

    def recv(self):
        raw, source = self.peer.recvfrom(65535)
        assert source == self.address
        fields = validate(raw, KEY, self.mode)
        assert [(k, v) for k, v, _ in fields[:4]] == [
            (6, b"remoteFrag:localFrag"), (0x24, struct.pack("!I", 1845494271)),
            (0x802A, struct.pack("!Q", 1)), (0x25, b"")]
        assert sum(k == 0x25 for k, _, _ in fields) == 1
        assert raw[8:20] == struct.pack("!III", 1, 2, 3)
        expected = sign(packet(b"".join(attr(k, v) for k, v, _ in fields[:4]), transaction=raw[8:20]), KEY, self.mode)
        assert raw == expected
        return raw

    def finish(self):
        _, err = self.process.communicate(timeout=4)
        self.output.close()
        log = self.log()
        assert self.process.returncode == 0 and log[-1] == "done", (err, log)
        assert not any(s.startswith("fixture-") for s in log), log
        state = next(s for s in log if s.startswith("state:"))
        assert "/listening" not in state and ":0/" not in state, state
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


# Loss causes one byte-exact retry from the same queried ephemeral address in
# all integrity modes, then a independently signed protected success completes.
for mode in ("legacy", "sha256", "dual"):
    with driver(mode=mode) as d:
        first = d.recv()
        started = time.monotonic()
        retry = d.recv()
        assert retry == first and time.monotonic() - started >= 0.4
        d.peer.sendto(response(first, "legacy" if mode == "legacy" else "sha256"), d.address)
        assert any(":done0-success" in s for s in d.finish())
    COUNT += 1

# Wrong authentication and wrong source cannot complete or reset the original
# deadline. The independently validated nominal packet still retries unchanged.
with driver() as d:
    raw = d.recv()
    d.peer.sendto(response(raw, key=b"wrong"), d.address)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
        other.bind(("127.0.0.1", 0))
        other.sendto(response(raw), d.address)
    assert d.recv() == raw
    d.peer.sendto(response(raw), d.address)
    assert any(":done0-success" in s for s in d.finish())
COUNT += 1

with driver() as d:
    raw = d.recv()
    d.peer.sendto(response(raw, error=500), d.address)
    assert any(":error500" in s for s in d.finish())
COUNT += 1

with driver() as d:
    raw = d.recv()
    assert d.recv() == raw
    assert any(":done0-timeout" in s for s in d.finish())
COUNT += 1

# Stop before the first retry. Late success/error stays a listener event, and
# no response retires at the original deadline without creating pair failure.
for outcome in ("success", "error", "expiry"):
    with driver(scenario="listen") as d:
        raw = d.recv()
        d.wait_line(":stop0")
        if outcome != "expiry":
            d.peer.sendto(response(raw, error=500 if outcome == "error" else 0), d.address)
        log = d.finish()
        marker = {"success": ":late0-success-legacy", "error": ":late0-error500-legacy", "expiry": ":retire0"}[outcome]
        assert any(marker in s for s in log) and not any(":done0-" in s for s in log), log
        assert not select.select([d.peer], [], [], 0.05)[0], "stopped nomination retried"
    COUNT += 1

# Reject a controlled request after actual binding and still release its port.
with driver(scenario="controlled") as d:
    assert "rejected" in d.finish()
    assert not select.select([d.peer], [], [], 0.05)[0]
COUNT += 1
print(f"ICE nomination UDP: {COUNT} protected-intent/loss/retry/auth/source/late/expiry/rejection/cleanup cases passed")
