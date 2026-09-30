"""Independent socket, byte, isolation, errno and resource-lifecycle checks."""
import contextlib
import errno
import select
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from udp_test_support import second_local_ipv4, udp_fd_count

COMMAND = sys.argv[1:]
COUNT = 0


def once(host, port=0):
    global COUNT
    result = subprocess.run(COMMAND + [host, str(port), "0", "0"], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, (host, port, result.stdout, result.stderr)
    COUNT += 1
    return result.stdout.splitlines()


class Driver:
    def __init__(self, host, port=0, reps=0, count=2):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "stdout"
        self.output = self.path.open("w")
        self.process = subprocess.Popen(COMMAND + [host, str(port), str(reps), str(count)],
                                        stdout=self.output, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 3
        while f"rejections:{reps}" not in self.path.read_text().splitlines():
            assert self.process.poll() is None, (self.path.read_text(), self.process.stderr.read())
            assert time.monotonic() < deadline, "address fixture did not become ready"
            time.sleep(0.01)
        line = self.path.read_text().splitlines()[0]
        assert line.startswith("bound:"), line
        _, bound_host, bound_port = line.split(":")
        self.address = (bound_host, int(bound_port))
        assert bound_host == host and 0 < self.address[1] <= 65535
        assert port == 0 or self.address[1] == port

    def finish(self):
        _, err = self.process.communicate(timeout=3)
        assert self.process.returncode == 0, (self.path.read_text(), err)
        assert self.path.read_text().splitlines()[-1] == "closed"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rebind:
            rebind.bind(self.address)

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.communicate()
        self.output.close()
        self.tmp.cleanup()


@contextlib.contextmanager
def driver(*args, **kwargs):
    d = Driver(*args, **kwargs)
    try:
        yield d
    finally:
        d.close()


# Canonical literal, assigned ephemeral port and truthful wildcard reporting.
for host in ("127.0.0.1", "0.0.0.0"):
    result = once(host)
    assert result[0].startswith(f"bound:{host}:") and int(result[0].split(":")[-1]) > 0
    assert result[-1] == "closed"
for host in ("", "localhost", "127.1", "127.0.0.256", "127.00.0.1", "127.0.0.1 ", " 127.0.0.1",
             "+127.0.0.1", "::1", "127.0.0.1:99", "127.0.0.1\n", "@nul", "１２７.0.0.1"):
    assert once(host) == [f"failed:{errno.EINVAL}"]
for port in (65536, 4294967295):
    assert once("127.0.0.1", port) == [f"failed:{errno.EINVAL}"]
assert once("192.0.2.1") == [f"failed:{errno.EADDRNOTAVAIL}"]

# OS address-in-use failures cannot steal an independent peer's socket.
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
    occupied.bind(("127.0.0.1", 0))
    assert once(*occupied.getsockname()) == [f"failed:{errno.EADDRINUSE}"]

# 1500 failed binds in ONE living process leave exactly its one UDP descriptor.
# All 256 octets and an empty datagram echo from the explicitly bound IP/port.
with driver("127.0.0.1", reps=1500) as d, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
    assert udp_fd_count(d.process.pid) == 1, "failed bind leaked UDP descriptors"
    peer.bind(("127.0.0.1", 0))
    peer.settimeout(1)
    for raw in (bytes(range(256)), b""):
        peer.sendto(raw, d.address)
        received, address = peer.recvfrom(65535)
        assert received == raw and address == d.address
    d.finish()
COUNT += 1

# Two explicitly bound IPs share a port without reuse options. Each independent
# peer receives only its target's payload, with the exact assigned source IP.
SECOND = second_local_ipv4()
with driver("127.0.0.1") as first, driver(SECOND, first.address[1]) as second:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as a, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as b:
        a.bind(("127.0.0.1", 0))
        b.bind(("127.0.0.1", 0))
        a.settimeout(1)
        b.settimeout(1)
        for pa, pb in ((b"first" + bytes(range(256)), b"second" + bytes(reversed(range(256)))), (b"", b"")):
            a.sendto(pa, first.address)
            b.sendto(pb, second.address)
            assert a.recvfrom(65535) == (pa, first.address)
            assert b.recvfrom(65535) == (pb, second.address)
        first.finish()
        second.finish()
COUNT += 1

# The binder must not silently fall back to wildcard: another unbound local IP
# at this same port delivers nothing; the valid target still receives its packet.
with driver("127.0.0.1", count=1) as d, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
    peer.bind(("127.0.0.1", 0))
    peer.settimeout(1)
    peer.sendto(b"wrong-destination", (SECOND, d.address[1]))
    assert not select.select([peer], [], [], 0.08)[0]
    peer.sendto(b"correct-destination", d.address)
    assert peer.recvfrom(65535) == (b"correct-destination", d.address)
    d.finish()
COUNT += 1
print(f"UDP address: {COUNT} literal/ephemeral/byte/same-port-IP/error/descriptor/cleanup cases passed; second IP {SECOND}")
