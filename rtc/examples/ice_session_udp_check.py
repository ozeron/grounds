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
from stun_reference import COOKIE, attr, attributes, fingerprint, packet, sign, validate

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "wire"))
from udp_test_support import second_local_ipv4

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


def free_port(host="127.0.0.1"):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


class Driver:
    def __init__(self, known=1, delay=0, duration=1300, capacity=4, first_host="127.0.0.1",
                 second_host="127.0.0.1", same_port=False, ephemeral=False, legacy=False):
        self.first = (first_host, 0 if ephemeral else free_port(first_host))
        self.second = (second_host, self.first[1] if same_port else (0 if ephemeral else free_port(second_host)))
        while self.second == self.first and not ephemeral:
            self.second = (second_host, free_port(second_host))
        self.peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.peer.bind(("127.0.0.1", 0))
        self.peer.settimeout(2)
        self.tmp = tempfile.TemporaryDirectory()
        self.output_path = Path(self.tmp.name) / "stdout"
        self.output = self.output_path.open("w")
        args = [str(self.first[1]), str(self.second[1]), str(self.peer.getsockname()[1]),
                str(delay), str(duration), str(known), str(capacity)] if legacy else [
                self.first[0], str(self.first[1]), self.second[0], str(self.second[1]), str(self.peer.getsockname()[1]),
                str(delay), str(duration), str(known), str(capacity)]
        self.process = subprocess.Popen(COMMAND + args, stdout=self.output, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 2
        while "ready" not in self.output_path.read_text().splitlines():
            assert self.process.poll() is None, (self.process.poll(), self.process.stderr.read(), self.output_path.read_text())
            assert time.monotonic() < deadline, "session never became ready"
            time.sleep(0.01)
        bases = next(s for s in self.output_path.read_text().splitlines() if s.startswith("bases:"))
        _, first, second = bases.split(":")
        actual = [(host, int(port)) for host, port in (first.split("/"), second.split("/"))]
        for configured, bound in zip((self.first, self.second), actual):
            assert configured[0] == bound[0] and (configured[1] == 0 or configured[1] == bound[1])
            assert 0 < bound[1] <= 65535
        self.first, self.second = actual

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
with driver(known=0, delay=350, duration=1200, legacy=True) as d:
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

# A signed response at the wrong registered local base immediately fails only
# the original pair. The second pair succeeds; no first-base retry is sent and
# a later symmetric copy cannot revive the old attempt. The original peer still
# selects its authenticated integrity algorithm for future requests.
with driver() as d:
    first, address, _ = d.recv()
    assert address == d.first
    wrong_local_reply = response(first, address)
    d.peer.sendto(wrong_local_reply, d.second)
    second, address2, _ = d.recv("legacy")
    assert address2 == d.second and second[8:20] != first[8:20]
    d.peer.sendto(response(second, address2), address2)
    d.peer.sendto(response(first, address), address)
    assert not select.select([d.peer], [], [], 0.75)[0], "non-symmetric failed attempt retransmitted"
    log = d.finish()
    assert any(s.startswith("non-symmetric:1:0:7:") and f":observed:1:1:127.0.0.1/{d.second[1]}:" in s for s in log)
    assert any(s.startswith("policy:") and s.endswith(":legacy") for s in log)
    assert not any(s.startswith("finished:0:") for s in log)
    assert sum(s.startswith("send:0:") for s in log) == 1 and sum(s.startswith("finished:1:") for s in log) == 1
    assert sum(s.startswith("pair:") and s.endswith(":3") for s in log) == 1
    assert sum(s.startswith("pair:") and s.endswith(":4") for s in log) == 1
COUNT += 1

# An independently bound peer source with valid credentials also triggers the
# failure transition. Its signed 487 cannot instead repair roles/requeue a check.
with driver() as d, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
    other.bind(("127.0.0.1", 0))
    first, address, _ = d.recv()
    other.sendto(response(first, address, error=487), address)
    second, address2, _ = d.recv()
    assert address2 == d.second
    d.peer.sendto(response(second, address2), address2)
    assert not select.select([d.peer], [], [], 0.75)[0]
    log = d.finish()
    assert any(s.startswith("non-symmetric:1:0:7:") and s.endswith(f"127.0.0.1/{other.getsockname()[1]}") for s in log)
    assert sum(s.startswith("send:") for s in log) == 2 and not any(s.startswith("finished:0:") for s in log)
    assert "schedule:controlling:0:1:0:2:7" in log
COUNT += 1

# A damaged MAC at another receiving base remains raw. It cannot fail or poison
# the original attempt; the exact first-base request retries and succeeds later.
with driver() as d:
    first, address, began = d.recv()
    bad = bytearray(response(first, address))
    mac_offset = next(pos for k, _, pos in attributes(bad) if k == 8)
    bad[mac_offset + 4] ^= 1
    bad = fingerprint(bytes(bad[:-8]))
    d.peer.sendto(bad, d.second)
    second, address2, _ = d.recv()
    d.peer.sendto(response(second, address2), address2)
    retry, source, retried = d.recv()
    assert retry == first and source == address and 0.44 <= retried - began <= 1.4
    d.peer.sendto(response(first, address), address)
    log = d.finish()
    assert "raw:" + bad.hex() in log and not any(s.startswith("non-symmetric:") for s in log)
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

# A signed non-symmetric old response retires the listener without touching the
# triggered replacement or the other base's active check, both of which retry.
with driver(duration=1450) as d:
    first, address, _ = d.recv()
    second, address2, _ = d.recv()
    d.incoming()
    replacement, replacement_source, replaced = d.recv()
    assert replacement_source == address
    d.peer.sendto(response(first, address, "sha256"), address2)
    retried = set()
    while len(retried) < 2:
        retry, source, stamp = d.recv()
        assert retry[8:20] != first[8:20]
        if retry[8:20] == second[8:20]:
            assert retry == second and source == address2
        else:
            assert retry == replacement and source == address and 0.44 <= stamp-replaced <= 1.4
        d.peer.sendto(response(retry, source), source)
        retried.add(retry[8:20])
    log = d.finish()
    assert any(s.startswith("non-symmetric:0:0:7:") for s in log)
    assert not any(s.startswith("finished:0:") or s.startswith("late:0:") or s.startswith("record:") for s in log)
    assert sum(s.startswith("pair:") and s.endswith(":3") for s in log) == 2
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

# The same port on two distinct explicitly bound local IPs proves IP identity.
# A first response at the second IP fails only the original first-IP pair;
# algorithm selection is shared by remote endpoint, while the second pair succeeds.
SECOND = second_local_ipv4()
with driver(second_host=SECOND, same_port=True) as d:
    first, address, _ = d.recv()
    assert address == d.first and d.first[1] == d.second[1] and d.first[0] != d.second[0]
    d.peer.sendto(response(first, address), d.second)
    second, address2, _ = d.recv("legacy")
    assert address2 == d.second and second[8:20] != first[8:20]
    d.peer.sendto(response(second, address2), address2)
    assert not select.select([d.peer], [], [], 0.75)[0]
    log = d.finish()
    assert any(s.startswith("non-symmetric:1:0:7:") and f":observed:1:1:{SECOND}/{d.second[1]}:" in s for s in log)
    assert sum(s.startswith("pair:") and s.endswith(":4") for s in log) == 1
    assert sum(s.startswith("pair:") and s.endswith(":3") for s in log) == 1
COUNT += 1

# Distinct-IP ordinary checks keep their actual source IP/port and retry bytes.
with driver(second_host=SECOND, same_port=True) as d:
    first, address, _ = d.recv()
    second, address2, began = d.recv()
    assert address == d.first and address2 == d.second
    d.peer.sendto(response(first, address), address)
    retry, source, retried = d.recv()
    assert retry == second and source == address2 and 0.44 <= retried-began <= 1.4
    d.peer.sendto(response(second, address2), address2)
    log = d.finish()
    assert not any(s.startswith("non-symmetric:") for s in log)
    assert sum(s.startswith("pair:") and s.endswith(":3") for s in log) == 2
COUNT += 1

# Port-zero binding uses the real queried address/port for candidate formation,
# outgoing requests, incoming response correlation and released-port rebinding.
with driver(second_host=SECOND, ephemeral=True) as d:
    first, address, _ = d.recv()
    second, address2, _ = d.recv()
    assert address == d.first and address2 == d.second
    d.peer.sendto(response(first, address), address)
    d.peer.sendto(response(second, address2), address2)
    log = d.finish()
    assert sum(s.startswith("pair:") and s.endswith(":3") for s in log) == 2
COUNT += 1

# A wildcard bind cannot provide received-IP identity for this ICE effects owner.
# Reject it before binding, and do not silently convert it to a concrete base.
for first_host, second_host in (("0.0.0.0", "127.0.0.1"), ("127.0.0.1", "0.0.0.0")):
    result = subprocess.run(COMMAND + [first_host, "0", second_host, "0", "20001", "0", "100", "1", "4"],
                            capture_output=True, text=True, timeout=2)
    assert result.returncode != 0 and "ready" not in result.stdout.splitlines()
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
print(f"ICE session UDP: {COUNT} pre-answer/two-IP-base/ephemeral/loss/interruption/late/role/capacity/cleanup cases passed; second IP {SECOND}")
