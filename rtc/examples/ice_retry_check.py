"""Independent UDP loss/timer/error/lifecycle evaluator for native and Bun."""
import contextlib
import socket
import struct
import subprocess
import sys
import time

from stun_reference import COOKIE, attr, fingerprint, length, packet, sign, validate

COMMAND = sys.argv[1:]
KEY = b"SyntheticPassword123456789"
COUNT = 0


def mapped(address):
    host, port = address
    return attr(0x20, b"\x00\x01" + struct.pack("!H", port ^ 0x2112) +
                bytes(a ^ b for a, b in zip(socket.inet_aton(host), COOKIE)))


def response(request, address, mode, body=None, kind=0x101):
    return sign(packet(mapped(address) if body is None else body, kind=kind,
                       transaction=request[8:20]), KEY, "sha256" if mode == "dual" else mode)


def request_fields(raw, mode, role="controlling"):
    items = validate(raw, KEY, mode)
    assert raw[:2] == b"\x00\x01"
    assert [(k, v) for k, v, _ in items[:3]] == [
        (6, b"remoteFrag:localFrag"), (0x24, struct.pack("!I", 1845494271)),
        (0x802A if role == "controlling" else 0x8029, bytes.fromhex("fedcba9876543210"))]


@contextlib.contextmanager
def session(mode="dual", policy="short"):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 0))
        server.settimeout(5)
        process = subprocess.Popen(COMMAND + [str(server.getsockname()[1]), mode, policy],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            yield server, process
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()


def finish(process, expected, timeout=5):
    global COUNT
    out, err = process.communicate(timeout=timeout)
    assert process.returncode == 0 and out.strip() == expected, (process.returncode, out, err, expected)
    COUNT += 1


def receive(server, mode="dual", role="controlling"):
    raw, address = server.recvfrom(65535)
    request_fields(raw, mode, role)
    return raw, address, time.monotonic()


def same(first, later):
    assert later[:2] == first[:2], "retry changed bytes/transaction/socket"


def interval(first, second, milliseconds):
    delta = second - first
    assert milliseconds / 1000 - 0.055 <= delta <= milliseconds / 1000 + 1.0, (delta, milliseconds)


# Lost requests/responses at every send of a short valid policy; algorithms stay
# selected across retransmission. Validate BOTH outgoing MACs for dual mode.
for mode in ("legacy", "sha256", "dual"):
    for lost in range(3):
        with session(mode) as (server, process):
            first = last = receive(server, mode)
            for retry in range(lost):
                current = receive(server, mode)
                same(first, current)
                interval(last[2], current[2], 500 * 2 ** retry)
                last = current
            server.sendto(response(first[0], first[1], mode), first[1])
            finish(process, f"{first[1][0]}:{first[1][1]}")
            server.settimeout(0.08)
            try:
                server.recvfrom(65535)
                raise AssertionError("send after completed transaction")
            except socket.timeout:
                pass

# Repeated invalid MACs/CRC, wrong source/transaction/class and algorithm are
# discarded, without postponing either retry or final timeout.
for recover in (False, True):
    with session() as (server, process), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
        first = receive(server)
        good = response(first[0], first[1], "dual")
        bad_mac = bytearray(sign(packet(mapped(first[1]), kind=0x101,
                                  transaction=first[0][8:20]), KEY, "sha256", with_fingerprint=False))
        bad_mac[-1] ^= 1
        wrong_tx = response(b"\x00" * 20, first[1], "dual")
        bad_crc = good[:-1] + bytes([good[-1] ^ 1])
        noise = [fingerprint(bad_mac), bad_crc, wrong_tx,
                 response(first[0], first[1], "dual", kind=1),
                 sign(packet(mapped(first[1]), kind=0x101, transaction=first[0][8:20]), KEY, "dual")]
        server.settimeout(0.02)
        requests = [first]
        index = 0
        while process.poll() is None and time.monotonic() - first[2] < 3.2:
            server.sendto(noise[index % len(noise)], first[1])
            other.sendto(good, first[1])
            index += 1
            try:
                current = receive(server)
                same(first, current)
                interval(requests[-1][2], current[2], 500 * 2 ** (len(requests) - 1))
                requests.append(current)
                if recover and len(requests) == 3:
                    server.sendto(good, first[1])
                    break
            except socket.timeout:
                pass
        assert len(requests) == 3, len(requests)
        if not recover:
            interval(first[2], time.monotonic(), 2000)
        finish(process, f"{first[1][0]}:{first[1][1]}" if recover else "integrity-violation")

# Unauthenticated errors and responses using an unselected algorithm cannot
# cancel a SHA-256 transaction. A subsequent authenticated response succeeds.
with session(mode="sha256") as (server, process):
    first = receive(server, "sha256")
    error_packet = packet(attr(9, b"\x00\x00\x04\x57"), kind=0x111, transaction=first[0][8:20])
    server.sendto(sign(error_packet, b"wrong key", "sha256"), first[1])
    server.sendto(sign(error_packet, KEY, "legacy"), first[1])
    retry = receive(server, "sha256")
    same(first, retry)
    interval(first[2], retry[2], 500)
    server.sendto(response(first[0], first[1], "sha256"), first[1])
    finish(process, f"{first[1][0]}:{first[1][1]}")

# Integrity violations are only recorded for a valid envelope from the peer,
# matching the live transaction and response class. Other traffic stays timeout.
for attack in ("bad-mac", "missing-mac", "wrong-source", "wrong-transaction", "wrong-class", "bad-fingerprint"):
    with session(policy="once") as (server, process):
        first = receive(server)
        raw = packet(mapped(first[1]), kind=1 if attack == "wrong-class" else 0x101,
                     transaction=b"\xff" * 12 if attack == "wrong-transaction" else first[0][8:20])
        raw = fingerprint(raw) if attack == "missing-mac" else sign(raw, b"wrong key", "sha256")
        if attack == "bad-fingerprint":
            raw = raw[:-1] + bytes([raw[-1] ^ 1])
        if attack == "wrong-source":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
                other.sendto(raw, first[1])
        else:
            server.sendto(raw, first[1])
        finish(process, "integrity-violation" if attack in ("bad-mac", "missing-mac") else "timeout", timeout=2)

# Exercise the ACTUAL RFC default, including every backoff and the final 8 s
# wait. Pure vector checks alone cannot prove the OS executor follows it.
with session(policy="default") as (server, process):
    first = last = receive(server)
    for wait_ms in (500, 1000, 2000, 4000, 8000, 16000):
        server.settimeout(wait_ms / 1000 + 2)
        current = receive(server)
        same(first, current)
        interval(last[2], current[2], wait_ms)
        last = current
    finish(process, "timeout", timeout=11)
    interval(last[2], time.monotonic(), 8000)
    interval(first[2], time.monotonic(), 39500)
    print("RFC default: seven identical sends, timeout at 39.5 s", flush=True)

# Authenticated response errors terminate immediately; they do not retry a
# role-conflicted request or reinterpret errors as mapped-address successes.
for mode, code in [(m, 487) for m in ("legacy", "sha256", "dual")] + [("dual", c) for c in (300, 400, 500, 600)]:
    with session(mode) as (server, process):
        first = receive(server, mode)
        body = attr(9, bytes([0xFF, 0xFF, 0xF8 | (code // 100), code % 100]) + "synthetic é".encode())
        server.sendto(response(first[0], first[1], mode, body, 0x111), first[1])
        finish(process, f"error:{code}", timeout=1)

# Bad authenticated response structure is a transaction failure, while unknown
# optional attrs and known-but-unexpected base attrs are harmless.
cases = [
    (0x111, b"", "invalid-response"),
    (0x111, attr(9, b"\x00\x00\x04"), "invalid-response"),
    (0x111, attr(9, b"\x00\x00\x02\x00"), "invalid-response"),
    (0x111, attr(9, b"\x00\x00\x07\x00"), "invalid-response"),
    (0x111, attr(9, b"\x00\x00\x04\x64"), "invalid-response"),
    (0x111, attr(9, b"\x00\x00\x04\x57\xff"), "invalid-response"),
    (0x111, attr(9, b"\x00\x00\x04\x57" + b"a" * 128), "invalid-response"),
    (0x111, attr(9, b"\x00\x00\x04\x57" + b"a" * 127), "error:487"),
    (0x111, attr(9, b"\x00\x00\x04\x57" + ("😀" * 127).encode()), "error:487"),
    (0x111, attr(9, b"\x00\x00\x04\x57" + ("😀" * 128).encode()), "invalid-response"),
    (0x111, attr(9, b"\x00\x00\x04\x57") + attr(9, b"\x00\x00\x05\x00"), "error:487"),
    (0x111, attr(0x7FFF, b"") + attr(9, b"\x00\x00\x04\x57"), "invalid-response"),
    (0x101, attr(0x7FFF, b""), "invalid-response"),
    (0x101, b"", "invalid-response"),
    (0x101, attr(0x20, b"\x00\x01"), "invalid-response"),
    (0x101, attr(0xFFFF, b"unknown optional"), "mapped"),
    (0x101, attr(0x14, b"unused realm"), "mapped"),
]
for kind, body, expected in cases:
    with session() as (server, process):
        first = receive(server)
        if kind == 0x101:
            body += mapped(first[1]) if expected == "mapped" or body else b""
        server.sendto(response(first[0], first[1], "dual", body, kind), first[1])
        finish(process, f"{first[1][0]}:{first[1][1]}" if expected == "mapped" else expected, timeout=1)

# Attributes after the integrity boundary cannot inject an error code or a
# comprehension-required failure, even when their enclosing CRC is correct.
for kind, protected, suffix, expected in [
    (0x101, "mapped", attr(0x7FFF, b""), "mapped"),
    (0x111, "empty", attr(9, b"\x00\x00\x04\x57"), "invalid-response"),
]:
    with session() as (server, process):
        first = receive(server)
        raw = sign(packet(mapped(first[1]) if protected == "mapped" else b"", kind=kind,
                          transaction=first[0][8:20]), KEY, "sha256", with_fingerprint=False)
        raw = fingerprint(length(raw + suffix, len(raw) + len(suffix) - 20))
        server.sendto(raw, first[1])
        finish(process, f"{first[1][0]}:{first[1][1]}" if expected == "mapped" else expected, timeout=1)

# Late response from a timed-out transaction cannot complete its successor.
# Both transactions and their retransmissions must use the same bound port.
with session(policy="reuse") as (server, process):
    first = receive(server)
    second = receive(server, role="controlled")
    assert first[1] == second[1] and first[0][8:20] != second[0][8:20]
    server.sendto(response(first[0], first[1], "dual"), first[1])
    retry = receive(server, role="controlled")
    same(second, retry)
    interval(second[2], retry[2], 500)
    server.sendto(response(second[0], second[1], "dual"), second[1])
    finish(process, f"timeout\n{second[1][0]}:{second[1][1]}")

# A dual response negotiates the algorithm for the next check to this peer.
for chosen in ("legacy", "sha256"):
    with session(policy="reuse-success") as (server, process):
        first = receive(server)
        server.sendto(response(first[0], first[1], chosen), first[1])
        second = receive(server, chosen, role="controlled")
        assert first[1] == second[1] and first[0][8:20] != second[0][8:20]
        server.sendto(response(second[0], second[1], chosen), second[1])
        address = f"{first[1][0]}:{first[1][1]}"
        finish(process, f"{address}\n{address}")

# Invalid policy never sends; a hard send failure does not enter retry waits.
for policy in ("invalid", "transport"):
    with session(policy=policy) as (server, process):
        out, err = process.communicate(timeout=1)
        assert process.returncode == 0 and (out.strip() == "invalid-input" if policy == "invalid"
                                            else out.startswith("transport:")), (out, err)
        server.settimeout(0.08)
        try:
            server.recvfrom(65535)
            raise AssertionError("invalid policy/transport failure sent a packet")
        except socket.timeout:
            COUNT += 1

print(f"ICE retry evaluator: {COUNT} loss/timing/error/lifecycle cases passed", flush=True)
