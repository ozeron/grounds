"""Independent peers verify overlapping Bend checks on ONE real bound socket."""
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


def mapped(address):
    host, port = address
    return attr(0x20, b"\x00\x01" + struct.pack("!H", port ^ 0x2112) +
                bytes(a ^ b for a, b in zip(socket.inet_aton(host), COOKIE)))


def response(raw, address, mode="sha256", code=None, key=KEY):
    body = mapped(address) if code is None else attr(9, bytes([0, 0, code // 100, code % 100]) + b"fixture error")
    return sign(packet(body, kind=0x101 if code is None else 0x111, transaction=raw[8:20]), key, mode)


def check_request(raw, token):
    fields = validate(raw, KEY, "dual")
    assert raw[:2] == b"\x00\x01" and raw[8:20] == struct.pack("!III", token + 1, 2, 3)
    assert [(k, v) for k, v, _ in fields[:3]] == [
        (6, b"remoteFrag:localFrag"), (0x24, struct.pack("!I", 1845494271)),
        (0x802A, bytes.fromhex("fedcba9876543210"))]


@contextlib.contextmanager
def bound():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        yield s


def evaluate(scenario):
    global COUNT
    with bound() as a, bound() as b, bound() as other, tempfile.TemporaryDirectory() as tmp:
        # Reserve a local port, then let Bend bind it. A rare competing bind is
        # a visible test failure, never inferred as a successful candidate path.
        with bound() as reserved:
            local_port = reserved.getsockname()[1]
        output_path = Path(tmp) / "stdout"
        with output_path.open("w") as output:
            process = subprocess.Popen(COMMAND + [str(local_port), str(a.getsockname()[1]),
                                      str(b.getsockname()[1]), scenario if scenario in ("cancel", "queued-cancel") else "normal"],
                                       stdout=output, stderr=subprocess.PIPE, text=True)
            requests = [[], []]
            expected_raw = []
            pending = []
            start = time.monotonic()
            repeated_bad = None
            bad_at = 0
            try:
                def send(sock, raw, at=None, observed=False):
                    if observed:
                        expected_raw.append(f"datagram:127.0.0.1:{sock.getsockname()[1]}:{raw.hex()}")
                    if at is None:
                        sock.sendto(raw, ("127.0.0.1", local_port))
                    else:
                        pending.append((at, sock, raw))

                while process.poll() is None and time.monotonic() - start < 4:
                    now = time.monotonic()
                    due = [item for item in pending if item[0] <= now]
                    pending[:] = [item for item in pending if item[0] > now]
                    for _, sock, raw in due:
                        send(sock, raw)
                    if repeated_bad and now >= bad_at:
                        send(a, repeated_bad)
                        bad_at = now + 0.02
                    readable, _, _ = select.select([a, b], [], [], 0.005)
                    for sock in readable:
                        token = 0 if sock is a else 1
                        raw, address = sock.recvfrom(65535)
                        now = time.monotonic()
                        assert address == ("127.0.0.1", local_port), address
                        check_request(raw, token)
                        prior = requests[token]
                        if prior:
                            assert raw == prior[0][0], "retry changed authenticated bytes"
                            wait = 0.5 * 2 ** (len(prior) - 1)
                            assert wait - 0.055 <= now - prior[-1][1] <= wait + 0.5, (scenario, token, prior, now)
                        prior.append((raw, now))
                        attempt = len(prior)
                        if token == 1 and attempt == 1:
                            assert scenario == "queued-cancel" or (requests[0] and now - requests[0][0][1] >= 0.043), "Ta pacing missing"
                        good = response(raw, address, "legacy" if token == 1 else "sha256")
                        if scenario == "out-of-order":
                            if token == 1:
                                send(b, good)
                                send(a, response(requests[0][0][0], address), now + 0.05)
                        elif scenario in ("loss-A", "loss-B", "loss-both"):
                            lose = token == (0 if scenario == "loss-A" else 1) or scenario == "loss-both"
                            target = 3 if scenario == "loss-both" else 2
                            if not lose or attempt == target:
                                send(sock, good)
                        elif scenario == "bad-A":
                            if token == 0:
                                repeated_bad = response(raw, address, key=b"wrong key")
                                send(a, repeated_bad)
                            else:
                                send(b, good)
                        elif scenario == "error-A":
                            send(sock, response(raw, address, code=487) if token == 0 else good)
                        elif scenario == "timeout":
                            pass
                        elif scenario in ("cancel", "queued-cancel"):
                            if token == 1:
                                # Retired A's late valid response must remain raw;
                                # cancelling A must not reset or cancel B.
                                send(a, response(requests[0][0][0] if requests[0] else packet(b"", transaction=struct.pack("!III", 1, 2, 3)), address), observed=True)
                                send(b, good, now + 0.05)
                        elif scenario == "raw":
                            if token == 1:
                                assert len(requests[0]) == 1
                                foreign = sign(packet(attr(6, b"localFrag:remoteFrag"), kind=1,
                                                      transaction=b"\xAA" * 12), b"LocalFixturePassword123456", "legacy")
                                payloads = [b"", b"not STUN", foreign, foreign[:-1] + bytes([foreign[-1] ^ 1]),
                                            bytes(range(256)) * 32,
                                            response(requests[0][0][0], ("203.0.113.9", 9))]
                                for index, payload in enumerate(payloads):
                                    # The final response has a valid MAC/transaction
                                    # but an unrelated source. All stay raw.
                                    send(other, payload, now + 0.015 * index, observed=True)
                                send(b, good, now + 0.12)
                                send(a, response(requests[0][0][0], address), now + 0.15)
                        else:
                            raise AssertionError(scenario)
                out, err = process.communicate(timeout=1)
                assert process.returncode == 0, (scenario, process.returncode, err, output_path.read_text())
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate()
        lines = output_path.read_text().splitlines()
        assert all(line in lines for line in expected_raw), (scenario, [line[:100] for line in expected_raw if line not in lines])
        assert len(requests[0]) == (0 if scenario == "queued-cancel" else 3 if scenario in ("loss-both", "bad-A", "timeout") else 2 if scenario == "loss-A" else 1)
        assert len(requests[1]) == (3 if scenario in ("loss-both", "timeout") else 2 if scenario == "loss-B" else 1)
        expected_checks = "checks:4:4" if scenario == "timeout" else "checks:4:3" if scenario in ("bad-A", "error-A", "cancel", "queued-cancel") else "checks:3:3"
        assert lines[-1] == expected_checks, (scenario, lines[-8:])
        for token in (0, 1):
            if scenario in ("cancel", "queued-cancel") and token == 0:
                assert "cancelled:0" in lines
                continue
            result = "timeout" if scenario == "timeout" else "integrity-violation" if scenario == "bad-A" and token == 0 else "error:487" if scenario == "error-A" and token == 0 else f"success:127.0.0.1/{local_port}"
            assert f"finished:{token}:{result}" in lines, (scenario, lines[-8:])
        if scenario == "out-of-order":
            assert next(i for i, s in enumerate(lines) if s.startswith("finished:1:")) < next(i for i, s in enumerate(lines) if s.startswith("finished:0:"))
        if scenario == "timeout":
            elapsed = time.monotonic() - requests[1][0][1]
            assert 1.97 <= elapsed <= 2.8, elapsed
        COUNT += 1


for scenario in ("out-of-order", "loss-A", "loss-B", "loss-both", "bad-A", "error-A", "timeout", "cancel", "queued-cancel", "raw"):
    evaluate(scenario)
print(f"ICE shared socket: {COUNT} overlapping/loss/pacing/raw-delivery/cancellation/checklist cases passed")
