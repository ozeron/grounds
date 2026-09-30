"""Clock-boundary expectations independent of the Bend engine implementation."""
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from stun_reference import COOKIE, attr, fingerprint, packet, sign

COMMAND = sys.argv[1:]
EXPECTED = {
    "pacing": ["50,5:0/500/2:send0", "later:50", "100,55:0/500/2:1/550/2:send1",
               "100,505:0/1500/1:1/550/2:send0", "100,505:0/1500/1:1/550/2",
               "100,555:0/1500/1:1/1550/1:send1", "100,1505:0/2000/0:1/1550/1:send0",
               "100,1555:0/2000/0:1/2050/0:send1", "100,1555:1/2050/0:done0-timeout",
               "100,1555:done1-timeout", "wake:37"],
    "ack": ["50,5:0/500/0:send0", "548,503:0/500/0", "548,503:done0-timeout",
            "later:548", "598,553:1/1048/0:send1", "598,553:done1-transport22", "wake:37"],
    "duplicate": ["50,5:0/500/0:send0", "rejected", "rejected", "100,55:0/500/0:1/550/0:send1",
                  "100,55:1/550/0:cancel0", "100,55:1/550/0", "100,55:done1-timeout", "wake:37"],
    "cancel": ["current", "50,5:cancel0", "stale-suppressed"],
    "stop-schedule": ["50,5:0/500/2:send0", "50,605:0/1600/1:send0",
                      "50,605:0/2100/listening:stop0", "50,605:0/2100/listening",
                      "50,605:0/2100/listening", "wake:50", "50,605:0/2100/listening",
                      "50,605:retire0", "50,605", "wake:37"],
    "stop-capacity": ["50,5:0/500/2:send0", "50,5:0/2000/listening:stop0", "rejected", "rejected",
                      "100,55:0/2000/listening:1/550/2:send1", "100,55:0/2000/listening:1/2050/listening:stop1",
                      "rejected", "100,55:1/2050/listening:cancel0", "150,105:1/2050/listening:0/600/0:send0",
                      "150,105:0/600/0:retire1", "150,105:done0-timeout", "wake:37"],
    "stop-queued": ["50,5:0/2000/listening:stop0", "stale-suppressed", "50,5:retire0", "wake:37"],
    "stop-queued-retry": ["50,505:0/2000/listening:stop0", "stale-suppressed", "50,505:retire0", "wake:37"],
    "stop-default": ["50,5:0/500/6:send0", "50,5:0/39500/listening:stop0", "50,5:0/39500/listening",
                     "wake:1", "50,5:retire0", "wake:37"],
    "stop-socket": ["50,5:0/500/2:send0", "50,5:0/2000/listening:stop0", "100,55:0/2000/listening:1/550/2:send1",
                    "100,55:socket77:retire0:done1-transport77", "wake:37"],
}
count = 0


def run(args, expected):
    global count
    result = subprocess.run(COMMAND + args, capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, (args, result.stderr, result.stdout)
    assert result.stdout.splitlines() == expected, (args, result.stdout, expected)
    count += 1


for base in (0, 1, 3000000000, 4294967295):
    for scenario, expected in EXPECTED.items():
        run([scenario, str(base)], expected)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "response"
        # Independent RFC XOR mapping and HMAC/CRC response construction.
        address = b"\x00\x01" + struct.pack("!H", 9000 ^ 0x2112) + bytes(
            a ^ b for a, b in zip(bytes([127, 0, 0, 1]), COOKIE))
        unsigned = packet(attr(0x20, address), kind=0x101, transaction=struct.pack("!III", 1, 2, 3))
        for mode in ("legacy", "sha256"):
            for good in (True, False):
                path.write_bytes(sign(unsigned, b"SyntheticPassword123456789" if good else b"wrong key", mode))
                expected = ["50,5:0/500/0:send0",
                            "50,5:done0-success" if good else "50,5:0/500/0:raw",
                            "50,5:done0-timeout:raw",
                            "50,5" if good else "50,5:done0-integrity", "wake:37"]
                run(["response", str(base), str(path)], expected)

        transaction = struct.pack("!III", 1, 2, 3)
        for mode in ("legacy", "sha256"):
            good = sign(unsigned, b"SyntheticPassword123456789", mode)
            error = sign(packet(attr(9, b"\x00\x00\x04\x57fixture"), kind=0x111, transaction=transaction),
                         b"SyntheticPassword123456789", mode)
            invalid = sign(packet(attr(0x1234, b""), kind=0x101, transaction=transaction),
                           b"SyntheticPassword123456789", mode)
            cases = [(good, f"success-{mode}", "success"), (error, f"error487-{mode}", "other"),
                     (invalid, "invalid", "other"),
                     (sign(unsigned, b"wrong key", mode), None, None),
                     (sign(packet(attr(0x20, address), kind=0x101, transaction=b"\xAA"*12), b"SyntheticPassword123456789", mode), None, None),
                     (sign(packet(attr(0x20, address), kind=1, transaction=transaction), b"SyntheticPassword123456789", mode), None, None),
                     (sign(unsigned, b"SyntheticPassword123456789", mode, with_fingerprint=False), None, None),
                     (good[:-1] + bytes([good[-1]^1]), None, None), (fingerprint(unsigned), None, None),
                     (sign(packet(attr(6, b"forbidden") + attr(0x20, address), kind=0x101, transaction=transaction), b"SyntheticPassword123456789", mode), None, None)]
            for raw, accepted, early in cases:
                for when in (1999, 2000, 2001):
                    path.write_bytes(raw)
                    prefix = "50,5:0/2000/listening"
                    expected = ["50,5:0/500/2:send0", f"50,5:done0-{early}" if early else "50,5:0/500/2:raw",
                                prefix+":stop0", prefix+":raw", prefix+":raw"]
                    correlated = raw[:2] in (b"\x01\x01", b"\x01\x11") and raw[8:20] == transaction
                    if when >= 2000 and correlated:
                        expected += ["50,5:retire0:raw", "50,5"]
                    elif when >= 2000:
                        expected += [prefix+":raw", "50,5:retire0"]
                    elif accepted:
                        expected += ["50,5:late0-"+accepted, "50,5"]
                    else:
                        expected += [prefix+":raw", "50,5:retire0"]
                    expected += ["50,5", "50,5"] if early else [prefix+":stop0", "50,5:retire0"]
                    expected += ["wake:37"]
                    run(["listening", str(base), str(when), str(path)], expected)
print(f"ICE clocks: {count} pacing/large-timestamp/deadline/duplicate/cancellation/transport/response-retention cases passed")
