"""Clock-boundary expectations independent of the Bend engine implementation."""
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from stun_reference import COOKIE, attr, packet, sign

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
print(f"ICE clocks: {count} pacing/large-timestamp/deadline/duplicate/cancellation/transport cases passed")
