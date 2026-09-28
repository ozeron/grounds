"""RFC 2202 and independent hashlib checks for Bend HMAC-SHA1."""

import hashlib
import hmac
from pathlib import Path
import random
import subprocess
import sys
import tempfile


vectors = [
    (b"\x0b" * 20, b"Hi There", "b617318655057264e28bc0b6fb378c8ef146be00"),
    (b"Jefe", b"what do ya want for nothing?", "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"),
    (b"\xaa" * 20, b"\xdd" * 50, "125d7342b9ac11cd91a39af48aa17b4f63f175d3"),
    (bytes(range(1, 26)), b"\xcd" * 50, "4c9007f4026250c6bc8414f9bf50c86c2d7235da"),
    (b"\x0c" * 20, b"Test With Truncation", "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"),
    (b"\xaa" * 80, b"Test Using Larger Than Block-Size Key - Hash Key First",
     "aa4ae5e15272d00e95705637ce8a3b55ed402112"),
    (b"\xaa" * 80, b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
     "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"),
]

rng = random.Random(0x2202)
cases = vectors + [
    (rng.randbytes(key_len), rng.randbytes(msg_len), None)
    for key_len, msg_len in [(0, 0), (1, 1), (63, 55), (64, 56),
                             (65, 64), (80, 65), (131, 1024), (32, 65536)]
]

with tempfile.TemporaryDirectory() as directory:
    key_path = Path(directory) / "key.bin"
    msg_path = Path(directory) / "message.bin"
    for key, message, published in cases:
        key_path.write_bytes(key)
        msg_path.write_bytes(message)
        result = subprocess.run(sys.argv[1:] + [str(key_path), str(msg_path)],
                                capture_output=True, text=True)
        expected = hmac.new(key, message, hashlib.sha1).hexdigest()
        assert published is None or published == expected, "published vector mismatch"
        assert result.returncode == 0 and result.stdout.strip() == expected, (
            f"key {len(key)}, message {len(message)}: {result.stdout.strip()} != {expected}; {result.stderr.strip()}")

print(f"HMAC-SHA1: {len(vectors)} RFC 2202 vectors and {len(cases) - len(vectors)} differential cases passed")
