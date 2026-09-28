"""SHA-1 standard and hashlib differential checks for WebSocket use."""

from pathlib import Path
import hashlib
import random
import subprocess
import sys
import tempfile


def main() -> None:
    binary = sys.argv[1:]
    long = bool(binary and binary[0] == "--long")
    if long:
        binary = binary[1:]
    rng = random.Random(0x5A1)
    cases = [b"", b"abc", b"a" * 55, b"a" * 56, b"a" * 64,
             b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"]
    cases += [rng.randbytes(n) for n in (1, 15, 63, 65, 127, 128, 129, 1024, 65536)]
    if long:
        cases.append(b"a" * 1_000_000)
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "message.bin"
        for data in cases:
            path.write_bytes(data)
            got = subprocess.run(binary + [str(path)], capture_output=True, text=True)
            expected = hashlib.sha1(data).hexdigest()
            assert got.returncode == 0 and got.stdout.strip() == expected, (
                f"length {len(data)}: {got.stdout.strip()} != {expected}; {got.stderr.strip()}")
    print(f"SHA-1: {len(cases)} standard and differential cases passed")


if __name__ == "__main__":
    main()
