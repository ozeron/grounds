"""Verify the public-pattern workload before relying on its timings."""
import json
import subprocess
import sys


def main():
    for mode in ("list", "bytes", "array"):
        for size in (0, 1, 3, 256, 257, 4096):
            out = subprocess.check_output([*sys.argv[1:], mode, str(size), "2"], text=True, timeout=10)
            value = json.loads(out)
            expected = sum(i & 255 for i in range(size)) * 2
            assert value["checksum"] == expected and value["ms"] >= 0, (mode, size, value)
    for args in (("list", "1048577", "1"), ("list", "1", "0"), ("list", "1", "1001"), ("unknown", "1", "1")):
        result = subprocess.run([*sys.argv[1:], *args], capture_output=True, text=True, timeout=10)
        assert result.returncode != 0, args
    print("Byte benchmark: 18 independent pattern/checksum cases and four argument rejections passed")


if __name__ == "__main__":
    main()
