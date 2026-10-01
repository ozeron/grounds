"""Inspect actual native/Bun RNG adapter lengths, octets and public bounds."""
import subprocess
import sys


def main():
    sizes = (0, 1, 3, 4, 15, 16, 31, 32, 255, 256, 4096, 65535, 65536, 65537, 1048576)
    for count in sizes:
        run = subprocess.run([*sys.argv[1:], str(count)], capture_output=True, text=True, timeout=30, check=True)
        assert run.stdout.startswith("bytes:") and run.stdout.endswith("\n"), run.stdout[:100]
        raw = bytes.fromhex(run.stdout.removeprefix("bytes:").strip())
        assert len(raw) == count, (count, len(raw))
        assert len(run.stdout.strip()) == 6 + count * 2
    for count in (1048577, 4294967295):
        run = subprocess.run([*sys.argv[1:], str(count)], capture_output=True, text=True, timeout=5, check=True)
        assert run.stdout == "failed:22\n", run.stdout
    for value in ("-1", "4294967296", "invalid"):
        run = subprocess.run([*sys.argv[1:], value], capture_output=True, text=True, timeout=5)
        assert run.returncode == 2 and "count must be a U32" in run.stderr
    print("Bulk RNG: 20 real size/bound cases passed; sample shape is not entropy or timing proof")


if __name__ == "__main__":
    main()
