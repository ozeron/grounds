"""Differential GF(2^255-19) field checks against Python big integers."""

from pathlib import Path
import random
import subprocess
import sys
import tempfile


P = (1 << 255) - 19
MASK = (1 << 255) - 1


def decoded(data: bytes) -> int:
    return (int.from_bytes(data, "little") & MASK) % P


def main() -> None:
    binary = sys.argv[1:]
    rng = random.Random(0x25519)
    edge = [0, 1, 18, 19, P - 1, P, P + 1, MASK, (1 << 256) - 1]
    pairs = [(a.to_bytes(32, "little"), b.to_bytes(32, "little"))
             for a in edge for b in edge]
    pairs.extend((rng.randbytes(32), rng.randbytes(32)) for _ in range(100))

    with tempfile.TemporaryDirectory() as folder:
        a_path = Path(folder) / "a.bin"
        b_path = Path(folder) / "b.bin"

        for a, b in pairs:
            a_path.write_bytes(a)
            b_path.write_bytes(b)
            av, bv = decoded(a), decoded(b)
            for name, result in (("add", av + bv), ("sub", av - bv), ("mul", av * bv)):
                got = subprocess.run(binary + [name, str(a_path), str(b_path)],
                                     capture_output=True, text=True)
                expected = (result % P).to_bytes(32, "little").hex()
                assert got.returncode == 0 and got.stdout.strip() == expected, (
                    f"{name}: {got.stdout.strip()} != {expected}; {got.stderr.strip()}")

        a_path.write_bytes(bytes(31))
        assert subprocess.run(binary + ["mul", str(a_path), str(b_path)],
                              capture_output=True).returncode != 0

    print(f"GF(2^255-19): {len(pairs)} operand pairs, three operations each passed")


if __name__ == "__main__":
    main()
