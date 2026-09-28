"""RFC 8439 Poly1305 vectors and a bigint differential reference."""

from pathlib import Path
import random
import subprocess
import sys
import tempfile


def reference(key: bytes, message: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    acc = 0
    for start in range(0, len(message), 16):
        block = message[start:start + 16]
        number = int.from_bytes(block + b"\x01", "little")
        acc = ((acc + number) * r) % ((1 << 130) - 5)
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def edge_vectors() -> list[tuple[bytes, bytes, str]]:
    zero = bytes(16)
    r1 = bytes([1]) + bytes(15)
    r2 = bytes([2]) + bytes(15)
    r_big = bytes([1]) + bytes(7) + bytes([4]) + bytes(7)
    first = bytes.fromhex("e33594d7505e43b9") + bytes(8)
    second = bytes.fromhex("3394d7505e4379cd01") + bytes(7)
    third = bytes(16)
    fourth = bytes([1]) + bytes(15)
    return [
        (bytes(32), bytes(64), zero.hex()),
        (r2 + zero, bytes([255]) * 16, (bytes([3]) + bytes(15)).hex()),
        (r2 + bytes([255]) * 16, bytes([2]) + bytes(15), (bytes([3]) + bytes(15)).hex()),
        (r1 + zero, bytes([255]) * 16 + bytes([240]) + bytes([255]) * 15 + bytes([17]) + bytes(15), (bytes([5]) + bytes(15)).hex()),
        (r1 + zero, bytes([255]) * 16 + bytes([251]) + bytes([254]) * 15 + bytes([1]) * 16, zero.hex()),
        (r2 + zero, bytes([253]) + bytes([255]) * 15, (bytes([250]) + bytes([255]) * 15).hex()),
        (r_big + zero, first + second + third + fourth, bytes.fromhex("14000000000000005500000000000000").hex()),
        (r_big + zero, first + second + third, bytes.fromhex("13000000000000000000000000000000").hex()),
    ]


def main() -> None:
    binary = sys.argv[1:]
    rng = random.Random(0x1305)
    main_key = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
    vectors = [(main_key, b"Cryptographic Forum Research Group", "a8061dc1305136c6c22b8baf0c0127a9")]
    vectors += edge_vectors()
    with tempfile.TemporaryDirectory() as folder:
        key_path = Path(folder) / "key.bin"
        message_path = Path(folder) / "message.bin"

        def bend(key: bytes, message: bytes) -> subprocess.CompletedProcess[str]:
            key_path.write_bytes(key)
            message_path.write_bytes(message)
            return subprocess.run(binary + [str(key_path), str(message_path)], capture_output=True, text=True)

        for key, message, expected in vectors:
            assert reference(key, message).hex() == expected, "bad copied RFC vector"
            got = bend(key, message)
            assert got.returncode == 0 and got.stdout.strip() == expected, f"RFC vector len={len(message)}: {got.stdout.strip()} != {expected}"

        lengths = (0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 513)
        count = 0
        for length in lengths:
            for _ in range(2):
                key = rng.randbytes(32)
                message = rng.randbytes(length)
                got = bend(key, message)
                expected = reference(key, message).hex()
                assert got.returncode == 0 and got.stdout.strip() == expected, f"differential len={length}: {got.stdout.strip()} != {expected}"
                count += 1

        assert bend(bytes(31), b"").returncode != 0, "accepted short key"
        assert bend(bytes(33), b"").returncode != 0, "accepted long key"

    print(f"Poly1305: {len(vectors)} RFC vectors and {count} differential cases passed")


if __name__ == "__main__":
    main()
