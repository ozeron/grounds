"""NIST CAVP GCM vectors and independent OpenSSL AES + bigint GHASH."""

import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import time


def aes_blocks(key: bytes, blocks: bytes) -> bytes:
    return subprocess.run(
        ["openssl", "enc", "-aes-128-ecb", "-K", key.hex(), "-nopad", "-nosalt"],
        input=blocks, capture_output=True, check=True,
    ).stdout


def multiply(x: int, y: int) -> int:
    z = 0
    for bit in range(127, -1, -1):
        if x & (1 << bit):
            z ^= y
        y = (y >> 1) ^ (0xE1000000000000000000000000000000 if y & 1 else 0)
    return z


def oracle(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    counter_blocks = b"".join(nonce + i.to_bytes(4, "big")
                              for i in range(2, 2 + (len(plaintext) + 15) // 16))
    encrypted = aes_blocks(key, bytes(16) + nonce + bytes.fromhex("00000001") + counter_blocks)
    h = int.from_bytes(encrypted[:16], "big")
    mask = int.from_bytes(encrypted[16:32], "big")
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, encrypted[32:]))
    data = (aad + bytes(-len(aad) % 16) + ciphertext + bytes(-len(ciphertext) % 16)
            + (8 * len(aad)).to_bytes(8, "big") + (8 * len(ciphertext)).to_bytes(8, "big"))
    digest = 0
    for start in range(0, len(data), 16):
        digest = multiply(digest ^ int.from_bytes(data[start:start + 16], "big"), h)
    return ciphertext, (digest ^ mask).to_bytes(16, "big")


def main() -> None:
    command = sys.argv[1:]
    rng = random.Random(0x38D128)
    vectors = json.loads(Path(__file__).with_name("gcm_vectors.json").read_text())["cases"]
    started = time.monotonic()
    length_cases = (0, 1, 15, 16, 17, (1 << 29) - 1, 1 << 29, (1 << 29) + 1,
                    (1 << 32) - 1, 1 << 32, (1 << 36) - 33, (1 << 36) - 32,
                    (1 << 36) - 31, (1 << 47) - 1, 1 << 47, (1 << 48) - 1)
    for length in length_cases:
        got = subprocess.run(command + ["length", str(length >> 32), str(length & 0xFFFFFFFF)],
                             capture_output=True, text=True, check=True)
        assert got.stdout.splitlines() == [(8 * length).to_bytes(8, "big").hex(),
                                          str(length <= (1 << 36) - 32).lower(),
                                          str((length + 15) // 16)], f"length {length}"
    assert subprocess.run(command + ["length", "65536", "0"], capture_output=True).returncode != 0
    with tempfile.TemporaryDirectory() as folder:
        paths = [Path(folder) / name for name in ("key", "nonce", "aad", "data", "tag")]

        field_cases = [(1 << bit, (1 << 128) - 1) for bit in range(128)]
        field_cases += [(0, 0), (0, (1 << 128) - 1), ((1 << 128) - 1, 0),
                        ((1 << 128) - 1, (1 << 128) - 1), (1, 1),
                        (1 << 127, 1 << 127)]
        field_cases += [(rng.getrandbits(128), rng.getrandbits(128)) for _ in range(32)]
        for x, y in field_cases:
            paths[0].write_bytes(x.to_bytes(16, "big"))
            paths[1].write_bytes(y.to_bytes(16, "big"))
            got = subprocess.run(command + ["multiply", str(paths[0]), str(paths[1])],
                                 capture_output=True, text=True, check=True)
            assert got.stdout.strip() == multiply(x, y).to_bytes(16, "big").hex(), (x, y)

        def bend(mode: str, key: bytes, nonce: bytes, aad: bytes, data: bytes,
                 tag: bytes | None = None) -> subprocess.CompletedProcess[str]:
            values = [key, nonce, aad, data] + ([tag] if tag is not None else [])
            for path, value in zip(paths, values):
                path.write_bytes(value)
            return subprocess.run(command + [mode] + [str(p) for p in paths[:len(values)]],
                                  capture_output=True, text=True, timeout=120)

        def verify(key: bytes, nonce: bytes, aad: bytes, data: bytes,
                   expected: tuple[bytes, bytes], label: str) -> None:
            assert oracle(key, nonce, aad, data) == expected, ("independent oracle", label)
            ciphertext, tag = expected
            sealed = bend("seal", key, nonce, aad, data)
            assert sealed.returncode == 0, (label, sealed.stderr)
            assert sealed.stdout.splitlines() == [ciphertext.hex(), tag.hex()], label
            opened = bend("open", key, nonce, aad, ciphertext, tag)
            assert opened.returncode == 0 and opened.stdout.strip() == data.hex(), label

        for case in vectors:
            key, nonce, aad, ciphertext, tag = (bytes.fromhex(case[k])
                                               for k in ("Key", "IV", "AAD", "CT", "Tag"))
            label = f'{case["source"]}:{case["settings"]}:{case["Count"]}'
            if case.get("FAIL"):
                opened = bend("open", key, nonce, aad, ciphertext, tag)
                assert opened.returncode != 0 and not opened.stdout.strip(), label
            else:
                verify(key, nonce, aad, bytes.fromhex(case["PT"]), (ciphertext, tag), label)

        lengths = (0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 257,
                   1024, 16384, 16385, 65536)
        for i, length in enumerate(lengths):
            key, nonce = rng.randbytes(16), rng.randbytes(12)
            aad = rng.randbytes((0, 1, 15, 16, 17, 31, 32, 33)[i % 8])
            data = rng.randbytes(length)
            verify(key, nonce, aad, data, oracle(key, nonce, aad, data), f"length {length}")

        key, nonce, aad, data = rng.randbytes(16), rng.randbytes(12), rng.randbytes(33), rng.randbytes(65)
        ciphertext, tag = oracle(key, nonce, aad, data)

        def reject(k: bytes = key, n: bytes = nonce, a: bytes = aad,
                   c: bytes = ciphertext, t: bytes = tag) -> None:
            p = bend("open", k, n, a, c, t)
            assert p.returncode != 0 and not p.stdout.strip(), "released unauthenticated plaintext"

        for i in range(16):
            altered = bytearray(tag)
            altered[i] ^= 1
            reject(t=altered)
        for i in (0, 15, 16, 63, 64):
            altered = bytearray(ciphertext)
            altered[i] ^= 0x80
            reject(c=altered)
        for i in (0, 15, 16, 32):
            altered = bytearray(aad)
            altered[i] ^= 1
            reject(a=altered)
        reject(k=bytes(x ^ 1 for x in key))
        reject(n=bytes(x ^ 1 for x in nonce))
        for size in (0, 1, 15, 17, 32):
            reject(t=bytes(size))
        for size in (0, 1, 15, 17, 24, 32):
            assert bend("seal", bytes(size), nonce, aad, data).returncode != 0
            reject(k=bytes(size))
        for size in (0, 1, 11, 13, 16):
            assert bend("seal", key, bytes(size), aad, data).returncode != 0
            reject(n=bytes(size))
    print(f"AES-128-GCM: {len(vectors)} selected NIST vectors (including 32 authentication "
          f"failures), {len(lengths)} independent differential/round-trip lengths through "
          f"64 KiB, 16 tag positions, payload/AAD/key/nonce tampering and malformed "
          f"lengths, {len(field_cases)} independent field products and "
          f"{len(length_cases)} compiled counter/length boundaries passed "
          f"in {time.monotonic() - started:.3f}s")


if __name__ == "__main__":
    main()
