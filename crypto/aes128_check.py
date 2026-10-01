"""FIPS 197, all 284 AESAVS AES-128 ECB KATs, and OpenSSL differentials."""

import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile


# FIPS 197 Table 4, row-major. This table is an oracle only, never Bend logic.
SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)


def oracle(key: bytes, block: bytes) -> bytes:
    return subprocess.run(
        ["openssl", "enc", "-aes-128-ecb", "-K", key.hex(), "-nopad", "-nosalt"],
        input=block, capture_output=True, check=True,
    ).stdout


def main() -> None:
    command = sys.argv[1:]
    table = subprocess.run(command + ["sbox"], capture_output=True, text=True, check=True)
    assert bytes.fromhex(table.stdout.strip()) == SBOX, "FIPS 197 S-box table"
    vectors = json.loads(Path(__file__).with_name("aes128_vectors.json").read_text())["cases"]
    rng = random.Random(0x197128)
    with tempfile.TemporaryDirectory() as folder:
        key_path, block_path = (Path(folder) / name for name in ("key", "block"))

        def bend(key: bytes, block: bytes) -> subprocess.CompletedProcess[str]:
            key_path.write_bytes(key)
            block_path.write_bytes(block)
            return subprocess.run(command + [str(key_path), str(block_path)],
                                  capture_output=True, text=True, timeout=30)

        def verify(key: bytes, block: bytes, expected: bytes, label: str) -> None:
            got = bend(key, block)
            assert got.returncode == 0, (label, got.stderr)
            assert bytes.fromhex(got.stdout.strip()) == expected, label
            assert oracle(key, block) == expected, ("OpenSSL", label)

        verify(bytes(range(16)), bytes.fromhex("00112233445566778899aabbccddeeff"),
               bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"), "FIPS 197 example")
        for case in vectors:
            verify(bytes.fromhex(case["key"]), bytes.fromhex(case["plaintext"]),
                   bytes.fromhex(case["ciphertext"]), f'{case["source"]}:{case["count"]}')
        for i in range(40):
            key, block = rng.randbytes(16), rng.randbytes(16)
            verify(key, block, oracle(key, block), f"differential {i}")
        for n in (0, 1, 15, 17, 24, 32):
            assert bend(bytes(n), bytes(16)).returncode != 0, f"accepted key length {n}"
            assert bend(bytes(16), bytes(n)).returncode != 0, f"accepted block length {n}"
    print(f"AES-128: FIPS example, all 256 S-box bytes, {len(vectors)} NIST KATs, "
          "40 OpenSSL differentials and 12 malformed lengths passed")


if __name__ == "__main__":
    main()
