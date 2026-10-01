"""SHA-256 standard vectors plus binary and padding-boundary differential cases."""

import hashlib
import hmac
import argparse
from pathlib import Path
import random
import subprocess
import tempfile


VECTORS = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
    (b"a" * 1000000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
]


def hkdf_expand_reference(prk: bytes, info: bytes, length: int) -> str:
    previous = b""
    output = b""
    for index in range(1, (length + 31) // 32 + 1):
        previous = hmac.digest(prk, previous + info + bytes([index]), "sha256")
        output += previous
    return output[:length].hex()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bun", action="store_true")
    parser.add_argument("sha256")
    parser.add_argument("hkdf")
    options = parser.parse_args()
    binary = (["bun"] if options.bun else []) + [options.sha256]
    hkdf_binary = (["bun"] if options.bun else []) + [options.hkdf]
    cases = VECTORS + [
        (bytes(range(n % 256)) if n < 256 else bytes(range(256)), None)
        for n in (1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 256)
    ]
    rng = random.Random(0x534841)
    cases += [(rng.randbytes(n), None) for n in (2, 3, 31, 32, 33, 54, 57, 62, 66, 117, 121, 255, 513)]
    hmac_vectors = [
        (b"\x0b" * 20, b"Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        (b"Jefe", b"what do ya want for nothing?", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        (b"\xaa" * 20, b"\xdd" * 50, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
        (b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First", "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
        (bytes(range(64)), bytes(range(256)), None),
    ]
    hmac_vectors += [
        (rng.randbytes(key_len), rng.randbytes(data_len), None)
        for key_len, data_len in ((0, 0), (1, 1), (63, 55), (64, 56), (65, 57), (128, 513))
    ]
    hkdf_vectors = [
        (
            bytes(range(13)), b"\x0b" * 22, bytes(range(0xF0, 0xFA)), 42,
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        ),
        (
            bytes(range(0x60, 0xB0)), bytes(range(80)), bytes(range(0xB0, 0x100)), 82,
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f1d87",
        ),
        (
            b"", b"\x0b" * 22, b"", 42,
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        ),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "message.bin"
        key_path = Path(tmp) / "key.bin"
        info_path = Path(tmp) / "info.bin"
        for data, known in cases:
            expected = known or hashlib.sha256(data).hexdigest()
            path.write_bytes(data)
            got = subprocess.run(binary + [str(path)], capture_output=True, text=True, check=True).stdout.strip()
            assert got == expected, f"SHA-256 len={len(data)}: {got} != {expected}"
        for key, data, known in hmac_vectors:
            expected = known or hmac.digest(key, data, "sha256").hex()
            key_path.write_bytes(key)
            path.write_bytes(data)
            got = subprocess.run(binary + [str(key_path), str(path)], capture_output=True, text=True, check=True).stdout.strip()
            assert got == expected, f"HMAC key={len(key)} data={len(data)}: {got} != {expected}"
        for salt, ikm, info, length, prk, okm in hkdf_vectors:
            key_path.write_bytes(salt)
            path.write_bytes(ikm)
            info_path.write_bytes(info)
            lines = subprocess.run(
                hkdf_binary + [str(key_path), str(path), str(info_path), str(length)],
                capture_output=True, text=True, check=True,
            ).stdout.splitlines()
            assert lines == [prk, okm], f"HKDF length={length}: {lines} != {[prk, okm]}"
        salt, ikm, info, _, prk, _ = hkdf_vectors[0]
        key_path.write_bytes(salt)
        path.write_bytes(ikm)
        info_path.write_bytes(info)
        for length in (0, 1, 31, 32, 33, 8160):
            lines = subprocess.run(
                hkdf_binary + [str(key_path), str(path), str(info_path), str(length)],
                capture_output=True, text=True, check=True,
            ).stdout.splitlines()
            expected = [prk, hkdf_expand_reference(bytes.fromhex(prk), info, length)]
            assert lines == expected, f"HKDF boundary length={length}: {lines} != {expected}"
        too_long = subprocess.run(
            hkdf_binary + [str(key_path), str(path), str(info_path), "8161"],
            capture_output=True, text=True,
        )
        assert too_long.returncode != 0, "HKDF accepted more than 255 hash blocks"
    print(f"SHA-256: {len(cases)} standard and differential cases passed")
    print(f"HMAC-SHA-256: {len(hmac_vectors)} standard and differential cases passed")
    print(f"HKDF-SHA-256: {len(hkdf_vectors)} RFC 5869 cases and 7 length boundaries passed")


if __name__ == "__main__":
    main()
