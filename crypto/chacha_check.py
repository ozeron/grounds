"""RFC 8439 vectors and independent OpenSSL ChaCha20 differential checks."""

from pathlib import Path
import random
import subprocess
import sys
import tempfile


BLOCK_VECTOR = (
    "10f1e7e4d13b5915500fdd1fa32071c4"
    "c7d1f4c733c068030422aa9ac3d46c4e"
    "d2826446079faa0914c2d705d98b02a2"
    "b5129cd1de164eb9cbd083e8a2503c4e"
)
CIPHER_VECTOR = (
    "6e2e359a2568f98041ba0728dd0d6981"
    "e97e7aec1d4360c20a27afccfd9fae0b"
    "f91b65c5524733ab8f593dabcd62b357"
    "1639d624e65152ab8f530c359f0861d8"
    "07ca0dbf500d6a6156a38e088a22b65e"
    "52bc514d16ccf806818ce91ab7793736"
    "5af90bbf74a35be6b40b8eedf2785e42"
    "874d"
)
PLAINTEXT = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you only "
    b"one tip for the future, sunscreen would be it."
)


def openssl(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    iv = counter.to_bytes(4, "little") + nonce
    return subprocess.run(
        ["openssl", "enc", "-chacha20", "-K", key.hex(), "-iv", iv.hex(), "-nosalt"],
        input=data, capture_output=True, check=True,
    ).stdout


def main() -> None:
    binary = sys.argv[1:]
    rng = random.Random(0x8439)
    with tempfile.TemporaryDirectory() as folder:
        key_path = Path(folder) / "key.bin"
        nonce_path = Path(folder) / "nonce.bin"
        message_path = Path(folder) / "message.bin"

        def bend(key: bytes, nonce: bytes, counter: int, data: bytes | None = None) -> subprocess.CompletedProcess[str]:
            key_path.write_bytes(key)
            nonce_path.write_bytes(nonce)
            args = binary + [str(key_path), str(nonce_path), str(counter)]
            if data is not None:
                message_path.write_bytes(data)
                args.append(str(message_path))
            return subprocess.run(args, capture_output=True, text=True)

        key = bytes(range(32))
        block_nonce = bytes.fromhex("000000090000004a00000000")
        got = bend(key, block_nonce, 1)
        assert got.returncode == 0 and got.stdout.strip() == BLOCK_VECTOR, "RFC 8439 block vector"
        assert openssl(key, block_nonce, 1, bytes(64)).hex() == BLOCK_VECTOR

        cipher_nonce = bytes.fromhex("000000000000004a00000000")
        got = bend(key, cipher_nonce, 1, PLAINTEXT)
        assert got.returncode == 0 and got.stdout.strip() == CIPHER_VECTOR, "RFC 8439 cipher vector"
        assert openssl(key, cipher_nonce, 1, PLAINTEXT).hex() == CIPHER_VECTOR

        block_cases = 0
        for counter in (0, 1, 42, 0xFFFFFFFF):
            for _ in range(2):
                key = rng.randbytes(32)
                nonce = rng.randbytes(12)
                got = bend(key, nonce, counter)
                assert got.returncode == 0
                assert got.stdout.strip() == openssl(key, nonce, counter, bytes(64)).hex()
                block_cases += 1

        stream_cases = 0
        for length in (0, 1, 31, 63, 64, 65, 127, 128, 129, 513):
            key = rng.randbytes(32)
            nonce = rng.randbytes(12)
            data = rng.randbytes(length)
            counter = 0 if length == 0 else 1
            got = bend(key, nonce, counter, data)
            assert got.returncode == 0
            expected = openssl(key, nonce, counter, data)
            assert got.stdout.strip() == expected.hex(), f"stream length {length}"
            recovered = bend(key, nonce, counter, expected)
            assert recovered.returncode == 0 and recovered.stdout.strip() == data.hex()
            stream_cases += 1

        key = rng.randbytes(32)
        nonce = rng.randbytes(12)
        assert bend(key[:-1], nonce, 0).returncode != 0, "accepted short key"
        assert bend(key, nonce[:-1], 0).returncode != 0, "accepted short nonce"
        assert bend(key, nonce, 0xFFFFFFFF, bytes(64)).returncode == 0
        assert bend(key, nonce, 0xFFFFFFFF, bytes(65)).returncode != 0, "counter wrapped"
        assert bend(key, nonce, 0xFFFFFFFE, bytes(128)).returncode == 0
        assert bend(key, nonce, 0xFFFFFFFE, bytes(129)).returncode != 0, "counter wrapped"

    print(f"ChaCha20: two RFC 8439 vectors, {block_cases} block cases, {stream_cases} stream cases, invalid lengths and counter limits passed")


if __name__ == "__main__":
    main()
