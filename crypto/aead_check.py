"""RFC 8439 AEAD vector, differential cases, and authentication failures."""

from pathlib import Path
import random
import subprocess
import sys
import tempfile

from chacha_check import openssl
from poly1305_check import reference as poly1305


RFC_CIPHERTEXT = (
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b6116"
)
RFC_TAG = "1ae10b594f09e26a7e902ecbd0600691"
RFC_MESSAGE = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you only "
    b"one tip for the future, sunscreen would be it."
)


def reference(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    one_time_key = openssl(key, nonce, 0, bytes(32))
    ciphertext = openssl(key, nonce, 1, plaintext)
    def padded(data: bytes) -> bytes:
        return data + bytes((-len(data)) % 16)
    mac_data = padded(aad) + padded(ciphertext)
    mac_data += len(aad).to_bytes(8, "little") + len(ciphertext).to_bytes(8, "little")
    return ciphertext, poly1305(one_time_key, mac_data)


def flip(data: bytes, at: int) -> bytes:
    changed = bytearray(data)
    changed[at] ^= 1
    return bytes(changed)


def main() -> None:
    binary = sys.argv[1:]
    rng = random.Random(0xAEAD8439)
    with tempfile.TemporaryDirectory() as folder:
        paths = {name: Path(folder) / f"{name}.bin" for name in ("key", "nonce", "aad", "message", "ciphertext", "tag")}

        def seal(key: bytes, nonce: bytes, aad: bytes, message: bytes) -> subprocess.CompletedProcess[str]:
            for name, data in (("key", key), ("nonce", nonce), ("aad", aad), ("message", message)):
                paths[name].write_bytes(data)
            return subprocess.run(binary + ["seal", *(str(paths[name]) for name in ("key", "nonce", "aad", "message"))], capture_output=True, text=True)

        def open_record(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes) -> subprocess.CompletedProcess[str]:
            for name, data in (("key", key), ("nonce", nonce), ("aad", aad), ("ciphertext", ciphertext), ("tag", tag)):
                paths[name].write_bytes(data)
            return subprocess.run(binary + ["open", *(str(paths[name]) for name in ("key", "nonce", "aad", "ciphertext", "tag"))], capture_output=True, text=True)

        rfc_key = bytes(range(0x80, 0xA0))
        rfc_nonce = bytes.fromhex("070000004041424344454647")
        rfc_aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        assert tuple(part.hex() for part in reference(rfc_key, rfc_nonce, rfc_aad, RFC_MESSAGE)) == (RFC_CIPHERTEXT, RFC_TAG)
        got = seal(rfc_key, rfc_nonce, rfc_aad, RFC_MESSAGE)
        assert got.returncode == 0 and got.stdout.splitlines() == [RFC_CIPHERTEXT, RFC_TAG], "RFC 8439 AEAD vector"

        cases = 0
        for aad_length, message_length in ((0, 0), (0, 1), (1, 0), (15, 15), (16, 16), (17, 17),
                                           (31, 63), (32, 64), (33, 65), (127, 128), (129, 255)):
            key = rng.randbytes(32)
            nonce = rng.randbytes(12)
            aad = rng.randbytes(aad_length)
            message = rng.randbytes(message_length)
            ciphertext, tag = reference(key, nonce, aad, message)
            got = seal(key, nonce, aad, message)
            assert got.returncode == 0 and got.stdout.splitlines() == [ciphertext.hex(), tag.hex()], f"seal lengths {aad_length},{message_length}"
            opened = open_record(key, nonce, aad, ciphertext, tag)
            assert opened.returncode == 0 and opened.stdout.strip() == message.hex(), "valid open"
            for pos in (0, 7, 15):
                rejected = open_record(key, nonce, aad, ciphertext, flip(tag, pos))
                assert rejected.returncode != 0 and rejected.stdout == "", f"tag byte {pos} accepted"
            if aad:
                rejected = open_record(key, nonce, flip(aad, 0), ciphertext, tag)
                assert rejected.returncode != 0 and rejected.stdout == "", "changed AAD accepted"
            if ciphertext:
                rejected = open_record(key, nonce, aad, flip(ciphertext, 0), tag)
                assert rejected.returncode != 0 and rejected.stdout == "", "changed ciphertext accepted"
            rejected = open_record(key, flip(nonce, 0), aad, ciphertext, tag)
            assert rejected.returncode != 0 and rejected.stdout == "", "changed nonce accepted"
            rejected = open_record(flip(key, 0), nonce, aad, ciphertext, tag)
            assert rejected.returncode != 0 and rejected.stdout == "", "changed key accepted"
            cases += 1

        key = rng.randbytes(32)
        nonce = rng.randbytes(12)
        aad = rng.randbytes(13)
        message = bytes(range(256)) * 256
        ciphertext, tag = reference(key, nonce, aad, message)
        got = seal(key, nonce, aad, message)
        assert got.returncode == 0 and got.stdout.splitlines() == [ciphertext.hex(), tag.hex()], "64 KiB record"
        opened = open_record(key, nonce, aad, ciphertext, tag)
        assert opened.returncode == 0 and opened.stdout.strip() == message.hex(), "64 KiB open"
        cases += 1

        assert seal(bytes(31), bytes(12), b"", b"").returncode != 0, "short key accepted"
        assert seal(bytes(32), bytes(11), b"", b"").returncode != 0, "short nonce accepted"
        assert open_record(bytes(32), bytes(12), b"", b"", bytes(15)).returncode != 0, "short tag accepted"
        assert open_record(bytes(32), bytes(12), b"", b"", bytes(17)).returncode != 0, "long tag accepted"

    print(f"ChaCha20-Poly1305: RFC 8439 vector, {cases} differential records and authentication-failure cases passed")


if __name__ == "__main__":
    main()
