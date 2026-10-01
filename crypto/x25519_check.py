"""RFC 7748 X25519 vectors and independent differential checks."""

from pathlib import Path
import random
import subprocess
import sys
import tempfile

P = (1 << 255) - 19
BASE = bytes([9]) + bytes(31)
PRIVATE_DER_PREFIX = bytes.fromhex("302e020100300506032b656e04220420")
PUBLIC_DER_PREFIX = bytes.fromhex("302a300506032b656e032100")
VECTORS = (
    (
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    ),
    (
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
    ),
)
ALICE = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
ALICE_PUBLIC = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
BOB = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
BOB_PUBLIC = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
SHARED = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")


def reference(scalar: bytes, u: bytes) -> bytes:
    key = bytearray(scalar)
    key[0] &= 248
    key[31] = (key[31] & 127) | 64
    k = int.from_bytes(key, "little")
    x1 = (int.from_bytes(u, "little") & ((1 << 255) - 1)) % P
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        bit = (k >> t) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + 121665 * e) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def openssl_public(private: bytes, private_path: Path) -> bytes:
    private_path.write_bytes(PRIVATE_DER_PREFIX + private)
    got = subprocess.run(
        ["openssl", "pkey", "-inform", "DER", "-in", str(private_path),
         "-pubout", "-outform", "DER"], capture_output=True, check=True,
    ).stdout
    assert got.startswith(PUBLIC_DER_PREFIX) and len(got) == len(PUBLIC_DER_PREFIX) + 32
    return got[-32:]


def openssl_shared(private: bytes, peer_public: bytes,
                   private_path: Path, peer_path: Path) -> bytes:
    private_path.write_bytes(PRIVATE_DER_PREFIX + private)
    peer_path.write_bytes(PUBLIC_DER_PREFIX + peer_public)
    return subprocess.run(
        ["openssl", "pkeyutl", "-derive", "-inkey", str(private_path),
         "-keyform", "DER", "-peerkey", str(peer_path), "-peerform", "DER"],
        capture_output=True, check=True,
    ).stdout


def main() -> None:
    binary = sys.argv[1:]
    iterated = bool(binary and binary[0] == "--iterated")
    if iterated:
        binary = binary[1:]
    rng = random.Random(0x7748)
    with tempfile.TemporaryDirectory() as folder:
        key_path = Path(folder) / "key.bin"
        u_path = Path(folder) / "u.bin"
        private_path = Path(folder) / "private.der"
        peer_path = Path(folder) / "peer.der"

        def run(mode: str, key: bytes, u: bytes | None = None) -> subprocess.CompletedProcess[str]:
            key_path.write_bytes(key)
            args = [mode, str(key_path)]
            if u is not None:
                u_path.write_bytes(u)
                args.append(str(u_path))
            return subprocess.run(binary + args, capture_output=True, text=True)

        def expect(mode: str, key: bytes, u: bytes | None, expected: bytes) -> None:
            got = run(mode, key, u)
            assert got.returncode == 0 and got.stdout.strip() == expected.hex(), (
                f"{mode}: {got.stdout.strip()} != {expected.hex()}; {got.stderr.strip()}")

        for key, u, output in VECTORS:
            key, u, output = bytes.fromhex(key), bytes.fromhex(u), bytes.fromhex(output)
            assert reference(key, u) == output
            expect("mult", key, u, output)

        for private, public in ((ALICE, ALICE_PUBLIC), (BOB, BOB_PUBLIC)):
            assert reference(private, BASE) == public
            expect("public", private, None, public)
        assert reference(ALICE, BOB_PUBLIC) == SHARED
        assert reference(BOB, ALICE_PUBLIC) == SHARED
        expect("shared", ALICE, BOB_PUBLIC, SHARED)
        expect("shared", BOB, ALICE_PUBLIC, SHARED)
        expect("mult", BASE, BASE, bytes.fromhex(
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"))

        # Noncanonical coordinates and the masked top bit must be accepted.
        for number in (P + i + high for high in (0, 1 << 255) for i in range(19)):
            u = number.to_bytes(32, "little")
            expect("mult", ALICE, u, reference(ALICE, u))

        # Public synthetic scalars exercise constant and alternating ladder bits.
        for key in (bytes(32), bytes([255]) * 32, bytes([85]) * 32,
                    bytes([170]) * 32):
            expect("public", key, None, reference(key, BASE))

        for _ in range(4):
            a, b = rng.randbytes(32), rng.randbytes(32)
            public_a = openssl_public(a, private_path)
            public_b = openssl_public(b, private_path)
            secret = openssl_shared(a, public_b, private_path, peer_path)
            assert reference(a, BASE) == public_a
            assert reference(a, public_b) == secret
            expect("public", a, None, public_a)
            expect("shared", a, public_b, secret)

        assert run("mult", ALICE, bytes(32)).stdout.strip() == bytes(32).hex()
        rejected = run("shared", ALICE, bytes(32))
        assert rejected.returncode != 0 and rejected.stdout == "", "accepted all-zero shared secret"
        assert run("public", ALICE[:-1]).returncode != 0, "accepted short scalar"
        assert run("mult", ALICE, BASE[:-1]).returncode != 0, "accepted short coordinate"

        if iterated:
            key = coordinate = BASE
            for _ in range(1000):
                old_key = key
                got = run("mult", key, coordinate)
                assert got.returncode == 0, got.stderr
                key, coordinate = bytes.fromhex(got.stdout.strip()), old_key
            assert key.hex() == (
                "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
            ), "RFC 7748 1000-iteration vector"

    print("X25519: RFC vectors, noncanonical inputs, four OpenSSL differential exchanges and zero rejection passed"
          + ("; 1000 iterations passed" if iterated else ""))


if __name__ == "__main__":
    main()
