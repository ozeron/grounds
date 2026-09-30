"""Compare the compiled Bend authentication interface with independent STUN bytes."""

import random
import subprocess
import sys
import tempfile
from pathlib import Path

from stun_reference import (
    RFC_KEY, RFC_SHA256, append_integrity, attr, attributes, fingerprint, length,
    packet, sign, validate,
)

command = sys.argv[1:]
count = 0

with tempfile.TemporaryDirectory() as directory:
    raw_path, key_path = Path(directory) / "packet", Path(directory) / "key"

    def run(op, mode, raw, key, expected=None, valid=True):
        global count
        raw_path.write_bytes(raw)
        key_path.write_bytes(key)
        result = subprocess.run(command + [op, mode, str(raw_path), str(key_path)],
                                capture_output=True, text=True, timeout=30)
        count += 1
        if valid:
            assert result.returncode == 0, (op, mode, result.stderr)
            if expected is not None:
                assert result.stdout.strip() == expected, (op, mode, result.stdout, expected)
        else:
            assert result.returncode == 1 and "invalid STUN" in result.stderr, (op, mode, result)
        return result.stdout.strip()

    run("verify", "sha256", RFC_SHA256, RFC_KEY)
    run("seal", "sha256", length(RFC_SHA256[:-36], 108), RFC_KEY, RFC_SHA256.hex())
    original = length(RFC_SHA256[:120] + RFC_SHA256[128:], 156)
    run("verify", "sha256", original, RFC_KEY, valid=False)

    rng = random.Random(8489)
    # Byte exact comparisons cover padding, long HMAC keys and hash block edges.
    for size in (0, 1, 3, 4, 55, 56, 63, 64, 65, 131, 257):
        key = rng.randbytes(size)
        value = rng.randbytes(size)
        unsigned = packet(attr(0x8022, value, pad=0xA5), transaction=rng.randbytes(12))
        for mode in ("legacy", "sha256", "dual"):
            expected = sign(unsigned, key, mode)
            run("sign", mode, unsigned, key, expected.hex())
            validate(expected, key, mode)
            run("verify", mode, expected, key)

    key = b"synthetic STUN password"
    unsigned = packet(attr(6, b"remote:local", pad=0x20))
    for mode in ("legacy", "sha256", "dual"):
        signed = sign(unsigned, key, mode)
        run("sign", mode, signed, key, valid=False)
        run("verify", mode, signed, b"wrong key", valid=False)
        for offset in (0, 3, 4, 8, 24, len(signed) - 1):
            changed = bytearray(signed)
            changed[offset] ^= 1
            run("verify", mode, changed, key, valid=False)
        for suffix in (b"\x00", attr(0x8028, b"\x00" * 4), attr(0x8022, b"later")):
            bad = length(signed + suffix, len(signed) - 20 + len(suffix))
            run("verify", mode, bad, key, valid=False)

    dual = sign(unsigned, key, "dual", with_fingerprint=False)
    # A valid SHA-1 must not rescue a failed SHA-256, even with a valid CRC.
    changed = bytearray(dual)
    changed[-1] ^= 1
    run("verify", "dual", fingerprint(changed), key, valid=False)
    run("verify", "legacy", fingerprint(dual), key, valid=False)
    run("verify", "sha256", sign(unsigned, key, "legacy"), key, valid=False)

    sha1 = sign(unsigned, key, "legacy", with_fingerprint=False)
    sha256 = sign(unsigned, key, "sha256", with_fingerprint=False)
    # Duplicates and inverted integrity order are rejected even with fresh MACs.
    for raw in (append_integrity(sha1, key, "sha1"),
                append_integrity(sha256, key, "sha256"),
                append_integrity(sha256, key, "sha1")):
        run("verify", "dual", fingerprint(raw), key, valid=False)
    for size in (0, 15, 16, 20, 28, 31, 33, 36):
        bad = packet(unsigned[20:] + attr(28, b"\x00" * size))
        run("verify", "dual", bad, key, valid=False)
    run("verify", "dual", unsigned, key, valid=False)

    # Parsed attributes after integrity cannot become authenticated data.
    suffix = attr(0x20, bytes.fromhex("00012112e112a643"))
    protected = "authenticated\n6:" + b"remote:local".hex()
    for sealed in (sha1, sha256, dual):
        raw = length(sealed + suffix, len(sealed) - 20 + len(suffix))
        run("verify", "dual", fingerprint(raw), key, protected)
    # Ignored data between the two MACs still contributes to SHA-256's bytes.
    between = length(sha1 + suffix, len(sha1) - 20 + len(suffix))
    run("verify", "dual", fingerprint(append_integrity(between, key, "sha256")), key, protected)

    response = packet(attr(0x20, bytes.fromhex("00012112e112a643")), kind=0x101)
    for mode in ("legacy", "sha256"):
        signed = sign(response, key, mode)
        run("response", mode, signed, key)
        run("response", "dual", signed, key)
        other = "legacy" if mode == "sha256" else "sha256"
        run("response", other, signed, key, valid=False)
    run("response", "dual", sign(response, key, "dual"), key, valid=False)
    run("response", "dual", sign(unsigned, key, "sha256"), key, valid=False)
    with_username = packet(response[20:] + attr(6, b"remote:local"), kind=0x101)
    run("response", "dual", sign(with_username, key, "sha256"), key, valid=False)

    # Maximal STUN body and exact signer overhead, including FINGERPRINT.
    for mode, overhead in (("legacy", 32), ("sha256", 44), ("dual", 68)):
        body_size = 65532 - overhead
        largest = packet(attr(0x8022, b"\x01" * (body_size - 4)))
        signed_hex = run("sign", mode, largest, key)
        assert bytes.fromhex(signed_hex) == sign(largest, key, mode)
        run("verify", mode, bytes.fromhex(signed_hex), key)
        too_large = packet(attr(0x8022, b"\x01" * body_size))
        run("sign", mode, too_large, key, valid=False)

print(f"STUN authentication: {count} compiled RFC/differential/malformed/policy checks passed")
