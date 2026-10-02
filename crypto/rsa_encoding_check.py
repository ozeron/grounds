"""Independent SHA-256 RSA encoding oracle, malformed cases and OpenSSL peers.

This checks EMSA/MGF1 only; it cannot establish Bend RSA exponentiation,
certificate validation, timing safety or key retirement.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import subprocess
import tempfile
import time


DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def mgf(seed, length, hash_name="sha256"):
    result = bytearray()
    size = hashlib.new(hash_name).digest_size
    for counter in range((length + size - 1) // size):
        result.extend(hashlib.new(hash_name, seed + counter.to_bytes(4, "big")).digest())
    return bytes(result[:length])


def pss_encode(bits, digest, salt, mask_hash="sha256"):
    length = (bits+7)//8
    assert len(digest) == 32 and length >= len(salt)+34
    h = hashlib.sha256(bytes(8)+digest+salt).digest()
    db = bytes(length-len(salt)-34)+b"\x01"+salt
    masked = bytearray(a ^ b for a, b in zip(db, mgf(h, len(db), mask_hash)))
    masked[0] &= 255 >> (8*length-bits)
    return bytes(masked)+h+b"\xbc"


def pss_decode(bits, digest, encoded):
    length = (bits+7)//8
    if len(digest) != 32 or len(encoded) != length or length < 66 or encoded[-1] != 188:
        return None
    unused = 8*length-bits
    if unused and encoded[0] >> (8-unused):
        return None
    h = encoded[-33:-1]
    db = bytearray(a ^ b for a, b in zip(encoded[:-33], mgf(h, length-33)))
    db[0] &= 255 >> unused
    if db[:length-66] != bytes(length-66) or db[length-66] != 1:
        return None
    salt = bytes(db[-32:])
    if hashlib.sha256(bytes(8)+digest+salt).digest() != h:
        return None
    return salt


def v15(length, digest):
    assert len(digest) == 32 and length >= 62
    return b"\x00\x01"+b"\xff"*(length-54)+b"\x00"+DIGEST_INFO+digest


def mgf_cases():
    cases = []
    for seed in (b"", bytes(32), b"\xff"*32, bytes(range(256)), b"\x55"*512):
        for length in (0, 1, 31, 32, 33, 63, 64, 65, 255, 256, 257, 479, 480, 511, 512):
            cases.append(("MGF1-counter/truncation", "0", [length, seed], mgf(seed, length).hex()))
    for length, seed in ((513, b""), (2**32-1, b""), (0, bytes(513)), (32, bytes(513))):
        cases.append(("MGF1-bounds", "0", [length, seed], "invalid"))
    return cases


def pss_cases():
    rng = random.Random(0x8017)
    cases = []
    digest, salt = bytes(32), bytes(range(32))
    widths = list(range(521, 537)) + [1023, 1024, 1025, 2047, 2048, 2049, 3071, 3072, 4095, 4096]
    for bits in widths:
        for d, s in ((digest, salt), (b"\xff"*32, bytes(32)), (rng.randbytes(32), rng.randbytes(32))):
            encoded = pss_encode(bits, d, s)
            assert pss_decode(bits, d, encoded) == s
            cases.extend((("PSS-bit/byte-boundary", "1", [bits, d, s], encoded.hex()),
                          ("PSS-bit/byte-boundary", "2", [bits, d, encoded], "true")))
        for bad in (encoded[:-1], encoded+b"\x00"):
            cases.append(("PSS-length", "2", [bits, d, bad], "false"))
    for bits in (0, 520, 4097, 2**32-1):
        cases.extend((("PSS-bit-range", "1", [bits, digest, salt], "invalid"),
                      ("PSS-bit-range", "2", [bits, digest, bytes(128)], "false")))
    good = pss_encode(2047, digest, salt)
    for bad in (b"", bytes(31), bytes(33)):
        cases.extend((("PSS-digest-length", "1", [2047, bad, salt], "invalid"),
                      ("PSS-digest-length", "2", [2047, bad, good], "false"),
                      ("PSS-salt-length", "1", [2047, digest, bad], "invalid")))
    for i in range(len(good)):
        bad = bytearray(good)
        bad[i] ^= 1
        assert pss_decode(2047, digest, bad) is None
        cases.append(("PSS-every-encoded-byte", "2", [2047, digest, bad], "false"))
    for i in range(32):
        bad = bytearray(digest)
        bad[i] ^= 1
        assert pss_decode(2047, bad, good) is None
        cases.append(("PSS-every-digest-byte", "2", [2047, bad, good], "false"))
    h = good[-33:-1]
    db = bytes(190)+b"\x01"+salt
    for i in range(191):
        bad_db = bytearray(db)
        bad_db[i] = 1 if i < 190 else 2
        masked = bytearray(a ^ b for a, b in zip(bad_db, mgf(h, len(db))))
        masked[0] &= 127
        bad = bytes(masked)+h+b"\xbc"
        assert pss_decode(2047, digest, bad) is None
        cases.append(("PSS-nonzero-PS/delimiter", "2", [2047, digest, bad], "false"))
    for trailer in range(256):
        if trailer != 188:
            cases.append(("PSS-trailer", "2", [2047, digest, good[:-1]+bytes([trailer])], "false"))
    for salt_length in (0, 20, 31, 33, 64):
        bad = pss_encode(2047, digest, bytes(salt_length))
        assert pss_decode(2047, digest, bad) is None
        cases.append(("PSS-wrong-salt-profile", "2", [2047, digest, bad], "false"))
    bad = pss_encode(2047, digest, salt, "sha1")
    assert pss_decode(2047, digest, bad) is None
    cases.append(("PSS-wrong-MGF-hash", "2", [2047, digest, bad], "false"))
    minimal = pss_encode(521, digest, salt)
    for bit in range(1, 8):
        bad = bytes([minimal[0] | (1 << bit)])+minimal[1:]
        assert pss_decode(521, digest, bad) is None
        cases.append(("PSS-unused-high-bits", "2", [521, digest, bad], "false"))
    return cases


def v15_cases():
    rng = random.Random(0x5154)
    cases = []
    for length in (62, 63, 64, 65, 127, 128, 129, 255, 256, 257, 384, 511, 512):
        for digest in (bytes(32), b"\xff"*32, rng.randbytes(32)):
            encoded = v15(length, digest)
            cases.extend((("v1.5-padding-boundary", "3", [length, digest], encoded.hex()),
                          ("v1.5-padding-boundary", "4", [digest, encoded], "true")))
    digest = bytes(32)
    for length in (0, 61, 513, 2**32-1):
        cases.append(("v1.5-length-range", "3", [length, digest], "invalid"))
    good = v15(256, digest)
    for bad in (b"", bytes(31), bytes(33)):
        cases.extend((("v1.5-digest-length", "3", [256, bad], "invalid"),
                      ("v1.5-digest-length", "4", [bad, good], "false")))
    for i in range(len(good)):
        bad = bytearray(good)
        bad[i] ^= 1
        cases.append(("v1.5-every-encoded-byte", "4", [digest, bad], "false"))
    # Absent NULL and BER length aliases must not replace the fixed DER T.
    absent_null = bytes.fromhex("302f300b06096086480165030402010420")+digest
    ber_alias = bytes.fromhex("308131300d060960864801650304020105000420")+digest
    for body in (absent_null, ber_alias):
        bad = b"\x00\x01"+b"\xff"*(256-len(body)-3)+b"\x00"+body
        cases.append(("v1.5-DigestInfo-canonical", "4", [digest, bad], "false"))
    for bad in (b"", good[:-1], good+b"\x00", bytes(61), bytes(513)):
        cases.append(("v1.5-malformed-length", "4", [digest, bad], "false"))
    return cases


def published_cases():
    fixture = json.loads(Path(__file__).with_name("rsa_encoding_vectors.json").read_text())
    cases = []
    for record in fixture["records"]:
        digest = bytes.fromhex(record["digest"])
        encoded = bytes.fromhex(record["encoded"])
        # Peer recovery checks fixture integrity; Grounds exponentiation is not
        # implemented or tested by this encoding-only evaluator.
        recovered = pow(int(record["signature"], 16), int(record["exponent"], 16),
                        int(record["modulus"], 16)).to_bytes(len(encoded), "big")
        assert recovered == encoded
        assert hashlib.sha256(bytes.fromhex(record["message"])).digest() == digest
        expected = record["encoding_expected"]
        if record["kind"] == "pss":
            assert (pss_decode(record["em_bits"], digest, encoded) is not None) == expected
            cases.append(("NIST-PSS-representative-admission", "2",
                          [record["em_bits"], digest, encoded], str(expected).lower()))
            if record["generated"]:
                cases.append(("NIST-PSS-encoding/salt-profile", "1",
                              [record["em_bits"], digest, bytes.fromhex(record["salt"])],
                              encoded.hex() if expected else "invalid"))
        else:
            assert (v15(len(encoded), digest) == encoded) == expected
            cases.append(("NIST-v1.5-representative-admission", "4",
                          [digest, encoded], str(expected).lower()))
            if record["generated"]:
                cases.append(("NIST-v1.5-encoding", "3", [len(encoded), digest], encoded.hex()))
    return cases


def openssl_cases(root, profiles):
    cases = []
    for requested_bits in (2048, 2049, 2050, 3072, 4096):
        private = root/f"rsa-{requested_bits}.pem"
        digest_path = root/f"digest-{requested_bits}.bin"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{requested_bits}",
                        "-pkeyopt", "rsa_keygen_pubexp:65537", "-out", str(private)],
                       capture_output=True, check=True, timeout=60)
        modulus = subprocess.run(["openssl", "rsa", "-in", str(private), "-noout", "-modulus"],
                                 capture_output=True, text=True, check=True, timeout=10).stdout.strip()
        n = int(modulus.split("=", 1)[1], 16)
        bits = n.bit_length()
        assert bits >= 2048 and bits <= requested_bits
        profiles.append({"requested_bits": requested_bits, "actual_modulus_bits": bits})
        digest = hashlib.sha256(f"grounds synthetic RSA requested {requested_bits}, actual {bits}".encode()).digest()
        digest_path.write_bytes(digest)
        for padding, salt_length, mask_hash in (("pss", 32, "sha256"), ("pss", 20, "sha256"),
                                                ("pss", 32, "sha1"), ("pkcs1", None, None)):
            command = ["openssl", "pkeyutl", "-sign", "-inkey", str(private), "-in", str(digest_path),
                       "-pkeyopt", "digest:sha256", "-pkeyopt", f"rsa_padding_mode:{padding}"]
            if padding == "pss":
                command += ["-pkeyopt", f"rsa_pss_saltlen:{salt_length}", "-pkeyopt", f"rsa_mgf1_md:{mask_hash}"]
            signature = subprocess.run(command, capture_output=True, check=True, timeout=10).stdout
            # Independent peer RSA recovery, never a Grounds RSA substitute.
            integer = pow(int.from_bytes(signature, "big"), 65537, n)
            length = (bits-1+7)//8 if padding == "pss" else (bits+7)//8
            encoded = integer.to_bytes(length, "big")
            if padding == "pss":
                salt = pss_decode(bits-1, digest, encoded)
                valid = salt_length == 32 and mask_hash == "sha256"
                assert (salt is not None) == valid
                cases.append(("OpenSSL-PSS-parameter-profile", "2", [bits-1, digest, encoded], str(valid).lower()))
                if valid:
                    cases.append(("Bend-EM-to-OpenSSL-recovered-EM", "1", [bits-1, digest, salt], encoded.hex()))
            else:
                assert encoded == v15(length, digest)
                cases.extend((("OpenSSL-v1.5-recovered-EM", "4", [digest, encoded], "true"),
                              ("Bend-v1.5-to-OpenSSL-recovered-EM", "3", [length, digest], encoded.hex())))
    return cases


def run(binary, cases, root, counts):
    for offset in range(0, len(cases), 16):
        batch = cases[offset:offset+16]
        arguments = []
        for i, (_, mode, inputs, _) in enumerate(batch):
            arguments.append(mode)
            for j, value in enumerate(inputs):
                if isinstance(value, int):
                    arguments.append(str(value))
                else:
                    path = root/f"input-{i}-{j}.bin"
                    path.write_bytes(value)
                    arguments.append(str(path))
        got = subprocess.run(binary+arguments, capture_output=True, text=True, timeout=90)
        assert got.returncode == 0, (offset, got.returncode, got.stderr)
        assert got.stdout.splitlines() == [c[3] for c in batch], (offset, [c[:2] for c in batch], got.stdout)
        counts.update(case[0] for case in batch)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--section", choices=("all", "mgf", "pss", "v15", "published", "openssl"), default="all")
    parser.add_argument("--report", type=Path)
    parser.add_argument("binary", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ["--"] else args.binary
    if not binary:
        parser.error("supply a Bend evaluator command after --")
    start, counts, profiles = time.monotonic(), Counter(), []
    with tempfile.TemporaryDirectory(prefix="grounds-rsa-encoding-") as folder:
        root = Path(folder)
        for section, factory in (("mgf", mgf_cases), ("pss", pss_cases), ("v15", v15_cases),
                                 ("published", published_cases),
                                 ("openssl", lambda: openssl_cases(root, profiles))):
            if args.section in ("all", section):
                run(binary, factory(), root, counts)
                print(f"RSA encoding {section}: {sum(counts.values())} cases passed so far", flush=True)
    report = {"binary": binary, "section": args.section, "cases": dict(counts),
              "total": sum(counts.values()), "elapsed_seconds": round(time.monotonic()-start, 3),
              "openssl_key_sizes": profiles,
              "RSA_exponentiation_checked": False, "timing_or_erasure_approval": False}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2)+"\n")
    print("RSA SHA256 encoding: "+json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
