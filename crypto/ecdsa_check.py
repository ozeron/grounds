"""Published ECDSA vectors, independent affine/HMAC oracle and DER interop."""

import argparse
from collections import Counter
import hashlib
import hmac
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import time

import p256_check as curve


N = curve.N


def integer(value):
    data = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if data[0] & 128:
        data = b"\x00" + data
    return b"\x02" + bytes([len(data)]) + data


def der(signature):
    body = integer(int.from_bytes(signature[:32], "big"))
    body += integer(int.from_bytes(signature[32:], "big"))
    return b"\x30" + bytes([len(body)]) + body


def decode_der(data):
    """Independent strict DER oracle; canonical integers in 1..n-1."""
    if len(data) < 8 or len(data) > 72 or data[:1] != b"\x30" or data[1] != len(data)-2:
        return None
    offset = 2
    values = []
    for _ in range(2):
        if offset + 2 > len(data) or data[offset] != 2:
            return None
        length = data[offset+1]
        offset += 2
        encoded = data[offset:offset+length]
        offset += length
        if not 1 <= length <= 33 or len(encoded) != length or encoded[0] & 128:
            return None
        if length > 1 and encoded[0] == 0 and encoded[1] < 128:
            return None
        value = int.from_bytes(encoded, "big")
        if not 0 < value < N:
            return None
        values.append(value.to_bytes(32, "big"))
    return b"".join(values) if offset == len(data) else None


def reference_sign(private, digest):
    # RFC6979 bits2octets, HMAC state and textbook affine arithmetic are
    # independent of Bend's byte-limb Montgomery/complete-projective formulas.
    z = int.from_bytes(digest, "big") % N
    seed = private.to_bytes(32, "big") + z.to_bytes(32, "big")
    key, value = bytes(32), b"\x01" * 32
    key = hmac.digest(key, value+b"\x00"+seed, "sha256")
    value = hmac.digest(key, value, "sha256")
    key = hmac.digest(key, value+b"\x01"+seed, "sha256")
    value = hmac.digest(key, value, "sha256")
    while True:
        value = hmac.digest(key, value, "sha256")
        nonce = int.from_bytes(value, "big")
        if 0 < nonce < N:
            r = curve.mul(nonce, curve.G)[0] % N
            s = pow(nonce, -1, N) * (z+r*private) % N
            if r and s:
                return r.to_bytes(32, "big") + s.to_bytes(32, "big")
        key = hmac.digest(key, value+b"\x00", "sha256")
        value = hmac.digest(key, value, "sha256")


def reference_verify(peer, digest, signature):
    if len(peer) != 65 or peer[0] != 4 or len(digest) != 32 or len(signature) != 64:
        return False
    x, y = int.from_bytes(peer[1:33], "big"), int.from_bytes(peer[33:], "big")
    if not (x < curve.P and y < curve.P and (y*y-x*x*x+3*x-curve.B) % curve.P == 0):
        return False
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if not (0 < r < N and 0 < s < N):
        return False
    inverse = pow(s, -1, N)
    point = curve.add(curve.mul(int.from_bytes(digest, "big")*inverse % N, curve.G),
                      curve.mul(r*inverse % N, (x, y)))
    return point is not None and point[0] % N == r


class Evaluator:
    def __init__(self, binary, root):
        self.binary = binary
        self.root = root
        self.counts = Counter()

    def run(self, cases):
        outputs = []
        for offset in range(0, len(cases), 4):
            portion = cases[offset:offset+4]
            args = []
            for i, (group, operation, inputs, expected) in enumerate(portion):
                args.append(operation)
                for j, data in enumerate(inputs):
                    path = self.root / f"input-{i}-{j}.bin"
                    path.write_bytes(data)
                    args.append(str(path))
            result = subprocess.run(self.binary+args, capture_output=True, text=True, timeout=180)
            if result.returncode:
                raise AssertionError((offset, result.returncode, result.stderr))
            actual = result.stdout.splitlines()
            expected = [case[3] for case in portion]
            if actual != expected:
                raise AssertionError((offset, [c[:2] for c in portion], actual, expected))
            outputs.extend(actual)
            self.counts.update(case[0] for case in portion)
        return outputs


def published(vectors):
    cases = []
    assert len(vectors["nist_siggen"]) == len(vectors["nist_sigver"]) == 15
    assert len(vectors["rfc_signatures"]) == 2
    for vector in vectors["nist_siggen"]:
        d, k = int(vector["d"], 16), int(vector["k"], 16)
        digest = hashlib.sha256(bytes.fromhex(vector["Msg"])).digest()
        raw = int(vector["R"], 16).to_bytes(32, "big") + int(vector["S"], 16).to_bytes(32, "big")
        peer = b"\x04"+int(vector["Qx"], 16).to_bytes(32, "big")+int(vector["Qy"], 16).to_bytes(32, "big")
        assert curve.sec1(curve.mul(d, curve.G)) == peer
        r = curve.mul(k, curve.G)[0] % N
        s = pow(k, -1, N)*(int.from_bytes(digest, "big")+r*d) % N
        assert raw == r.to_bytes(32, "big")+s.to_bytes(32, "big")
        cases.append(("NIST-known-nonce", "known-nonce",
                      [d.to_bytes(32, "little"), digest, k.to_bytes(32, "little")], raw.hex()))
        cases.append(("NIST-DER-valid", "verify", [peer, digest, der(raw)], "true"))
    for vector in vectors["nist_sigver"]:
        peer = b"\x04"+int(vector["Qx"], 16).to_bytes(32, "big")+int(vector["Qy"], 16).to_bytes(32, "big")
        digest = hashlib.sha256(bytes.fromhex(vector["Msg"])).digest()
        raw = int(vector["R"], 16).to_bytes(32, "big")+int(vector["S"], 16).to_bytes(32, "big")
        expected = vector["Result"].startswith("P")
        assert reference_verify(peer, digest, raw) == expected
        cases.append(("NIST-SigVer", "verify", [peer, digest, der(raw)], str(expected).lower()))
    for vector in vectors["rfc_signatures"]:
        d = int(vector["private"], 16)
        digest = hashlib.sha256(vector["message"].encode()).digest()
        raw = bytes.fromhex(vector["signature"])
        assert reference_sign(d, digest) == raw
        cases.append(("RFC6979", "sign", [d.to_bytes(32, "big"), digest], der(raw).hex()))
        cases.append(("RFC6979-verify", "verify", [curve.sec1(curve.mul(d, curve.G)), digest, der(raw)], "true"))
    return cases


def differential():
    rng = random.Random(0xE256)
    samples = [(1, bytes(32)), (N-1, b"\xff"*32), (2, N.to_bytes(32, "big")),
               (3, (N+1).to_bytes(32, "big"))]
    samples += [(rng.randrange(1, N), hashlib.sha256(rng.randbytes(23+i)).digest()) for i in range(8)]
    cases = []
    for private, digest in samples:
        signature = reference_sign(private, digest)
        peer = curve.sec1(curve.mul(private, curve.G))
        assert reference_verify(peer, digest, signature)
        for _ in range(2):
            cases.append(("deterministic-repeat", "sign", [private.to_bytes(32, "big"), digest], der(signature).hex()))
        cases.append(("differential-verify", "verify", [peer, digest, der(signature)], "true"))
        cases.append(("raw-differential-sign", "sign-raw", [private.to_bytes(32, "big"), digest], signature.hex()))
        cases.append(("raw-differential-verify", "verify-raw", [peer, digest, signature], "true"))
    return cases


def invalid_cases():
    private, digest = 1, bytes(32)
    peer = curve.sec1(curve.G)
    raw = reference_sign(private, digest)
    signature = der(raw)
    cases = []
    for i in range(64):
        mutated = bytearray(raw)
        mutated[i] ^= 1
        assert not reference_verify(peer, digest, bytes(mutated))
        cases.append(("every-signature-byte", "verify", [peer, digest, der(bytes(mutated))], "false"))
    for i in range(32):
        mutated = bytearray(digest)
        mutated[i] ^= 1
        assert not reference_verify(peer, bytes(mutated), raw)
        cases.append(("every-digest-byte", "verify", [peer, bytes(mutated), signature], "false"))
    for i in range(65):
        mutated = bytearray(peer)
        mutated[i] ^= 1
        assert not reference_verify(bytes(mutated), digest, raw)
        cases.append(("every-peer-byte", "verify", [bytes(mutated), digest, signature], "false"))
    for r, s in [(0, 1), (1, 0), (N, 1), (1, N), (N+1, 1), (1, N+1)]:
        bad = r.to_bytes(32, "big")+s.to_bytes(32, "big")
        cases.append(("scalar-range", "verify", [peer, digest, der(bad)], "false"))
    for bad in [b"", bytes(31), bytes(33)]:
        cases.append(("digest-length", "verify", [peer, bad, signature], "false"))
        cases.append(("signing-digest-length", "sign", [(1).to_bytes(32, "big"), bad], "invalid"))
    for bad in [b"", bytes(31), bytes(33), bytes(32), N.to_bytes(32, "big"), (N+1).to_bytes(32, "big")]:
        cases.append(("private-range-length", "sign", [bad, digest], "invalid"))
    bad_points = [b"", b"\x00", peer[:-1], peer+b"\x00", b"\x02"+peer[1:33],
                  b"\x03"+peer[1:33], b"\x06"+peer[1:], b"\x07"+peer[1:],
                  b"\x04"+curve.P.to_bytes(32, "big")+peer[33:],
                  peer[:33]+curve.P.to_bytes(32, "big"), b"\x04"+bytes(64)]
    for bad in bad_points:
        cases.append(("strict-peer-profile", "verify", [bad, digest, signature], "false"))
    cases.append(("wrong-valid-key", "verify", [curve.sec1(curve.mul(2, curve.G)), digest, signature], "false"))
    # Malformed strict DER must fail at the actual public verifier boundary.
    invalid_der = [b"", b"\x30", signature[:-1], signature+b"\x00", b"\x31"+signature[1:],
                   b"\x30\x81"+signature[1:], b"\x30\x80"+signature[2:]+b"\x00\x00"]
    invalid_der += [b"\x30"+bytes([len(body)])+body for body in (
        b"\x02\x00"+integer(1), b"\x02\x01\x80"+integer(1),
        b"\x02\x02\x00\x01"+integer(1), integer(1)+b"\x02\x01\xff",
        b"\x03\x01\x01"+integer(1), integer(1)+b"\x02\x81\x01\x01",
    )]
    for bad in invalid_der:
        assert decode_der(bad) is None
        cases.append(("DER-public-boundary", "verify", [peer, digest, bad], "false"))
    for bad in [b"", raw[:-1], raw+b"\x00"]:
        cases.append(("raw-signature-length", "verify-raw", [peer, digest, bad], "false"))
    for r, s in [(0, 1), (1, 0), (N, 1), (1, N)]:
        bad = r.to_bytes(32, "big")+s.to_bytes(32, "big")
        cases.append(("raw-scalar-range", "verify-raw", [peer, digest, bad], "false"))
    # A valid r,s whose verification sum is infinity: Q=G, s=1, z=n-r.
    raw_infinity = (1).to_bytes(32, "big")*2
    cases.append(("verification-infinity", "verify", [peer, (N-1).to_bytes(32, "big"), der(raw_infinity)], "false"))
    return cases


def rejection_cases(vectors):
    cases = []
    one = (1).to_bytes(32, "little")
    cases.append(("actual-zero-s", "known-nonce", [one, (N-curve.G[0]).to_bytes(32, "big"), one], "invalid"))
    cases.append(("injected-zero-r", "zero-r", [one, bytes(32), one], "invalid"))
    cases.append(("known-nonce-control", "known-nonce", [one, bytes(32), one], (curve.G[0].to_bytes(32, "big")*2).hex()))
    rng = random.Random(0x6979)
    for _ in range(8):
        key, value = rng.randbytes(32), rng.randbytes(32)
        next_key = hmac.digest(key, value+b"\x00", "sha256")
        next_value = hmac.digest(next_key, value, "sha256")
        for operation in ("reject", "candidate-none", "signature-none"):
            cases.append(("RFC6979-rejected-state", operation, [key, value], (next_key+next_value).hex()))
        for scalar in (0, N, N+1):
            candidate = scalar.to_bytes(32, "big")
            next_key = hmac.digest(key, candidate+b"\x00", "sha256")
            next_value = hmac.digest(next_key, candidate, "sha256")
            cases.append(("actual-candidate-range", "candidate-range", [key, candidate], (next_key+next_value).hex()))
    return cases


def interop(evaluator):
    cases = []
    root = evaluator.root
    openssl_counts = Counter()
    for i, (private, message) in enumerate([(1, b""), (N-1, b"digest boundary"),
                                            (2, b"\x00"*32), (3, b"\xff"*1000)]):
        digest = hashlib.sha256(message).digest()
        peer = curve.sec1(curve.mul(private, curve.G))
        reference = reference_sign(private, digest)
        # These bytes come directly from Bend's public DER signing API.
        actual = evaluator.run([("Bend-DER-to-OpenSSL", "sign",
                                 [private.to_bytes(32, "big"), digest], der(reference).hex())])[0]
        signature_path = root / f"interop-{i}.der"
        digest_path = root / f"digest-{i}.bin"
        public_path = root / f"public-{i}.der"
        private_path = root / f"private-{i}.der"
        signature_path.write_bytes(bytes.fromhex(actual))
        digest_path.write_bytes(digest)
        public_path.write_bytes(curve.PUBLIC_PREFIX+peer)
        private_path.write_bytes(curve.PRIVATE_PREFIX+private.to_bytes(32, "big")+curve.PRIVATE_SUFFIX)
        result = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                                 "-inkey", str(public_path), "-sigfile", str(signature_path),
                                 "-in", str(digest_path), "-pkeyopt", "digest:sha256"],
                                capture_output=True, timeout=10)
        assert result.returncode == 0, result.stderr
        openssl_counts["OpenSSL-verified-Bend-DER"] += 1
        result = subprocess.run(["openssl", "pkeyutl", "-sign", "-keyform", "DER", "-inkey",
                                 str(private_path), "-in", str(digest_path), "-pkeyopt", "digest:sha256"],
                                capture_output=True, check=True, timeout=10)
        parsed = decode_der(result.stdout)
        assert parsed is not None and reference_verify(peer, digest, parsed)
        openssl_counts["OpenSSL-generated-DER"] += 1
        cases.append(("OpenSSL-DER-to-Bend", "verify", [peer, digest, result.stdout], "true"))
        changed = bytes([digest[0] ^ 1])+digest[1:]
        cases.append(("OpenSSL-changed-digest", "verify", [peer, changed, result.stdout], "false"))
    evaluator.run(cases)
    return dict(openssl_counts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--section", choices=["all", "vectors", "signing", "tampering", "rejection", "interop"], default="all")
    parser.add_argument("--report", type=Path)
    parser.add_argument("binary", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ["--"] else args.binary
    if not binary:
        parser.error("Supply an evaluator command after --")
    start = time.monotonic()
    vectors = json.loads(Path(__file__).with_name("ecdsa_vectors.json").read_text())
    with tempfile.TemporaryDirectory(prefix="grounds-ecdsa-") as directory:
        evaluator = Evaluator(binary, Path(directory))
        factories = {"vectors": lambda: published(vectors), "signing": differential,
                     "tampering": invalid_cases, "rejection": lambda: rejection_cases(vectors)}
        for section, factory in factories.items():
            if args.section in ("all", section):
                evaluator.run(factory())
                print(f"ECDSA {section}: {sum(evaluator.counts.values())} cases passed so far in {time.monotonic()-start:.3f}s", file=sys.stderr, flush=True)
        openssl = interop(evaluator) if args.section in ("all", "interop") else {}
        report = {"section": args.section, "binary": binary, "cases": dict(evaluator.counts),
                  "total": sum(evaluator.counts.values()), "openssl": openssl,
                  "elapsed_seconds": round(time.monotonic()-start, 3)}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2)+"\n")
    print("ECDSA P-256/SHA-256: "+json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
