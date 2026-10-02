"""Full Bend RSA-PSS/v1.5 SHA-256 digest verification against independent peers.

Public fixtures only. Host exponentiation is an oracle, never the implementation
under test. This does not approve private operations, trust, timing or erasure.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time

from rsa_encoding_check import pss_decode, v15


ROOT = Path(__file__).parent
SECTIONS = ("published", "peers", "admission", "tamper_pss", "tamper_v15")


def be(value):
    return value.to_bytes(max(1, (value.bit_length()+7)//8), "big")


def oracle(kind, values):
    modulus, exponent, digest, signature = values
    n, e, s = (int.from_bytes(v, "big") for v in (modulus, exponent, signature))
    if (len(digest) != 32 or not modulus or modulus[0] == 0 or
            not 2048 <= n.bit_length() <= 4096 or n % 2 != 1 or
            not exponent or exponent[0] == 0 or e <= 1 or e >= n or e % 2 != 1 or
            len(signature) != len(modulus) or s >= n):
        return False
    recovered = pow(s, e, n)
    if kind == "pss":
        bits = n.bit_length()-1
        length = (bits+7)//8
        if recovered >= 1 << (8*length):
            return False
        return pss_decode(bits, digest, recovered.to_bytes(length, "big")) is not None
    return recovered.to_bytes(len(modulus), "big") == v15(len(modulus), digest)


def case(tag, kind, values, expected):
    assert oracle(kind, values) == expected, (tag, kind)
    return tag, "0" if kind == "pss" else "1", values, str(expected).lower()


def published_cases():
    records = json.loads((ROOT/"rsa_encoding_vectors.json").read_text())["records"]
    cases = []
    for record in records:
        values = [be(int(record[k], 16)) for k in ("modulus", "exponent")]
        # Published signatures are integer hex, including odd-nibble values.
        # RSASSA consumes the corresponding exactly-k-byte I2OSP value.
        values += [bytes.fromhex(record["digest"]),
                   int(record["signature"], 16).to_bytes(len(values[0]), "big")]
        assert hashlib.sha256(bytes.fromhex(record["message"])).digest() == values[2]
        tag = f"NIST-{record['kind']}-full-signature"
        cases.append(case(tag, record["kind"], values, record["encoding_expected"]))
    return cases


def peer_cases():
    records = json.loads((ROOT/"rsa_signature256_vectors.json").read_text())["cases"]
    cases = []
    for record in records:
        values = [bytes.fromhex(record[k]) for k in ("modulus", "exponent", "digest", "signature")]
        n, e, _, signature = values
        assert int.from_bytes(n, "big").bit_length() == record["modulus_bits"]
        recovered = pow(int.from_bytes(signature, "big"), int.from_bytes(e, "big"), int.from_bytes(n, "big"))
        assert recovered.to_bytes(len(n), "big").hex() == record["recovered_encoding"]
        cases.append(case(record["tag"], record["kind"], values, record["expected"]))
    return cases


def baseline(kind):
    records = json.loads((ROOT/"rsa_signature256_vectors.json").read_text())["cases"]
    record = next(r for r in records if r["kind"] == kind and r["modulus_bits"] == 2048
                  and r["tag"] == "OpenSSL-full-signature" and r["expected"])
    return [bytes.fromhex(record[k]) for k in ("modulus", "exponent", "digest", "signature")]


def admission_cases():
    cases = []
    for kind in ("pss", "v15"):
        values = baseline(kind)
        modulus, exponent, digest, signature = values
        n = int.from_bytes(modulus, "big")
        cases.append(case("admission-positive-control", kind, values, True))
        replacements = (
            (0, "modulus-empty", b""), (0, "modulus-zero", b"\x00"),
            (0, "modulus-leading-zero", b"\x00"+modulus),
            (0, "modulus-even", modulus[:-1]+bytes([modulus[-1] & 254])),
            (0, "modulus-too-small", b"\x7f"+modulus[1:]),
            (0, "modulus-too-large", b"\x01"+bytes(511)+b"\x01"),
            (1, "exponent-empty", b""), (1, "exponent-zero", b"\x00"),
            (1, "exponent-one", b"\x01"), (1, "exponent-even", b"\x02"),
            (1, "exponent-leading-zero", b"\x00"+exponent),
            (1, "exponent-equals-modulus", modulus),
            (1, "exponent-above-modulus", be(n+2)),
            (2, "digest-empty", b""), (2, "digest-short", digest[:-1]),
            (2, "digest-long", digest+b"\x00"), (2, "digest-other-hash-length", bytes(48)),
            (3, "signature-short", signature[:-1]),
            (3, "signature-long", b"\x00"+signature),
            (3, "signature-equals-modulus", modulus),
            (3, "signature-above-modulus", (n+1).to_bytes(len(modulus), "big")),
            (3, "signature-zero", bytes(len(modulus))),
            (3, "signature-maximal", b"\xff"*len(modulus)),
            (0, "wrong-admitted-public-key", modulus[:-1]+bytes([modulus[-1]^2])),
            (1, "wrong-admitted-public-exponent", b"\x03"),
        )
        for index, tag, replacement in replacements:
            changed = values.copy()
            changed[index] = replacement
            cases.append(case(tag, kind, changed, False))
    return cases


def tamper_cases(kind):
    values = baseline(kind)
    cases = [case(f"{kind}-tamper-positive-control", kind, values, True)]
    for index, tag in ((2, "digest"), (3, "signature")):
        for offset in range(len(values[index])):
            changed = values.copy()
            mutation = bytearray(changed[index])
            mutation[offset] ^= 1
            changed[index] = bytes(mutation)
            cases.append(case(f"{kind}-every-{tag}-byte", kind, changed, False))
    return cases


def run(binary, cases, directory, counts, batch_size):
    for offset in range(0, len(cases), batch_size):
        batch = cases[offset:offset+batch_size]
        arguments = []
        for index, (_, mode, values, _) in enumerate(batch):
            arguments.append(mode)
            for field, value in enumerate(values):
                path = directory/f"{index}-{field}.bin"
                path.write_bytes(value)
                arguments.append(str(path))
        result = subprocess.run(binary+arguments, capture_output=True, text=True, timeout=90)
        assert result.returncode == 0, (offset, result.returncode, result.stderr)
        actual, expected = result.stdout.splitlines(), [c[3] for c in batch]
        assert actual == expected, (offset, [c[0] for c in batch], actual, expected)
        counts.update(c[0] for c in batch)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--section", choices=("all",)+SECTIONS, default="all")
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument("--report", type=Path)
    parser.add_argument("binary", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ["--"] else args.binary
    if not binary or not 1 <= args.batch_size <= 16:
        parser.error("supply an evaluator after -- and batch size 1..16")
    start, counts = time.monotonic(), Counter()
    factories = (published_cases, peer_cases, admission_cases,
                 lambda: tamper_cases("pss"), lambda: tamper_cases("v15"))
    with tempfile.TemporaryDirectory(prefix="grounds-rsa-signature-check-") as folder:
        for section, factory in zip(SECTIONS, factories):
            if args.section in ("all", section):
                run(binary, factory(), Path(folder), counts, args.batch_size)
                print(f"RSA signatures {section}: {sum(counts.values())} cases passed so far", flush=True)
    report = {"binary": binary, "section": args.section, "cases": dict(counts),
              "total": sum(counts.values()), "elapsed_seconds": round(time.monotonic()-start, 3),
              "input_sha256": {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in
                  ("rsa_signature256.bend", "rsa_signature256_cli.bend", "rsa_signature256_check.py",
                   "rsa_signature256_vectors.json", "rsa_encoding_vectors.json", "rsa_encoding_check.py",
                   "rsa_integer.bend", "rsa_encoding.bend", "bytes.bend", "sha256.bend")},
              "private_operations_checked": False, "trust_or_timing_approval": False}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2)+"\n")
    print("RSA signatures: "+json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
