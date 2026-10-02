"""Measure admitted RSA public powers with frozen public operands.

Reported time includes process startup and fixture file I/O. Synthetic alternate
exponents test arithmetic admission, not valid RSA keys or certificate trust.
Run this under tools/build_guard.py; it does not compile an evaluator.
"""

import argparse
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import tempfile
import time


ROOT = Path(__file__).parent


def be(value):
    return value.to_bytes(max(1, (value.bit_length()+7)//8), "big")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bits", type=int, choices=(2048, 3072, 4096), required=True)
    parser.add_argument("--profile", choices=("all", "65537", "sparse", "dense"), default="all")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("binary", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ["--"] else args.binary
    if not binary or not 1 <= args.repeats <= 5:
        parser.error("supply an evaluator after -- and repeats 1..5")
    fixture = ROOT/"rsa_signature256_vectors.json"
    records = json.loads(fixture.read_text())["cases"]
    record = next(r for r in records if r["modulus_bits"] == args.bits and
                  r["tag"] == "OpenSSL-full-signature" and r["kind"] == "pss")
    n, signature = int(record["modulus"], 16), int(record["signature"], 16)
    width = (n.bit_length()+7)//8
    exponents = {"65537": 65537, "sparse": (1 << (args.bits-1))+1, "dense": n-2}
    results = []
    with tempfile.TemporaryDirectory(prefix="grounds-public-rsa-cost-") as folder:
        directory = Path(folder)
        modulus_path, exponent_path, signature_path = [directory/f"{part}.bin" for part in ("n", "e", "s")]
        modulus_path.write_bytes(be(n))
        signature_path.write_bytes(signature.to_bytes(width, "big"))
        for profile, exponent in exponents.items():
            if args.profile not in ("all", profile):
                continue
            assert 1 < exponent < n and exponent % 2 == 1
            exponent_path.write_bytes(be(exponent))
            expected = pow(signature, exponent, n).to_bytes(width, "big").hex()
            samples = []
            for _ in range(args.repeats):
                started = time.monotonic()
                result = subprocess.run(binary+["4", str(modulus_path), str(exponent_path), str(signature_path)],
                                        capture_output=True, text=True, timeout=90)
                elapsed = time.monotonic()-started
                assert result.returncode == 0, (profile, result.returncode, result.stderr)
                assert result.stdout.splitlines() == [expected], (profile, result.stdout)
                samples.append(round(elapsed, 6))
            measurement = {"profile": profile, "modulus_bits": args.bits,
                           "exponent_bits": exponent.bit_length(), "exponent_set_bits": exponent.bit_count(),
                           "exponent_hex": be(exponent).hex(), "samples_seconds": samples,
                           "median_seconds": round(statistics.median(samples), 6),
                           "representative_sha256": hashlib.sha256(signature.to_bytes(width, "big")).hexdigest(),
                           "oracle_output_sha256": hashlib.sha256(bytes.fromhex(expected)).hexdigest()}
            results.append(measurement)
            print(json.dumps(measurement), flush=True)
    report = {"binary": binary, "fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
              "input_sha256": {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in
                  ("rsa_integer.bend", "rsa_integer_cli.bend", "rsa_integer_bench.py", "bytes.bend")},
              "measurements": results, "repeats": args.repeats,
              "scope": "public arithmetic including evaluator startup/file I/O; not an integrated handshake",
              "alternate_exponent_key_validity_checked": False, "timing_or_private_approval": False}
    args.report.write_text(json.dumps(report, indent=2)+"\n")


if __name__ == "__main__":
    main()
