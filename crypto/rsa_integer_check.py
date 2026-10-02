"""Independent RSA integer arithmetic and published RSAVP1 comparisons."""

import argparse
from collections import Counter
import json
from pathlib import Path
import random
import subprocess
import tempfile
import time


def be(value, length=None):
    return value.to_bytes(length or max(1, (value.bit_length()+7)//8), "big")


def moduli(max_bits):
    rng = random.Random(0x1532767)
    for bits in (3, 14, 15, 16, 29, 30, 31, 127, 255, 256, 1023, 1024,
                 2047, 2048, 2049, 2050, 3072, 4095, 4096):
        if bits <= max_bits:
            for n in ((1 << bits)-1, (1 << (bits-1))+1,
                      rng.getrandbits(bits) | (1 << (bits-1)) | 1):
                yield n


def byte_cases():
    rng = random.Random(0x1415)
    cases = []
    for length in (0, 1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 33, 127, 128,
                   255, 256, 257, 511, 512):
        for data in (bytes(length), bytes([255])*length, rng.randbytes(length)):
            cases.append(("BE/15-bit-roundtrip", "0", [data], data.hex()))
    cases.append(("all-byte-values", "0", [bytes(range(256))], bytes(range(256)).hex()))
    return cases


def inverse_cases():
    rng = random.Random(0x32768)
    values = {1, 3, 5, 7, 255, 257, 16383, 16385, 32765, 32767}
    values.update((1 << i)+1 for i in range(1, 15))
    values.update((1 << i)-1 for i in range(1, 15))
    values.update(rng.randrange(1, 32768, 2) for _ in range(128))
    return [("negative-low-inverse", "1", [be(n)], str((-pow(n, -1, 32768)) & 32767))
            for n in sorted(values)]


def mont_cases(max_bits):
    rng = random.Random(0x1436)
    cases = []
    for n in moduli(max_bits):
        length = (n.bit_length()+7)//8
        limbs = (n.bit_length()+14)//15
        inverse_r = pow(1 << (15*limbs), -1, n)
        for a, b in ((0, 0), (1, 1), (n-1, n-1), (n-1, 1),
                     (rng.randrange(n), rng.randrange(n))):
            expected = (a*b*inverse_r) % n
            cases.append(("Montgomery-carry/final-subtraction", "2",
                          [be(n), be(a, length), be(b, length)], be(expected, length).hex()))
    return cases


def r2_cases(max_bits):
    return [("R2-context", "3", [be(n)],
             be(pow(2, 30*((n.bit_length()+14)//15), n), len(be(n))).hex())
            for n in moduli(max_bits)]


def power_cases(max_bits):
    rng = random.Random(0x8017)
    cases = []
    for bits in (15, 16, 31, 256, 1024, 2048, 2050, 3072, 4096):
        if bits > max_bits:
            continue
        n = rng.getrandbits(bits) | (1 << (bits-1)) | 1
        for e, a in ((3, 0), (17, 1), (65537, n-1), (16777215, rng.randrange(n)),
                     (4294967295, rng.randrange(n))):
            if e >= n:
                continue
            length = len(be(n))
            cases.append(("public-power-exponents", "4" if bits >= 2048 else "5",
                          [be(n), be(e), be(a, length)], be(pow(a, e, n), length).hex()))
    # Nontrivial exponent beyond U32: this tests the generic byte scanner.
    if max_bits >= 256:
        n, e, a = (1 << 256)-189, (1 << 64)+13, 0x123456789abcdef
        cases.append(("public-power-wide-exponent", "5", [be(n), be(e), be(a, 32)], be(pow(a, e, n), 32).hex()))
    return cases


def published_cases(max_bits):
    fixture = json.loads(Path(__file__).with_name("rsa_encoding_vectors.json").read_text())
    cases = []
    for record in fixture["records"]:
        if record["modulus_bits"] > max_bits:
            continue
        n, e, s = (int(record[k], 16) for k in ("modulus", "exponent", "signature"))
        length = len(be(n))
        assert 0 <= s < n
        recovered = be(pow(s, e, n), length)
        assert recovered == bytes.fromhex(record["encoded"])
        cases.append(("NIST-RSAVP1-representative", "4",
                      [be(n), be(e), be(s, length)], recovered.hex()))
    return cases


def admission_cases():
    n = (1 << 2048)-159
    modulus = be(n)
    good = [modulus, be(65537), be(2, 256)]
    cases = []
    for bad in (b"", bytes(256), b"\x00"+modulus, be(n-1), be((1 << 2047)-1), be((1 << 4096)+1)):
        cases.append(("modulus-admission", "4", [bad, *good[1:]], "invalid"))
    for bad in (b"", b"\x00", b"\x01", b"\x02", b"\x04", b"\x00\x03", be(n), be(n+2)):
        cases.append(("exponent-admission", "4", [modulus, bad, good[2]], "invalid"))
    for bad in (b"", be(2), good[2][:-1], b"\x00"+good[2], be(n), be(n+1), bytes([255])*256):
        cases.append(("signature-width/range", "4", [modulus, good[1], bad], "invalid"))
    return cases


def run(binary, cases, root, counts):
    for offset in range(0, len(cases), 4):
        batch = cases[offset:offset+4]
        arguments = []
        for i, (_, mode, inputs, _) in enumerate(batch):
            arguments.append(mode)
            for j, value in enumerate(inputs):
                path = root/f"input-{i}-{j}.bin"
                path.write_bytes(value)
                arguments.append(str(path))
        result = subprocess.run(binary+arguments, capture_output=True, text=True, timeout=90)
        assert result.returncode == 0, (offset, result.returncode, result.stderr)
        got = result.stdout.splitlines()
        expected = [case[3] for case in batch]
        assert got == expected, (offset, [c[0] for c in batch], got, expected)
        counts.update(case[0] for case in batch)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--section", choices=("all", "bytes", "inverse", "mont", "r2", "power", "published", "admission"), default="all")
    parser.add_argument("--max-bits", type=int, default=4096)
    parser.add_argument("--report", type=Path)
    parser.add_argument("binary", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ["--"] else args.binary
    if not binary:
        parser.error("supply a Bend evaluator command after --")
    start, counts = time.monotonic(), Counter()
    with tempfile.TemporaryDirectory(prefix="grounds-rsa-integer-") as folder:
        for section, factory in (("bytes", byte_cases), ("inverse", inverse_cases),
                                 ("mont", lambda: mont_cases(args.max_bits)),
                                 ("r2", lambda: r2_cases(args.max_bits)),
                                 ("power", lambda: power_cases(args.max_bits)),
                                 ("published", lambda: published_cases(args.max_bits)),
                                 ("admission", admission_cases)):
            if args.section in ("all", section):
                run(binary, factory(), Path(folder), counts)
                print(f"RSA integer {section}: {sum(counts.values())} cases passed so far", flush=True)
    report = {"binary": binary, "section": args.section, "max_bits": args.max_bits,
              "cases": dict(counts), "total": sum(counts.values()),
              "elapsed_seconds": round(time.monotonic()-start, 3),
              "private_exponentiation_checked": False, "timing_or_erasure_approval": False}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2)+"\n")
    print("RSA integer: "+json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
