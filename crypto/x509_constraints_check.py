"""Independent integer/bit-set oracle for RFC 5280 constraint payloads."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import subprocess
import tempfile


def tlv(tag, body):
    size = len(body)
    length = bytes([size]) if size < 128 else (
        bytes([0x80 + (size.bit_length() + 7) // 8])
        + size.to_bytes((size.bit_length() + 7) // 8, "big"))
    return bytes([tag]) + length + body


def integer(value):
    body = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    return (b"\x00" if body[0] & 128 else b"") + body


def basic(ca, limit=None):
    return tlv(48, (b"\x01\x01\xff" if ca else b"")
               + (tlv(2, integer(limit)) if limit is not None else b""))


def usage(mask):
    # Construct a named bit list by bit positions, independent of Bend masks.
    last = mask.bit_length() - 1
    body = bytearray(last // 8 + 1)
    for index in range(last + 1):
        if mask & (1 << index):
            body[index // 8] |= 1 << (7 - index % 8)
    return tlv(3, bytes([7 - last % 8]) + body)


def wire_mask(mask):
    return sum(1 << (7 - i % 8 + 8 * (i // 8)) for i in range(9) if mask & (1 << i))


def policy(ca, limit, mask):
    positions = {i for i in range(9) if mask & (1 << i)}
    return ((5 not in positions or ca)
            and (limit is None or 5 in positions)
            and (not positions.intersection({7, 8}) or 4 in positions))


def cases():
    result = []

    def add(group, operation, values, expected):
        result.append((group, str(operation), values, str(expected).lower()))

    # Exact payloads from RFC 5280 Appendix C.1/C.2, not synthetic acceptance.
    add("published-basic", 0, [bytes.fromhex("30030101ff")], "true:none")
    add("published-usage", 1, [bytes.fromhex("03020106")], 6)
    add("published-usage", 1, [bytes.fromhex("030206c0")], 192)
    add("empty-basic", 0, [basic(False)], "false:none")
    add("absent-payloads-policy", 5, [], True)
    for value in [basic(False), basic(True), basic(True, 0), basic(True, 2**128)]:
        add("absent-usage-policy", 6, [value], True)
    for value in [b"", b"\x30", b"\x30\x03\x01\x01\x00"]:
        add("malformed-is-not-absence", 6, [value], False)
        add("malformed-is-not-absence", 4, [value], False)
    rng = random.Random(0x5280)
    limits = [0, 1, 127, 128, 255, 256, 65535, 65536,
              2**24-1, 2**24, 2**31-1, 2**31, 2**32-1, 2**32,
              2**48, 2**128-1, 2**1024]
    limits += [rng.getrandbits(rng.randrange(1, 2048)) for _ in range(32)]
    for limit in limits:
        value = basic(True, limit)
        add("arbitrary-size-limit", 0, [value], "true:" + integer(limit).hex())
        for count in sorted({0, 1, 2**32-1, min(limit, 2**32-1),
                             max(0, min(limit-1, 2**32-1)), min(limit+1, 2**32-1)}):
            add("depth-comparison", 2, [value, count.to_bytes(4, "big")], limit >= count)
            add("raw-depth-comparison", 7, [integer(limit), count.to_bytes(4, "big")], limit >= count)
    for raw in [b"", b"\x80", b"\xff", b"\x00\x00", b"\x00\x7f", bytes(65536)]:
        add("malformed-raw-limit", 7, [raw, bytes(4)], False)
    add("unlimited", 2, [basic(True), b"\xff"*4], True)
    for count in [b"", bytes(3), bytes(5)]:
        add("count-width", 2, [basic(True, 0), count], False)
    # Max-sized DER input with an enormous canonical positive INTEGER. It
    # remains exact; depth comparison never wraps or rejects a large limit.
    huge = b"\x01" + bytes(65524)
    value = tlv(48, b"\x01\x01\xff" + tlv(2, huge))
    assert len(value) == 65536
    add("input-bound", 0, [value], "none")
    huge = huge[:-1]
    value = tlv(48, b"\x01\x01\xff" + tlv(2, huge))
    assert len(value) == 65535
    add("maximum-limit", 2, [value, b"\xff"*4], True)
    bad_bodies = [b"\x01\x01\x00", b"\x01\x01\x01", b"\x01\x00",
                  b"\x01\x02\xff\xff", tlv(2, b"\x00"),
                  b"\x01\x01\xff" + tlv(2, b""),
                  b"\x01\x01\xff" + tlv(2, b"\x80"),
                  b"\x01\x01\xff" + tlv(2, b"\xff"),
                  b"\x01\x01\xff" + tlv(2, b"\x00\x00"),
                  b"\x01\x01\xff" + tlv(2, b"\x00\x7f"),
                  b"\x01\x01\xff"*2,
                  b"\x01\x01\xff" + tlv(2, b"\x00")*2,
                  tlv(2, b"\x00") + b"\x01\x01\xff"]
    for body in bad_bodies:
        add("basic-malformed", 0, [tlv(48, body)], "none")
    # Every nonempty combination of the nine bits is syntactically admitted;
    # cross-field/local purpose policy is an explicitly separate operation.
    for mask in range(1, 512):
        encoded = usage(mask)
        add("all-bit-combinations", 1, [encoded], wire_mask(mask))
        add("absent-basic-policy", 4, [encoded], policy(False, None, mask))
        for ca, limit in [(False, None), (True, None), (True, 0)]:
            add("cross-field-policy", 3, [basic(ca, limit), encoded], policy(ca, limit, mask))
        # DER named-bit-list uniqueness: same bits with an extra trailing zero
        # byte or a wrong unused-bit count must not be accepted.
        body = encoded[2:]
        add("nonminimal-named-list", 1, [tlv(3, b"\x00" + body[1:] + b"\x00")], "none")
        for unused in range(9):
            if unused != body[0]:
                add("wrong-unused-bits", 1, [tlv(3, bytes([unused]) + body[1:])], "none")
    for body in [b"", b"\x00", b"\x00\x00", b"\x07\x00\x00",
                 b"\x06\x00\x40", b"\x07\x00\x81", b"\x07\x00\x80\x00"]:
        add("usage-malformed", 1, [tlv(3, body)], "none")
    for valid in [basic(False), basic(True, 128), usage(1), usage(256)]:
        operation = 0 if valid[0] == 48 else 1
        for cut in range(len(valid)):
            add("every-truncation", operation, [valid[:cut]], "none")
        for malformed in [valid+b"\x00", valid+b"\x05\x00", bytes([valid[0]^32])+valid[1:],
                          bytes([valid[0], 0x80])+valid[2:]+b"\x00\x00",
                          bytes([valid[0], 0x81, valid[1]])+valid[2:]]:
            add("DER-envelope", operation, [malformed], "none")
    for bc, ku in [(b"", usage(1)), (basic(True), b""), (basic(True), b"\x03\x00")]:
        add("rejected-payload-policy", 3, [bc, ku], False)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("binary", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ["--"] else args.binary
    if not binary:
        parser.error("supply evaluator command after --")
    corpus = cases()
    counts = Counter()
    identity = hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix="grounds-constraints-") as directory:
        root = Path(directory)
        for offset in range(0, len(corpus), 32):
            batch = corpus[offset:offset+32]
            command = binary + ["check"]
            for i, (group, mode, values, expected) in enumerate(batch):
                command.append(mode)
                identity.update(json.dumps([group, mode, [v.hex() for v in values], expected]).encode())
                for j, value in enumerate(values):
                    path = root / f"{i}-{j}.bin"
                    path.write_bytes(value)
                    command.append(str(path))
            completed = subprocess.run(command, capture_output=True, text=True, timeout=20)
            assert completed.returncode == 0, (offset, completed.returncode, completed.stderr)
            actual = completed.stdout.splitlines()
            expected = [case[3] for case in batch]
            assert actual == expected, (offset, [case[:2] for case in batch], actual, expected)
            counts.update(case[0] for case in batch)
    report = {"binary": binary, "total": sum(counts.values()), "cases": dict(counts),
              "corpus_sha256": identity.hexdigest(), "chain_or_trust_acceptance": False}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
