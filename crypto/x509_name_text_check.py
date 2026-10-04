"""Independent Python codec/UCS-2 checks for ASN.1 value transcoding."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import subprocess
import tempfile


PRINTABLE = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?")
TAGS = (12, 19, 22, 28, 30)


def oracle(tag, data):
    if len(data) > 65535:
        return 'none'
    try:
        if tag == 19:
            if any(byte not in PRINTABLE for byte in data):
                return 'none'
            text = data.decode('ascii')
        elif tag == 22:
            text = data.decode('ascii', errors='strict')
        elif tag == 30:
            # BMPString is UCS-2, not UTF-16: even paired surrogates fail.
            if len(data) % 2:
                return 'none'
            codes = [int.from_bytes(data[i:i+2], 'big') for i in range(0, len(data), 2)]
            if any(0xd800 <= code <= 0xdfff for code in codes):
                return 'none'
            text = ''.join(map(chr, codes))
        elif tag in (12, 28):
            text = data.decode('utf-8' if tag == 12 else 'utf-32-be', errors='strict')
        else:
            return 'none'
        return 'some:' + ''.join(f'{ord(char)},' for char in text)
    except UnicodeError:
        return 'none'


def cases():
    def row(group, tag, data, expected=None):
        result = oracle(tag, data)
        if expected is not None:
            assert result == expected, (group, tag, data, result, expected)
        return group, tag, data, result
    for tag in range(256):
        yield row('empty-and-unsupported-tags', tag, b'', 'some:' if tag in TAGS else 'none')
        yield row('empty-and-unsupported-tags', tag, b'a')
    for tag in TAGS:
        for byte in range(256):
            yield row('every-single-octet', tag, bytes([byte]))
    for code in range(0xd800, 0xe000):
        yield row('every-BMP-surrogate', 30, code.to_bytes(2, 'big'), 'none')
        yield row('every-Universal-surrogate', 28, code.to_bytes(4, 'big'), 'none')
    for tag, good in ((12, 'A\u00e9\u20ac\U0001f600'.encode()),
                      (30, 'A\u00e9\u20ac\ufeff'.encode('utf-16-be')),
                      (28, 'A\u00e9\u20ac\U0001f600'.encode('utf-32-be'))):
        for cut in range(len(good) + 1):
            yield row('every-truncation', tag, good[:cut])
        for at in range(len(good)):
            for bit in range(8):
                bad = bytearray(good); bad[at] ^= 1 << bit
                yield row('every-bit-mutation', tag, bytes(bad))
    for data in (b'\xc0\x80', b'\xc1\xbf', b'\xe0\x80\x80', b'\xf0\x80\x80\x80',
                 b'\xed\xa0\x80', b'\xed\xbf\xbf', b'\xf4\x90\x80\x80', b'\xf5\x80\x80\x80',
                 b'\xff', b'\x80', b'\xc2', b'\xe2\x82', b'\xf0\x9f\x98'):
        yield row('strict-UTF8-negative-controls', 12, data, 'none')
    for data in (b'\xd8\x3d\xde\x00', b'\xde\x00\xd8\x3d'):
        yield row('UTF16-pairs-are-not-BMPString', 30, data, 'none')
    for code in (0, 9, 32, 65, 0x7f, 0x80, 0x7ff, 0x800, 0xd7ff, 0xe000, 0xfeff,
                 0xfffe, 0xffff, 0x10000, 0x10ffff, 0x110000, 0x7fffffff, 0xffffffff):
        yield row('Universal-width-and-scalar-boundaries', 28, code.to_bytes(4, 'big'))
    # Transcoding preserves controls, BOM, noncharacters and unassigned values.
    # Unicode 3.2 preparation applies its own mapping/prohibition afterward.
    preserved = [0xfeff, 0, 9, 32, 0x034f, 0xfffe, 0x0221, 0x10ffff, 65]
    text = ''.join(map(chr, preserved))
    expected = 'some:' + ''.join(f'{code},' for code in preserved)
    yield row('preparation-is-separate', 12, text.encode('utf-8'), expected)
    yield row('preparation-is-separate', 28, text.encode('utf-32-be'), expected)
    randomizer = random.Random(52804518)
    for _ in range(1024):
        codes = []
        for _ in range(randomizer.randrange(1, 9)):
            code = randomizer.randrange(0x110000)
            if not 0xd800 <= code <= 0xdfff:
                codes.append(code)
        text = ''.join(map(chr, codes))
        for tag, codec in ((12, 'utf-8'), (28, 'utf-32-be')):
            yield row('seeded-scalar-order-cross-encoding', tag, text.encode(codec))
        bmp = ''.join(chr(code) for code in codes if code <= 0xffff)
        yield row('seeded-scalar-order-cross-encoding', 30, bmp.encode('utf-16-be'))
    for tag in (12, 19, 22):
        for size in (65534, 65535, 65536):
            yield row('exact-octet-bound-and-tail-walk', tag, b'A' * size)
    for tag, unit in ((30, b'\x00A'), (28, b'\x00\x00\x00A')):
        for size in (65532, 65534, 65535, 65536):
            yield row('wide-octet-bound-and-tail-walk', tag, (unit * 16384)[:size] if tag == 28 else (unit * 32768)[:size])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ['--'] else args.binary
    if not binary:
        parser.error('supply evaluator')
    counts, identity = Counter(), hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix='grounds-name-text-') as directory:
        root = Path(directory)
        def evaluate(rows):
            command = binary + ['check']
            for index, (group, tag, data, expected) in enumerate(rows):
                path = root / f'{index}.value'; path.write_bytes(data)
                command += [str(tag), str(path)]
                identity.update(json.dumps([group, tag, data.hex(), expected]).encode())
            result = subprocess.run(command, capture_output=True, text=True, timeout=25)
            assert result.returncode == 0, (result.returncode, result.stderr[-1000:])
            actual = result.stdout.splitlines()
            assert len(actual) == len(rows), (len(actual), len(rows))
            for answer, (group, tag, data, expected) in zip(actual, rows):
                assert answer == expected, (sum(counts.values()), group, tag, len(data), answer[:300], expected[:300])
                counts[group] += 1
        batch = []
        for row in cases():
            large = len(row[2]) > 4096
            if len(batch) == 64 or large:
                if batch: evaluate(batch); batch = []
            if large: evaluate([row])
            else: batch.append(row)
        if batch: evaluate(batch)
    report = {'total': sum(counts.values()), 'groups': dict(counts), 'corpus_sha256': identity.hexdigest(),
              'binary': binary, 'Teletex_and_unknown_tags_not_transcoded': True,
              'unicode_preparation_Name_matching_or_chain_authorization': False}
    if args.report: args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
