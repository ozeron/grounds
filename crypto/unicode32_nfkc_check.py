"""Complete official Unicode 3.2 NFKC vectors and independent differential checks."""
import argparse
import gzip
import hashlib
import itertools
import json
import random
import struct
import subprocess
import tempfile
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parent
U = unicodedata.ucd_3_2_0
SOURCE_SHA = 'c4513869bb7098d19838be4a1fd5d760843c5804bfe03bd6bbb20623ceb6e57d'


def official():
    archive = ROOT / 'unicode32_nfkc_vectors.gz'
    identity = hashlib.sha256()
    rows = 0
    with gzip.open(archive, 'rb') as stream:
        for line in stream:
            identity.update(line)
            content = line.split(b'#')[0].strip()
            if not content or content.startswith(b'@'):
                continue
            columns = [[int(code, 16) for code in part.split()] for part in content.split(b';')[:5]]
            assert len(columns) == 5
            rows += 1
            for column in columns:
                yield column, columns[3], 'official'
    assert identity.hexdigest() == SOURCE_SHA, 'official vector source hash'
    assert rows == 16992, rows


def expected(codes):
    if len(codes) > 262140 or any(code > 0x10ffff or 0xd800 <= code <= 0xdfff for code in codes):
        return None
    return [ord(c) for c in U.normalize('NFKC', ''.join(chr(code) for code in codes))]


def differential():
    fixed = [[], [0], [0x10ffff], [0x13a0], [0x1c90], [0xf951],
             [0x2f868], [0x2f874], [0x2f91f], [0x2f95f], [0x2f9bf],
             [0x1100, 0x1161, 0x11a8], [0x1100, 0x301, 0x1161],
             [0x41, 0x300, 0x301], [0x41, 0x301, 0x300], [0x301, 0x323, 0x41],
             [0x41, 0x315, 0x300, 0x42], [0x41, 0x323, 0x300, 0x42],
             [0xd800], [0xdfff], [0x110000], [0xffffffff], [0x41, 0xd800, 0x42],
             [0x41, 0x110000, 0x42], [0xfdfa, 0x33c6], [0x344, 0x301]]
    for codes in fixed:
        yield codes, expected(codes), 'differential'
    pool = [0, 0x20, 0x41, 0x42, 0xe9, 0x1e0a, 0x1e0c, 0x1e14,
            0x300, 0x301, 0x304, 0x307, 0x308, 0x315, 0x323, 0x345, 0x5b0,
            0x5bd, 0x9c7, 0x9be, 0x9cb, 0x94e, 0x1100, 0x1112, 0x1161,
            0x1175, 0x11a8, 0x11c2, 0xac00, 0xac01, 0xd7a3, 0xfdfa, 0x33c6,
            0x1d15e, 0x1d1c0, 0x2f868, 0x2f95f, 0x1d400, 0x10ffff]
    random_source = random.Random(3204518)
    for _ in range(1024):
        codes = [random_source.choice(pool) for _ in range(random_source.randrange(0, 33))]
        yield codes, expected(codes), 'differential'


def batch_bytes(cases):
    result = bytearray(struct.pack('>I', len(cases)))
    for codes, _, _ in cases:
        result.extend(struct.pack('>I', len(codes)))
        for code in codes:
            result.extend(struct.pack('>I', code))
    return result


def check_output(output, cases, identity):
    output.seek(0)
    for codes, wanted, kind in cases:
        header = output.readline().rstrip(b'\n')
        if wanted is None:
            assert header == b'none', (kind, codes[:30], header)
            encoded = b'none'
        else:
            assert header == f'some:{len(wanted)}'.encode(), (kind, codes[:30], header, len(wanted))
            actual = []
            for offset in range(0, len(wanted), 256):
                raw = output.readline().rstrip(b'\n')
                assert len(raw) == 6 * min(256, len(wanted) - offset), (kind, 'chunk length', len(raw))
                actual.extend(int(raw[i:i + 6], 16) for i in range(0, len(raw), 6))
            assert actual == wanted, (kind, codes[:30], actual[:30], wanted[:30])
            encoded = b''.join(struct.pack('>I', code) for code in wanted)
        identity.update(kind.encode() + batch_bytes([(codes, None, kind)]) + header + encoded)
    assert output.read(1) == b'', 'trailing evaluator output'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--limit', type=int)
    parser.add_argument('--batch-size', type=int, default=256)
    parser.add_argument('--asset-controls', action='store_true')
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ['--'] else args.binary
    if not binary:
        parser.error('supply evaluator')
    assert U.unidata_version == '3.2.0'
    source = itertools.chain(official(), differential())
    if args.limit is not None:
        source = itertools.islice(source, args.limit)
    counts = {'official': 0, 'differential': 0}
    identity = hashlib.sha256()
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        path = directory / 'batch.bin'
        while True:
            cases = list(itertools.islice(source, args.batch_size))
            if not cases:
                break
            path.write_bytes(batch_bytes(cases))
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                result = subprocess.run([*binary, 'check', str(ROOT / 'unicode32_nfkc.bin'), str(path)], stdout=output, stderr=errors, timeout=100)
                errors.seek(0, 2); errors.seek(max(0, errors.tell() - 1200))
                assert result.returncode == 0, (result.returncode, errors.read())
                check_output(output, cases, identity)
            for _, _, kind in cases:
                counts[kind] += 1
            if sum(counts.values()) % 8192 == 0:
                print('verified', sum(counts.values()), flush=True)
        asset_cases = 0
        if args.asset_controls:
            raw = (ROOT / 'unicode32_nfkc.bin').read_bytes()
            variants = [b'', raw[:-1], raw + b'\0']
            for offset in [0, 8, len(raw) // 2, len(raw) - 1]:
                altered = bytearray(raw); altered[offset] ^= 1; variants.append(altered)
            path.write_bytes(batch_bytes([([], [], 'control')]))
            for index, altered in enumerate(variants):
                asset = directory / f'asset-{index}.bin'; asset.write_bytes(altered)
                result = subprocess.run([*binary, 'check', str(asset), str(path)], capture_output=True, timeout=20)
                assert result.returncode == 2 and b'invalid Unicode 3.2 table asset' in result.stderr, (index, result.returncode, result.stderr[-300:])
                asset_cases += 1
    report = {'binary': binary, 'unicode_version': U.unidata_version, **counts,
              'complete_official_vectors': args.limit is None, 'asset_rejection_cases': asset_cases,
              'corpus_sha256': identity.hexdigest(), 'complete_StringPrep_or_Name_comparison': False}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
