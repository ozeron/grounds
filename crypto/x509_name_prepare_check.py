"""Independent ASN.1/type/SIZE and Unicode 3.2 stored attribute preparation."""
import argparse
from collections import Counter
import hashlib
import itertools
import json
from pathlib import Path
import random
import struct
import subprocess
import tempfile

import x509_name_check as N
import x509_name_text_check as T
from unicode32_prepare_check import expected as scalar_oracle, FOLD, U
from unicode32_nfkc_check import check_output

ROOT = Path(__file__).resolve().parent
NAME = bytes.fromhex('550429')
COMMON = bytes.fromhex('550403')
QUALIFIER = bytes.fromhex('55042e')
CODECS = ((12, 'utf-8'), (28, 'utf-32-be'), (30, 'utf-16-be'))


def expected(oid, tag, data):
    if len(oid) > 65535 or len(data) > 65535 or tag not in (12, 19, 28, 30):
        return None
    try:
        N.E.oid_contents(oid)
        if not N.value(oid, tag, data):
            return None
        # UCS-2 validation above rejects even paired UTF-16 surrogates.
        text = data.decode({12: 'utf-8', 19: 'ascii', 28: 'utf-32-be', 30: 'utf-16-be'}[tag])
        return scalar_oracle([ord(c) for c in text], True)
    except (ValueError, UnicodeError):
        return None


def cases():
    def row(kind, oid, tag, data):
        return oid, tag, data, expected(oid, tag, data), kind
    literals = [
        (COMMON, 19, b'  FOO   BAR ', [32, 102, 111, 111, 32, 32, 98, 97, 114, 32]),
        (COMMON, 12, 'Stra\u00dfe'.encode(), [32, 115, 116, 114, 97, 115, 115, 101, 32]),
        (COMMON, 12, 'A\u030a'.encode(), [32, 0xe5, 32]),
        (COMMON, 12, b'\xef\xbb\xbfA\0', [32, 97, 32]),
        (COMMON, 12, '\u00ad'.encode(), [32, 32]),
        (COMMON, 12, '\u0221'.encode(), None),
        (COMMON, 12, b'', None),
        (COMMON, 12, b'A' * 65, None),
        # SIZE precedes removal, so a mapped-empty oversize value still fails.
        (COMMON, 12, '\u00ad'.encode() * 65, None),
        (COMMON, 20, b'A', None),
        (N.DC, 22, b'EXAMPLE', None),
        (N.EMAIL, 22, b'A@example.test', None),
        (QUALIFIER, 19, b'', [32, 32]),
        (bytes.fromhex('550406'), 19, b'US', [32, 117, 115, 32]),
    ]
    for oid, tag, data, wanted in literals:
        assert expected(oid, tag, data) == wanted, ('literal oracle', oid, tag, data, wanted)
        yield oid, tag, data, wanted, 'literal'
    for group, tag, data, _ in T.cases():
        yield row('transcoding/' + group, NAME, tag, data)
    for code in FOLD:
        codes = [65, code, 32, 0x300, 66]
        text = ''.join(map(chr, codes))
        for tag, codec in CODECS:
            if tag == 30 and code > 0xffff:
                continue
            yield row('published-fold-cross-encoding', NAME, tag, text.encode(codec))
    for attr in [3, 4, 5, 6, 7, 8, 10, 11, 12, 41, 42, 43, 44, 46, 65]:
        oid = bytes([85, 4, attr])
        for tag in [12, 19, 20, 22, 28, 30, 4]:
            for count in [0, 1, 2, 63, 64, 65, 127, 128, 129, 255, 256]:
                unit = {28: b'\0\0\0A', 30: b'\0A'}.get(tag, b'A')
                yield row('original-type-and-SIZE', oid, tag, unit * count)
    for oid in [b'', b'\x80\x55\x04\x03', b'\x55\x04\x80\x03',
                b'\x55\x04\x83', bytes.fromhex('2a0304'), N.DC, N.EMAIL]:
        for tag in range(256):
            yield row('OID-and-unsupported-profile', oid, tag, b'A')
    randomizer = random.Random(5280451832)
    pool = [0, 9, 32, 65, 97, 0xad, 0xdf, 0x300, 0x315, 0x323, 0x34f,
            0x5bd, 0x903, 0x5d0, 0x13a0, 0x1c90, 0xe000, 0xfdfa, 0xfffd,
            0x1100, 0x1161, 0x11a8, 0x2f868, 0x1d400, 0x10ffff]
    for _ in range(1024):
        text = ''.join(chr(randomizer.choice(pool)) for _ in range(randomizer.randrange(0, 65)))
        for tag, codec in CODECS:
            yield row('seeded-order-space-mark-cross-encoding', NAME, tag, text.encode(codec))
    for tag, codec in CODECS:
        for count in [32767, 32768, 32769]:
            yield row('original-large-SIZE-bound', NAME, tag, ('A' * count).encode(codec))
    for count in [65534, 65535, 65536]:
        yield row('full-Printable-octet-bound', QUALIFIER, 19, b'A' * count)
    # Full input bound with long decoded lists and normalization expansion.
    yield row('full-byte-bound-fold-expansion', NAME, 12, '\ufdfa'.encode() * 21845)
    yield row('full-byte-bound-mapping-removal', NAME, 12, '\u00ad'.encode() * 32767)
    yield row('mark-ordering-through-transcoding', NAME, 12, ('A\u0315\u0323\u0300' * 1024).encode())


def batch_bytes(rows):
    out = bytearray(struct.pack('>I', len(rows)))
    for oid, tag, data, _, _ in rows:
        out.extend(struct.pack('>II', tag, len(oid))); out.extend(oid)
        out.extend(struct.pack('>I', len(data))); out.extend(data)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--limit', type=int, help='diagnostic prefix; not complete acceptance')
    parser.add_argument('--asset-controls', action='store_true')
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ['--'] else args.binary
    if not binary:
        parser.error('supply evaluator')
    if args.limit is not None and args.limit < 0:
        parser.error('limit must be nonnegative')
    counts, identity = Counter(), hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix='grounds-name-prepare-') as directory:
        directory = Path(directory)
        paths = [directory / f'batch-{i}.bin' for i in range(2)]
        def evaluate(rows):
            selected = []
            for i, start in enumerate(range(0, len(rows), 128)):
                data = batch_bytes(rows[start:start + 128])
                paths[i].write_bytes(data); selected.append(str(paths[i]))
                identity.update(data)
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                result = subprocess.run([*binary, 'check', str(ROOT / 'unicode32_nfkc.bin'), str(ROOT / 'unicode32_prepare.bin'), *selected], stdout=output, stderr=errors, timeout=100)
                errors.seek(0, 2); errors.seek(max(0, errors.tell() - 1200))
                assert result.returncode == 0, (result.returncode, errors.read())
                # Chunk/status validation reuses only the output transport
                # verifier; all expected scalar values come from the oracle.
                check_output(output, [(list(data), wanted, kind) for _, _, data, wanted, kind in rows], identity)
            counts.update(kind for _, _, _, _, kind in rows)
        pending = []
        source = cases() if args.limit is None else itertools.islice(cases(), args.limit)
        for row in source:
            if len(pending) == 256 or len(row[2]) > 4096:
                if pending: evaluate(pending); pending = []
            if len(row[2]) > 4096: evaluate([row])
            else: pending.append(row)
        if pending: evaluate(pending)
        controls = 0
        if args.asset_controls:
            good = [(COMMON, 19, b'A', [32, 97, 32], 'control')]
            paths[0].write_bytes(batch_bytes(good))
            for selected in ['unicode32_nfkc.bin', 'unicode32_prepare.bin']:
                raw = (ROOT / selected).read_bytes()
                variants = [b'', raw[:-1], raw + b'\0']
                for offset in [0, 8, len(raw) // 2, len(raw) - 1]:
                    altered = bytearray(raw); altered[offset] ^= 1; variants.append(altered)
                for i, data in enumerate(variants):
                    asset = directory / f'{selected}-{i}'; asset.write_bytes(data)
                    assets = [str(asset if name == selected else ROOT / name) for name in ['unicode32_nfkc.bin', 'unicode32_prepare.bin']]
                    result = subprocess.run([*binary, 'check', *assets, str(paths[0])], capture_output=True, timeout=20)
                    assert result.returncode == 2 and b'invalid Unicode 3.2 table asset' in result.stderr, (selected, i, result.returncode, result.stderr[-300:])
                    controls += 1
    report = {'binary': binary, 'Unicode_version': U.unidata_version, 'total': sum(counts.values()),
              'groups': dict(counts), 'complete_corpus': args.limit is None, 'asset_rejections': controls,
              'corpus_sha256': identity.hexdigest(), 'Name_RDN_comparison_or_chain_authorization': False,
              'IA5_unknown_equality_and_Teletex_profiles': 'unsupported'}
    if args.report: args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
