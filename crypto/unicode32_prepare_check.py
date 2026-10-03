"""Stored-value RFC 4518 scalar preparation against independent Unicode 3.2 rules."""
import argparse
import hashlib
import itertools
import json
import random
import subprocess
import tempfile
import unicodedata
from pathlib import Path

from unicode32_profile_check import expected as property_oracle
from unicode32_nfkc_check import official, batch_bytes, check_output

ROOT = Path(__file__).resolve().parent
U = unicodedata.ucd_3_2_0
PUBLISHED = json.loads((ROOT / 'unicode32_fold_vectors.json').read_text())
FOLD = {int(code, 16): [int(v, 16) for v in values] for code, values in PUBLISHED['mappings']}
assert len(FOLD) == 1371 and U.unidata_version == '3.2.0'


def expected(codes, casefold):
    if len(codes) > 65535 or any(code > 0x10ffff or 0xd800 <= code <= 0xdfff for code in codes):
        return None
    mapped = []
    for code in codes:
        _, action = property_oracle(code)
        if action == 0:
            continue
        code = 32 if action == 1 else code
        mapped.extend(FOLD.get(code, [code]) if casefold else [code])
    normalized = [ord(c) for c in U.normalize('NFKC', ''.join(chr(c) for c in mapped))]
    masks = [property_oracle(code)[0] for code in normalized]
    if any(mask & 4 for mask in masks):
        return None
    # Identify SPACE tokens from the definitive mark property of the next code.
    spaces = [code == 32 and (at + 1 == len(normalized) or not masks[at + 1] & 8)
              for at, code in enumerate(normalized)]
    nonspaces = [at for at, space in enumerate(spaces) if not space]
    if not nonspaces:
        return [32, 32]
    result = [32]
    at, end = nonspaces[0], nonspaces[-1]
    while at <= end:
        if spaces[at]:
            result.extend([32, 32])
            while spaces[at]:
                at += 1
        else:
            result.append(normalized[at])
            at += 1
    return result + [32]


def literal_cases(casefold):
    literals = [
        ([], [32, 32]), ([32, 32, 32], [32, 32]),
        ([0, 0xad, 0x34f, 0xfe0f, 0xfffc], [32, 32]),
        ([9, 10, 13, 0xa0, 0x2002, 0x3000], [32, 32]),
        ([32, 0x300], [32, 32, 0x300, 32]),
        ([32, 0x903], [32, 32, 0x903, 32]),  # Mark with CCC zero.
        ([32, 0x5bd], [32, 0x5bd, 32]),  # Omitted from definitive Appendix A.
        ([0x341], [32, 0x301, 32]),  # Deprecated input becomes allowed after NFKC.
        ([0x1100, 0x1161, 0x11a8], [32, 0xac01, 32]),
        ([0x2f868], [32, 0x2136a, 32]),
        ([0x5d0, 65], [32, 0x5d0, 97 if casefold else 65, 32]),  # No bidi restriction.
        ([0xe000], None), ([0x1c90], None), ([0x94e], None),
        ([0xfffd], None), ([0x10ffff], None),
        ([65, 0xd800, 66], None), ([0xffffffff], None),
        ([65, 0xe000, 66], None),
        ([65, 32, 32, 66, 32], [32, 97 if casefold else 65, 32, 32, 98 if casefold else 66, 32]),
        ([0xdf], [32, 115, 115, 32] if casefold else [32, 0xdf, 32]),
        ([0x13a0], [32, 0x13a0, 32]),
    ]
    for codes, wanted in literals:
        assert expected(codes, casefold) == wanted, ('literal oracle', codes, wanted)
        yield codes, wanted, 'literal'


def sequences(casefold):
    pool = [0, 9, 32, 65, 66, 97, 0xad, 0xdf, 0xa0, 0xe9, 0x300, 0x301,
            0x315, 0x323, 0x341, 0x34f, 0x5bd, 0x5d0, 0x903, 0x94e, 0x1100,
            0x1161, 0x11a8, 0xac00, 0x13a0, 0x1c90, 0x200b, 0xe000,
            0xfdfa, 0x33c6, 0xfe0f, 0xfffd, 0x2f868, 0x2f95f]
    random_source = random.Random(451832)
    for _ in range(2048):
        codes = [random_source.choice(pool) for _ in range(random_source.randrange(0, 65))]
        yield codes, expected(codes, casefold), 'random'
    # Exhaustively exercise short space/mark/deletion neighborhoods.
    for length in range(1, 6):
        for codes in itertools.product([32, 65, 0x300, 0x903, 0x5bd, 0xad], repeat=length):
            codes = list(codes)
            yield codes, expected(codes, casefold), 'neighborhood'
    for code in FOLD:
        codes = [65, code, 32, 0x300, 66]
        yield codes, expected(codes, casefold), 'published_fold'


def cases(casefold):
    yield from literal_cases(casefold)
    for codes, _, _ in official():
        yield codes, expected(codes, casefold), 'official_inputs'
    yield from sequences(casefold)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', required=True, choices=['fold', 'exact'])
    parser.add_argument('--report', type=Path)
    parser.add_argument('--start', type=int, default=0, help='first corpus case for isolated diagnosis')
    parser.add_argument('--limit', type=int)
    parser.add_argument('--asset-controls', action='store_true')
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ['--'] else args.binary
    if not binary:
        parser.error('supply evaluator')
    if args.start < 0 or args.limit is not None and args.limit < 0:
        parser.error('start and limit must be nonnegative')
    source = cases(args.mode == 'fold')
    source = itertools.islice(source, args.start, None if args.limit is None else args.start + args.limit)
    counts, identity = {}, hashlib.sha256()
    with tempfile.TemporaryDirectory() as directory:
        paths = [Path(directory) / f'batch-{at}.bin' for at in range(2)]
        while batch := list(itertools.islice(source, 256)):
            # Keep each scalar-fixture transport bounded while retaining one
            # authenticated table owner across both files in the evaluator.
            selected = []
            for at, start in enumerate(range(0, len(batch), 128)):
                paths[at].write_bytes(batch_bytes(batch[start:start + 128]))
                selected.append(str(paths[at]))
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                result = subprocess.run([*binary, args.mode, str(ROOT / 'unicode32_nfkc.bin'), str(ROOT / 'unicode32_prepare.bin'), *selected], stdout=output, stderr=errors, timeout=100)
                errors.seek(0, 2); errors.seek(max(0, errors.tell() - 1200))
                assert result.returncode == 0, (result.returncode, errors.read())
                check_output(output, batch, identity)
            for _, _, kind in batch:
                counts[kind] = counts.get(kind, 0) + 1
            if sum(counts.values()) % 8192 == 0:
                print('verified', args.mode, sum(counts.values()), flush=True)
    asset_controls = 0
    if args.asset_controls:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            batch = directory / 'empty.bin'
            batch.write_bytes(batch_bytes([([], [32, 32], 'control')]))
            for selected in ['unicode32_nfkc.bin', 'unicode32_prepare.bin']:
                raw = (ROOT / selected).read_bytes()
                variants = [b'', raw[:-1], raw + b'\0']
                for offset in [0, 8, len(raw) // 2, len(raw) - 1]:
                    altered = bytearray(raw); altered[offset] ^= 1; variants.append(altered)
                for at, data in enumerate(variants):
                    asset = directory / f'{selected}-{at}'
                    asset.write_bytes(data)
                    paths = [str(asset if name == selected else ROOT / name) for name in ['unicode32_nfkc.bin', 'unicode32_prepare.bin']]
                    result = subprocess.run([*binary, args.mode, *paths, str(batch)], capture_output=True, timeout=20)
                    assert result.returncode == 2 and b'invalid Unicode 3.2 table asset' in result.stderr, (selected, at, result.returncode, result.stderr[-300:])
                    asset_controls += 1
    report = {'binary': binary, 'mode': args.mode, 'Unicode_version': U.unidata_version, 'asset_rejections': asset_controls,
              'cases': counts, 'start': args.start, 'complete_corpus': args.start == 0 and args.limit is None,
              'scalar_stored_preparation_only_not_transcoding_Name_or_certificate_authorization': True,
              'corpus_sha256': identity.hexdigest()}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
