"""Generate the exact Unicode 3.2 normalization asset from pinned official data."""
import argparse
import hashlib
import gzip
import io
import json
import re
import struct
from functools import lru_cache
from pathlib import Path

HASHES = {
    'UnicodeData-3.2.0.txt': '5e444028b6e76d96f9dc509609c5e3222bf609056f35e5fcde7e6fb8a58cd446',
    'NormalizationTest-3.2.0.txt': 'c4513869bb7098d19838be4a1fd5d760843c5804bfe03bd6bbb20623ceb6e57d',
    'CompositionExclusions-3.2.0.txt': '1d3a450d0f39902710df4972ac4a60ec31fbcb54ffd4d53cd812fc1200c732cb',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unicode-data', required=True, type=Path)
    parser.add_argument('--exclusions', required=True, type=Path)
    parser.add_argument('--normalization-test', required=True, type=Path)
    parser.add_argument('--output-dir', type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    sources = [args.unicode_data, args.exclusions, args.normalization_test]
    for path in sources:
        assert hashlib.sha256(path.read_bytes()).hexdigest() == HASHES[path.name], path
    official = args.normalization_test.read_bytes()
    assert official.startswith(b'# NormalizationTest-3.2.0.txt') and official.rstrip().endswith(b'# END OF FILE')
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode='wb', filename='', mtime=0, compresslevel=9) as stream:
        stream.write(official)
    archive = compressed.getvalue()
    (args.output_dir / 'unicode32_nfkc_vectors.gz').write_bytes(archive)
    ccc, decomposition, canonical = {}, {}, {}
    for line in args.unicode_data.read_text().splitlines():
        fields = line.split(';')
        code = int(fields[0], 16)
        if fields[3] != '0':
            ccc[code] = int(fields[3])
        value = fields[5].split()
        if value:
            compatible = value[0].startswith('<')
            mapped = tuple(int(v, 16) for v in value[1:] if compatible) if compatible else tuple(int(v, 16) for v in value)
            decomposition[code] = mapped
            if not compatible:
                canonical[code] = mapped
    exclusions = {int(line.split('#')[0].strip(), 16) for line in args.exclusions.read_text().splitlines() if line.split('#')[0].strip()}
    assert len(decomposition) == 5143 and len(ccc) == 327

    @lru_cache(None)
    def expand(code):
        if 0xac00 <= code <= 0xd7a3:
            s = code - 0xac00
            result = (0x1100 + s // 588, 0x1161 + s // 28 % 21)
            return result + ((0x11a7 + s % 28,) if s % 28 else ())
        if code in decomposition:
            return tuple(value for part in decomposition[code] for value in expand(part))
        return (code,)

    index, values = [], []
    for code in sorted(decomposition):
        mapped = expand(code)
        assert 1 <= len(mapped) <= 18
        index.extend((code, len(values) * 32 + len(mapped)))
        values.extend((value << 8) | ccc.get(value, 0) for value in mapped)
    classes = [v for code in sorted(ccc) for v in (code, ccc[code])]
    pairs = sorted((mapped[0], mapped[1], code) for code, mapped in canonical.items()
                   if len(mapped) == 2 and code not in exclusions and ccc.get(mapped[0], 0) == 0)
    assert len({(a, b) for a, b, _ in pairs}) == len(pairs)
    assert all(ccc.get(c, 0) == 0 for _, _, c in pairs)
    composition = [v for row in pairs for v in row]
    segments = [('index', index), ('values', values), ('classes', classes), ('composition', composition)]
    raw = b'GRNF3201' + b''.join(struct.pack('>I', value) for _, words in segments for value in words)
    digest = hashlib.sha256(raw).hexdigest()
    (args.output_dir / 'unicode32_nfkc.bin').write_bytes(raw)
    manifest = {'unicode_version': '3.2.0', 'composition_version': '3.1.0', 'asset_sha256': digest,
                'bytes': len(raw), 'format': 'GRNF3201 + big-endian U32 index, packed values, CCC rows, composition triples',
                'sources': HASHES, 'normalization_vectors_gzip_sha256': hashlib.sha256(archive).hexdigest(), 'decomposition_rows': len(decomposition), 'combining_class_rows': len(ccc),
                'composition_rows': len(pairs), 'explicit_exclusions': len(exclusions), 'max_expansion': 18,
                'segments': {name: {'words': len(words), 'array_exponent': (len(words) - 1).bit_length()} for name, words in segments},
                'descriptor': '32 * values offset + length', 'packed_value': '256 * scalar + combining class',
                'pre_corrigendum4': {f'{code:05X}': [f'{v:X}' for v in expand(code)] for code in [0x2f868, 0x2f874, 0x2f91f, 0x2f95f, 0x2f9bf]}}
    (args.output_dir / 'unicode32_nfkc_data.json').write_text(json.dumps(manifest, indent=2) + '\n')
    text = 'import Base\n\n# Generated exact Unicode 3.2 asset metadata; see unicode32_nfkc_data.json.\n'
    text += f'\ndef hash() -> String:\n  "{digest}"\n\ndef bytes() -> Nat:\n  {len(raw)}n\n'
    for name, words in segments:
        text += f'\ndef {name}.words() -> Nat:\n  {len(words)}n\n\ndef {name}.exponent() -> Nat:\n  {(len(words) - 1).bit_length()}n\n'
    for name, count in [('decomposition', len(decomposition)), ('classes', len(ccc)), ('composition', len(pairs))]:
        text += f'\ndef {name}.rows() -> U32:\n  {count}\n'
    (args.output_dir / 'unicode32_nfkc_data.bend').write_text(text)
    print(json.dumps(manifest, sort_keys=True))


if __name__ == '__main__':
    main()
