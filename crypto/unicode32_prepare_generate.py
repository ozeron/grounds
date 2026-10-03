"""Generate authenticated preparation tables from pinned published/property artifacts."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

SOURCES = {'unicode32_fold_vectors.json': '1a20249fc862b1fa010515a753538129e387b8a4e532673de9d307dd9d4c2f87',
           'unicode32_ranges.json': '04f7088a9b6070888bc32f1dd9b88abe64db90c528e5451fb11f7ff7ed429fe8'}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--output-dir', type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    for name, expected in SOURCES.items():
        assert hashlib.sha256((args.source_dir / name).read_bytes()).hexdigest() == expected, name
    fold = json.loads((args.source_dir / 'unicode32_fold_vectors.json').read_text())
    profile = json.loads((args.source_dir / 'unicode32_ranges.json').read_text())
    index, values = [], []
    for code, mapping in fold['mappings']:
        assert 1 <= len(mapping) <= 4
        index.extend((int(code, 16), len(values) * 8 + len(mapping)))
        values.extend(int(c, 16) for c in mapping)
    unassigned = [v for row in profile['unassigned'] for v in row]
    marks = [v for row in profile['marks'] for v in row]
    segments = [('index', index), ('values', values), ('unassigned', unassigned), ('marks', marks)]
    assert [len(v) for _, v in segments] == [2742, 1561, 792, 224]
    raw = b'GRPR3201' + b''.join(struct.pack('>I', value) for _, words in segments for value in words)
    digest = hashlib.sha256(raw).hexdigest()
    manifest = {'unicode_version': '3.2.0', 'format': 'GRPR3201 + U32BE B.2 index/values, unassigned ranges, definitive mark ranges',
                'asset_sha256': digest, 'bytes': len(raw), 'source_artifacts': SOURCES,
                'RFC3454_sha256': fold['source_sha256'], 'RFC4518_sha256': profile['sources']['rfc4518_sha256'],
                'segments': {name: {'words': len(words), 'array_exponent': (len(words) - 1).bit_length()} for name, words in segments}}
    (args.output_dir / 'unicode32_prepare.bin').write_bytes(raw)
    (args.output_dir / 'unicode32_prepare_data.json').write_text(json.dumps(manifest, indent=2) + '\n')
    text = 'import Base\n\n# Generated authenticated B.2/property metadata; see unicode32_prepare_data.json.\n'
    text += f'\ndef hash() -> String:\n  "{digest}"\n\ndef bytes() -> Nat:\n  {len(raw)}n\n'
    for name, words in segments:
        text += f'\ndef {name}.words() -> Nat:\n  {len(words)}n\n\ndef {name}.exponent() -> Nat:\n  {(len(words) - 1).bit_length()}n\n'
    (args.output_dir / 'unicode32_prepare_data.bend').write_text(text)
    print(json.dumps(manifest, sort_keys=True))

if __name__ == '__main__':
    main()
